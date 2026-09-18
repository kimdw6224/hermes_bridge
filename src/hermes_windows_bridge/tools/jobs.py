"""Durable generic jobs의 strict MCP 입력과 service adapter입니다."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003 - Pydantic runtime annotation입니다.
from typing import TYPE_CHECKING, Annotated, ClassVar, Literal, final
from uuid import UUID, uuid4

from mcp.types import CallToolResult, ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, field_validator

from hermes_windows_bridge.gateway.dispatcher import DispatchCall, GatewayDispatcher
from hermes_windows_bridge.gateway.job_models import (
    MAX_JOB_OUTPUT_CHUNK_BYTES,
    JobKind,
    JobOutput,
    JobSnapshot,
    JobSpec,
)


class _ToolModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)


class JobStartInput(_ToolModel):
    """즉시 handle을 반환하는 job_start 입력입니다."""

    operation_id: UUID
    approval_id: UUID | None = None
    kind: JobKind = JobKind.PROCESS
    argv: Annotated[tuple[str, ...], Field(min_length=1, max_length=256)]
    cwd: Path

    @field_validator("argv")
    @classmethod
    def argv_has_no_empty_or_nul_values(cls, argv: tuple[str, ...]) -> tuple[str, ...]:
        """CreateProcess 경계를 흐리는 빈 값과 NUL을 거부합니다."""
        if any(not value or "\0" in value for value in argv):
            raise InvalidJobArgumentError
        return argv


class JobStatusInput(_ToolModel):
    """Durable job metadata 조회 입력입니다."""

    job_id: UUID


class JobOutputInput(_ToolModel):
    """한 stream의 bounded UTF-8 byte window 입력입니다."""

    job_id: UUID
    stream: Literal["stdout", "stderr"] = "stdout"
    offset: Annotated[int, Field(ge=0)] = 0
    limit: Annotated[int, Field(gt=0, le=MAX_JOB_OUTPUT_CHUNK_BYTES)] = MAX_JOB_OUTPUT_CHUNK_BYTES


class JobCancelInput(_ToolModel):
    """명시적 job handle 취소 입력입니다."""

    job_id: UUID


@final
class JobTools:
    """Gateway-owned registry를 MCP 도구 표면에 연결합니다."""

    def __init__(self, registry: JobRegistry) -> None:
        """Gateway registry를 보관합니다."""
        self._registry = registry

    def job_start(self, request: JobStartInput) -> JobSnapshot:
        """작업을 background에 제출하고 bounded 시간 안에 ID를 반환합니다."""
        return self._registry.start(
            JobSpec(
                operation_id=request.operation_id,
                kind=request.kind,
                argv=request.argv,
                cwd=request.cwd,
            )
        )

    def job_status(self, request: JobStatusInput) -> JobSnapshot:
        """현재 durable metadata snapshot을 반환합니다."""
        return self._registry.status(request.job_id)

    def job_output(self, request: JobOutputInput) -> JobOutput:
        """요청한 stream window만 반환합니다."""
        return self._registry.output(
            request.job_id,
            stream=request.stream,
            offset=request.offset,
            limit=request.limit,
        )

    def job_cancel(self, request: JobCancelInput) -> JobSnapshot:
        """전체 process tree cancellation을 요청합니다."""
        return self._registry.cancel(request.job_id)


def register_remote_job_tools(server: GatewayMCPServer, dispatcher: GatewayDispatcher) -> None:
    """운영 job 도구를 정책/승인 후 로그인 Worker로 전달하도록 등록합니다."""
    dispatcher = _require_dispatcher(dispatcher)

    async def job_start(
        operation_id: UUID,
        argv: Annotated[tuple[str, ...], Field(min_length=1, max_length=256)],
        cwd: Path,
        kind: JobKind = JobKind.PROCESS,
        approval_id: UUID | None = None,
    ) -> CallToolResult:
        request = JobStartInput(
            operation_id=operation_id,
            approval_id=approval_id,
            kind=kind,
            argv=argv,
            cwd=cwd,
        )
        payload: JsonPayload = {
            "kind": request.kind.value,
            "argv": list(request.argv),
            "cwd": str(request.cwd),
        }
        return await _dispatch(
            dispatcher,
            "job_start",
            request.operation_id,
            payload,
            approval_id=request.approval_id,
        )

    async def job_status(job_id: UUID) -> CallToolResult:
        request = JobStatusInput(job_id=job_id)
        return await _dispatch(dispatcher, "job_status", uuid4(), {"job_id": str(request.job_id)})

    async def job_output(
        job_id: UUID,
        stream: Literal["stdout", "stderr"] = "stdout",
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(gt=0, le=MAX_JOB_OUTPUT_CHUNK_BYTES)] = (
            MAX_JOB_OUTPUT_CHUNK_BYTES
        ),
    ) -> CallToolResult:
        request = JobOutputInput(job_id=job_id, stream=stream, offset=offset, limit=limit)
        return await _dispatch(
            dispatcher,
            "job_output",
            uuid4(),
            {
                "job_id": str(request.job_id),
                "stream": request.stream,
                "offset": request.offset,
                "limit": request.limit,
            },
        )

    async def job_cancel(job_id: UUID) -> CallToolResult:
        request = JobCancelInput(job_id=job_id)
        return await _dispatch(dispatcher, "job_cancel", uuid4(), {"job_id": str(request.job_id)})

    server.add_closed_tool(
        job_start,
        input_model=JobStartInput,
        name="job_start",
        description="Start a durable bounded background process and return its job ID immediately.",
        annotations=_annotations(
            read_only=False,
            destructive=True,
            idempotent=True,
            open_world=True,
        ),
        structured_output=True,
    )
    server.add_closed_tool(
        job_status,
        input_model=JobStatusInput,
        name="job_status",
        description="Poll durable job metadata by explicit job ID.",
        annotations=_annotations(read_only=True, destructive=False, idempotent=True),
        structured_output=True,
    )
    server.add_closed_tool(
        job_output,
        input_model=JobOutputInput,
        name="job_output",
        description="Read one bounded UTF-8 output window by explicit job ID.",
        annotations=_annotations(read_only=True, destructive=False, idempotent=True),
        structured_output=True,
    )
    server.add_closed_tool(
        job_cancel,
        input_model=JobCancelInput,
        name="job_cancel",
        description="Cancel a durable job and its entire Windows process tree.",
        annotations=_annotations(read_only=False, destructive=True, idempotent=True),
        structured_output=True,
    )


def register_job_tools(server: GatewayMCPServer, dispatcher: GatewayDispatcher) -> None:
    """Task 17 호출자를 위해 기존 job 등록 API를 보존합니다."""
    register_remote_job_tools(server, dispatcher)


def _annotations(
    *,
    read_only: bool,
    destructive: bool,
    idempotent: bool,
    open_world: bool = False,
) -> ToolAnnotations:
    return ToolAnnotations(
        read_only_hint=read_only,
        destructive_hint=destructive,
        idempotent_hint=idempotent,
        open_world_hint=open_world,
    )


def _require_dispatcher(candidate: GatewayDispatcher | JobTools) -> GatewayDispatcher:
    if not isinstance(candidate, GatewayDispatcher):
        raise InvalidJobDispatcherError
    return candidate


async def _dispatch(
    dispatcher: GatewayDispatcher,
    tool_name: str,
    operation_id: UUID,
    payload: JsonPayload,
    *,
    approval_id: UUID | None = None,
) -> CallToolResult:
    outcome = await dispatcher.dispatch(
        DispatchCall(
            operation_id=operation_id,
            tool_name=tool_name,
            payload=payload,
            requested_at=datetime.now(UTC),
            timeout_ms=5_000,
            approval_id=approval_id,
        )
    )
    return outcome.result


class InvalidJobArgumentError(ValueError):
    """Job argv의 빈 값 또는 NUL을 거부합니다."""


class InvalidJobDispatcherError(TypeError):
    """Public job 등록은 GatewayDispatcher 없이는 fail-closed 합니다."""


if TYPE_CHECKING:
    from hermes_windows_bridge.gateway.jobs import JobRegistry
    from hermes_windows_bridge.gateway.mcp_server import GatewayMCPServer
    from hermes_windows_bridge.ipc.protocol import JsonPayload
