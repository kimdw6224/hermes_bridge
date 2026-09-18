"""승인된 local job 호출의 typed invocation과 canonical idempotency adapter입니다."""

# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime  # noqa: TC003 - Pydantic runtime annotation입니다.
from pathlib import Path  # noqa: TC003 - Pydantic runtime annotation입니다.
from typing import TYPE_CHECKING, Annotated, ClassVar, Literal, assert_never, override
from uuid import UUID  # noqa: TC003 - Pydantic runtime annotation입니다.

from anyio import fail_after, to_thread
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

from hermes_windows_bridge.gateway import job_models
from hermes_windows_bridge.gateway.idempotency import (
    IdempotencyConflictError,
    IdempotencyStore,
    OperationCall,
)
from hermes_windows_bridge.ipc import protocol as ipc
from hermes_windows_bridge.models import policy as policy_models

if TYPE_CHECKING:
    from hermes_windows_bridge.gateway.jobs import JobRegistry

type _JobToolName = Literal["job_start", "job_status", "job_output", "job_cancel"]
type JobDispatchErrorCode = Literal[
    "dispatch_timeout",
    "idempotency_conflict",
    "invalid_request",
    "job_not_found",
    "job_service_unavailable",
]
_JSON_PAYLOAD_ADAPTER: TypeAdapter[ipc.JsonPayload] = TypeAdapter(ipc.JsonPayload)
_IDEMPOTENCY_CONFLICT = "idempotency_conflict"
_INVALID_REQUEST = "invalid_request"
_JOB_NOT_FOUND = "job_not_found"
_JOB_UNAVAILABLE = "job_service_unavailable"
_DISPATCH_TIMEOUT = "dispatch_timeout"


class JobDispatchCall(policy_models.StrictFrozenModel):
    """Gateway 정책 승인이 끝난 local job 호출입니다."""

    operation_id: UUID
    tool_name: _JobToolName
    payload: ipc.JsonPayload
    requested_at: datetime


@dataclass(frozen=True, slots=True)
class JobDispatchResult:
    """Local 실행 결과 또는 sanitized 오류 코드입니다."""

    payload: ipc.JsonPayload
    replayed: bool


class JobDispatchError(RuntimeError):
    """Gateway presentation 경계로 전달하는 sanitized 오류입니다."""

    def __init__(self, code: JobDispatchErrorCode) -> None:
        """예외 traceback을 허용하면서 공개 가능한 코드만 보관합니다."""
        super().__init__(code)
        self.code: JobDispatchErrorCode = code

    @override
    def __str__(self) -> str:
        return self.code


class _JobPayload(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)


class _JobStartPayload(_JobPayload):
    kind: job_models.JobKind = job_models.JobKind.PROCESS
    argv: Annotated[tuple[str, ...], Field(min_length=1, max_length=256)]
    cwd: Path


class _JobIdPayload(_JobPayload):
    job_id: UUID


class _JobOutputPayload(_JobIdPayload):
    stream: job_models.JobOutputStream = "stdout"
    offset: Annotated[int, Field(ge=0)]
    limit: Annotated[int, Field(gt=0, le=job_models.MAX_JOB_OUTPUT_CHUNK_BYTES)]


async def dispatch_job(
    registry: JobRegistry | None,
    idempotency: IdempotencyStore,
    call: JobDispatchCall,
    timeout_ms: int,
) -> JobDispatchResult:
    """Local 호출도 MCP 제한 시간 안에서만 기다립니다."""
    if registry is None:
        raise JobDispatchError(_JOB_UNAVAILABLE)
    try:
        with fail_after(timeout_ms / 1_000):
            return await to_thread.run_sync(
                execute_job_call,
                registry,
                idempotency,
                call,
                abandon_on_cancel=True,
            )
    except TimeoutError as error:
        raise JobDispatchError(_DISPATCH_TIMEOUT) from error


def execute_job_call(
    registry: JobRegistry,
    idempotency: IdempotencyStore,
    call: JobDispatchCall,
) -> JobDispatchResult:
    """Canonical request를 한 번 실행하고 동일 결과만 replay합니다."""
    try:
        cached = idempotency.execute(
            call=__operation_call(call),
            operation=lambda: policy_models.canonicalize_payload(_invoke(registry, call)),
        )
        payload = _JSON_PAYLOAD_ADAPTER.validate_json(cached.payload)
    except IdempotencyConflictError as error:
        raise JobDispatchError(_IDEMPOTENCY_CONFLICT) from error
    except (
        ValidationError,
        job_models.InvalidJobSpecError,
        job_models.InvalidOutputWindowError,
    ) as error:
        raise JobDispatchError(_INVALID_REQUEST) from error
    except job_models.JobNotFoundError as error:
        raise JobDispatchError(_JOB_NOT_FOUND) from error
    except job_models.JobRegistryClosedError as error:
        raise JobDispatchError(_JOB_UNAVAILABLE) from error
    return JobDispatchResult(payload, cached.replayed)


def __operation_call(call: JobDispatchCall) -> OperationCall:
    return OperationCall(
        operation_id=call.operation_id,
        payload={"tool": call.tool_name, "payload": call.payload},
        requested_at=call.requested_at,
    )


def _invoke(registry: JobRegistry, call: JobDispatchCall) -> ipc.JsonPayload:
    match call.tool_name:
        case "job_start":
            request = _JobStartPayload.model_validate(call.payload)
            result = registry.start(
                job_models.JobSpec(call.operation_id, request.kind, request.argv, request.cwd)
            )
        case "job_status":
            result = registry.status(_JobIdPayload.model_validate(call.payload).job_id)
        case "job_output":
            request = _JobOutputPayload.model_validate(call.payload)
            result = registry.output(
                request.job_id,
                stream=request.stream,
                offset=request.offset,
                limit=request.limit,
            )
        case "job_cancel":
            result = registry.cancel(_JobIdPayload.model_validate(call.payload).job_id)
        case unreachable:
            assert_never(unreachable)
    return _JSON_PAYLOAD_ADAPTER.validate_python(result.model_dump(mode="json"))
