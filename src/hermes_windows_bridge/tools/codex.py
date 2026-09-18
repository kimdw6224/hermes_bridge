"""Codex adapter의 closed input models와 service facade입니다."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003 - Pydantic runtime annotation입니다.
from typing import TYPE_CHECKING, Annotated, ClassVar, Final, Literal, Protocol, final
from uuid import UUID  # noqa: TC003 - Pydantic runtime annotation입니다.

from mcp.types import CallToolResult, ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, field_validator

from hermes_windows_bridge.gateway.dispatcher import DispatchCall
from hermes_windows_bridge.gateway.job_models import JobSnapshot  # noqa: TC001
from hermes_windows_bridge.models.policy import StrictFrozenModel

if TYPE_CHECKING:
    from hermes_windows_bridge.gateway.dispatcher import GatewayDispatcher
    from hermes_windows_bridge.gateway.mcp_server import GatewayMCPServer
    from hermes_windows_bridge.ipc.protocol import JsonPayload

_CODEX_DISPATCH_TIMEOUT_MS: Final = 10_000
_MAX_COMMAND_OUTPUT: Final = 1_000_000


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Credential을 해석하지 않는 bounded command 결과입니다."""

    exit_code: int
    stdout: str
    stderr: str


class CommandRunner(Protocol):
    """CLI 및 Git read-only probe를 대체할 수 있는 좁은 seam입니다."""

    def __call__(self, argv: tuple[str, ...], cwd: Path, timeout_s: int) -> CommandResult:
        """Literal argv를 실행해 bounded text를 반환합니다."""
        ...


def run_bounded_command(argv: tuple[str, ...], cwd: Path, timeout_s: int) -> CommandResult:
    """Shell 없이 literal argv를 실행하고 출력을 전역 상한으로 자릅니다."""
    try:
        completed = subprocess.run(  # noqa: S603 - literal argv이며 shell을 사용하지 않습니다.
            argv,
            cwd=cwd,
            capture_output=True,
            timeout=timeout_s,
            check=False,
            # pythonw Worker에서도 조회용 CLI가 콘솔이나 입력 대기를 만들지 않게 합니다.
            creationflags=subprocess.CREATE_NO_WINDOW,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError, subprocess.TimeoutExpired:
        return CommandResult(127, "", "")
    return CommandResult(
        completed.returncode,
        completed.stdout[:_MAX_COMMAND_OUTPUT].decode("utf-8", errors="replace"),
        completed.stderr[:_MAX_COMMAND_OUTPUT].decode("utf-8", errors="replace"),
    )


class _CodexInput(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)


class CodexRunInput(_CodexInput):
    """codex_run의 strict 외부 입력입니다."""

    operation_id: UUID
    prompt: Annotated[str, Field(min_length=1, max_length=32_767)]
    cwd: Path
    model: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    effort: Literal["low", "medium", "high", "xhigh", "max", "ultra"] | None = None
    dirty_policy: Literal["preserve"] | None = None
    timeout_s: Annotated[int, Field(gt=0, le=86_400)] = 900

    @field_validator("prompt", "model")
    @classmethod
    def reject_nul(cls, value: str | None) -> str | None:
        """Win32 argv를 조기에 자르는 NUL을 거부합니다."""
        if value is not None and "\0" in value:
            raise InvalidCodexArgumentError
        return value


class CodexStatusInput(_CodexInput):
    """codex_status의 idempotency/audit correlation 입력입니다."""

    operation_id: UUID


class CodexAdapterProtocol(Protocol):
    """Service facade가 요구하는 adapter 계약입니다."""

    def status(self) -> CodexStatus:
        """Credential-free 상태를 반환합니다."""
        ...

    def start(  # noqa: PLR0913 - CodexRunInput과 동일한 typed fields입니다.
        self,
        *,
        operation_id: UUID,
        prompt: str,
        cwd: Path,
        model: str | None,
        effort: str | None,
        dirty_policy: str | None,
        timeout_s: int,
    ) -> CodexJobStart:
        """Durable Codex job을 시작합니다."""
        ...

    def postflight(self, job_id: UUID) -> CodexPostflight:
        """Terminal job의 Git 상태를 반환합니다."""
        ...


@final
class CodexTools:
    """Logged-in-user adapter 외에는 Codex를 실행하지 않는 facade입니다."""

    def __init__(self, adapter: CodexAdapterProtocol) -> None:
        """현재 logged-in-user adapter를 보관합니다."""
        self._adapter = adapter

    def codex_status(self) -> CodexStatus:
        """Credential을 제외한 CLI 상태를 반환합니다."""
        return self._adapter.status()

    def codex_run(self, request: CodexRunInput) -> CodexJobStart:
        """Git-safe Codex durable job을 시작합니다."""
        return self._adapter.start(
            operation_id=request.operation_id,
            prompt=request.prompt,
            cwd=request.cwd,
            model=request.model,
            effort=request.effort,
            dirty_policy=request.dirty_policy,
            timeout_s=request.timeout_s,
        )

    def codex_postflight(self, job_id: UUID) -> CodexPostflight:
        """완료된 Codex job의 Git postflight를 반환합니다."""
        return self._adapter.postflight(job_id)


class InvalidCodexArgumentError(ValueError):
    """Codex prompt/model은 NUL을 포함할 수 없습니다."""


class CodexStatus(StrictFrozenModel):
    """Credential 내용을 포함하지 않는 현재 CLI 기능 상태입니다."""

    executable: Path | None
    version: str | None
    callable: bool
    login_available: bool
    exec_supported: bool
    model_option_supported: bool
    effort_option_supported: bool


class GitSnapshot(StrictFrozenModel):
    """Git read-only pre/postflight의 typed 기록입니다."""

    is_repository: bool
    repo_root: Path | None = None
    branch: str | None = None
    head: str | None = None
    status_porcelain: tuple[str, ...] = ()
    dirty_files: tuple[str, ...] = ()
    diff_stat: str = ""


class CodexInvocation(StrictFrozenModel):
    """Prompt 본문을 노출하지 않는 capability-derived 호출 기록입니다."""

    command_prefix: tuple[str, ...]
    argument_count: int
    model_applied: bool
    effort_applied: bool
    preservation_instruction_applied: bool
    requested_timeout_s: int


class CodexJobStart(StrictFrozenModel):
    """Durable job handle과 실행 전 Git 상태입니다."""

    job: JobSnapshot
    preflight: GitSnapshot
    invocation: CodexInvocation


class CodexPostflight(StrictFrozenModel):
    """Terminal job과 같은 cwd에서 다시 읽은 Git 상태입니다."""

    job_id: UUID
    job: JobSnapshot
    preflight: GitSnapshot
    postflight: GitSnapshot


def register_codex_tools(server: GatewayMCPServer, dispatcher: GatewayDispatcher) -> None:
    """Public Codex calls를 Gateway 정책/IPC 경계에만 등록합니다."""

    async def codex_status(operation_id: UUID) -> CallToolResult:
        request = CodexStatusInput(operation_id=operation_id)
        return await _dispatch(dispatcher, request.operation_id, "codex_status", {})

    async def codex_run(  # noqa: PLR0913, PLR0917 - 공개 schema 필드를 명시합니다.
        operation_id: UUID,
        prompt: Annotated[str, Field(min_length=1, max_length=32_767)],
        cwd: Path,
        model: Annotated[str, Field(min_length=1, max_length=256)] | None = None,
        effort: Literal["low", "medium", "high", "xhigh", "max", "ultra"] | None = None,
        dirty_policy: Literal["preserve"] | None = None,
        timeout_s: Annotated[int, Field(gt=0, le=86_400)] = 900,
    ) -> CallToolResult:
        request = CodexRunInput(
            operation_id=operation_id,
            prompt=prompt,
            cwd=cwd,
            model=model,
            effort=effort,
            dirty_policy=dirty_policy,
            timeout_s=timeout_s,
        )
        payload: JsonPayload = {
            "prompt": request.prompt,
            "cwd": str(request.cwd),
            "model": request.model,
            "effort": request.effort,
            "dirty_policy": request.dirty_policy,
            "timeout_s": request.timeout_s,
        }
        return await _dispatch(dispatcher, request.operation_id, "codex_run", payload)

    server.add_closed_tool(
        codex_status,
        input_model=CodexStatusInput,
        name="codex_status",
        description=(
            "Report local Codex CLI callability and login availability without credentials."
        ),
        annotations=ToolAnnotations(
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
        structured_output=False,
    )
    server.add_closed_tool(
        codex_run,
        input_model=CodexRunInput,
        name="codex_run",
        description="Start a Git-preserving Codex job as the logged-in user.",
        annotations=ToolAnnotations(
            read_only_hint=False,
            destructive_hint=True,
            idempotent_hint=True,
            open_world_hint=True,
        ),
        structured_output=False,
    )


async def _dispatch(
    dispatcher: GatewayDispatcher,
    operation_id: UUID,
    tool_name: Literal["codex_status", "codex_run"],
    payload: JsonPayload,
) -> CallToolResult:
    outcome = await dispatcher.dispatch(
        DispatchCall(
            operation_id=operation_id,
            tool_name=tool_name,
            payload=payload,
            requested_at=datetime.now(UTC),
            timeout_ms=_CODEX_DISPATCH_TIMEOUT_MS,
        )
    )
    return outcome.result
