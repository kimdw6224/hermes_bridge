"""엄격한 shell_run 입력 경계와 logged-in-user Worker 어댑터입니다."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003 - Pydantic runtime annotation입니다.
from typing import TYPE_CHECKING, Annotated, ClassVar, Literal, final
from uuid import UUID  # noqa: TC003 - Pydantic runtime annotation입니다.

from mcp.types import CallToolResult, ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, field_validator

from hermes_windows_bridge.gateway.dispatcher import DispatchCall

DEFAULT_TIMEOUT_SECONDS = 60
MAX_SYNC_SECONDS = 110

if TYPE_CHECKING:

    from hermes_windows_bridge.gateway.dispatcher import GatewayDispatcher
    from hermes_windows_bridge.gateway.mcp_server import GatewayMCPServer
    from hermes_windows_bridge.ipc.protocol import JsonPayload
    from hermes_windows_bridge.models.config import PolicySettings
    from hermes_windows_bridge.worker.shell import ShellResult, ShellWorker


class ShellRunInput(BaseModel):
    """외부 shell_run payload의 유일한 parse 경계입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    operation_id: UUID
    command: Annotated[str, Field(min_length=1, max_length=32_767)]
    cwd: Path
    shell: Literal["powershell", "cmd", "git-bash"] = "powershell"
    timeout_s: Annotated[int, Field(gt=0, le=MAX_SYNC_SECONDS)] = DEFAULT_TIMEOUT_SECONDS

    @field_validator("command")
    @classmethod
    def command_has_no_nul(cls, command: str) -> str:
        """Win32 command line을 조기에 자르는 NUL을 거부합니다."""
        if "\0" in command:
            raise InvalidShellCommandError
        return command


@final
class ShellTools:
    """Gateway/Helper에서 실행하지 않고 Worker 구현만 호출합니다."""

    def __init__(self, worker: ShellWorker) -> None:
        """실행 권한을 가진 Worker만 보관합니다."""
        self._worker = worker

    @classmethod
    def from_settings(cls, policy: PolicySettings) -> ShellTools:
        """정책의 동기 시간/output 상한으로 Worker를 구성합니다."""
        from hermes_windows_bridge.worker.shell import ShellWorker  # noqa: PLC0415

        return cls(
            ShellWorker(
                max_output_bytes=policy.shell.max_output_bytes,
                max_sync_seconds=policy.shell.max_sync_seconds,
                inspect_commands_for_accident_prevention=(
                    policy.shell.inspect_commands_for_accident_prevention
                ),
            )
        )

    def shell_run(self, request: ShellRunInput) -> ShellResult:
        """검증된 payload를 현재 interactive Worker로 전달합니다."""
        from hermes_windows_bridge.worker.shell import ShellKind, ShellRequest  # noqa: PLC0415

        return self._worker.run(
            ShellRequest(
                command=request.command,
                cwd=request.cwd,
                shell=ShellKind(request.shell),
                timeout_s=request.timeout_s,
            )
        )


class InvalidShellCommandError(ValueError):
    """Command는 비어 있지 않고 NUL을 포함하지 않아야 합니다."""


def register_shell_tool(server: GatewayMCPServer, dispatcher: GatewayDispatcher) -> None:
    """공식 MCP API에 Worker IPC로만 위임하는 shell_run을 등록합니다."""

    async def shell_run(
        operation_id: UUID,
        command: Annotated[str, Field(min_length=1, max_length=32_767)],
        cwd: Path,
        shell: Literal["powershell", "cmd", "git-bash"] = "powershell",
        timeout_s: Annotated[int, Field(gt=0, le=MAX_SYNC_SECONDS)] = DEFAULT_TIMEOUT_SECONDS,
    ) -> CallToolResult:
        request = ShellRunInput(
            operation_id=operation_id,
            command=command,
            cwd=cwd,
            shell=shell,
            timeout_s=timeout_s,
        )
        payload: JsonPayload = {
            "command": request.command,
            "cwd": str(request.cwd),
            "shell": request.shell,
            "timeout_s": request.timeout_s,
        }
        outcome = await dispatcher.dispatch(
            DispatchCall(
                operation_id=request.operation_id,
                tool_name="shell_run",
                payload=payload,
                requested_at=datetime.now(UTC),
                timeout_ms=request.timeout_s * 1_000,
            )
        )
        return outcome.result

    server.add_closed_tool(
        shell_run,
        input_model=ShellRunInput,
        name="shell_run",
        description="Run a bounded shell command through the interactive user Worker.",
        annotations=ToolAnnotations(
            read_only_hint=False,
            destructive_hint=True,
            idempotent_hint=False,
            open_world_hint=True,
        ),
        structured_output=False,
    )
