"""승인 receipt가 필요한 typed 전원 MCP 도구입니다."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Annotated, ClassVar
from uuid import UUID  # noqa: TC003 - Pydantic/runtime MCP annotation입니다.

from mcp.server.mcpserver import Context  # noqa: TC002 - SDK가 runtime annotation을 검사합니다.
from mcp.types import CallToolResult, ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field

from hermes_windows_bridge.gateway.approval_elicitation import McpElicitationApprovalSurface
from hermes_windows_bridge.gateway.dispatcher import DispatchCall, GatewayDispatcher
from hermes_windows_bridge.gateway.policy import (
    ApprovalCoordinator,
    ApprovalDeniedError,
    ApprovalExpiredError,
    ApprovalManager,
    ApprovalSubmission,
)

if TYPE_CHECKING:
    from hermes_windows_bridge.gateway.mcp_server import GatewayMCPServer
    from hermes_windows_bridge.ipc.protocol import JsonPayload

__all__ = (
    "InvalidSystemDispatcherError",
    "SystemLockInput",
    "SystemRebootInput",
    "SystemShutdownInput",
    "SystemSleepInput",
    "register_system_tools",
)


class _PowerInput(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    operation_id: UUID
    approval_id: UUID | None = None
    delay_seconds: Annotated[int, Field(ge=0, le=300)] = 0
    reason: Annotated[str, Field(min_length=1, max_length=200)]


class SystemRebootInput(_PowerInput):
    """`system_reboot`의 closed model-visible 입력입니다."""


class SystemShutdownInput(_PowerInput):
    """`system_shutdown`의 closed model-visible 입력입니다."""


class _SessionPowerInput(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    operation_id: UUID


class SystemLockInput(_SessionPowerInput):
    """`system_lock`의 closed model-visible 입력입니다."""


class SystemSleepInput(_SessionPowerInput):
    """`system_sleep`의 closed model-visible 입력입니다."""


class InvalidSystemDispatcherError(TypeError):
    """System 도구가 정책 dispatcher를 우회하려는 구성을 거부합니다."""


def register_system_tools(
    server: GatewayMCPServer,
    dispatcher: GatewayDispatcher | None,
    approval_manager: ApprovalManager | None = None,
) -> None:
    """모든 typed system 도구를 GatewayDispatcher 경유로 등록합니다."""
    if not isinstance(dispatcher, GatewayDispatcher):
        raise InvalidSystemDispatcherError

    async def system_reboot(
        operation_id: UUID,
        reason: Annotated[str, Field(min_length=1, max_length=200)],
        context: Context[None, None],
        approval_id: UUID | None = None,
        delay_seconds: Annotated[int, Field(ge=0, le=300)] = 0,
    ) -> CallToolResult:
        request = SystemRebootInput(
            operation_id=operation_id,
            approval_id=approval_id,
            delay_seconds=delay_seconds,
            reason=reason,
        )
        return await _dispatch(dispatcher, approval_manager, context, "system_reboot", request)

    async def system_shutdown(
        operation_id: UUID,
        reason: Annotated[str, Field(min_length=1, max_length=200)],
        context: Context[None, None],
        approval_id: UUID | None = None,
        delay_seconds: Annotated[int, Field(ge=0, le=300)] = 0,
    ) -> CallToolResult:
        request = SystemShutdownInput(
            operation_id=operation_id,
            approval_id=approval_id,
            delay_seconds=delay_seconds,
            reason=reason,
        )
        return await _dispatch(dispatcher, approval_manager, context, "system_shutdown", request)

    async def system_lock(operation_id: UUID) -> CallToolResult:
        request = SystemLockInput(operation_id=operation_id)
        return await _dispatch_session_power(dispatcher, "system_lock", request)

    async def system_sleep(operation_id: UUID) -> CallToolResult:
        request = SystemSleepInput(operation_id=operation_id)
        return await _dispatch_session_power(dispatcher, "system_sleep", request)

    annotations = ToolAnnotations(
        read_only_hint=False,
        destructive_hint=True,
        idempotent_hint=True,
        open_world_hint=False,
    )
    server.add_closed_tool(
        system_reboot,
        input_model=SystemRebootInput,
        name="system_reboot",
        description="Restart Windows after consuming an independent one-shot approval receipt.",
        annotations=annotations,
        structured_output=True,
    )
    server.add_closed_tool(
        system_shutdown,
        input_model=SystemShutdownInput,
        name="system_shutdown",
        description="Shut down Windows after consuming an independent one-shot approval receipt.",
        annotations=annotations,
        structured_output=True,
    )
    session_annotations = ToolAnnotations(
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    )
    server.add_closed_tool(
        system_lock,
        input_model=SystemLockInput,
        name="system_lock",
        description="Lock the current logged-in user workstation through the interactive Worker.",
        annotations=session_annotations,
        structured_output=True,
    )
    server.add_closed_tool(
        system_sleep,
        input_model=SystemSleepInput,
        name="system_sleep",
        description="Request normal sleep through the interactive non-elevated Worker.",
        annotations=session_annotations,
        structured_output=True,
    )


async def _dispatch(
    dispatcher: GatewayDispatcher,
    approval_manager: ApprovalManager | None,
    context: Context[None, None],
    tool_name: str,
    request: _PowerInput,
) -> CallToolResult:
    payload: JsonPayload = {
        "delay_seconds": request.delay_seconds,
        "reason": request.reason,
    }
    approval_id = request.approval_id
    if approval_id is None and approval_manager is not None:
        requested_at = datetime.now(UTC)
        coordinator = ApprovalCoordinator(
            approval_manager,
            (McpElicitationApprovalSurface(context), None),
        )
        try:
            receipt = await coordinator.resolve(
                ApprovalSubmission(
                    operation_id=request.operation_id,
                    tool_name=tool_name,
                    payload=payload,
                    requested_at=requested_at,
                    expires_at=requested_at + timedelta(minutes=5),
                )
            )
        except (ApprovalDeniedError, ApprovalExpiredError):
            approval_id = None
        else:
            approval_id = receipt.approval_id
    outcome = await dispatcher.dispatch(
        DispatchCall(
            operation_id=request.operation_id,
            tool_name=tool_name,
            payload=payload,
            requested_at=datetime.now(UTC),
            timeout_ms=5_000,
            approval_id=approval_id,
        )
    )
    return outcome.result


async def _dispatch_session_power(
    dispatcher: GatewayDispatcher,
    tool_name: str,
    request: _SessionPowerInput,
) -> CallToolResult:
    """Operation ID를 IPC payload에서 제외해 zero-argument Worker adapter를 보존합니다."""
    outcome = await dispatcher.dispatch(
        DispatchCall(
            operation_id=request.operation_id,
            tool_name=tool_name,
            payload={},
            requested_at=datetime.now(UTC),
            timeout_ms=5_000,
        )
    )
    return outcome.result
