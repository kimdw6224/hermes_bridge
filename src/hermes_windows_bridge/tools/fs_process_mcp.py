"""Filesystem/process MCP 등록을 Gateway IPC 경계로만 제한합니다."""

# pyright: reportFunctionMemberAccess=false, reportUnnecessaryComparison=false

from __future__ import annotations

from datetime import UTC, datetime
from inspect import Parameter, Signature
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, assert_never
from uuid import UUID, uuid4

from mcp.types import CallToolResult, ToolAnnotations
from pydantic import BaseModel, ConfigDict, JsonValue, field_validator

from hermes_windows_bridge.gateway.dispatcher import DispatchCall, GatewayDispatcher
from hermes_windows_bridge.tools.filesystem import (
    DeleteInput,
    ListInput,
    MkdirInput,
    MoveInput,
    ReadInput,
    WriteInput,
)
from hermes_windows_bridge.tools.process import (
    AppOpenInput,
    ProcessKillInput,
    ProcessStartInput,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from hermes_windows_bridge.gateway.mcp_server import GatewayMCPServer
    from hermes_windows_bridge.ipc.protocol import JsonPayload


_DISPATCH_TIMEOUT_MS = 5_000


class _OperationInput(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    operation_id: UUID

    @field_validator("operation_id", mode="before")
    @classmethod
    def parse_operation_id(cls, value: JsonValue | UUID) -> UUID:
        if isinstance(value, UUID):
            return value
        if isinstance(value, str):
            return UUID(value)
        raise _InvalidOperationIdError


class _InvalidOperationIdError(ValueError): ...


class FsWriteMcpInput(WriteInput, _OperationInput):
    """Closed fs_write schema."""


class FsMoveMcpInput(MoveInput, _OperationInput):
    """Closed fs_move schema."""


class FsCopyMcpInput(MoveInput, _OperationInput):
    """Closed fs_copy schema."""


class FsDeleteMcpInput(DeleteInput, _OperationInput):
    """Closed fs_delete schema."""


class FsMkdirMcpInput(MkdirInput, _OperationInput):
    """Closed fs_mkdir schema."""


class _ProcessListMcpInput(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)


class ProcessStartMcpInput(ProcessStartInput, _OperationInput):
    """Closed process_start schema."""


class ProcessKillMcpInput(ProcessKillInput, _OperationInput):
    """Closed process_kill schema."""


class AppOpenMcpInput(AppOpenInput, _OperationInput):
    """Closed app_open schema."""


type McpRequest = (
    ListInput
    | ReadInput
    | FsWriteMcpInput
    | FsMoveMcpInput
    | FsCopyMcpInput
    | FsDeleteMcpInput
    | FsMkdirMcpInput
    | _ProcessListMcpInput
    | ProcessStartMcpInput
    | ProcessKillMcpInput
    | AppOpenMcpInput
)
type FilesystemMcpRequest = (
    ListInput
    | ReadInput
    | FsWriteMcpInput
    | FsMoveMcpInput
    | FsCopyMcpInput
    | FsDeleteMcpInput
    | FsMkdirMcpInput
)
type ProcessMcpRequest = (
    _ProcessListMcpInput | ProcessStartMcpInput | ProcessKillMcpInput | AppOpenMcpInput
)


def register_filesystem_tools(server: GatewayMCPServer, dispatcher: GatewayDispatcher) -> None:
    """Register filesystem tools through the Gateway dispatcher only."""
    _register(
        server,
        dispatcher,
        (
            ("fs_list", ListInput, True, False, True),
            ("fs_stat", ReadInput, True, False, True),
            ("fs_read", ReadInput, True, False, True),
            ("fs_write", FsWriteMcpInput, False, False, True),
            ("fs_move", FsMoveMcpInput, False, False, False),
            ("fs_copy", FsCopyMcpInput, False, False, False),
            ("fs_delete", FsDeleteMcpInput, False, True, True),
            ("fs_mkdir", FsMkdirMcpInput, False, False, True),
        ),
    )


def register_process_tools(server: GatewayMCPServer, dispatcher: GatewayDispatcher) -> None:
    """Register process and app tools through the Gateway dispatcher only."""
    _register(
        server,
        dispatcher,
        (
            ("process_list", _ProcessListMcpInput, True, False, True),
            ("process_start", ProcessStartMcpInput, False, False, False),
            ("process_kill", ProcessKillMcpInput, False, True, False),
            ("app_open", AppOpenMcpInput, False, False, False),
        ),
    )


type Registration = tuple[str, type[McpRequest], bool, bool, bool]


def _register(
    server: GatewayMCPServer,
    dispatcher: GatewayDispatcher,
    registrations: tuple[Registration, ...],
) -> None:
    for name, model, read_only, destructive, idempotent in registrations:
        server.add_closed_tool(
            _handler_for(dispatcher, name, model),
            input_model=model,
            name=name,
            description=(
                "List entries plus unavailable_entries and reasons; denied entries stay blocked."
                if name == "fs_list"
                else f"Dispatch {name} through the interactive user Worker."
            ),
            annotations=ToolAnnotations(
                read_only_hint=read_only,
                destructive_hint=destructive,
                idempotent_hint=idempotent,
                open_world_hint=False,
            ),
            structured_output=False,
        )


def _handler_for(
    dispatcher: GatewayDispatcher,
    name: str,
    model: type[McpRequest],
) -> Callable[..., Awaitable[CallToolResult]]:
    async def handler(**arguments: JsonValue) -> CallToolResult:
        request = model.model_validate(arguments)
        return await _dispatch(dispatcher, name, request)

    handler.__signature__ = _handler_signature(model)
    return handler


def _handler_signature(model: type[McpRequest]) -> Signature:
    value_type = JsonValue | UUID | Path | tuple[str, ...]
    parameters = tuple(
        Parameter(
            parameter_name,
            kind=Parameter.KEYWORD_ONLY,
            default=None,
            annotation=value_type,
        )
        for parameter_name in model.model_fields
    )
    return Signature(parameters=parameters)


async def _dispatch(
    dispatcher: GatewayDispatcher,
    name: str,
    request: McpRequest,
) -> CallToolResult:
    operation_id, payload = _dispatch_values(request)
    outcome = await dispatcher.dispatch(
        DispatchCall(
            operation_id=operation_id,
            tool_name=name,
            payload=payload,
            requested_at=datetime.now(UTC),
            timeout_ms=_DISPATCH_TIMEOUT_MS,
        )
    )
    return outcome.result


def _dispatch_values(request: McpRequest) -> tuple[UUID, JsonPayload]:
    match request:
        case (
            ListInput()
            | ReadInput()
            | FsWriteMcpInput()
            | FsMoveMcpInput()
            | FsCopyMcpInput()
            | FsDeleteMcpInput()
            | FsMkdirMcpInput()
        ):
            return _filesystem_dispatch_values(request)
        case (
            _ProcessListMcpInput()
            | ProcessStartMcpInput()
            | ProcessKillMcpInput()
            | AppOpenMcpInput()
        ):
            return _process_dispatch_values(request)
        case unreachable:
            assert_never(unreachable)


def _filesystem_dispatch_values(request: FilesystemMcpRequest) -> tuple[UUID, JsonPayload]:
    operation_id: UUID
    payload: JsonPayload
    match request:
        case ListInput(path=path):
            operation_id, payload = uuid4(), {"path": str(path)}
        case ReadInput(path=path, offset=offset, length=length, encoding=encoding):
            operation_id, payload = (
                uuid4(),
                {
                    "path": str(path),
                    "offset": offset,
                    "length": length,
                    "encoding": encoding,
                },
            )
        case FsWriteMcpInput(operation_id=operation_id, path=path, text=text, base64_data=data):
            payload = {"path": str(path), "text": text, "base64_data": data}
        case (
            FsMoveMcpInput(operation_id=operation_id, source=source, destination=destination)
            | FsCopyMcpInput(operation_id=operation_id, source=source, destination=destination)
        ):
            payload = {"source": str(source), "destination": str(destination)}
        case FsDeleteMcpInput(operation_id=operation_id, path=path, recursive=recursive):
            payload = {"path": str(path), "recursive": recursive}
        case FsMkdirMcpInput(operation_id=operation_id, path=path, parents=parents):
            payload = {"path": str(path), "parents": parents}
        case unreachable:
            assert_never(unreachable)
    return operation_id, payload


def _process_dispatch_values(request: ProcessMcpRequest) -> tuple[UUID, JsonPayload]:
    operation_id: UUID
    payload: JsonPayload
    match request:
        case _ProcessListMcpInput():
            operation_id, payload = uuid4(), {}
        case ProcessStartMcpInput(
            operation_id=operation_id,
            argv=argv,
            cwd=cwd,
            lifecycle_managed=lifecycle_managed,
        ):
            return operation_id, {
                "argv": list(argv),
                "cwd": str(cwd) if cwd is not None else None,
                "lifecycle_managed": lifecycle_managed,
            }
        case ProcessKillMcpInput(operation_id=operation_id, pid=pid):
            payload = {"pid": pid}
        case AppOpenMcpInput(
            operation_id=operation_id, target=target, arguments=arguments, cwd=cwd
        ):
            payload = {
                "target": target,
                "arguments": list(arguments),
                "cwd": str(cwd) if cwd is not None else None,
            }
        case unreachable:
            assert_never(unreachable)
    return operation_id, payload
