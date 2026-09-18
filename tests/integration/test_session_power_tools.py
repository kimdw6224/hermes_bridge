from __future__ import annotations

import ctypes
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import ClassVar, Never, final
from uuid import UUID

import anyio
import pytest
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult, TextContent
from pydantic import BaseModel, ConfigDict

from hermes_windows_bridge.gateway.audit import AuditRecorder
from hermes_windows_bridge.gateway.dispatcher import (
    DispatcherServices,
    GatewayDispatcher,
)
from hermes_windows_bridge.gateway.idempotency import IdempotencyStore
from hermes_windows_bridge.gateway.mcp_server import create_gateway_server
from hermes_windows_bridge.gateway.policy import ApprovalManager
from hermes_windows_bridge.ipc import protocol as ipc
from hermes_windows_bridge.privileged.ipc_server import HelperRegistry
from hermes_windows_bridge.tools.system import register_system_tools
from hermes_windows_bridge.worker.ipc_client import WorkerRegistry
from hermes_windows_bridge.worker.session_power import (
    SessionPowerUnavailableError,
    SessionPowerWorker,
)

OPERATION_ID = UUID("018f0000-0000-7000-8000-000000000021")
NOW = datetime(2026, 9, 6, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class _Session:
    session_id: int
    elevated: bool
    active: bool


@final
class _RecordingBackend:
    def __init__(self) -> None:
        self.lock_calls = 0
        self.sleep_arguments: list[tuple[bool, bool, bool]] = []

    def lock_workstation(self) -> bool:
        self.lock_calls += 1
        return True

    def set_suspend_state(
        self,
        *,
        hibernate: bool,
        force: bool,
        wakeup_events_disabled: bool,
    ) -> bool:
        self.sleep_arguments.append((hibernate, force, wakeup_events_disabled))
        return True


@final
class _WorkerEndpoint:
    def __init__(self) -> None:
        self.requests: list[ipc.IpcRequest] = []

    def exchange(self, request: ipc.RequestMessage) -> ipc.IpcResponse:
        worker_request = ipc.IpcRequest.model_validate(request)
        self.requests.append(worker_request)
        return ipc.IpcResponse(
            request_id=worker_request.request_id,
            ok=True,
            payload={"operation": worker_request.operation, "initiated": True},
        )

    def cancel(self, request_id: UUID, reason: str) -> bool:
        del request_id, reason
        return False


class _ResultPayload(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)

    operation: str
    initiated: bool


@final
class _RejectingWindowsApi:
    def __init__(self, calls: list[str]) -> None:
        self._calls: list[str] = calls

    def __getattr__(self, name: str) -> Never:
        self._calls.append(name)
        raise AssertionError


def _dispatcher(worker: _WorkerEndpoint | None) -> GatewayDispatcher:
    workers = WorkerRegistry()
    if worker is not None:
        workers.register(
            ipc.WorkerRegistration(
                registration_id=UUID("018f0000-0000-7000-8000-000000000121"),
                generation=1,
                session_id=2,
                username="DOMAIN\\worker",
            ),
            worker,
        )
    return GatewayDispatcher(
        DispatcherServices(
            workers=workers,
            helpers=HelperRegistry(),
            idempotency=IdempotencyStore(ttl=timedelta(minutes=1)),
            approvals=ApprovalManager(),
            audit=AuditRecorder(),
        )
    )


def _result_text(result: CallToolResult) -> str:
    return TextContent.model_validate(result.content[0]).text


@pytest.mark.integration
def test_session_power_mcp_tools_dispatch_to_worker_with_strict_empty_payload() -> None:
    # Given: online Worker endpoint와 system tool 등록 MCP server입니다.
    endpoint = _WorkerEndpoint()
    server = create_gateway_server("test-token")
    register_system_tools(server, _dispatcher(endpoint))

    # When: 공식 MCP call_tool 경계에서 lock과 sleep을 호출합니다.
    lock = anyio.run(
        server.call_tool,
        "system_lock",
        {"operation_id": str(OPERATION_ID)},
    )
    sleep = anyio.run(
        server.call_tool,
        "system_sleep",
        {"operation_id": "018f0000-0000-7000-8000-000000000031"},
    )

    # Then: operation_id는 IPC payload에 없고 GatewayDispatcher Worker route만 사용합니다.
    assert isinstance(lock, CallToolResult)
    assert isinstance(sleep, CallToolResult)
    operations = [
        _ResultPayload.model_validate_json(_result_text(item)).operation
        for item in (lock, sleep)
    ]
    assert operations == [
        "system_lock",
        "system_sleep",
    ]
    assert [(request.operation, request.payload) for request in endpoint.requests] == [
        ("system_lock", {}),
        ("system_sleep", {}),
    ]


@pytest.mark.integration
def test_session_power_worker_unavailable_is_typed_mcp_failure() -> None:
    # Given: Worker가 등록되지 않은 GatewayDispatcher입니다.
    server = create_gateway_server("test-token")
    register_system_tools(server, _dispatcher(None))

    # When: public system_sleep tool을 호출합니다.
    result = anyio.run(
        server.call_tool,
        "system_sleep",
        {"operation_id": str(OPERATION_ID)},
    )

    # Then: Gateway 직접 실행 없이 typed worker_unavailable 응답을 반환합니다.
    assert isinstance(result, CallToolResult)
    assert result.is_error is True
    assert _result_text(result) == '{"error":{"code":"worker_unavailable"}}'


@pytest.mark.integration
def test_session_power_public_schema_is_strict_and_reboot_shutdown_remain_registered() -> None:
    # Given: system surface 전체를 등록한 MCP server입니다.
    server = create_gateway_server("test-token")
    register_system_tools(server, _dispatcher(None))
    tools = {tool.name: tool for tool in anyio.run(server.list_tools)}

    # When/Then: lock/sleep은 operation_id 외 입력을 허용하지 않고 비승인 Worker mutation입니다.
    assert set(tools) == {"system_lock", "system_sleep", "system_reboot", "system_shutdown"}
    for name in ("system_lock", "system_sleep"):
        annotations = tools[name].annotations
        assert tools[name].input_schema["additionalProperties"] is False
        assert tools[name].input_schema["required"] == ["operation_id"]
        assert annotations is not None
        assert annotations.read_only_hint is False
        assert annotations.destructive_hint is False
        assert annotations.idempotent_hint is True
        assert annotations.open_world_hint is False
    with pytest.raises(ToolError, match="unexpected"):
        _ = anyio.run(
            server.call_tool,
            "system_lock",
            {"operation_id": str(OPERATION_ID), "unexpected": True},
        )
    assert tools["system_reboot"].input_schema["required"] == [
        "operation_id",
        "reason",
    ]
    assert tools["system_shutdown"].input_schema["required"] == [
        "operation_id",
        "reason",
    ]


@pytest.mark.integration
def test_session_power_adapter_uses_injected_backend_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: 정상 non-elevated session과 recording backend 및 OS API sentinel입니다.
    backend = _RecordingBackend()
    os_calls: list[str] = []
    monkeypatch.setattr(ctypes, "WinDLL", _RejectingWindowsApi(os_calls))
    adapter = SessionPowerWorker(
        session=_Session(session_id=2, elevated=False, active=True),
        expected_session_id=2,
        backend=backend,
    )

    # When: typed zero-argument lock/sleep adapter를 호출합니다.
    lock = adapter.system_lock()
    sleep = adapter.system_sleep()

    # Then: injected backend만 exact Win32 semantics로 호출되고 OS API 호출은 0입니다.
    assert (lock.operation, lock.initiated) == ("system_lock", True)
    assert (sleep.operation, sleep.initiated) == ("system_sleep", True)
    assert (backend.lock_calls, backend.sleep_arguments) == (1, [(False, False, False)])
    assert os_calls == []

    # And Given/When/Then: active/elevation/session mismatch는 backend 호출 전 fail-closed 합니다.
    for session, expected_session_id in (
        (_Session(session_id=2, elevated=False, active=False), 2),
        (_Session(session_id=2, elevated=True, active=True), 2),
        (_Session(session_id=3, elevated=False, active=True), 2),
    ):
        with pytest.raises(SessionPowerUnavailableError):
            _ = SessionPowerWorker(
                session=session,
                expected_session_id=expected_session_id,
                backend=backend,
            ).system_lock()
    assert (backend.lock_calls, backend.sleep_arguments) == (1, [(False, False, False)])
