# pyright: reportAny=false
# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

import base64
import ctypes
from datetime import timedelta
from typing import TYPE_CHECKING, assert_never
from unittest.mock import Mock
from uuid import UUID

import anyio
import pytest
from mcp.types import CallToolResult, ImageContent
from pydantic import ValidationError

from hermes_windows_bridge.gateway.audit import AuditRecorder
from hermes_windows_bridge.gateway.dispatcher import DispatcherServices, GatewayDispatcher
from hermes_windows_bridge.gateway.idempotency import IdempotencyStore
from hermes_windows_bridge.gateway.mcp_server import create_gateway_server
from hermes_windows_bridge.gateway.policy import ApprovalManager
from hermes_windows_bridge.ipc import protocol as ipc
from hermes_windows_bridge.privileged.ipc_server import HelperRegistry
from hermes_windows_bridge.tools.computer import (
    observation_result_to_mcp,
    register_computer_tool,
)
from hermes_windows_bridge.worker.desktop import (
    Bounds,
    enable_per_monitor_v2_awareness,
    is_primary_monitor,
)
from hermes_windows_bridge.worker.ipc_client import WorkerRegistry

if TYPE_CHECKING:
    from pydantic import JsonValue

    from hermes_windows_bridge.gateway.mcp_server import GatewayMCPServer

_PRIVATE_PNG = b"\x89PNG\r\n\x1a\nprivate-screen-body"


class PrivateImageEndpoint:
    def __init__(
        self,
        image_data: str | None = None,
        sha256: str = "9a71dc2217b467fda593f1fc4d949d1c52bb522014fccb28f3d4bf085cd12bce",
    ) -> None:
        self.image_data: str = image_data or base64.b64encode(_PRIVATE_PNG).decode("ascii")
        self.sha256: str = sha256

    def exchange(self, request: ipc.RequestMessage) -> ipc.IpcResponse:
        match request:
            case ipc.IpcRequest(operation="computer_observe"):
                return ipc.IpcResponse(
                    request_id=request.request_id,
                    ok=True,
                    payload={
                        "monitors": [],
                        "mouse": {"x": 0, "y": 0},
                        "active_window": None,
                        "screenshot": {
                            "image_data": self.image_data,
                            "mime_type": "image/png",
                            "width": 1,
                            "height": 1,
                            "physical_bounds": {"left": 0, "top": 0, "width": 1, "height": 1},
                            "scale_x": 1.0,
                            "scale_y": 1.0,
                            "sha256": self.sha256,
                        },
                    },
                )
            case ipc.IpcRequest() | ipc.RebootIpcRequest() | ipc.ShutdownIpcRequest():
                raise AssertionError
            case unreachable:
                assert_never(unreachable)

    def cancel(self, request_id: UUID, reason: str) -> bool:
        del request_id, reason
        return False


def _server_and_audit() -> tuple[GatewayMCPServer, AuditRecorder]:
    audit = AuditRecorder()
    workers = WorkerRegistry()
    workers.register(
        ipc.WorkerRegistration(
            registration_id=UUID("8a03f58c-73a7-49a8-a012-f31e776714ed"),
            generation=1,
            session_id=1,
            username="fixture",
        ),
        PrivateImageEndpoint(),
    )
    dispatcher = GatewayDispatcher(
        DispatcherServices(
            workers=workers,
            helpers=HelperRegistry(),
            idempotency=IdempotencyStore(ttl=timedelta(minutes=1)),
            approvals=ApprovalManager(),
            audit=audit,
        )
    )
    server = create_gateway_server("test-token")
    register_computer_tool(server, dispatcher)
    return server, audit


@pytest.mark.security
@pytest.mark.parametrize(("context_matches", "expected"), [(1, 1), (0, 0)])
def test_dpi_awareness_reports_effective_thread_context(
    monkeypatch: pytest.MonkeyPatch,
    context_matches: int,
    expected: int,
) -> None:
    user32 = ctypes.windll.user32
    monkeypatch.setattr(user32, "SetProcessDpiAwarenessContext", Mock(return_value=0))
    monkeypatch.setattr(user32, "GetThreadDpiAwarenessContext", Mock(return_value=-4))
    monkeypatch.setattr(user32, "SetThreadDpiAwarenessContext", Mock(return_value=0))
    monkeypatch.setattr(
        user32, "AreDpiAwarenessContextsEqual", Mock(return_value=context_matches)
    )

    assert enable_per_monitor_v2_awareness() is bool(expected)


@pytest.mark.security
def test_dpi_awareness_uses_thread_override_when_process_context_is_locked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: UIA가 process DPI를 먼저 고정했지만 thread override는 허용됩니다.
    user32 = ctypes.windll.user32
    monkeypatch.setattr(user32, "SetProcessDpiAwarenessContext", Mock(return_value=0))
    monkeypatch.setattr(user32, "GetThreadDpiAwarenessContext", Mock(side_effect=(18, 34)))
    monkeypatch.setattr(user32, "AreDpiAwarenessContextsEqual", Mock(side_effect=(0, 1)))
    set_thread = Mock(return_value=18)
    monkeypatch.setattr(user32, "SetThreadDpiAwarenessContext", set_thread)

    # When: Worker thread의 effective DPI awareness를 초기화합니다.
    enabled = enable_per_monitor_v2_awareness()

    # Then: process 실패를 thread PMv2로 보완하고 실제 effective context를 확인합니다.
    assert enabled is True
    assert set_thread.call_count == 1


@pytest.mark.security
def test_primary_monitor_is_inferred_without_mss_specific_flag() -> None:
    assert is_primary_monitor(Bounds(left=0, top=0, width=1920, height=1080)) is True
    assert is_primary_monitor(Bounds(left=1920, top=0, width=1920, height=1080)) is False


@pytest.mark.security
class TestScreenshotAudit:
    def test_audit_omits_image_bytes_by_default(self) -> None:
        server, audit = _server_and_audit()

        arguments: dict[str, JsonValue] = {}
        result = anyio.run(server.call_tool, "computer_observe", arguments)

        assert isinstance(result, CallToolResult)
        image = next(block for block in result.content if isinstance(block, ImageContent))
        assert base64.b64decode(image.data) == _PRIVATE_PNG
        serialized_records = "".join(record.model_dump_json() for record in audit.records)
        assert base64.b64encode(_PRIVATE_PNG).decode("ascii") not in serialized_records
        assert "private-screen-body" not in serialized_records
        assert audit.records[0].operation_id is not None

    def test_mcp_metadata_surfaces_no_image_body(self) -> None:
        server, _ = _server_and_audit()

        arguments: dict[str, JsonValue] = {}
        result = anyio.run(server.call_tool, "computer_observe", arguments)

        assert isinstance(result, CallToolResult)
        assert result.structured_content is not None
        assert "image_data" not in result.structured_content.get("screenshot", {})
        assert result.structured_content["screenshot"]["width"] == 1

    @pytest.mark.parametrize(
        ("image_data", "sha256"),
        [
            ("%%%", "9a71dc2217b467fda593f1fc4d949d1c52bb522014fccb28f3d4bf085cd12bce"),
            (base64.b64encode(_PRIVATE_PNG).decode("ascii"), "0" * 64),
        ],
    )
    def test_invalid_worker_image_is_rejected_before_mcp_emission(
        self,
        image_data: str,
        sha256: str,
    ) -> None:
        request = ipc.IpcRequest(
            request_id=UUID("00000000-0000-4000-8000-000000000013"),
            target=ipc.PeerRole.WORKER,
            operation="computer_observe",
            payload={},
            timeout_ms=1_000,
        )
        response = PrivateImageEndpoint(image_data, sha256).exchange(request)

        with pytest.raises(ValidationError):
            _ = observation_result_to_mcp(
                CallToolResult(content=[], structured_content=response.payload)
            )
