# pyright: reportAny=false
# pyright: reportImplicitStringConcatenation=false
# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

import base64
import json
import shutil
import socket
import subprocess
import sys
from datetime import timedelta
from pathlib import Path
from threading import Thread
from typing import TYPE_CHECKING, assert_never
from uuid import UUID

import anyio
import pytest
import uvicorn
from mcp.types import CallToolResult, ImageContent, TextContent
from pydantic import ValidationError

from hermes_windows_bridge.gateway.audit import AuditRecorder
from hermes_windows_bridge.gateway.dispatcher import DispatcherServices, GatewayDispatcher
from hermes_windows_bridge.gateway.idempotency import IdempotencyStore
from hermes_windows_bridge.gateway.mcp_server import create_gateway_server
from hermes_windows_bridge.gateway.origin_host import GatewayTransportPolicy
from hermes_windows_bridge.gateway.policy import ApprovalManager
from hermes_windows_bridge.ipc import protocol as ipc
from hermes_windows_bridge.privileged.ipc_server import HelperRegistry
from hermes_windows_bridge.tools.computer import (
    ComputerObserveInput,
    ComputerTools,
    observation_to_ipc_payload,
    register_computer_tool,
)
from hermes_windows_bridge.worker.desktop import (
    ActiveWindow,
    Bounds,
    DesktopObservation,
    DesktopObserveRequest,
    DesktopWorker,
    MonitorInfo,
    MousePosition,
    ScreenshotCapture,
)
from hermes_windows_bridge.worker.ipc_client import WorkerRegistry

if TYPE_CHECKING:
    from pydantic import JsonValue

_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUB"
    "AScY42YAAAAASUVORK5CYII="
)


class DeterministicObserver:
    def observe(self, request: DesktopObserveRequest) -> DesktopObservation:
        capture = (
            ScreenshotCapture(
                png=_PNG,
                width=1,
                height=1,
                physical_bounds=Bounds(left=0, top=0, width=1920, height=1080),
                scale_x=1920.0,
                scale_y=1080.0,
                sha256="431ced6916a2a21a156e38701afe55bbd7f88969fbbfc56d7fe099d47f265460",
            )
            if request.screenshot
            else None
        )
        return DesktopObservation(
            monitors=(
                MonitorInfo(
                    index=1,
                    is_primary=True,
                    physical_bounds=Bounds(left=0, top=0, width=1920, height=1080),
                    logical_bounds=Bounds(left=0, top=0, width=1536, height=864),
                    dpi_scale=1.25,
                ),
            ),
            mouse=MousePosition(x=40, y=50),
            active_window=ActiveWindow(
                title="Fixture",
                pid=123,
                process_name="fixture.exe",
                bounds=Bounds(left=10, top=20, width=300, height=200),
            ),
            screenshot=capture,
        )


class ObservationEndpoint:
    def exchange(self, request: ipc.RequestMessage) -> ipc.IpcResponse:
        match request:
            case ipc.IpcRequest(operation="computer_observe"):
                parsed = ComputerObserveInput.model_validate(
                    {"operation_id": request.request_id, **request.payload}
                )
                result = ComputerTools(DeterministicObserver()).computer_observe(parsed)
                return ipc.IpcResponse(
                    request_id=request.request_id,
                    ok=True,
                    payload=observation_to_ipc_payload(result),
                )
            case ipc.IpcRequest() | ipc.RebootIpcRequest() | ipc.ShutdownIpcRequest():
                raise AssertionError
            case unreachable:
                assert_never(unreachable)

    def cancel(self, request_id: UUID, reason: str) -> bool:
        del request_id, reason
        return False


def _dispatcher() -> GatewayDispatcher:
    workers = WorkerRegistry()
    workers.register(
        ipc.WorkerRegistration(
            registration_id=UUID("8a03f58c-73a7-49a8-a012-f31e776714ed"),
            generation=1,
            session_id=1,
            username="fixture",
        ),
        ObservationEndpoint(),
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


@pytest.mark.integration
def test_registered_observe_converts_worker_png_to_mcp_image() -> None:
    server = create_gateway_server("test-token")
    register_computer_tool(server, _dispatcher())

    arguments: dict[str, JsonValue] = {}
    result = anyio.run(server.call_tool, "computer_observe", arguments)

    assert isinstance(result, CallToolResult)
    assert isinstance(result.content[0], TextContent)
    assert isinstance(result.content[1], ImageContent)
    assert base64.b64decode(result.content[1].data, validate=True) == _PNG
    assert result.content[1].mime_type == "image/png"
    assert "iVBOR" not in result.content[0].text
    assert result.structured_content is not None
    assert "image_data" not in result.structured_content
    assert result.structured_content["monitors"][0]["dpi_scale"] == 1.25


@pytest.mark.integration
def test_observe_input_rejects_malformed_and_extra_fields() -> None:
    with pytest.raises(ValidationError):
        _ = ComputerObserveInput.model_validate({"monitor": 0})
    with pytest.raises(ValidationError):
        _ = ComputerObserveInput.model_validate({"unexpected": True})


@pytest.mark.integration
def test_observe_without_screenshot_returns_metadata_only() -> None:
    result = ComputerTools(DeterministicObserver()).computer_observe(
        ComputerObserveInput(screenshot=False)
    )

    assert result.screenshot is None
    assert result.monitors[0].physical_bounds.width == 1920
    assert result.mouse == MousePosition(x=40, y=50)


@pytest.mark.integration
def test_live_mcp_curl_returns_observation_image_and_metadata() -> None:
    server = create_gateway_server("test-token")
    register_computer_tool(server, _dispatcher())
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    host = f"127.0.0.1:{listener.getsockname()[1]}"
    app = server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        transport_security=GatewayTransportPolicy(
            allowed_hosts=(host,), allowed_origins=("http://localhost",)
        ).sdk_settings(),
        host="127.0.0.1",
    )
    http = uvicorn.Server(uvicorn.Config(app, log_level="error"))
    http_thread = Thread(target=http.run, kwargs={"sockets": [listener]})
    http_thread.start()
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": {
                "name": "computer_observe",
                "arguments": {},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "computer-observe-curl-test",
                        "version": "1.0",
                    },
                },
            },
        }
    )
    curl_path = shutil.which("curl.exe")
    assert curl_path is not None
    try:
        completed = subprocess.run(
            [
                curl_path, "-sS", "--fail-with-body", f"http://{host}/mcp",
                "-H", "Authorization: Bearer test-token", "-H", "Origin: http://localhost",
                "-H", "Content-Type: application/json",
                "-H", "Accept: application/json, text/event-stream",
                "-H", "MCP-Protocol-Version: 2026-07-28",
                "-H", "Mcp-Method: tools/call", "-H", "Mcp-Name: computer_observe",
                "--data", body,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    finally:
        http.should_exit = True
        http_thread.join(3)
    assert completed.returncode == 0, completed.stderr
    response = json.loads(completed.stdout)
    result = response["result"]
    metadata = json.loads(result["content"][0]["text"])
    assert result["content"][1]["type"] == "image"
    assert metadata["monitors"]
    assert metadata["active_window"]["title"] == "Fixture"
    evidence = Path(".omo/evidence/task-13-hermes-windows-bridge.json")
    _ = evidence.write_text(completed.stdout, encoding="utf-8")
    assert http_thread.is_alive() is False


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "win32", reason="Windows desktop capture")
def test_actual_worker_capture_is_in_memory_and_bounded(tmp_path: Path) -> None:
    before = set(tmp_path.iterdir())
    worker = DesktopWorker()

    result = worker.observe(DesktopObserveRequest(screenshot=True, monitor=1))

    assert worker.dpi_awareness_enabled is True
    assert result.screenshot is not None
    assert result.screenshot.png.startswith(b"\x89PNG\r\n\x1a\n")
    assert len(base64.b64encode(result.screenshot.png)) <= 900_000
    response = ipc.IpcResponse(
        request_id=UUID("00000000-0000-4000-8000-000000000013"),
        ok=True,
        payload=observation_to_ipc_payload(result),
    )
    assert len(ipc.serialize_message(response)) < 1_048_576
    assert result.monitors
    assert result.mouse.x >= result.monitors[0].physical_bounds.left
    assert set(tmp_path.iterdir()) == before
