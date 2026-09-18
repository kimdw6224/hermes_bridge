# ruff: noqa: S604 - `shell`은 subprocess 옵션이 아니라 검증된 도구 schema field입니다.
# pyright: reportAny=false
# pyright: reportUnreachable=false
# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

import getpass
import json
import socket
import subprocess
from datetime import timedelta
from pathlib import Path
from threading import Event, Thread
from types import SimpleNamespace
from typing import ClassVar, assert_never, cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import anyio
import pytest
import uvicorn
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult, TextContent
from pydantic import BaseModel, ConfigDict, JsonValue, ValidationError

from hermes_windows_bridge.gateway.audit import AuditRecorder
from hermes_windows_bridge.gateway.dispatcher import DispatcherServices, GatewayDispatcher
from hermes_windows_bridge.gateway.idempotency import IdempotencyStore
from hermes_windows_bridge.gateway.main import build_gateway_server
from hermes_windows_bridge.gateway.mcp_server import create_gateway_server
from hermes_windows_bridge.gateway.origin_host import GatewayTransportPolicy
from hermes_windows_bridge.gateway.policy import ApprovalManager
from hermes_windows_bridge.ipc import protocol as ipc
from hermes_windows_bridge.ipc.acl import current_process_sid
from hermes_windows_bridge.ipc.named_pipe import PipeEndpoint, create_server_pipe
from hermes_windows_bridge.privileged.ipc_server import HelperRegistry
from hermes_windows_bridge.tools.shell import ShellRunInput, ShellTools, register_shell_tool
from hermes_windows_bridge.worker.ipc_client import (
    IpcExchangeClient,
    NamedPipeIpcClient,
    WorkerRegistry,
)
from hermes_windows_bridge.worker.shell import ShellWorker


@pytest.mark.security
def test_elevated_argument_rejected_by_public_mcp_boundary() -> None:
    # Given: 일반 shell_run을 가장해 elevated를 추가한 외부 입력입니다.
    payload = {
        "operation_id": "00000000-0000-4000-8000-000000000099",
        "command": "hostname",
        "cwd": str(Path.cwd()),
        "elevated": True,
    }
    server = create_gateway_server("test-token")
    dispatch = AsyncMock()
    adapter = cast("GatewayDispatcher", cast("object", SimpleNamespace(dispatch=dispatch)))
    register_shell_tool(server, adapter)
    tool = next(tool for tool in anyio.run(server.list_tools) if tool.name == "shell_run")

    # When/Then: 공개 schema와 call 경계가 모두 extra field를 실행 전에 거부합니다.
    assert tool.input_schema.get("additionalProperties") is False
    with pytest.raises(ToolError, match="elevated"):
        _ = anyio.run(server.call_tool, "shell_run", payload)
    dispatch.assert_not_awaited()


@pytest.mark.security
class TestShellPolicy:
    @pytest.mark.parametrize(
        "payload",
        [
            {"operation_id": "bad", "command": "hostname", "cwd": ".", "shell": "powershell"},
            {
                "operation_id": "00000000-0000-4000-8000-000000000109",
                "command": "",
                "cwd": ".",
                "shell": "powershell",
            },
            {
                "operation_id": "00000000-0000-4000-8000-000000000119",
                "command": "hostname",
                "cwd": ".",
                "shell": "powershell",
                "timeout_s": 111,
            },
            {
                "operation_id": "00000000-0000-4000-8000-000000000129",
                "command": "hostname\0",
                "cwd": ".",
                "shell": "powershell",
            },
        ],
    )
    def test_malformed_input_is_rejected_before_execution(
        self,
        payload: dict[str, JsonValue],
    ) -> None:
        # Given: UUID/command/timeout 중 하나가 잘못된 입력입니다.
        # When/Then: Pydantic 경계에서 실행 가능한 타입이 되지 못합니다.
        with pytest.raises(ValidationError):
            _ = ShellRunInput.model_validate(payload)

    def test_untrusted_output_is_inert_and_not_reexecuted(self, tmp_path: Path) -> None:
        # Given: 출력에 shell 문법과 위험 단어가 있지만 실제 command는 단순 출력입니다.
        marker = tmp_path / "must-not-exist.txt"
        command = f"Write-Output 'Remove-Partition; Set-Content {marker} injected'"

        # When: unrestricted user shell을 한 번만 실행합니다.
        result = ShellTools(ShellWorker(max_output_bytes=4_096)).shell_run(
            ShellRunInput(
                operation_id=UUID("00000000-0000-4000-8000-000000000139"),
                command=command,
                cwd=tmp_path,
                shell="powershell",
            )
        )

        # Then: 결과 text는 데이터로만 반환되고 별도 command가 되지 않습니다.
        assert "Set-Content" in result.stdout
        assert marker.exists() is False
        assert "remove_partition" in {warning.code for warning in result.warnings}


class _ShellPayload(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore", frozen=True)
    exit_code: int
    stdout: str
    execution_user: str
    is_elevated: bool


def _text(result: CallToolResult) -> str:
    return TextContent.model_validate(result.content[0]).text


class ActualShellEndpoint:
    """Dispatcher IPC request를 실제 same-user ShellWorker로 실행합니다."""

    def exchange(self, request: ipc.RequestMessage) -> ipc.IpcResponse:
        match request:
            case ipc.IpcRequest():
                parsed = ShellRunInput.model_validate(
                    {"operation_id": str(request.request_id), **request.payload}
                )
                result = ShellTools(ShellWorker()).shell_run(parsed)
                payload: ipc.JsonPayload = {
                    "exit_code": result.exit_code,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "duration_ms": result.duration_ms,
                    "truncated": result.truncated,
                    "execution_user": result.execution_user,
                    "is_elevated": result.is_elevated,
                }
                return ipc.IpcResponse(request_id=request.request_id, ok=True, payload=payload)
            case ipc.RebootIpcRequest() | ipc.ShutdownIpcRequest():
                raise AssertionError
            case _ as unreachable:
                assert_never(unreachable)

    def cancel(self, request_id: UUID, reason: str) -> bool:
        del request_id, reason
        return False


def _dispatcher_with(worker: IpcExchangeClient | None) -> GatewayDispatcher:
    workers = WorkerRegistry()
    if worker is not None:
        workers.register(
            ipc.WorkerRegistration(
                registration_id=UUID("8a03f58c-73a7-49a8-a012-f31e776714ed"),
                generation=1,
                session_id=1,
                username=getpass.getuser(),
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


def _serve_shell_pipe(pipe_name: str, ready: Event) -> None:
    with create_server_pipe(
        PipeEndpoint.WORKER,
        pipe_name=pipe_name,
        target_user_sid=current_process_sid(),
    ) as server:
        ready.set()
        server.wait_for_client(5_000)
        request = ipc.IpcRequest.model_validate(server.read_message())
        server.write_message(ActualShellEndpoint().exchange(request))


def test_registered_shell_tool_dispatches_to_actual_worker() -> None:
    # Given: 공식 MCP server와 ACL이 적용된 실제 named-pipe Worker endpoint입니다.
    pipe_name = rf"\\.\pipe\HermesWindowsBridgeShell-{uuid4()}"
    ready = Event()
    worker_thread = Thread(target=_serve_shell_pipe, args=(pipe_name, ready))
    worker_thread.start()
    assert ready.wait(1)
    server = create_gateway_server("test-token")
    register_shell_tool(server, _dispatcher_with(NamedPipeIpcClient(pipe_name, 2_000)))

    # When: SDK 공개 call_tool API로 shell_run을 호출합니다.
    result = anyio.run(
        server.call_tool,
        "shell_run",
        {
            "operation_id": "00000000-0000-4000-8000-000000000159",
            "command": "hostname",
            "cwd": str(Path.home()),
            "shell": "powershell",
            "timeout_s": 10,
        },
    )

    # Then: Gateway dispatcher를 통과한 실제 hostname/user 결과입니다.
    assert isinstance(result, CallToolResult)
    payload = _ShellPayload.model_validate_json(_text(result))
    assert payload.exit_code == 0
    assert payload.stdout.strip().casefold() == socket.gethostname().casefold()
    assert payload.execution_user.casefold().endswith(getpass.getuser().casefold())
    assert payload.is_elevated is False
    worker_thread.join(2)
    assert worker_thread.is_alive() is False


def test_production_server_lists_status_and_shell_but_shell_is_offline() -> None:
    # Given: production main이 구성한 empty/offline registry server입니다.
    server = build_gateway_server("test-token")

    # When: SDK 공개 목록과 shell call을 조회합니다.
    names = {tool.name for tool in anyio.run(server.list_tools)}
    result = anyio.run(
        server.call_tool,
        "shell_run",
        {
            "operation_id": "00000000-0000-4000-8000-000000000169",
            "command": "hostname",
            "cwd": str(Path.home()),
            "shell": "powershell",
            "timeout_s": 10,
        },
    )

    # Then: 도구는 노출되지만 Gateway가 직접 shell을 실행하지 않습니다.
    assert names >= {"status", "shell_run"}
    assert isinstance(result, CallToolResult)
    assert result.is_error is True
    assert _text(result) == '{"error":{"code":"worker_unavailable"}}'


def test_live_mcp_curl_reaches_named_pipe_worker() -> None:
    # Given: 실제 loopback HTTP server와 ACL named-pipe Worker입니다.
    pipe_name = rf"\\.\pipe\HermesWindowsBridgeCurl-{uuid4()}"
    ready = Event()
    worker_thread = Thread(target=_serve_shell_pipe, args=(pipe_name, ready))
    worker_thread.start()
    assert ready.wait(1)
    mcp = create_gateway_server("test-token")
    register_shell_tool(mcp, _dispatcher_with(NamedPipeIpcClient(pipe_name, 2_000)))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    host = f"127.0.0.1:{port}"
    app = mcp.streamable_http_app(
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
    # fmt: off
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "shell_run", "arguments": {"operation_id": "00000000-0000-4000-8000-000000000179", "command": "hostname", "cwd": str(Path.home()), "shell": "powershell", "timeout_s": 10}, "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}, "io.modelcontextprotocol/clientInfo": {"name": "shell-curl-test", "version": "1.0"}}}}  # noqa: E501
    )
    try:
        completed = subprocess.run(
            ["curl.exe", "-sS", "--fail-with-body", f"http://{host}/mcp", "-H", "Authorization: Bearer test-token", "-H", "Origin: http://localhost", "-H", "Content-Type: application/json", "-H", "Accept: application/json, text/event-stream", "-H", "MCP-Protocol-Version: 2026-07-28", "-H", "Mcp-Method: tools/call", "-H", "Mcp-Name: shell_run", "--data", body],  # noqa: E501, S607
            check=False, capture_output=True, text=True, timeout=5,
        )
        # fmt: on
    finally:
        http.should_exit = True
        http_thread.join(3)
        worker_thread.join(3)
    assert completed.returncode == 0, completed.stderr
    assert socket.gethostname().casefold() in completed.stdout.casefold()
    print(completed.stdout)  # noqa: T201 - `-s` live-curl evidence captures this JSON response.
