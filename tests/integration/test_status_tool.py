from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import timedelta
from typing import TYPE_CHECKING, ClassVar
from uuid import UUID

import anyio
import httpx2
import pytest
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field

from hermes_windows_bridge.gateway.audit import AuditRecorder
from hermes_windows_bridge.gateway.dispatcher import DispatcherServices, GatewayDispatcher
from hermes_windows_bridge.gateway.idempotency import IdempotencyStore
from hermes_windows_bridge.gateway.mcp_server import create_gateway_server
from hermes_windows_bridge.gateway.origin_host import GatewayTransportPolicy
from hermes_windows_bridge.gateway.policy import ApprovalManager
from hermes_windows_bridge.ipc.protocol import IpcResponse, WorkerRegistration
from hermes_windows_bridge.models.tool_results import ResourceStatus, StatusResult, TailscaleStatus
from hermes_windows_bridge.privileged.ipc_server import HelperRegistry
from hermes_windows_bridge.tools.status import (
    StatusCollector,
    StatusSystemInfo,
    register_status_tool,
)
from hermes_windows_bridge.worker.ipc_client import WorkerRegistry

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from mcp.server.mcpserver import MCPServer
    from starlette.applications import Starlette

    from hermes_windows_bridge.ipc.protocol import RequestMessage

TOKEN = "test-token"  # noqa: S105 - 테스트 전용 공개 fixture입니다.
HOST = "127.0.0.1"
ORIGIN = "https://main-pc.example.ts.net"


class _McpToolResult(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore", frozen=True)
    structured_content: StatusResult = Field(alias="structuredContent")


class _McpResponse(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore", frozen=True)
    result: _McpToolResult


class _McpError(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore", frozen=True)
    code: int


class _McpErrorResponse(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore", frozen=True)
    error: _McpError


class WorkerEndpoint:
    def exchange(self, request: RequestMessage) -> IpcResponse:
        return IpcResponse(
            request_id=request.request_id,
            ok=True,
            payload={
                "username": "DOMAIN\\worker",
                "session_id": 3,
                "desktop_unlocked": True,
                "remote_input_enabled": True,
                "active_window": {"title": "Terminal", "process": "WindowsTerminal.exe"},
            },
        )

    def cancel(self, request_id: UUID, reason: str) -> bool:
        del request_id, reason
        return False


def build_server() -> MCPServer[None]:
    workers = WorkerRegistry()
    helpers = HelperRegistry()
    workers.register(
        WorkerRegistration(
            registration_id=UUID("8a03f58c-73a7-49a8-a012-f31e776714ed"),
            generation=1,
            session_id=3,
            username="DOMAIN\\worker",
        ),
        WorkerEndpoint(),
    )
    dispatcher = GatewayDispatcher(
        DispatcherServices(
            workers=workers,
            helpers=helpers,
            idempotency=IdempotencyStore(ttl=timedelta(minutes=1)),
            approvals=ApprovalManager(),
            audit=AuditRecorder(),
        )
    )
    collector = StatusCollector(
        dispatcher=dispatcher,
        helpers=helpers,
        app_capability_verified=lambda: True,
        system_probe=lambda: StatusSystemInfo(hostname="MAIN-PC", windows_version="Windows 11"),
        tailscale_probe=lambda: TailscaleStatus(
            connected=True, ip="100.64.0.1", app_capability_verified=True
        ),
        resource_probe=lambda: ResourceStatus(
            cpu_percent=1.0, ram_used_gb=2.0, ram_total_gb=4.0, disk_free_gb=10.0
        ),
    )
    server = create_gateway_server(TOKEN)
    register_status_tool(server, collector)
    return server


def build_app() -> Starlette:
    server = build_server()
    return server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        transport_security=GatewayTransportPolicy(
            allowed_hosts=(HOST,), allowed_origins=(ORIGIN,)
        ).sdk_settings(),
        host=HOST,
    )


@asynccontextmanager
async def client(app: Starlette) -> AsyncGenerator[httpx2.AsyncClient]:
    async with (
        app.router.lifespan_context(app),
        httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            base_url="http://test",
            timeout=httpx2.Timeout(connect=5, read=30, write=10, pool=10),
            follow_redirects=True,
        ) as http_client,
    ):
        yield http_client


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.integration
@pytest.mark.anyio
async def test_status_tool_returns_typed_overview_through_mcp() -> None:
    # Given: 실제 MCP 앱에 status 도구가 등록돼 있습니다.
    app = build_app()
    request = {
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {
            "name": "status",
            "arguments": {},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {
                    "name": "status-integration-test",
                    "version": "1.0",
                },
            },
        },
    }
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "Host": HOST,
        "Origin": ORIGIN,
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/call",
        "Mcp-Name": "status",
    }

    # When: MCP HTTP 경계에서 status를 호출합니다.
    started = anyio.current_time()
    async with client(app) as http_client:
        response = await http_client.post("/mcp", headers=headers, json=request)
    elapsed = anyio.current_time() - started

    # Then: 2초 안에 명시적 Worker/Helper/resources 상태가 반환됩니다.
    assert response.status_code == 200, response.text
    payload = _McpResponse.model_validate_json(response.content).result.structured_content
    assert elapsed < 2
    assert payload.interactive_worker.online is True
    assert payload.privileged_helper.online is False
    assert payload.resources.ram_total_gb == 4.0


@pytest.mark.integration
@pytest.mark.anyio
async def test_status_tool_rejects_malformed_input() -> None:
    # Given: arguments가 JSON object가 아닌 실제 MCP 요청입니다.
    app = build_app()
    request = {
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {
            "name": "status",
            "arguments": "malformed",
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {
                    "name": "status-integration-test",
                    "version": "1.0",
                },
            },
        },
    }
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "Host": HOST,
        "Origin": ORIGIN,
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/call",
        "Mcp-Name": "status",
    }

    # When: HTTP 경계에서 호출합니다.
    async with client(app) as http_client:
        response = await http_client.post("/mcp", headers=headers, json=request)

    # Then: MCP invalid params로 거부됩니다.
    error = _McpErrorResponse.model_validate_json(response.content)
    assert response.status_code == 400
    assert error.error.code == -32602


@pytest.mark.integration
@pytest.mark.anyio
async def test_status_annotation_is_read_only() -> None:
    # Given: status가 등록된 MCP 서버입니다.
    server = build_server()

    # When: 공개 도구 목록을 조회합니다.
    tools = await server.list_tools()

    # Then: status는 닫힌 세계의 읽기 전용 멱등 도구입니다.
    status = next(tool for tool in tools if tool.name == "status")
    assert status.annotations == ToolAnnotations(
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    )
