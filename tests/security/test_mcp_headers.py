from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import httpx2
import pytest

from hermes_windows_bridge.gateway.mcp_server import create_gateway_app
from hermes_windows_bridge.gateway.origin_host import GatewayTransportPolicy

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from pydantic import JsonValue
    from starlette.applications import Starlette

TOKEN = "test-token"  # noqa: S105 - 테스트 전용 공개 fixture입니다.
HOST = "main-pc.example.ts.net"
ORIGIN = "https://main-pc.example.ts.net"


def _app() -> Starlette:
    return create_gateway_app(
        token=TOKEN,
        policy=GatewayTransportPolicy(
            allowed_hosts=("127.0.0.1", "localhost", HOST),
            allowed_origins=(ORIGIN,),
        ),
    )


@asynccontextmanager
async def _client() -> AsyncGenerator[httpx2.AsyncClient]:
    app = _app()
    async with (
        app.router.lifespan_context(app),
        httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            base_url="http://test",
        ) as client,
    ):
        yield client


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _headers(**overrides: str) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Host": HOST,
        "Origin": ORIGIN,
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/list",
    }
    headers.update(overrides)
    return headers


def _request(*, method: str = "tools/list", version: str = "2026-07-28") -> dict[str, JsonValue]:
    return {
        "jsonrpc": "2.0",
        "id": 7,
        "method": method,
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": version,
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {
                    "name": "header-test",
                    "version": "1.0",
                },
            }
        },
    }


class TestModernProtocolHeaders:
    @pytest.mark.anyio
    async def test_matching_headers_return_tool_catalog(self) -> None:
        async with _client() as client:
            response = await client.post("/mcp", headers=_headers(), json=_request())

        assert response.status_code == 200
        assert response.json()["result"]["tools"] == []

    @pytest.mark.anyio
    async def test_method_header_mismatch_is_rejected_by_sdk(self) -> None:
        async with _client() as client:
            response = await client.post(
                "/mcp",
                headers=_headers(**{"Mcp-Method": "ignore/all/security"}),
                json=_request(),
            )

        assert response.status_code == 400
        assert response.json()["error"]["code"] == -32020

    @pytest.mark.anyio
    async def test_protocol_header_mismatch_is_rejected_by_sdk(self) -> None:
        async with _client() as client:
            response = await client.post(
                "/mcp",
                headers=_headers(**{"MCP-Protocol-Version": "2025-11-25"}),
                json=_request(),
            )

        assert response.status_code == 400
        assert response.json()["error"]["code"] == -32600

    @pytest.mark.anyio
    async def test_name_header_mismatch_is_rejected_by_sdk(self) -> None:
        request: dict[str, JsonValue] = {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "status",
                "arguments": {},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            },
        }

        async with _client() as client:
            response = await client.post(
                "/mcp",
                headers=_headers(
                    **{"Mcp-Method": "tools/call", "Mcp-Name": "ignore-security"}
                ),
                json=request,
            )

        assert response.status_code == 400
        assert response.json()["error"]["code"] == -32020

    @pytest.mark.anyio
    async def test_unsupported_protocol_version_is_rejected_by_sdk(self) -> None:
        async with _client() as client:
            response = await client.post(
                "/mcp",
                headers=_headers(**{"MCP-Protocol-Version": "2099-01-01"}),
                json=_request(version="2099-01-01"),
            )

        assert response.status_code == 400
        assert response.json()["error"]["code"] == -32022

    @pytest.mark.anyio
    async def test_malformed_json_returns_parse_error(self) -> None:
        async with _client() as client:
            response = await client.post("/mcp", headers=_headers(), content=b"{")

        assert response.status_code == 400
        assert response.json()["error"]["code"] == -32700


class TestLegacyCompatibilityAdapter:
    @pytest.mark.anyio
    async def test_2025_11_25_initialize_remains_sdk_compatible(self) -> None:
        request = {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "legacy-hermes", "version": "1.0"},
            },
        }
        headers = {
            "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Host": HOST,
            "Origin": ORIGIN,
        }

        async with _client() as client:
            response = await client.post("/mcp", headers=headers, json=request)

        assert response.status_code == 200
        assert response.json()["result"]["protocolVersion"] == "2025-11-25"
