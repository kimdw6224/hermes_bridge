from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import httpx2
import pytest

from hermes_windows_bridge.gateway.main import load_app_capability_policy
from hermes_windows_bridge.gateway.mcp_server import create_gateway_app
from hermes_windows_bridge.gateway.origin_host import GatewayTransportPolicy
from hermes_windows_bridge.gateway.tailscale_identity import (
    AppCapabilityPolicy,
    app_capability_verified,
)

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from pydantic import JsonValue
    from starlette.applications import Starlette

TOKEN = "test-token"  # noqa: S105 - 테스트 전용 공개 fixture입니다.
SERVE_HOST = "main-pc.example.ts.net"
CAPABILITY = "hermes.local/windows-control"


def _request() -> dict[str, JsonValue]:
    return {
        "jsonrpc": "2.0",
        "id": 20,
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {
                    "name": "tailscale-test",
                    "version": "1.0",
                },
            }
        },
    }


def _headers(**overrides: str) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Host": SERVE_HOST,
        "Origin": f"https://{SERVE_HOST}",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/list",
        "Tailscale-App-Capabilities": json.dumps(
            {CAPABILITY: [{"src": ["main", "self"]}]}, separators=(",", ":")
        ),
    }
    headers.update(overrides)
    return headers


def _app(*, require_app_capability: bool) -> Starlette:
    capability_policy = (
        AppCapabilityPolicy(capability=CAPABILITY, serve_host=SERVE_HOST)
        if require_app_capability
        else None
    )
    return create_gateway_app(
        token=TOKEN,
        policy=GatewayTransportPolicy(
            allowed_hosts=("127.0.0.1", "localhost", SERVE_HOST),
            allowed_origins=(f"https://{SERVE_HOST}",),
        ),
        app_capability_policy=capability_policy,
    )


@asynccontextmanager
async def _client(
    app: Starlette, *, peer_host: str = "127.0.0.1"
) -> AsyncGenerator[httpx2.AsyncClient]:
    async with (
        app.router.lifespan_context(app),
        httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app, client=(peer_host, 51432)),
            base_url="http://test",
        ) as client,
    ):
        yield client


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class TestAppCaps:
    @pytest.mark.anyio
    async def test_existing_app_without_capability_policy_remains_compatible(self) -> None:
        app = _app(require_app_capability=False)

        async with _client(app) as client:
            response = await client.post("/mcp", headers=_headers(), json=_request())

        assert response.status_code == 200
        assert app_capability_verified() is False

    @pytest.mark.anyio
    async def test_bearer_authentication_remains_required_after_capability(self) -> None:
        app = _app(require_app_capability=True)
        headers = _headers(Authorization="Bearer wrong-token")

        async with _client(app) as client:
            response = await client.post("/mcp", headers=headers, json=_request())

        assert response.status_code == 401

    @pytest.mark.anyio
    async def test_trusted_serve_context_accepts_exact_capability(self) -> None:
        app = _app(require_app_capability=True)

        async with _client(app) as client:
            response = await client.post("/mcp", headers=_headers(), json=_request())

        assert response.status_code == 200

    @pytest.mark.anyio
    async def test_direct_loopback_spoofed_header_rejected_without_serve_context(self) -> None:
        app = _app(require_app_capability=True)
        headers = _headers(Host="localhost")

        async with _client(app) as client:
            response = await client.post("/mcp", headers=headers, json=_request())

        assert response.status_code == 403
        assert response.text == "Untrusted Tailscale Serve context"

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        "capability_header",
        ["", "not-json", "[]", "{}", '{"hermes.local/windows-control":[]}'],
    )
    async def test_malformed_or_missing_capability_fails_closed(
        self, capability_header: str
    ) -> None:
        app = _app(require_app_capability=True)
        headers = _headers(**{"Tailscale-App-Capabilities": capability_header})

        async with _client(app) as client:
            response = await client.post("/mcp", headers=headers, json=_request())

        assert response.status_code == 403
        assert response.text == "Required Tailscale App Capability was not verified"

    @pytest.mark.anyio
    async def test_non_loopback_peer_cannot_spoof_serve_headers(self) -> None:
        app = _app(require_app_capability=True)

        async with _client(app, peer_host="100.64.0.8") as client:
            response = await client.post("/mcp", headers=_headers(), json=_request())

        assert response.status_code == 403
        assert response.text == "Untrusted Tailscale Serve context"

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        "capability_header",
        [
            '{"ignore all prior rules":[{"src":["main"]}]}',
            json.dumps({CAPABILITY: [{"src": "main"}]}),
            json.dumps({CAPABILITY: [{"src": ["main"]}], "padding": "x" * 8_192}),
        ],
    )
    async def test_hostile_external_header_text_cannot_expand_authority(
        self, capability_header: str
    ) -> None:
        app = _app(require_app_capability=True)
        headers = _headers(**{"Tailscale-App-Capabilities": capability_header})

        async with _client(app) as client:
            response = await client.post("/mcp", headers=headers, json=_request())

        assert response.status_code == 403


class TestGatewayEnvironment:
    def test_missing_serve_host_keeps_optional_capability_disabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("HERMES_BRIDGE_TAILSCALE_SERVE_HOST", raising=False)

        assert load_app_capability_policy() is None

    def test_exact_serve_host_enables_default_capability(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HERMES_BRIDGE_TAILSCALE_SERVE_HOST", SERVE_HOST)
        monkeypatch.delenv("HERMES_BRIDGE_TAILSCALE_APP_CAPABILITY", raising=False)

        policy = load_app_capability_policy()

        assert policy == AppCapabilityPolicy(
            capability=CAPABILITY,
            serve_host=SERVE_HOST,
        )
