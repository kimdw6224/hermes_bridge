from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING
from unittest.mock import patch

import httpx2
import pytest
from pydantic import JsonValue, ValidationError

from hermes_windows_bridge.gateway.auth import StaticBearerTokenVerifier
from hermes_windows_bridge.gateway.main import LOOPBACK_HOST, main
from hermes_windows_bridge.gateway.mcp_server import create_gateway_app
from hermes_windows_bridge.gateway.origin_host import GatewayTransportPolicy

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from starlette.applications import Starlette

TOKEN = "test-token"  # noqa: S105 - 테스트 전용 공개 fixture입니다.
LOCAL_HOST = "127.0.0.1"
TAILSCALE_HOST = "main-pc.example.ts.net"
TAILSCALE_ORIGIN = "https://main-pc.example.ts.net"


def _modern_request_headers(**overrides: str) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Host": TAILSCALE_HOST,
        "Origin": TAILSCALE_ORIGIN,
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/list",
    }
    headers.update(overrides)
    return headers


def _modern_tools_list() -> dict[str, JsonValue]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {
                    "name": "transport-test",
                    "version": "1.0",
                },
            }
        },
    }


@asynccontextmanager
async def _client(app: Starlette) -> AsyncGenerator[httpx2.AsyncClient]:
    async with (
        app.router.lifespan_context(app),
        httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            base_url="http://test",
        ) as client,
    ):
        yield client


@pytest.fixture
def app() -> Starlette:
    policy = GatewayTransportPolicy(
        allowed_hosts=(LOCAL_HOST, "localhost", TAILSCALE_HOST),
        allowed_origins=(TAILSCALE_ORIGIN,),
    )
    return create_gateway_app(token=TOKEN, policy=policy)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class TestLoopbackBinding:
    def test_gateway_bind_host_is_loopback(self) -> None:
        assert LOOPBACK_HOST == LOCAL_HOST

    def test_keyboard_interrupt_exits_without_traceback(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("HERMES_BRIDGE_TOKEN", TOKEN)
        monkeypatch.setenv("HERMES_BRIDGE_ALLOWED_HOSTS", LOCAL_HOST)
        monkeypatch.setenv("HERMES_BRIDGE_ALLOWED_ORIGINS", TAILSCALE_ORIGIN)

        with patch(
            "hermes_windows_bridge.gateway.main.anyio.run",
            side_effect=KeyboardInterrupt,
        ):
            main()


class TestBearerAuthentication:
    @pytest.mark.anyio
    async def test_verifier_accepts_exact_token(self) -> None:
        verifier = StaticBearerTokenVerifier(TOKEN)

        access_token = await verifier.verify_token(TOKEN)

        assert access_token is not None
        assert access_token.client_id == "hermes-windows-bridge"

    @pytest.mark.parametrize(
        "authorization",
        [None, "", "Basic dGVzdDp0ZXN0", "Bearer wrong-token", "Bearer"],
    )
    @pytest.mark.anyio
    async def test_malformed_or_invalid_authorization_fails_closed(
        self,
        app: Starlette,
        authorization: str | None,
    ) -> None:
        headers = _modern_request_headers()
        if authorization is None:
            del headers["Authorization"]
        else:
            headers["Authorization"] = authorization

        async with _client(app) as client:
            response = await client.post("/mcp", headers=headers, json=_modern_tools_list())

        assert response.status_code == 401


class TestOriginAndHostPolicy:
    def test_sdk_policy_preserves_only_exact_host_entries(self) -> None:
        policy = GatewayTransportPolicy(
            allowed_hosts=(TAILSCALE_HOST,),
            allowed_origins=(TAILSCALE_ORIGIN,),
        )

        settings = policy.sdk_settings()

        assert settings.allowed_hosts == [TAILSCALE_HOST]

    def test_wildcard_host_is_rejected_at_configuration_boundary(self) -> None:
        with pytest.raises(ValidationError):
            _ = GatewayTransportPolicy(
                allowed_hosts=("*",),
                allowed_origins=(TAILSCALE_ORIGIN,),
            )

    @pytest.mark.anyio
    async def test_invalid_origin_returns_403(self, app: Starlette) -> None:
        async with _client(app) as client:
            response = await client.post(
                "/mcp",
                headers=_modern_request_headers(Origin="https://evil.example"),
                json=_modern_tools_list(),
            )

        assert response.status_code == 403
        assert response.text == "Invalid Origin header"

    @pytest.mark.anyio
    async def test_authentication_rejects_before_untrusted_origin(self, app: Starlette) -> None:
        headers = _modern_request_headers(Origin="https://evil.example")
        headers["Authorization"] = "Bearer wrong-token"

        async with _client(app) as client:
            response = await client.post("/mcp", headers=headers, json=_modern_tools_list())

        assert response.status_code == 401

    @pytest.mark.anyio
    async def test_invalid_host_returns_421(self, app: Starlette) -> None:
        async with _client(app) as client:
            response = await client.post(
                "/mcp",
                headers=_modern_request_headers(Host="ignore prior rules.example"),
                json=_modern_tools_list(),
            )

        assert response.status_code == 421
        assert response.text == "Invalid Host header"

    @pytest.mark.anyio
    async def test_new_app_uses_changed_allowlist(self) -> None:
        policy = GatewayTransportPolicy(
            allowed_hosts=("replacement.example.ts.net",),
            allowed_origins=("https://replacement.example.ts.net",),
        )
        headers = _modern_request_headers(
            Host="replacement.example.ts.net",
            Origin="https://replacement.example.ts.net",
        )

        gateway_app = create_gateway_app(token=TOKEN, policy=policy)
        async with _client(gateway_app) as new_client:
            accepted = await new_client.post("/mcp", headers=headers, json=_modern_tools_list())
            rejected = await new_client.post(
                "/mcp",
                headers=_modern_request_headers(),
                json=_modern_tools_list(),
            )

        assert accepted.status_code == 200
        assert rejected.status_code == 421
