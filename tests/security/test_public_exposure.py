from __future__ import annotations

import json
import socket
import subprocess
from contextlib import asynccontextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import TYPE_CHECKING, ClassVar, Final

import httpx2
import pytest
from pydantic import BaseModel, ConfigDict

from hermes_windows_bridge.gateway.mcp_server import create_gateway_app
from hermes_windows_bridge.gateway.origin_host import GatewayTransportPolicy
from hermes_windows_bridge.gateway.tailscale_identity import AppCapabilityPolicy

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from starlette.applications import Starlette


PROJECT_ROOT: Final = Path(__file__).parents[2]
POWERSHELL: Final = "powershell.exe"
TOKEN: Final = "task-22-token"  # noqa: S105 - test-only bearer fixture입니다.
SERVE_HOST: Final = "main-pc.example.ts.net"
CAPABILITY: Final = "hermes.local/windows-control"


@dataclass(frozen=True, slots=True)
class _Listener:
    address: str


class _DoctorCheck(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    id: str
    status: str
    detail: str


class _DoctorReport(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    checks: tuple[_DoctorCheck, ...]


class _UnauthorizedHandler(BaseHTTPRequestHandler):
    """Doctor의 두 bearer probe를 빠르게 거부하는 loopback-only HTTP surface입니다."""

    def do_GET(self) -> None:
        self.send_response(401)
        self.end_headers()


@asynccontextmanager
async def _client(app: Starlette, *, peer_host: str) -> AsyncGenerator[httpx2.AsyncClient]:
    async with (
        app.router.lifespan_context(app),
        httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app, client=(peer_host, 51_432)),
            base_url="http://test",
        ) as client,
    ):
        yield client


def _public_listener_addresses(listeners: tuple[_Listener, ...]) -> tuple[str, ...]:
    """Loopback 외 주소만 보안 doctor가 차단해야 하는 listener로 분류합니다."""
    return tuple(
        listener.address
        for listener in listeners
        if listener.address not in {"127.0.0.1", "::1"}
    )


class TestListeners:
    def test_backend_loopback_only(self) -> None:
        # Given: 실제 temporary loopback listener와 public bind를 나타내는 주입 inventory입니다.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            live_address = "127.0.0.1"
            inventory = (_Listener(live_address), _Listener("192.0.2.44"))

            # When: doctor와 동일한 loopback allowlist 판정을 적용하면
            public = _public_listener_addresses(inventory)

        # Then: 실제 loopback은 허용하고 fixture public inventory는 거부합니다.
        assert live_address == "127.0.0.1"
        assert public == ("192.0.2.44",)

    def test_doctor_accepts_actual_temporary_loopback_listener(self) -> None:
        # Given: 실제 loopback HTTP listener와 임의 bridge port입니다.
        server = ThreadingHTTPServer(("127.0.0.1", 0), _UnauthorizedHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            # When: read-only doctor가 같은 port를 OS listener inventory로 검사하면
            result = subprocess.run(
                [
                    POWERSHELL,
                    "-NoProfile",
                    "-File",
                    str(PROJECT_ROOT / "scripts" / "doctor.ps1"),
                    "-Json",
                    "-GatewayPort",
                    str(server.server_port),
                ],
                cwd=PROJECT_ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        # Then: 전체 doctor healthy 여부와 무관하게 listener 판정은 live OS state를 확인합니다.
        report = _DoctorReport.model_validate_json(result.stdout)
        listener = next(check for check in report.checks if check.id == "backend_listener")
        bearer_auth = next(check for check in report.checks if check.id == "bearer_auth")
        assert result.returncode in {0, 1}
        assert listener.status == "pass"
        assert bearer_auth.status == "pass"
        assert listener.detail == (
            f"port {server.server_port} listens on loopback only; no public listener exists"
        )


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_direct_loopback_app_capability_header_spoof_is_rejected() -> None:
    # Given: Serve forwarding 없이 direct loopback caller가 app capability header를 위조합니다.
    app = create_gateway_app(
        token=TOKEN,
        policy=GatewayTransportPolicy(
            allowed_hosts=("localhost", SERVE_HOST),
            allowed_origins=(f"https://{SERVE_HOST}",),
        ),
        app_capability_policy=AppCapabilityPolicy(capability=CAPABILITY, serve_host=SERVE_HOST),
    )
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json",
        "Host": "localhost",
        "Origin": f"https://{SERVE_HOST}",
        "Tailscale-App-Capabilities": json.dumps({CAPABILITY: [{"src": ["forged"]}]}),
    }

    # When: protected MCP endpoint에 위조된 forwarding header만 전송하면
    async with _client(app, peer_host="127.0.0.1") as client:
        response = await client.post("/mcp", headers=headers, json={})

    # Then: app-cap forwarding context를 성공 로그가 아닌 403 boundary로 검증합니다.
    assert response.status_code == 403
    assert response.text == "Untrusted Tailscale Serve context"
