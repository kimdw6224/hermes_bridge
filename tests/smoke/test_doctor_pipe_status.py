"""Authenticated MCP status 기반 named-pipe ACL doctor regressions."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
from contextlib import contextmanager
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Event, Thread
from typing import TYPE_CHECKING, ClassVar, Final, Literal, final, override

import pytest
import uvicorn
from pydantic import BaseModel, ConfigDict, TypeAdapter

from hermes_windows_bridge.gateway.audit import AuditRecorder
from hermes_windows_bridge.gateway.dispatcher import DispatcherServices, GatewayDispatcher
from hermes_windows_bridge.gateway.idempotency import IdempotencyStore
from hermes_windows_bridge.gateway.mcp_server import create_gateway_server
from hermes_windows_bridge.gateway.origin_host import GatewayTransportPolicy
from hermes_windows_bridge.gateway.policy import ApprovalManager
from hermes_windows_bridge.gateway.tailscale_identity import AppCapabilityPolicy
from hermes_windows_bridge.models.tool_results import (
    ResourceStatus,
    TailscaleStatus,
)
from hermes_windows_bridge.privileged.ipc_server import HelperRegistry
from hermes_windows_bridge.tools.status import (
    StatusCollector,
    StatusSystemInfo,
    register_status_tool,
)
from hermes_windows_bridge.worker.ipc_client import WorkerRegistry

if TYPE_CHECKING:
    from collections.abc import Generator, Mapping


PROJECT_ROOT: Final = Path(__file__).parents[2]
DOCTOR_PATH: Final = PROJECT_ROOT / "scripts" / "doctor.ps1"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None
TOKEN: Final = "doctor-pipe-status-fixture-token"  # noqa: S105 - isolated fixture token입니다.
SERVE_HOST: Final = "fixture-bridge.example.ts.net"
CAPABILITY: Final = "hermes.local/windows-control"


class _DoctorCheck(BaseModel):
    """공개 doctor check의 비밀 없는 최소 경계입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    id: Literal["worker_pipe_acl", "privileged_pipe_acl"]
    status: Literal["pass", "warn", "fail"]
    critical: bool
    detail: str


class _StatusRequestHandler(BaseHTTPRequestHandler):
    """실제 HTTP method/header와 bounded status body를 기록하는 local fixture입니다."""

    response_status: ClassVar[int] = 200
    response_body: ClassVar[bytes] = b"{}"
    response_content_type: ClassVar[str] = "application/json"
    request_count: ClassVar[int] = 0
    received_method: ClassVar[str] = ""
    received_path: ClassVar[str] = ""
    received_headers: ClassVar[dict[str, str]] = {}

    def do_POST(self) -> None:
        type(self).request_count += 1
        type(self).received_method = self.command
        type(self).received_path = self.path
        type(self).received_headers = {key.lower(): value for key, value in self.headers.items()}
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        self.send_response(type(self).response_status)
        self.send_header("Content-Type", type(self).response_content_type)
        self.send_header("Content-Length", str(len(type(self).response_body)))
        self.end_headers()
        _ = self.wfile.write(type(self).response_body)

    @override
    def log_message(self, format: str, *args: object) -> None:
        del format, args


class _RedirectHandler(BaseHTTPRequestHandler):
    """doctor가 redirect target에 연결하지 않는지 검증합니다."""

    location: ClassVar[str] = ""

    def do_POST(self) -> None:
        self.send_response(302)
        self.send_header("Location", type(self).location)
        self.end_headers()

    @override
    def log_message(self, format: str, *args: object) -> None:
        del format, args


@final
class _ReadyUvicornServer(uvicorn.Server):
    """production `_serve`와 같은 listener readiness 경계를 제공합니다."""

    def __init__(self, config: uvicorn.Config) -> None:
        super().__init__(config)
        self.ready = Event()

    @override
    async def startup(self, sockets: list[socket.socket] | None = None) -> None:
        await super().startup(sockets=sockets)
        self.ready.set()


@contextmanager
def _http_server(handler: type[BaseHTTPRequestHandler]) -> Generator[int]:
    """fixture를 고정 loopback ephemeral port에서만 실행합니다."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


@contextmanager
def _production_streamable_status_gateway() -> Generator[int]:
    """`_serve`와 같은 json_response=False modern MCP streamable endpoint입니다."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    _, port = TypeAdapter(tuple[str, int]).validate_python(listener.getsockname())
    policy = GatewayTransportPolicy(
        allowed_hosts=("127.0.0.1", "localhost", SERVE_HOST),
        allowed_origins=(f"https://{SERVE_HOST}",),
    )
    workers = WorkerRegistry()
    helpers = HelperRegistry()
    collector = StatusCollector(
        dispatcher=GatewayDispatcher(
            DispatcherServices(
                workers=workers,
                helpers=helpers,
                idempotency=IdempotencyStore(ttl=timedelta(minutes=1)),
                approvals=ApprovalManager(),
                audit=AuditRecorder(),
            )
        ),
        helpers=helpers,
        workers=workers,
        app_capability_verified=lambda: True,
        system_probe=lambda: StatusSystemInfo(hostname="fixture-host", windows_version="fixture"),
        tailscale_probe=lambda: TailscaleStatus(
            connected=True, ip="100.64.0.1", app_capability_verified=True
        ),
        resource_probe=ResourceStatus.unavailable,
    )
    server = create_gateway_server(
        TOKEN,
        register_tools=lambda server: register_status_tool(server, collector),
        app_capability_policy=AppCapabilityPolicy(capability=CAPABILITY, serve_host=SERVE_HOST),
    )
    app = server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=False,
        transport_security=policy.sdk_settings(),
        host="127.0.0.1",
    )
    http_server = _ReadyUvicornServer(uvicorn.Config(app, log_level="error", access_log=False))
    thread = Thread(target=http_server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    assert http_server.ready.wait(5)
    try:
        yield port
    finally:
        http_server.should_exit = True
        thread.join(timeout=5)
        listener.close()
        assert not thread.is_alive()


def _status_payload(worker: str, privileged: str) -> bytes:
    """현재 authenticated status MCP response의 필요한 envelope만 만듭니다."""
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "doctor-pipe-acl-status",
            "result": {
                "structuredContent": {
                    "pipe_acl": {"worker": worker, "privileged": privileged}
                }
            },
        }
    ).encode("utf-8")


def _invoke_pipe_checks(
    port: int, token_path: Path, variables: Mapping[str, str] | None = None
) -> list[_DoctorCheck]:
    """doctor의 status-only functions만 fresh Windows PowerShell에서 실행합니다."""
    command = r"""
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:HERMES_TEST_DOCTOR,[ref]$tokens,[ref]$errors)
if($errors.Count -ne 0){exit 31}
foreach($name in @(
 'New-CheckResult', 'Initialize-BridgeDoctorJsonInspector',
 'Test-BridgeDoctorJsonNoDuplicateProperties', 'Read-BridgeDoctorBoundedHttpContent',
 'Get-BridgeDoctorSseJsonMessage', 'Get-AuthenticatedPipeAclStatus',
 'Get-PipeAclStatusChecks'
)){
 $definition=$ast.Find({param($node)
  $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
 },$true)
 if($null -eq $definition){exit 32}
 . ([scriptblock]::Create($definition.Extent.Text))
}
Get-PipeAclStatusChecks -Port ([int]$env:HERMES_TEST_PORT) `
 -ServeHost 'fixture-bridge.example.ts.net' `
 -Capability 'hermes.local/windows-control' -TokenPath $env:HERMES_TEST_TOKEN_PATH |
 ConvertTo-Json -Compress
"""
    environment = os.environ.copy()
    environment.update(variables or {})
    environment.update(
        {
            "HERMES_TEST_DOCTOR": str(DOCTOR_PATH),
            "HERMES_TEST_PORT": str(port),
            "HERMES_TEST_TOKEN_PATH": str(token_path),
            "PSModulePath": str(
                Path(environment["WINDIR"])
                / "System32"
                / "WindowsPowerShell"
                / "v1.0"
                / "Modules"
            ),
        }
    )
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    return TypeAdapter(list[_DoctorCheck]).validate_json(result.stdout)


def _fixture_token(tmp_path: Path, value: str = TOKEN) -> Path:
    token_path = tmp_path / "protected-token"
    _ = token_path.write_text(value, encoding="utf-8")
    return token_path


def _configure_status_response(
    *, status: int = 200, body: bytes, content_type: str = "application/json"
) -> None:
    _StatusRequestHandler.response_status = status
    _StatusRequestHandler.response_body = body
    _StatusRequestHandler.response_content_type = content_type
    _StatusRequestHandler.request_count = 0
    _StatusRequestHandler.received_method = ""
    _StatusRequestHandler.received_path = ""
    _StatusRequestHandler.received_headers = {}


def test_pipe_acl_status_passes_only_current_verified_authenticated_response(
    tmp_path: Path,
) -> None:
    # Given: 두 endpoint의 현재 exact observer 상태가 verified인 authenticated MCP response입니다.
    _configure_status_response(body=_status_payload("verified", "verified"))
    token_path = _fixture_token(tmp_path)

    # When: proxy 환경 변수가 있어도 doctor의 loopback status-only check를 실행하면
    with _http_server(_StatusRequestHandler) as port:
        checks = _invoke_pipe_checks(
            port,
            token_path,
            {"HTTP_PROXY": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1"},
        )

    # Then: status tool 한 번만 호출하고 두 endpoint만 pass입니다.
    assert [check.status for check in checks] == ["pass", "pass"]
    assert all(check.critical for check in checks)
    assert _StatusRequestHandler.request_count == 1
    assert _StatusRequestHandler.received_method == "POST"
    assert _StatusRequestHandler.received_path == "/mcp"
    assert _StatusRequestHandler.received_headers["authorization"] == f"Bearer {TOKEN}"
    assert _StatusRequestHandler.received_headers["host"] == SERVE_HOST
    assert "application/json" in _StatusRequestHandler.received_headers["accept"]
    assert "text/event-stream" in _StatusRequestHandler.received_headers["accept"]
    assert _StatusRequestHandler.received_headers["mcp-protocol-version"] == "2026-07-28"
    assert _StatusRequestHandler.received_headers["mcp-name"] == "status"


@pytest.mark.security
def test_pipe_acl_status_passes_real_production_streamable_http_transport(tmp_path: Path) -> None:
    # Given: Gateway `_serve`와 동일한 json_response=False + 2026-07-28 modern route입니다.
    token_path = _fixture_token(tmp_path)

    # When: doctor status probe를 실제 SDK streamable HTTP endpoint에 보냅니다.
    with _production_streamable_status_gateway() as port:
        checks = _invoke_pipe_checks(port, token_path)

    # Then: initialize/session 없이 real status surface의 unverified state는 warning으로 유지됩니다.
    assert [check.status for check in checks] == ["warn", "warn"]


def test_pipe_acl_status_fails_only_exact_template_mismatch(tmp_path: Path) -> None:
    # Given: Helper exact DACL template mismatch와 Worker verified observation입니다.
    _configure_status_response(body=_status_payload("verified", "mismatch"))

    # When: authenticated status를 읽습니다.
    with _http_server(_StatusRequestHandler) as port:
        checks = _invoke_pipe_checks(port, _fixture_token(tmp_path))

    # Then: mismatch만 fail closed이며 다른 endpoint는 verified pass를 보존합니다.
    assert [(check.id, check.status) for check in checks] == [
        ("worker_pipe_acl", "pass"),
        ("privileged_pipe_acl", "fail"),
    ]


def test_pipe_acl_status_warns_for_offline_and_unverified_observations(
    tmp_path: Path,
) -> None:
    # Given: stale/disconnected Worker와 native proof를 얻지 못한 Helper observation입니다.
    _configure_status_response(body=_status_payload("offline", "unverified"))

    # When: current status surface를 읽습니다.
    with _http_server(_StatusRequestHandler) as port:
        checks = _invoke_pipe_checks(port, _fixture_token(tmp_path))

    # Then: online 추정이나 false pass 없이 둘 다 warning입니다.
    assert [check.status for check in checks] == ["warn", "warn"]


def test_pipe_acl_status_warns_for_older_or_malformed_response_schema(
    tmp_path: Path,
) -> None:
    # Given: pipe_acl field가 없는 older gateway response와 malformed JSON response입니다.
    token_path = _fixture_token(tmp_path)
    _configure_status_response(
        body=json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "doctor-pipe-acl-status",
                "result": {"structuredContent": {}},
            }
        ).encode("utf-8")
    )
    with _http_server(_StatusRequestHandler) as port:
        older = _invoke_pipe_checks(port, token_path)
    _configure_status_response(body=b"{not-json")
    with _http_server(_StatusRequestHandler) as port:
        malformed = _invoke_pipe_checks(port, token_path)

    # Then: older/malformed payload 모두 proof가 없으므로 warning입니다.
    assert [check.status for check in older] == ["warn", "warn"]
    assert [check.status for check in malformed] == ["warn", "warn"]


def test_pipe_acl_status_rejects_duplicate_json_property_or_tool_error(tmp_path: Path) -> None:
    # Given: duplicate pipe key와 isError=true를 각각 포함한 otherwise-positive responses입니다.
    token_path = _fixture_token(tmp_path)
    duplicate = (
        b'{"jsonrpc":"2.0","id":"doctor-pipe-acl-status","result":'
        b'{"structuredContent":{"pipe_acl":{"worker":"verified","worker":"mismatch",'
        b'"privileged":"verified"}}}}'
    )
    _configure_status_response(body=duplicate)
    with _http_server(_StatusRequestHandler) as port:
        duplicate_checks = _invoke_pipe_checks(port, token_path)
    _configure_status_response(
        body=json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "doctor-pipe-acl-status",
                "result": {
                    "isError": True,
                    "structuredContent": {
                        "pipe_acl": {"worker": "verified", "privileged": "verified"}
                    },
                },
            }
        ).encode("utf-8")
    )
    with _http_server(_StatusRequestHandler) as port:
        error_checks = _invoke_pipe_checks(port, token_path)

    # Then: forged duplicate 및 tool failure는 verified payload를 포함해도 warning입니다.
    assert [check.status for check in duplicate_checks] == ["warn", "warn"]
    assert [check.status for check in error_checks] == ["warn", "warn"]


def test_pipe_acl_status_accepts_single_current_sse_message(tmp_path: Path) -> None:
    # Given: json_response=False streamable endpoint가 반환할 수 있는 one-message SSE body입니다.
    event = (
        b"event: message\r\ndata: "
        + _status_payload("verified", "verified")
        + b"\r\n\r\n"
    )
    _configure_status_response(body=event, content_type="text/event-stream")

    # When: authenticated status-only probe가 SSE event를 읽습니다.
    with _http_server(_StatusRequestHandler) as port:
        checks = _invoke_pipe_checks(port, _fixture_token(tmp_path))

    # Then: 정확히 하나의 current JSON-RPC message만 parsed proof가 됩니다.
    assert [check.status for check in checks] == ["pass", "pass"]


def test_pipe_acl_status_warns_without_protected_token_and_does_not_send_request(
    tmp_path: Path,
) -> None:
    # Given: selected protected token file이 없는 live status probe입니다.
    _configure_status_response(body=_status_payload("verified", "verified"))

    # When: missing token path로 status-only check를 실행하면
    with _http_server(_StatusRequestHandler) as port:
        checks = _invoke_pipe_checks(port, tmp_path / "missing-token")

    # Then: 인증을 우회하거나 online 상태를 pass로 올리지 않습니다.
    assert [check.status for check in checks] == ["warn", "warn"]
    assert _StatusRequestHandler.request_count == 0
    assert TOKEN not in " ".join(check.detail for check in checks)


def test_pipe_acl_status_does_not_follow_redirect(tmp_path: Path) -> None:
    # Given: 성공 response를 내는 별도 loopback target으로 보내는 redirect입니다.
    _configure_status_response(body=_status_payload("verified", "verified"))
    with _http_server(_StatusRequestHandler) as target_port:
        _RedirectHandler.location = f"http://127.0.0.1:{target_port}/mcp"

        # When: authenticated status-only request를 redirect source에 보냅니다.
        with _http_server(_RedirectHandler) as source_port:
            checks = _invoke_pipe_checks(source_port, _fixture_token(tmp_path))

    # Then: target의 success body를 읽지 않아 unverified warning으로 정규화합니다.
    assert [check.status for check in checks] == ["warn", "warn"]
    assert _StatusRequestHandler.request_count == 0
