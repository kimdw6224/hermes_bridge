"""실제 loopback Gateway로 doctor transport sensor를 독립 검증합니다."""

from __future__ import annotations

import os
import socket
import subprocess
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Event, Thread
from typing import TYPE_CHECKING, ClassVar, Final, Literal, final, override

import pytest
import uvicorn
from pydantic import BaseModel, ConfigDict, TypeAdapter

from hermes_windows_bridge.gateway.mcp_server import create_gateway_server
from hermes_windows_bridge.gateway.origin_host import GatewayTransportPolicy
from hermes_windows_bridge.gateway.tailscale_identity import AppCapabilityPolicy

if TYPE_CHECKING:
    from collections.abc import Generator, Mapping

PROJECT_ROOT: Final = Path(__file__).parents[2]
DOCTOR_PATH: Final = PROJECT_ROOT / "scripts" / "doctor.ps1"
POWERSHELL_PATH: Final = "powershell.exe"
TOKEN: Final = "transport-doctor-test-token"  # noqa: S105 - isolated fixture token입니다.
SERVE_HOST: Final = "fixture-bridge.example.ts.net"
CAPABILITY: Final = "hermes.local/windows-control"
ORIGIN: Final = f"https://{SERVE_HOST}"


class _TransportCheck(BaseModel):
    """비밀 없는 transport check 결과의 최소 JSON 경계입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    id: Literal["transport_policy"]
    status: Literal["pass", "warn", "fail"]


class _ProbeResult(BaseModel):
    """상태 코드만 내보내는 단일 loopback probe 경계입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    state: Literal["observed", "unavailable"]
    status: int


@final
class _ReadyUvicornServer(uvicorn.Server):
    """listener startup을 Event로 외부 fixture에 알립니다."""

    def __init__(self, config: uvicorn.Config) -> None:
        super().__init__(config)
        self.ready = Event()

    @override
    async def startup(self, sockets: list[socket.socket] | None = None) -> None:
        await super().startup(sockets=sockets)
        self.ready.set()


class _RedirectHandler(BaseHTTPRequestHandler):
    """redirect가 follow되지 않는지 확인하는 loopback-only endpoint입니다."""

    def do_GET(self) -> None:
        self.send_response(302)
        self.send_header("Location", "http://127.0.0.1:1/mcp")
        self.end_headers()


class _DelayedHandler(BaseHTTPRequestHandler):
    """doctor의 5초 HTTP timeout을 실제 socket 대기에서 검증합니다."""

    release: ClassVar[Event] = Event()

    def do_GET(self) -> None:
        _ = self.release.wait(10)
        self.send_response(204)
        self.end_headers()


@contextmanager
def _gateway(*, allowed_origins: tuple[str, ...] = (ORIGIN,)) -> Generator[int]:
    """production과 같은 app assembly를 임시 loopback socket에서 제공합니다."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = TypeAdapter(tuple[str, int]).validate_python(listener.getsockname())[1]
    policy = GatewayTransportPolicy(
        allowed_hosts=("127.0.0.1", "localhost", SERVE_HOST),
        allowed_origins=allowed_origins,
    )
    server = create_gateway_server(
        TOKEN,
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


@contextmanager
def _http_server(handler: type[BaseHTTPRequestHandler]) -> Generator[int]:
    """redirect와 timeout 경계를 위한 local-only HTTP endpoint를 제공합니다."""
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


def _invoke_extracted(
    function_names: tuple[str, ...], expression: str, variables: Mapping[str, str]
) -> str:
    """doctor source의 named functions만 fresh Windows PowerShell에서 실행합니다."""
    names = ",".join(f"'{name}'" for name in function_names)
    command = f"""
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:HERMES_TEST_DOCTOR,[ref]$tokens,[ref]$errors)
if($errors.Count -ne 0){{exit 31}}
foreach($name in @({names})){{
 $definition=$ast.Find({{param($node)
  $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
 }},$true)
 if($null -eq $definition){{exit 32}}
 . ([scriptblock]::Create($definition.Extent.Text))
}}
{expression} | ConvertTo-Json -Compress
"""
    environment = os.environ.copy()
    environment.update(variables)
    environment["HERMES_TEST_DOCTOR"] = str(DOCTOR_PATH)
    environment["PSModulePath"] = str(
        Path(environment["WINDIR"]) / "System32" / "WindowsPowerShell" / "v1.0" / "Modules"
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
    assert result.returncode == 0
    return result.stdout


def _transport_check(port: int, token_path: Path, variables: Mapping[str, str]) -> _TransportCheck:
    """actual Gateway fixture에 대한 doctor transport check 결과를 파싱합니다."""
    values = dict(variables)
    values.update({"HERMES_TEST_PORT": str(port), "HERMES_TEST_TOKEN_PATH": str(token_path)})
    output = _invoke_extracted(
        ("New-CheckResult", "Get-TransportPolicyProbeStatus", "Get-TransportPolicyCheck"),
        (
            "Get-TransportPolicyCheck -Port ([int]$env:HERMES_TEST_PORT) "
            "-ServeHost 'fixture-bridge.example.ts.net' "
            "-Capability 'hermes.local/windows-control' -TokenPath $env:HERMES_TEST_TOKEN_PATH"
        ),
        values,
    )
    return _TransportCheck.model_validate_json(output)


def _probe(port: int) -> _ProbeResult:
    """direct probe의 redirect/timeout 상태만 파싱합니다."""
    output = _invoke_extracted(
        ("Get-TransportPolicyProbeStatus",),
        (
            "Get-TransportPolicyProbeStatus -Port ([int]$env:HERMES_TEST_PORT) "
            "-HostHeader 'fixture-bridge.example.ts.net' "
            "-Origin 'https://fixture-bridge.example.ts.net' "
            "-Capability 'hermes.local/windows-control' -Token 'transport-doctor-test-token'"
        ),
        {"HERMES_TEST_PORT": str(port)},
    )
    return _ProbeResult.model_validate_json(output)


@pytest.mark.security
def test_transport_check_passes_actual_gateway_matrix_without_proxy(tmp_path: Path) -> None:
    # Given: real Gateway app와 접근 불가한 process proxy, test-only protected token입니다.
    token_path = tmp_path / "token"
    _ = token_path.write_text(TOKEN, encoding="utf-8")
    with _gateway() as port:
        # When: doctor source에서 추출한 transport check를 fresh WinPS5에서 실행하면
        check = _transport_check(
            port,
            token_path,
            {"HTTP_PROXY": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1"},
        )

    # Then: proxy 없이 canonical/negative boundary matrix를 통과합니다.
    assert check.status == "pass"


@pytest.mark.security
def test_transport_check_warns_when_token_is_unavailable(tmp_path: Path) -> None:
    # Given: 존재하지 않는 protected token path입니다.
    missing_token = tmp_path / "missing-token"
    with _gateway() as port:
        # When: doctor transport check를 실행하면
        check = _transport_check(port, missing_token, {})

    # Then: live policy failure로 오진하지 않고 explicit warn을 반환합니다.
    assert check.status == "warn"


@pytest.mark.security
def test_transport_check_fails_when_gateway_allows_wrong_origin(tmp_path: Path) -> None:
    # Given: canonical Origin 외 reserved wrong Origin까지 허용한 actual Gateway policy입니다.
    token_path = tmp_path / "token"
    _ = token_path.write_text(TOKEN, encoding="utf-8")
    with _gateway(allowed_origins=(ORIGIN, "https://invalid-doctor-origin.invalid")) as port:
        # When: doctor transport check를 실행하면
        check = _transport_check(port, token_path, {})

    # Then: wrong Origin이 403으로 거부되지 않아 aggregate transport sensor가 fail입니다.
    assert check.status == "fail"


@pytest.mark.security
def test_transport_probe_does_not_follow_redirect() -> None:
    # Given: 다른 endpoint로 보내는 local redirect입니다.
    with _http_server(_RedirectHandler) as port:
        # When: direct doctor probe를 실행하면
        probe = _probe(port)

    # Then: redirect target로 이동하지 않고 원 응답 상태만 관측합니다.
    assert probe.state == "observed"
    assert probe.status == 302


@pytest.mark.security
def test_transport_probe_reports_unavailable_after_bounded_timeout() -> None:
    # Given: response header를 5초보다 길게 보류하는 local endpoint입니다.
    _DelayedHandler.release.clear()
    with _http_server(_DelayedHandler) as port:
        # When: direct doctor probe를 실행하면
        probe = _probe(port)
        _DelayedHandler.release.set()

    # Then: raw timeout을 노출하지 않고 unavailable 상태를 반환합니다.
    assert probe.state == "unavailable"
    assert probe.status == 0
