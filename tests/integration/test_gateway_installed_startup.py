"""설치 구성에서 시작하는 실제 Gateway 프로세스를 검증합니다."""

from __future__ import annotations

import os
import subprocess
import sys
from typing import TYPE_CHECKING

import anyio
import httpx2
import pytest
import yaml
from anyio.abc import SocketAttribute

from hermes_windows_bridge.config import InvalidConfigurationError
from hermes_windows_bridge.gateway.main import GatewayEnvironmentError, run_gateway_server

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.anyio
async def test_service_starts_from_installed_files_without_token_environment(
    tmp_path: Path,
) -> None:
    # Given: 설치기가 저장하는 파일과 충돌하는 개발 환경값을 준비합니다.
    runtime = tmp_path / "HermesWindowsBridge"
    runtime.mkdir()
    token_file = runtime / "token"
    _ = token_file.write_text("fixture-service-token", encoding="utf-8")
    async with await anyio.create_tcp_listener(local_host="127.0.0.1") as reservation:
        port = reservation.extra(SocketAttribute.local_port)  # noqa: S610 - AnyIO 소켓 속성입니다.
    config = {
        "paths": {
            "program_data": str(runtime),
            "user_data": str(runtime),
            "token_file": str(token_file),
        },
        "server": {
            "port": port,
            "allowed_hosts": ["127.0.0.1", "pc.fixture.ts.net"],
            "allowed_origins": ["https://pc.fixture.ts.net"],
        },
    }
    _ = (runtime / "config.yaml").write_text(yaml.safe_dump(config), encoding="utf-8")
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("HERMES_BRIDGE_")
    }
    environment["ProgramData"] = str(tmp_path)
    command = (
        "import anyio; import hermes_windows_bridge.gateway.main as gateway; "
        "gateway.load_installed_worker_sid = lambda: 'S-1-5-21-1-2-3-4'; "
        "from hermes_windows_bridge.gateway.main import run_gateway_server; "
        "anyio.run(run_gateway_server)"
    )

    # When: SCM이 호출하는 runner를 새 프로세스에서 시작합니다.
    async with await anyio.open_process(
        [sys.executable, "-c", command],
        env=environment,
        stdout=subprocess.DEVNULL,
    ) as process:
        try:
            assert process.stderr is not None
            output = b""
            with anyio.fail_after(15):
                while b"Uvicorn running" not in output:
                    output += await process.stderr.receive()
            async with httpx2.AsyncClient() as client:
                response = await client.get(f"http://127.0.0.1:{port}/mcp")
                authorized = await client.get(
                    f"http://127.0.0.1:{port}/mcp",
                    headers={"Authorization": "Bearer fixture-service-token"},
                )
                invalid = await client.get(
                    f"http://127.0.0.1:{port}/mcp",
                    headers={
                        "Host": "pc.fixture.ts.net",
                        "Tailscale-App-Capabilities": (
                            '{"hermes.local/windows-control":[{"src":["tag:hermes"]}]}'
                        ),
                        "Authorization": "Bearer wrong-token",
                    },
                )
                forwarded = await client.get(
                    f"http://127.0.0.1:{port}/mcp",
                    headers={
                        "Host": "pc.fixture.ts.net",
                        "Tailscale-App-Capabilities": (
                            '{"hermes.local/windows-control":[{"src":["tag:hermes"]}]}'
                        ),
                        "X-Forwarded-For": "100.64.0.1",
                    },
                )
            # Then: 지정 포트에서 HTTP가 응답하며 capability 없는 요청은 거부됩니다.
            assert response.status_code == 403
            assert authorized.status_code == 403
            assert invalid.status_code == 401
            assert forwarded.status_code == 401
            script = r"""$externalCommandTimeoutSeconds = 5
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path scripts/doctor.ps1), [ref]$null, [ref]$null)
$names = @('New-CheckResult', 'Get-UnauthorizedStatus', 'Get-BearerAuthCheck')
$ast.FindAll({param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -in $names
}, $true) | ForEach-Object { Invoke-Expression $_.Extent.Text }
$result = Get-BearerAuthCheck -Port PORT_VALUE -ServeHost 'pc.fixture.ts.net'
if ($result.status -ne 'pass') { throw $result.detail }
""".replace("PORT_VALUE", str(port))
            probe = await anyio.run_process(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                check=False,
            )
            assert probe.returncode == 0, probe.stderr.decode(errors="replace")
        finally:
            process.terminate()
            _ = await process.wait()


@pytest.mark.anyio
async def test_development_runner_requires_explicit_token_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: 개발 실행 경로에 token 환경 변수가 없습니다.
    monkeypatch.delenv("HERMES_BRIDGE_TOKEN", raising=False)
    # When / Then: 설치 파일로 묵시적 전환하지 않고 기존 환경 오류를 반환합니다.
    with pytest.raises(GatewayEnvironmentError, match="HERMES_BRIDGE_TOKEN"):
        await run_gateway_server(environment=True)


@pytest.mark.anyio
@pytest.mark.parametrize("serve_hosts", [[], ["a.fixture.ts.net", "b.fixture.ts.net"]])
async def test_required_capability_rejects_ambiguous_installed_host(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    serve_hosts: list[str],
) -> None:
    # Given: capability 검증에 필요한 단일 Serve host가 없는 설치 구성입니다.
    runtime = tmp_path / "HermesWindowsBridge"
    runtime.mkdir()
    token_file = runtime / "token"
    _ = token_file.write_text("fixture-service-token", encoding="utf-8")
    config = {
        "paths": {
            "program_data": str(runtime),
            "user_data": str(runtime),
            "token_file": str(token_file),
        },
        "server": {
            "allowed_hosts": ["127.0.0.1", *serve_hosts],
            "allowed_origins": ["https://pc.fixture.ts.net"],
        },
    }
    _ = (runtime / "config.yaml").write_text(yaml.safe_dump(config), encoding="utf-8")
    monkeypatch.setenv("ProgramData", str(tmp_path))
    # When / Then: 서버를 시작하기 전에 닫힌 구성 오류로 거부합니다.
    with pytest.raises(InvalidConfigurationError):
        await run_gateway_server()
