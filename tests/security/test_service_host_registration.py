"""Service Host 앵커를 통한 서비스 등록 차단 경계를 검증합니다."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import ClassVar, Final

import pytest
from pydantic import BaseModel, ConfigDict, Field

_PROJECT_ROOT: Final = Path(__file__).parents[2]
_POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert _POWERSHELL_PATH is not None


class RegistrationResult(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    state: str
    failure_reason: str | None = Field(default=None, alias="failureReason")


class SimulatedHostRegistration(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    applied: bool
    state: str
    argv: tuple[str, ...]


@pytest.mark.parametrize(
    ("script_name", "profile"),
    [
        ("register-gateway-service.ps1", "gateway"),
        ("register-privileged-service.ps1", "privileged"),
    ],
)
def test_simulate_uses_verified_service_host_contract_argv(
    script_name: str,
    profile: str,
    tmp_path: Path,
) -> None:
    # Given: production entrypoint와 같은 위치에 검증 성공을 반환하는 Host 계약입니다.
    script_root = tmp_path / "scripts"
    _ = script_root.mkdir()
    _ = shutil.copy2(_PROJECT_ROOT / "scripts" / script_name, script_root / script_name)
    _ = shutil.copy2(
        _PROJECT_ROOT / "scripts" / "service-object-security.ps1",
        script_root / "service-object-security.ps1",
    )
    host_root = tmp_path / "hosts" / ("a" * 64) / profile
    release_root = tmp_path / "release"
    _ = host_root.mkdir(parents=True)
    _ = release_root.mkdir()
    host_executable = host_root / "HermesBridge.ServiceHost.exe"
    mock_contract = f"""
param([switch]$LibraryMode, [string]$Profile)
function Get-BridgeServiceHostContract {{
    param([string]$HostRoot, [string]$Profile, [string]$ReleaseRoot)
    $hostExecutable = Join-Path $HostRoot 'HermesBridge.ServiceHost.exe'
    [pscustomobject]@{{
        verified = $true
        profile = $Profile
        hostRoot = [IO.Path]::GetFullPath($HostRoot)
        hostDigest = '{'a' * 64}'
        hostExecutable = $hostExecutable
        argv = @($hostExecutable, '--profile', $Profile)
        releaseRoot = [IO.Path]::GetFullPath($ReleaseRoot)
        manifestSha256 = '{'b' * 64}'
        releaseExecutable = (Join-Path $ReleaseRoot 'venv\\Scripts\\python.exe')
    }}
}}
"""
    _ = (script_root / "service-host.ps1").write_text(mock_contract, encoding="utf-8")

    # When: Python executable 검증 없이 public Simulate adapter를 호출합니다.
    result = subprocess.run(
        [
            _POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(script_root / script_name),
            "-Apply",
            "-AdapterMode",
            "Simulate",
            "-ExecutablePath",
            "not-python.exe",
            "-ServiceHostRoot",
            str(host_root),
            "-RuntimeReleaseRoot",
            str(release_root),
            "-Json",
        ],
        cwd=_PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    # Then: 자동 $Host 변수 충돌 없이 검증된 Host argv만 반환합니다.
    registration = SimulatedHostRegistration.model_validate_json(result.stdout)
    assert result.returncode == 0, result.stderr
    assert not registration.applied
    assert registration.state == "simulated"
    assert registration.argv == (str(host_executable), "--profile", profile)


@pytest.mark.parametrize(
    "script_name",
    ["register-gateway-service.ps1", "register-privileged-service.ps1"],
)
@pytest.mark.parametrize("host_root", ["", r"C:\\invalid-host-anchor"])
def test_inspect_blocks_explicit_invalid_service_host_root(
    script_name: str,
    host_root: str,
    tmp_path: Path,
) -> None:
    # Given: runtime release와 일치하지 않는 명시적 Service Host 앵커입니다.
    release_root = tmp_path / "release"
    _ = release_root.mkdir()

    # When: SCM을 읽기 전에 public Inspect adapter로 검증을 요청합니다.
    result = subprocess.run(
        [
            _POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(_PROJECT_ROOT / "scripts" / script_name),
            "-Operation",
            "Inspect",
            "-ServiceHostRoot",
            host_root,
            "-RuntimeReleaseRoot",
            str(release_root),
            "-Json",
        ],
        cwd=_PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    # Then: Python fallback이나 SCM 조회 없이 fail closed 결과를 반환합니다.
    receipt = RegistrationResult.model_validate_json(result.stdout)
    assert result.returncode == 3, result.stderr
    assert receipt.state == "conflict"
    assert receipt.failure_reason == "runtime-entrypoint-unverified"
