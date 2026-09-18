"""SCM 변경 없이 보호 service Python launch manifest를 회귀 검증합니다."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import ClassVar, Final

import pytest
from pydantic import BaseModel, ConfigDict, Field

from hermes_windows_bridge.gateway.windows_service import GATEWAY_SERVICE
from hermes_windows_bridge.privileged.windows_service import PRIVILEGED_SERVICE

_GATEWAY_MODULE: Final = "hermes_windows_bridge.gateway.windows_service"
_PRIVILEGED_MODULE: Final = "hermes_windows_bridge.privileged.main"
_PROJECT_ROOT: Final = Path(__file__).parents[2]
_POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert _POWERSHELL_PATH is not None
_ISOLATION_PROBE: Final = (
    "import json,site,sys;"
    "print(json.dumps({'dont_write_bytecode':sys.dont_write_bytecode,"
    "'enable_user_site':site.ENABLE_USER_SITE,'sys_path':sys.path}))"
)


class IsolationProbe(BaseModel):
    """Isolated child가 공개하는 Python runtime boundary입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    dont_write_bytecode: bool
    enable_user_site: bool
    sys_path: tuple[str, ...]


class SimulatedRegistration(BaseModel):
    """No-op service registration adapter가 반환하는 고정 launch contract입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    applied: bool
    state: str
    argv: tuple[str, ...]
    failure_reason: str | None = Field(alias="failureReason", default=None)


class LaunchContract(BaseModel):
    """Release-only launch authority가 반환하는 read-only 결과입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    schema_version: int = Field(alias="schemaVersion")
    verified: bool
    failure_reasons: tuple[str, ...] = Field(alias="failureReasons")


def _write_schema1_manifest(release_root: Path) -> Path:
    """Schema 1 runtime contract fixture를 생성합니다."""
    base_executable = release_root / "python" / "python.exe"
    service_executable = release_root / "venv" / "Scripts" / "python.exe"
    _ = base_executable.parent.mkdir(parents=True)
    _ = service_executable.parent.mkdir(parents=True)
    _ = base_executable.write_bytes(b"base-python")
    _ = service_executable.write_bytes(b"service-python")
    inventory = [
        {
            "relativePath": "python/python.exe",
            "sha256": hashlib.sha256(base_executable.read_bytes()).hexdigest(),
            "size": base_executable.stat().st_size,
        },
        {
            "relativePath": "venv/Scripts/python.exe",
            "sha256": hashlib.sha256(service_executable.read_bytes()).hexdigest(),
            "size": service_executable.stat().st_size,
        },
    ]
    manifest = {
        "schemaVersion": 1,
        "releaseId": release_root.name,
        "sourceDigest": "b" * 64,
        "lockDigest": "c" * 64,
        "pythonVersion": "3.14.3",
        "architecture": "x64",
        "uvVersion": "0.12.8",
        "fileInventory": inventory,
        "baseExecutable": str(base_executable),
        "serviceExecutable": str(service_executable),
    }
    manifest_path = release_root / "release-manifest.json"
    _ = manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest_path


def test_service_manifests_use_isolated_non_bytecode_module_argv() -> None:
    # Given: SCM registration이 소비할 두 service manifest입니다.
    services = (GATEWAY_SERVICE, PRIVILEGED_SERVICE)

    # When: interpreter options와 fixed module을 관찰합니다.
    argv = tuple(service.argv for service in services)

    # Then: CWD/user site/PYTHON* injection을 막고 release tree를 쓰지 않습니다.
    assert argv == (
        (sys.executable, "-I", "-B", "-m", _GATEWAY_MODULE),
        (sys.executable, "-I", "-B", "-m", _PRIVILEGED_MODULE),
    )


@pytest.mark.parametrize(
    ("script_name", "module"),
    [
        ("register-gateway-service.ps1", _GATEWAY_MODULE),
        ("register-privileged-service.ps1", _PRIVILEGED_MODULE),
    ],
)
def test_simulated_registration_uses_fixed_isolated_service_argv(
    script_name: str,
    module: str,
) -> None:
    # Given: SCM API를 호출하지 않는 explicit Simulate adapter입니다.
    result = subprocess.run(
        [
            _POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(_PROJECT_ROOT / "scripts" / script_name),
            "-Apply",
            "-AdapterMode",
            "Simulate",
            "-Json",
            "-ExecutablePath",
            "python.exe",
        ],
        cwd=_PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    # When: returned registration manifest를 typed boundary에서 해석합니다.
    manifest = SimulatedRegistration.model_validate_json(result.stdout)

    # Then: production과 같은 isolated argv shape만 보고하며 외부 등록은 하지 않습니다.
    assert result.returncode == 0, result.stderr
    assert manifest.applied is False
    assert manifest.state == "simulated"
    assert manifest.argv == ("python.exe", "-I", "-B", "-m", module)


def test_launch_contract_rejects_schema1_runtime_without_receipt(tmp_path: Path) -> None:
    # Given: receipt가 존재하지 않는 legacy schema 1 release fixture입니다.
    release_root = tmp_path / ("a" * 64)
    manifest_path = _write_schema1_manifest(release_root)
    command = (
        f". '{_PROJECT_ROOT / 'scripts' / 'service-runtime.ps1'}' -LibraryMode; "
        "Get-BridgeServiceLaunchContract "
        f"-ManifestPath '{manifest_path}' -ReleaseRoot '{release_root}' | "
        "ConvertTo-Json -Compress"
    )

    # When: production launch authority를 조회합니다.
    result = subprocess.run(
        [_POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=_PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )

    # Then: legacy file contract가 어떤 상태여도 executable fallback 없이 차단합니다.
    contract = LaunchContract.model_validate_json(result.stdout)
    assert result.returncode == 0, result.stderr
    assert contract.schema_version == 1
    assert not contract.verified
    assert contract.failure_reasons == ("runtime-entrypoint-unverified",)


@pytest.mark.parametrize(
    "script_name",
    ["register-gateway-service.ps1", "register-privileged-service.ps1"],
)
def test_production_registration_blocks_before_administrator_gate_without_release_authority(
    script_name: str,
) -> None:
    # Given: manifest/release authority가 전혀 전달되지 않은 production registration입니다.
    result = subprocess.run(
        [
            _POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(_PROJECT_ROOT / "scripts" / script_name),
            "-Apply",
            "-AdapterMode",
            "Production",
            "-Json",
        ],
        cwd=_PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    # When/Then: supplied executable나 administrator 권한으로 fallback하지 않습니다.
    # Authority failure를 반환합니다.
    manifest = SimulatedRegistration.model_validate_json(result.stdout)
    assert result.returncode == 3, result.stderr
    assert manifest.failure_reason == "runtime-entrypoint-unverified"


@pytest.mark.parametrize(
    "script_name",
    ["register-gateway-service.ps1", "register-privileged-service.ps1"],
)
def test_production_registration_rejects_schema1_release_authority(
    script_name: str,
    tmp_path: Path,
) -> None:
    # Given: valid-looking legacy runtime release와 caller supplied Python executable입니다.
    release_root = tmp_path / ("a" * 64)
    manifest_path = _write_schema1_manifest(release_root)

    # When: schema 1 snapshot을 production registration authority로 제출합니다.
    result = subprocess.run(
        [
            _POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(_PROJECT_ROOT / "scripts" / script_name),
            "-Apply",
            "-AdapterMode",
            "Production",
            "-ExecutablePath",
            "python.exe",
            "-RuntimeManifestPath",
            str(manifest_path),
            "-RuntimeReleaseRoot",
            str(release_root),
            "-Json",
        ],
        cwd=_PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )

    # Then: caller executable이나 legacy verified snapshot으로 fallback하지 않습니다.
    manifest = SimulatedRegistration.model_validate_json(result.stdout)
    assert result.returncode == 3, result.stderr
    assert manifest.failure_reason == "runtime-entrypoint-unverified"


@pytest.mark.parametrize(
    ("script_name", "service_name", "account"),
    [
        (
            "register-gateway-service.ps1",
            "HermesWindowsBridgeGateway",
            "NT AUTHORITY\\LocalService",
        ),
        (
            "register-privileged-service.ps1",
            "HermesWindowsBridgePrivileged",
            "LocalSystem",
        ),
    ],
)
def test_registration_adapter_rejects_legacy_service_argv_with_typed_error(
    script_name: str,
    service_name: str,
    account: str,
) -> None:
    # Given: service의 현재 5항 argv와 다른 legacy adapter 기대값입니다.
    command = (
        "$ErrorActionPreference='Stop'; . $env:HERMES_TEST_COMMON; "
        "try { Invoke-BridgeRegistrationAdapter -ScriptRoot $env:HERMES_TEST_SCRIPTS "
        f"-ScriptName '{script_name}' -ArgumentList @('-ExecutablePath','python.exe') "
        "-AdapterMode Simulate -Operation Register "
        f"-ExpectedName '{service_name}' -ExpectedAccount '{account}' "
        "-ExpectedArgv @('python.exe','-m','legacy.module') | Out-Null; exit 0 "
        "} catch [IO.InvalidDataException] { "
        "[Console]::Error.Write($_.Exception.Message); exit 7 } "
        "catch { [Console]::Error.Write($_.Exception.Message); exit 8 }"
    )
    environment = os.environ.copy()
    environment["HERMES_TEST_COMMON"] = str(_PROJECT_ROOT / "scripts" / "lifecycle-common.ps1")
    environment["HERMES_TEST_SCRIPTS"] = str(_PROJECT_ROOT / "scripts")

    # When: no-op adapter에 옛 service argv를 제공해 contract mismatch를 강제합니다.
    result = subprocess.run(
        [_POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=_PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    # Then: type-resolution crash가 아니라 stable fail-closed contract error를 반환합니다.
    assert result.returncode == 7, result.stderr
    assert "BridgeRegistrationAdapterMismatch" in result.stderr


@pytest.mark.parametrize("service_argv", [GATEWAY_SERVICE.argv, PRIVILEGED_SERVICE.argv])
def test_service_interpreter_options_ignore_hostile_path_and_disable_bytecode(
    service_argv: tuple[str, ...],
    tmp_path: Path,
) -> None:
    # Given: CWD 및 PYTHONPATH에서 code injection을 시도하는 비어 있는 fixture입니다.
    hostile_path = tmp_path / "hostile-pythonpath"
    _ = hostile_path.mkdir()
    _ = (hostile_path / "sitecustomize.py").write_text(
        "raise RuntimeError('hostile sitecustomize loaded')\n", encoding="utf-8"
    )
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(hostile_path)

    # When: 각 service manifest의 executable과 interpreter options로 안전 probe를 실행합니다.
    result = subprocess.run(
        [*service_argv[:-2], "-c", _ISOLATION_PROBE],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    # Then: hostile PYTHONPATH/CWD가 import path에 없고 bytecode writing도 비활성입니다.
    assert result.returncode == 0, result.stderr
    probe = IsolationProbe.model_validate_json(result.stdout)
    assert probe.dont_write_bytecode is True
    assert probe.enable_user_site is False
    assert str(hostile_path) not in probe.sys_path
    assert str(tmp_path) not in probe.sys_path
