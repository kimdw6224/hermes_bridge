"""Gateway LocalService base-runtime access lifecycle contracts."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import ClassVar, Final

from pydantic import BaseModel, ConfigDict, Field

PROJECT_ROOT: Final = Path(__file__).parents[2]
INSTALL_SCRIPT: Final = PROJECT_ROOT / "scripts" / "install.ps1"
UNINSTALL_SCRIPT: Final = PROJECT_ROOT / "scripts" / "uninstall.ps1"
COMMON_SCRIPT: Final = PROJECT_ROOT / "scripts" / "lifecycle-common.ps1"
VENV_PYTHON: Final = PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None


class RuntimeIdentity(BaseModel):
    """Resolved interpreter identity emitted by the trusted Python probe."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    executable: str
    base_executable: str = Field(alias="baseExecutable")
    base_root: str = Field(alias="baseRoot")


class RuntimeManifest(BaseModel):
    """Relevant portion of the install runtime contract."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    runtime: RuntimeIdentity


class RuntimeContract(BaseModel):
    """Verified runtime wrapper returned by the installer."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    verified: bool
    contract: RuntimeManifest


class InstallPlan(BaseModel):
    """Install plan fields needed for runtime-access verification."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    runtime_contract: RuntimeContract = Field(alias="runtimeContract")


class LifecycleResult(BaseModel):
    """Stable failure fields for mutation-free lifecycle probes."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    state: str
    failed_step: str | None = Field(alias="failedStep", default=None)
    failure_reason: str | None = Field(alias="failureReason", default=None)
    external_calls: int | None = Field(alias="externalCalls", default=None)


class RuntimeAccessRule(BaseModel):
    """Exact LocalService directory ACE emitted by the lifecycle helper."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    sid: str
    rights: int
    inheritance: str
    propagation: str
    access_type: str = Field(alias="accessType")


def _run_install(*arguments: str, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(INSTALL_SCRIPT),
            *arguments,
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )


def test_install_contract_reports_actual_base_runtime_identity(tmp_path: Path) -> None:
    # Given: venv redirector와 실제 base interpreter가 분리된 설치 환경입니다.
    expected = subprocess.run(
        [
            str(VENV_PYTHON),
            "-c",
            (
                "import json, pathlib, sys; "
                "print(json.dumps({'executable': sys.executable, "
                "'baseExecutable': sys._base_executable, "
                "'baseRoot': str(pathlib.Path(sys._base_executable).parent)}))"
            ),
        ],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    environment = os.environ.copy()
    environment["ProgramData"] = str(tmp_path / "program-data")
    environment["LOCALAPPDATA"] = str(tmp_path / "local-data")

    # When: installer의 read-only runtime probe를 실행합니다.
    result = _run_install("-WhatIf", "-Json", environment=environment)

    # Then: service가 실제로 필요로 하는 base executable/root가 typed JSON에 고정됩니다.
    plan = InstallPlan.model_validate_json(result.stdout)
    runtime = plan.runtime_contract.contract.runtime
    assert result.returncode == 0, result.stderr
    assert plan.runtime_contract.verified
    assert runtime == RuntimeIdentity.model_validate_json(expected.stdout)
    assert Path(runtime.base_executable).parent == Path(runtime.base_root)


def test_runtime_access_rule_is_exact_inherited_read_execute_without_mutation() -> None:
    # Given: LocalService에 부여할 단일 ACE factory입니다.
    command = (
        ". $env:HERMES_TEST_COMMON; $rule = New-BridgeBaseRuntimeRule; "
        "[pscustomobject]@{sid=$rule.IdentityReference.Value; rights=[int]$rule.FileSystemRights; "
        "inheritance=$rule.InheritanceFlags.ToString(); "
        "propagation=$rule.PropagationFlags.ToString(); "
        "accessType=$rule.AccessControlType.ToString()} | ConvertTo-Json -Compress"
    )
    environment = os.environ.copy()
    environment["HERMES_TEST_COMMON"] = str(COMMON_SCRIPT)

    # When: 실제 ACL을 변경하지 않고 rule 값을 생성합니다.
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    # Then: broad Users/Everyone 권한 없이 LocalService RX inheritance만 존재합니다.
    rule = RuntimeAccessRule.model_validate_json(result.stdout)
    assert result.returncode == 0, result.stderr
    assert rule == RuntimeAccessRule(
        sid="S-1-5-19",
        rights=1179817,
        inheritance="ContainerInherit, ObjectInherit",
        propagation="None",
        accessType="Allow",
    )


def test_installer_labels_each_component_start_before_invocation() -> None:
    # Given: 등록 완료 뒤 시작 단계에서 발생하는 실패입니다.
    source = INSTALL_SCRIPT.read_text(encoding="utf-8")

    # When/Then: 직전 등록 단계가 아니라 실제 실패한 component start가 보고됩니다.
    privileged_label = source.index("'privileged_start' = 'privileged_service_start'")
    gateway_label = source.index("'gateway_start' = 'gateway_service_start'")
    worker_label = source.index("$currentStep = 'worker_task_start'")
    assert privileged_label > source.index("Start-Service -Name $serviceName")
    assert gateway_label > source.index("Start-Service -Name $serviceName")
    assert worker_label < source.index("Start-ScheduledTask", worker_label)


def test_gateway_start_simulation_reports_exact_step_without_mutation(tmp_path: Path) -> None:
    # Given: production start 직전까지의 모든 단계가 성공한 deterministic simulator입니다.
    environment = os.environ.copy()
    environment["ProgramData"] = str(tmp_path / "program-data")
    environment["LOCALAPPDATA"] = str(tmp_path / "local-data")
    before = set(tmp_path.rglob("*"))

    # When: Gateway start 단계에만 실패를 주입합니다.
    result = _run_install(
        "-Apply",
        "-AdapterMode",
        "Simulate",
        "-SimulationFailureStep",
        "gateway_service_start",
        "-Json",
        environment=environment,
    )

    # Then: 과거 interactive_worker_task 오표시 없이 정확한 단계와 0 mutation을 보고합니다.
    plan = LifecycleResult.model_validate_json(result.stdout)
    assert result.returncode == 2
    assert plan.state == "failed"
    assert plan.failed_step == "gateway_service_start"
    assert plan.external_calls == 0
    assert set(tmp_path.rglob("*")) == before


def test_uninstall_blocks_tampered_runtime_marker_before_simulated_removal(tmp_path: Path) -> None:
    # Given: bridge-owned 위치에 있지만 무결성이 없는 marker입니다.
    runtime_root = tmp_path / "program-data" / "HermesWindowsBridge"
    marker = runtime_root / "secrets" / "runtime-access.json"
    _ = marker.parent.mkdir(parents=True)
    _ = marker.write_text("{}", encoding="utf-8")
    before = marker.read_bytes()
    environment = os.environ.copy()
    environment["ProgramData"] = str(tmp_path / "program-data")
    environment["LOCALAPPDATA"] = str(tmp_path / "local-data")

    # When: mutation-free uninstall simulator가 preflight를 수행합니다.
    result = subprocess.run(
        [
            POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(UNINSTALL_SCRIPT),
            "-Apply",
            "-AdapterMode",
            "Simulate",
            "-Json",
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    # Then: registration adapter 전에 marker 검증으로 차단하고 fixture를 그대로 둡니다.
    plan = LifecycleResult.model_validate_json(result.stdout)
    assert result.returncode == 2
    assert plan.state == "blocked"
    assert plan.failure_reason == "runtime-access-marker-unverified"
    assert marker.read_bytes() == before


def test_runtime_marker_hash_rejects_tampered_payload_without_acl_mutation(tmp_path: Path) -> None:
    # Given: 제한 디렉터리 밖에서 만든, hash가 일치하지 않는 hostile marker입니다.
    runtime_root = tmp_path / "runtime"
    marker = runtime_root / "secrets" / "runtime-access.json"
    _ = marker.parent.mkdir(parents=True)
    base_executable = tmp_path / "python.exe"
    _ = base_executable.write_bytes(b"")
    _ = marker.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "status": "applied",
                "baseRoot": str(tmp_path),
                "baseExecutable": str(base_executable),
                "preAclHash": "0" * 64,
                "markerHash": "f" * 64,
            }
        ),
        encoding="utf-8",
    )
    command = (
        ". $env:HERMES_TEST_COMMON; "
        "try { Read-BridgeRuntimeAccessMarker -RuntimeRoot $env:HERMES_TEST_RUNTIME "
        "-MarkerPath $env:HERMES_TEST_MARKER | Out-Null; exit 0 } "
        "catch { [Console]::Error.Write($_.Exception.Message); exit 7 }"
    )
    environment = os.environ.copy()
    environment["HERMES_TEST_COMMON"] = str(COMMON_SCRIPT)
    environment["HERMES_TEST_MARKER"] = str(marker)
    environment["HERMES_TEST_RUNTIME"] = str(runtime_root)

    # When: restore boundary가 marker를 parse합니다.
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    # Then: ACL 명령 전에 stable integrity error로 fail closed 합니다.
    assert result.returncode == 7
    assert "BridgeRuntimeAccessMarkerHashMismatch" in result.stderr
