"""Task 21 bridge-token ACL contract using a PowerShell-owned temporary file."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import ClassVar, Final, Literal
from uuid import uuid4

import pytest
from pydantic import BaseModel, ConfigDict, Field

PROJECT_ROOT: Final = Path(__file__).parents[2]
COMMON_SCRIPT: Final = PROJECT_ROOT / "scripts" / "lifecycle-common.ps1"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None
ALLOWED_SIDS: Final = frozenset({"S-1-5-18", "S-1-5-19", "S-1-5-32-544"})
BROAD_SIDS: Final = frozenset({"S-1-1-0", "S-1-5-11", "S-1-5-32-545"})


class AccessRule(BaseModel):
    """One binary ACL entry returned by the Windows ACL API."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    sid: str
    inherited: bool
    access_type: str


class SecretAclReport(BaseModel):
    """Token generation and ACL observables with no token representation."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    token_length: int
    distinct_tokens: bool
    inheritance_protected: bool
    current_user_sid: str
    rules: list[AccessRule]


class LifecycleReceipt(BaseModel):
    """무변경 lifecycle adapter가 남기는 단계별 영수증입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    step: str
    state: Literal["simulated", "failed-simulated", "rollback-simulated"]
    external_calls: Literal[0] = Field(alias="externalCalls")


class SimulatedLifecyclePlan(BaseModel):
    """Apply simulator의 원자성 및 무변경 계약입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    mode: Literal["apply", "what-if"]
    applied: bool
    state: Literal["blocked", "planned", "simulated", "failed"]
    receipts: list[LifecycleReceipt]
    rollback: list[LifecycleReceipt]
    failed_step: str | None = Field(alias="failedStep")
    external_calls: Literal[0] = Field(alias="externalCalls")


def _run_lifecycle(
    script_name: str, *arguments: str, environment: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    command = [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-File",
        str(PROJECT_ROOT / "scripts" / script_name), *arguments]
    return subprocess.run(command, cwd=PROJECT_ROOT, env=environment, check=False,
        capture_output=True, text=True, timeout=15)


def _lifecycle_environment(tmp_path: Path) -> tuple[Path, Path, dict[str, str]]:
    program_root, local_root = tmp_path / "program-data", tmp_path / "local-data"
    environment = os.environ.copy()
    environment["ProgramData"], environment["LOCALAPPDATA"] = str(program_root), str(local_root)
    return program_root, local_root, environment


def test_secret_helper_generates_distinct_strong_tokens_and_restricts_actual_temp_acl(
    tmp_path: Path,
) -> None:
    # Given: pytest-owned token path; no ProgramData or pre-existing secret is used.
    token_path = tmp_path / f"runtime-{uuid4().hex}" / "secrets" / "token"
    probe_path = tmp_path / "secret-acl-probe.ps1"
    probe = """
param([string]$CommonScript, [string]$TokenPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. $CommonScript
$first = New-BridgeToken
$second = New-BridgeToken
New-Item -ItemType Directory -Path (Split-Path -Parent $TokenPath) -Force | Out-Null
[IO.File]::WriteAllText($TokenPath, $first)
Set-BridgeSecretAcl -TokenPath $TokenPath
$acl = Get-Acl -LiteralPath $TokenPath
[pscustomobject]@{
  token_length = $first.Length
  distinct_tokens = ($first -cne $second)
  inheritance_protected = $acl.AreAccessRulesProtected
  current_user_sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  rules = @($acl.Access | ForEach-Object {
    [pscustomobject]@{
      sid = $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
      inherited = $_.IsInherited
      access_type = $_.AccessControlType.ToString()
    }
  })
} | ConvertTo-Json -Depth 4 -Compress
"""
    _ = probe_path.write_text(probe, encoding="utf-8")
    environment = os.environ.copy()
    environment["PSModulePath"] = str(Path(POWERSHELL_PATH).parent / "Modules")

    # When: the shared lifecycle helper creates a token and sets its real Windows DACL.
    result = subprocess.run(
        [
            POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(probe_path),
            "-CommonScript",
            str(COMMON_SCRIPT),
            "-TokenPath",
            str(token_path),
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        env=environment,
        text=True,
        timeout=15,
    )

    # Then: only service/admin SIDs receive explicit access; token values never enter pytest output.
    assert result.returncode == 0, result.stderr
    report = SecretAclReport.model_validate_json(result.stdout)
    direct_rules = [rule for rule in report.rules if not rule.inherited]
    direct_sids = {rule.sid for rule in direct_rules}
    assert report.token_length >= 43
    assert report.distinct_tokens
    assert report.inheritance_protected
    assert direct_sids == ALLOWED_SIDS
    assert all(rule.access_type == "Allow" for rule in direct_rules)
    assert not (direct_sids & BROAD_SIDS)
    assert report.current_user_sid not in direct_sids
    assert token_path.exists()


@pytest.mark.parametrize(
    ("script_name", "arguments", "expected_steps"),
    [
        (
            "install.ps1",
            (),
            (
                "dependencies", "runtime_directories", "runtime_access", "token",
                "token_acl", "hermes_config", "gateway_service", "privileged_helper_service",
                "interactive_worker_task", "privileged_service_start", "gateway_service_start",
                "worker_task_start", "doctor", "backup_resume",
            ),
        ),
        (
            "uninstall.ps1",
            ("-RemoveUserData",),
            (
                "backup_state", "interactive_worker_task", "gateway_service",
                "privileged_helper_service", "remove_user_data", "runtime_access_restore",
            ),
        ),
        (
            "rotate-token.ps1",
            (),
            ("generate_token", "backup_token", "atomic_replace", "token_acl", "doctor"),
        ),
    ],
)
def test_lifecycle_simulate_apply_records_fixed_steps_without_mutating_temp_data(
    tmp_path: Path,
    script_name: str,
    arguments: tuple[str, ...],
    expected_steps: tuple[str, ...],
) -> None:
    # Given: 삭제 동의가 있어도 보존되어야 하는 pytest 전용 token 및 사용자 데이터입니다.
    program_root, local_root, environment = _lifecycle_environment(tmp_path)
    token_path = program_root / "HermesWindowsBridge" / "secrets" / "token"
    _ = token_path.parent.mkdir(parents=True)
    _ = token_path.write_text("fixture-token", encoding="utf-8")
    user_file = local_root / "HermesWindowsBridge" / "browser-profile" / "keep.txt"
    _ = user_file.parent.mkdir(parents=True)
    _ = user_file.write_text("preserve", encoding="utf-8")

    # When: 고정된 Simulate adapter로 Apply orchestration을 실제 CLI에서 실행합니다.
    result = _run_lifecycle(
        script_name,
        "-Apply",
        "-AdapterMode",
        "Simulate",
        "-Json",
        "-ProgramDataRoot",
        str(program_root),
        *(() if script_name == "rotate-token.ps1" else ("-LocalDataRoot", str(local_root))),
        *arguments,
        environment=environment,
    )

    # Then: 계획된 단계와 무변경 영수증만 반환하고 token 및 사용자 데이터를 유지합니다.
    plan = SimulatedLifecyclePlan.model_validate_json(result.stdout)
    assert result.returncode == 0
    assert not plan.applied
    assert plan.state == "simulated"
    assert plan.failed_step is None
    assert tuple(receipt.step for receipt in plan.receipts) == expected_steps
    assert all(receipt.state == "simulated" for receipt in plan.receipts)
    assert not plan.rollback
    assert token_path.read_text(encoding="utf-8") == "fixture-token"
    assert user_file.read_text(encoding="utf-8") == "preserve"


@pytest.mark.parametrize(
    ("script_name", "failure_step"),
    [
        ("install.ps1", "gateway_service"),
        ("uninstall.ps1", "gateway_service"),
        ("rotate-token.ps1", "atomic_replace"),
    ],
)
def test_lifecycle_simulate_failure_rolls_back_completed_steps_without_mutation(
    tmp_path: Path,
    script_name: str,
    failure_step: str,
) -> None:
    # Given: 실패 주입과 비교할 pytest 전용 파일 트리입니다.
    program_root, local_root, environment = _lifecycle_environment(tmp_path)
    sentinel = local_root / "HermesWindowsBridge" / "keep.txt"
    _ = sentinel.parent.mkdir(parents=True)
    _ = sentinel.write_text("unchanged", encoding="utf-8")

    # When: 중간 고정 단계를 실패시켜 rollback 순서를 실제 CLI로 확인합니다.
    result = _run_lifecycle(
        script_name,
        "-Apply",
        "-AdapterMode",
        "Simulate",
        "-SimulationFailureStep",
        failure_step,
        "-Json",
        "-ProgramDataRoot",
        str(program_root),
        *(() if script_name == "rotate-token.ps1" else ("-LocalDataRoot", str(local_root))),
        environment=environment,
    )

    # Then: 실패 영수증 뒤에 완료 단계의 역순 rollback만 남고 파일은 보존됩니다.
    plan = SimulatedLifecyclePlan.model_validate_json(result.stdout)
    completed = [receipt.step for receipt in plan.receipts[:-1]]
    assert result.returncode == 2
    assert not plan.applied
    assert plan.state == "failed"
    assert plan.failed_step == failure_step
    assert plan.receipts[-1].state == "failed-simulated"
    assert [receipt.step for receipt in plan.rollback] == list(reversed(completed))
    assert all(receipt.state == "rollback-simulated" for receipt in plan.rollback)
    assert sentinel.read_text(encoding="utf-8") == "unchanged"


@pytest.mark.parametrize("script_name", ["install.ps1", "uninstall.ps1", "rotate-token.ps1"])
def test_lifecycle_apply_whatif_is_a_zero_mutation_noop(
    tmp_path: Path, script_name: str
) -> None:
    # Given: Apply가 있어도 WhatIf가 우선해야 하는 pytest 전용 roots입니다.
    program_root, local_root, environment = _lifecycle_environment(tmp_path)

    # When: Simulate Apply를 WhatIf와 함께 요청합니다.
    result = _run_lifecycle(
        script_name,
        "-Apply",
        "-WhatIf",
        "-AdapterMode",
        "Simulate",
        "-Json",
        "-ProgramDataRoot",
        str(program_root),
        *(() if script_name == "rotate-token.ps1" else ("-LocalDataRoot", str(local_root))),
        environment=environment,
    )

    # Then: Apply receipt 없이 WhatIf 계획만 반환하며 filesystem도 건드리지 않습니다.
    plan = SimulatedLifecyclePlan.model_validate_json(result.stdout)
    assert result.returncode == 0
    assert plan.mode == "what-if"
    assert not plan.applied
    assert not plan.receipts
    assert not any(tmp_path.iterdir())
