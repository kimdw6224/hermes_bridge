"""Evaluation registration adapter argument regressions."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Final, TypedDict

from pydantic import TypeAdapter

PROJECT_ROOT: Final = Path(__file__).resolve().parents[2]
SECURITY_ROOT: Final = (
    PROJECT_ROOT / ".omo" / "evidence" / "service-protection-eval-vm-20260908" / "security"
)
GUEST_PATH: Final = SECURITY_ROOT / "guest-security-checks.ps1"
PRIVILEGED_ADAPTER_PATH: Final = PROJECT_ROOT / "scripts" / "register-privileged-service.ps1"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None


class GuestRegistrationArgumentResult(TypedDict):
    confirmArgumentCount: int
    adapterCallCount: int


class PrivilegedAdapterPlan(TypedDict):
    mode: str
    applied: bool


GUEST_REGISTRATION_ARGUMENT_RESULT_ADAPTER: Final = TypeAdapter(GuestRegistrationArgumentResult)
PRIVILEGED_ADAPTER_PLAN_ADAPTER: Final = TypeAdapter(PrivilegedAdapterPlan)


def test_guest_registration_arguments_omit_file_mode_confirm_switch() -> None:
    """Guest adapter 호출은 powershell.exe -File에서 지원하지 않는 Confirm 값을 넘기지 않습니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_GUEST, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) { throw 'GuestParseFailed' }
$calls = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -ceq 'Invoke-BridgeRegistrationAdapter'
}, $true))
$confirm = @($calls | ForEach-Object {
    @($_.CommandElements | Where-Object {
        $_ -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
            $_.Value -ceq '-Confirm:$false'
    })
}).Count
[ordered]@{
    confirmArgumentCount = $confirm
    adapterCallCount = $calls.Count
} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={**os.environ, "HERMES_QA_GUEST": str(GUEST_PATH)},
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert GUEST_REGISTRATION_ARGUMENT_RESULT_ADAPTER.validate_json(result.stdout) == {
        "confirmArgumentCount": 0,
        "adapterCallCount": 6,
    }


def test_privileged_adapter_file_mode_returns_non_apply_json_plan_without_confirm() -> None:
    """Representative register 인수는 -Apply 없이 JSON 계획만 반환합니다."""
    result = subprocess.run(
        [
            POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(PRIVILEGED_ADAPTER_PATH),
            "-RuntimeManifestPath",
            r"C:\evaluation\release-manifest.json",
            "-RuntimeReleaseRoot",
            r"C:\evaluation",
            "-Json",
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    plan = PRIVILEGED_ADAPTER_PLAN_ADAPTER.validate_json(result.stdout)
    assert plan["mode"] == "dry-run"
    assert plan["applied"] is False
