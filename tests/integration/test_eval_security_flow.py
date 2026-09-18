"""Evaluation guest security harness top-level flow regressions."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Final, Literal, TypedDict

from pydantic import TypeAdapter

PROJECT_ROOT: Final = Path(__file__).resolve().parents[2]
SCRIPT_PATH: Final = (
    PROJECT_ROOT
    / ".omo"
    / "evidence"
    / "service-protection-eval-vm-20260908"
    / "security"
    / "guest-security-checks.ps1"
)
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None


class FlowReceipt(TypedDict):
    outcome: Literal["passed", "failed"]
    failureReason: str | None
    executionStage: str
    registrationsRemoved: bool
    fixtureRemoved: bool
    calls: list[str]


FLOW_RECEIPT_ADAPTER: Final = TypeAdapter(FlowReceipt)


def _run_top_level_flow(
    scenario: Literal["happy", "remove_failure", "recovery_failure"],
) -> FlowReceipt:
    """Production TryStatementAst를 fake external seam으로 실행합니다.

    Receipt와 cleanup 순서를 수집합니다.

    실제 guest의 외부 변경 함수만 대체하므로 VM, 서비스, 파일에는 접근하지 않습니다.
    """
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_GUEST_SECURITY_SCRIPT, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) { throw 'GuestSecurityParseFailed' }
$topLevelTry = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.TryStatementAst] -and
        $node.Extent.Text -match 'Register-TemporarySecurityComponents' -and
        $node.Extent.Text -match 'Test-IsolatedFixtureTamperContract'
}, $true))
if ($topLevelTry.Count -ne 1) { throw 'GuestSecurityTopLevelTryMissing' }
$scenario = $env:HERMES_QA_FLOW_SCENARIO
$script:AllowedFailureReasons = @(
    'gateway_recovery_unverified', 'temporary_registration_unverified'
)
$script:FailureReason = 'access_probe_unverified'
$script:VerifiedOutputRoot = $null
$script:calls = [Collections.Generic.List[string]]::new()
$Nonce = [guid]'8fb55a28-69e7-41f2-b449-df8148645bc0'
$Apply = $true
$fixture = $null
$registration = $null
$receipt = [ordered]@{
    outcome = 'failed'; executionStage = 'host_guard'; failureReason = 'access_probe_unverified'
    tokenGate = $false; immutableFileWriteDenied = $false; immutableDirectoryWriteDenied = $false
    pristineLaunchContractVerified = $false; tamperedLaunchContractRejected = $false
    pipeMetadataOpenConsumesConnection = $null; livePipeDaclVerified = $null
    gatewayRecoveryVerified = $null; receiptPersisted = $false
    cleanup = [ordered]@{ registrationsRemoved = $false; fixtureRemoved = $false }
}
function Add-FlowCall { param([string]$Name); $script:calls.Add($Name) }
function Fail-SecurityCheck {
    param([string]$Reason)
    $script:FailureReason = $Reason
    throw [Security.SecurityException]::new('test_security_failure')
}
function Assert-ExistingRegularDirectory { param([string]$Path); return $Path }
function Assert-GuestIdentityAndToken {}
function Resolve-ProtectedRelease {
    return [pscustomobject]@{
        root = 'C:\fixture\release'
        manifest = 'C:\fixture\manifest.json'
    }
}
function Test-FilteredTokenWriteDenial {
    param($FilePath,$DirectoryPath)
    return [pscustomobject]@{
        immutableFileWriteDenied = $true
        immutableDirectoryWriteDenied = $true
    }
}
function Test-PipeMetadataOpenSafety {
    return [pscustomobject]@{
        openSucceeded = $true
        waitResult = 'connected'
        connectionConsumed = $true
        cleanupSucceeded = $true
    }
}
function Assert-FixtureSourceMatchesInput { return [pscustomobject]@{} }
function New-IsolatedBuildFixture {
    param($Source)
    Add-FlowCall 'build'
    return [pscustomobject]@{ id = 'fixture' }
}
function New-TemporaryRegistrationContext {
    param($Fixture)
    Add-FlowCall 'registration'
    return [pscustomobject]@{ id = 'registration' }
}
function Register-TemporarySecurityComponents { param($Registration); Add-FlowCall 'register' }
function Test-LivePipeDaclAndRecovery {
    param($Registration)
    Add-FlowCall 'recovery'
    return [pscustomobject]@{
        livePipeDaclVerified = $true
        gatewayRecoveryVerified = ($scenario -ne 'recovery_failure')
    }
}
function Remove-TemporarySecurityComponents {
    param($Registration)
    Add-FlowCall 'remove'
    return $scenario -ne 'remove_failure'
}
function Test-IsolatedFixtureTamperContract {
    param($Fixture)
    Add-FlowCall 'tamper'
    return [pscustomobject]@{
        pristineLaunchContractVerified = $true
        tamperedLaunchContractRejected = $true
    }
}
function Remove-IsolatedFixture { param($Fixture); Add-FlowCall 'delete'; return $true }
function Write-SafeReceipt { param($Receipt); $Receipt.receiptPersisted = $true; return $true }

& ([scriptblock]::Create($topLevelTry[0].Extent.Text))
[ordered]@{
    outcome = [string]$receipt.outcome
    failureReason = if ($null -eq $receipt.failureReason) {
        $null
    } else {
        [string]$receipt.failureReason
    }
    executionStage = [string]$receipt.executionStage
    registrationsRemoved = [bool]$receipt.cleanup.registrationsRemoved
    fixtureRemoved = [bool]$receipt.cleanup.fixtureRemoved
    calls = @($script:calls)
} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={
            **os.environ,
            "HERMES_QA_GUEST_SECURITY_SCRIPT": str(SCRIPT_PATH),
            "HERMES_QA_FLOW_SCENARIO": scenario,
        },
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    return FLOW_RECEIPT_ADAPTER.validate_python(json.loads(result.stdout))


def test_guest_security_flow_runs_tamper_only_after_registration_removal() -> None:
    """Happy flow는 build→register→recovery→remove→tamper→delete 순서로 완료합니다."""
    receipt = _run_top_level_flow("happy")

    assert receipt == {
        "outcome": "passed",
        "failureReason": None,
        "executionStage": "completed",
        "registrationsRemoved": True,
        "fixtureRemoved": True,
        "calls": ["build", "registration", "register", "recovery", "remove", "tamper", "delete"],
    }


def test_guest_security_flow_preserves_fixture_when_registration_removal_fails() -> None:
    """Registration cleanup failure는 tamper/delete를 건너뛰고 failed receipt를 남깁니다."""
    receipt = _run_top_level_flow("remove_failure")

    assert receipt == {
        "outcome": "failed",
        "failureReason": "temporary_registration_unverified",
        "executionStage": "registration_cleanup",
        "registrationsRemoved": False,
        "fixtureRemoved": False,
        "calls": ["build", "registration", "register", "recovery", "remove", "remove"],
    }


def test_guest_security_flow_fails_after_cleanup_when_gateway_recovery_is_false() -> None:
    """Recovery false는 성공을 금지하되 registration과 fixture cleanup은 실행합니다."""
    receipt = _run_top_level_flow("recovery_failure")

    assert receipt == {
        "outcome": "failed",
        "failureReason": "gateway_recovery_unverified",
        "executionStage": "live_pipe_dacl_and_recovery",
        "registrationsRemoved": True,
        "fixtureRemoved": True,
        "calls": ["build", "registration", "register", "recovery", "remove", "delete"],
    }
