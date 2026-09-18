"""Evaluation guest failure-stage receipt regressions."""

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

FailureScenario = Literal["cleanup_succeeds", "cleanup_fails"]


class FailureReceipt(TypedDict):
    """등록 실패 후 receipt에서 보존해야 하는 공개 상태입니다."""

    executionStage: str
    failureReason: str
    registrationsRemoved: bool
    fixtureRemoved: bool


FAILURE_RECEIPT_ADAPTER: Final = TypeAdapter(FailureReceipt)


def _run_registration_failure(scenario: FailureScenario) -> FailureReceipt:
    """Production TryStatementAst를 등록 실패와 cleanup 결과만 대체해 실행합니다."""
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
$scenario = $env:HERMES_QA_FAILURE_STAGE_SCENARIO
$script:AllowedFailureReasons = @('temporary_registration_unverified')
$script:FailureReason = 'access_probe_unverified'
$script:VerifiedOutputRoot = $null
$Nonce = [guid]'7d57861c-4a76-4286-b041-7b83e66d78da'
$Apply = $true
$fixture = $null
$registration = $null
$pipeMetadataOpenConsumesConnection = $false
$receipt = [ordered]@{
    schemaVersion = 1; nonce = $Nonce.Guid; outcome = 'failed'; executionStage = 'host_guard'
    writes = $false; tokenGate = $false; failureReason = 'access_probe_unverified'
    immutableFileWriteDenied = $false; immutableDirectoryWriteDenied = $false
    pristineLaunchContractVerified = $false; tamperedLaunchContractRejected = $false
    pipeMetadataOpenSucceeded = $null; pipeMetadataWaitResult = $null
    pipeMetadataOpenConsumesConnection = $null; pipeMetadataCleanupSucceeded = $null
    livePipeDaclVerified = $null; gatewayRecoveryVerified = $null
    cleanup = [ordered]@{ fixtureRemoved = $false; registrationsRemoved = $false }
    receiptPersisted = $false
}
function Fail-SecurityCheck {
    param([string]$Reason)
    $script:FailureReason = $Reason
    throw [Security.SecurityException]::new('test_security_failure')
}
function Assert-ExistingRegularDirectory { param([string]$Path); return $Path }
function Assert-GuestIdentityAndToken {}
function Resolve-ProtectedRelease {
    return [pscustomobject]@{ root = 'C:\fixture\release'; manifest = 'C:\fixture\manifest.json' }
}
function Test-FilteredTokenWriteDenial {
    param($FilePath, $DirectoryPath)
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
    return [pscustomobject]@{
        sourceRoot = 'C:\fixture'
        releaseRoot = 'C:\fixture\release'
        stagingRoot = 'C:\fixture\staging'
    }
}
function New-TemporaryRegistrationContext {
    param($Fixture)
    return [pscustomobject]@{ id = 'registration' }
}
function Register-TemporarySecurityComponents {
    param($Registration)
    Fail-SecurityCheck 'temporary_registration_unverified'
}
function Test-LivePipeDaclAndRecovery { param($Registration); throw 'unexpected_live_stage' }
function Remove-TemporarySecurityComponents {
    param($Registration)
    return $scenario -eq 'cleanup_succeeds'
}
function Test-IsolatedFixtureTamperContract { param($Fixture); throw 'unexpected_tamper_stage' }
function Remove-IsolatedFixture { param($Fixture); return $true }
function Write-SafeReceipt { param($Receipt); $Receipt.receiptPersisted = $true; return $true }

& ([scriptblock]::Create($topLevelTry[0].Extent.Text))
[ordered]@{
    executionStage = [string]$receipt.executionStage
    failureReason = [string]$receipt.failureReason
    registrationsRemoved = [bool]$receipt.cleanup.registrationsRemoved
    fixtureRemoved = [bool]$receipt.cleanup.fixtureRemoved
} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={
            **os.environ,
            "HERMES_QA_FAILURE_STAGE_SCENARIO": scenario,
            "HERMES_QA_GUEST_SECURITY_SCRIPT": str(SCRIPT_PATH),
        },
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    return FAILURE_RECEIPT_ADAPTER.validate_python(json.loads(result.stdout))


def test_guest_preserves_registration_stage_when_cleanup_succeeds() -> None:
    """등록 실패 뒤 cleanup이 성공해도 최초 실패 단계를 보존합니다."""
    receipt = _run_registration_failure("cleanup_succeeds")

    assert receipt == {
        "executionStage": "temporary_registration",
        "failureReason": "temporary_registration_unverified",
        "registrationsRemoved": True,
        "fixtureRemoved": True,
    }


def test_guest_preserves_registration_stage_when_cleanup_fails() -> None:
    """등록 실패 뒤 cleanup이 실패해도 최초 실패 단계를 보존합니다."""
    receipt = _run_registration_failure("cleanup_fails")

    assert receipt == {
        "executionStage": "temporary_registration",
        "failureReason": "temporary_registration_unverified",
        "registrationsRemoved": False,
        "fixtureRemoved": False,
    }
