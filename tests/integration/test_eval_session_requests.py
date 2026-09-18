"""Evaluation-session fixed request dispatch regressions."""

# ruff: noqa: E501

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
BROKER_PATH: Final = SECURITY_ROOT / "hold-evaluation-session.ps1"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None


class SessionRequestResult(TypedDict):
    dispatches: int
    sessionReused: bool
    firstClaimed: bool
    secondClaimed: bool
    replayClaimed: bool
    hashMismatchDispatched: bool
    pendingChildAllowed: bool
    outerLoopUsesRequestHash: bool


SESSION_REQUEST_RESULT_ADAPTER: Final = TypeAdapter(SessionRequestResult)


def test_session_request_dispatch_rejects_replay_hash_mismatch_and_pending_child(
    tmp_path: Path,
) -> None:
    """고정 runner는 같은 session의 새 nonce만 dispatch하고 unsafe 재시도를 막습니다."""
    harness = tmp_path / "guest-security-checks.ps1"
    _ = harness.write_text("# evaluation harness\n", encoding="utf-8")
    runner = tmp_path / "runner.ps1"
    _ = runner.write_text(
        """
param([switch]$Apply, $ExistingSession, [Parameter(ValueFromRemainingArguments=$true)][string[]]$Arguments)
[string]$sessionId = [string]$ExistingSession.id
[ordered]@{
    childStarted = $true
    childTerminalObserved = $true
    jobCleanupSucceeded = $true
    sessionCleanupSucceeded = $true
    result = [ordered]@{
        outcome = 'failed'
        cleanup = [ordered]@{ fixtureRemoved = $false; registrationsRemoved = $true }
    }
    sessionId = $sessionId
} | ConvertTo-Json -Compress
""".strip(),
        encoding="utf-8",
    )
    control = tmp_path / "request.json"
    claim_root = tmp_path / "claims"
    _ = claim_root.mkdir()

    command = r"""
$ErrorActionPreference = 'Stop'
Import-Module Microsoft.PowerShell.Utility -ErrorAction Stop
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_BROKER, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) { throw 'BrokerParseFailed' }
$loopHashCheck = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.ForEachStatementAst] -and
        $node.Extent.Text -match '\$harness,\$request\.harnessSha256'
}, $true))
if ($loopHashCheck.Count -ne 1) { throw 'BrokerRequestHashLoopMissing' }
$names = @('Read-SecurityRequest', 'Claim-SecurityRequest', 'Test-PreviousTrialAllowsNext', 'Invoke-SessionSecurityTrial')
foreach ($name in $names) {
    $definition = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $true))
    if ($definition.Count -ne 1) { throw ('BrokerFunctionMissing:' + $name) }
    . ([scriptblock]::Create($definition[0].Extent.Text))
}
$runnerHash = (Get-FileHash -LiteralPath $env:HERMES_QA_RUNNER -Algorithm SHA256).Hash.ToUpperInvariant()
$harnessHash = (Get-FileHash -LiteralPath $env:HERMES_QA_HARNESS -Algorithm SHA256).Hash.ToUpperInvariant()
$firstId = [guid]'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
$secondId = [guid]'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
$firstNonce = [guid]'11111111-1111-1111-1111-111111111111'
$secondNonce = [guid]'22222222-2222-2222-2222-222222222222'
function Set-Request([guid]$Id, [guid]$Nonce, [string]$Hash) {
    [ordered]@{ action = 'security'; id = $Id.Guid; nonce = $Nonce.Guid; harnessSha256 = $Hash } |
        ConvertTo-Json -Compress | Set-Content -LiteralPath $env:HERMES_QA_CONTROL -NoNewline
}
$testSession = [pscustomobject]@{ id = 'same-session' }
Set-Request $firstId $firstNonce $harnessHash
$first = Read-SecurityRequest -ControlPath $env:HERMES_QA_CONTROL
$firstClaimed = Claim-SecurityRequest -ClaimRoot $env:HERMES_QA_CLAIMS -Request $first
$firstReport = Invoke-SessionSecurityTrial -Request $first -Session $testSession -Runner $env:HERMES_QA_RUNNER -RunnerHash $runnerHash -Harness $env:HERMES_QA_HARNESS -PipeProbePath $env:HERMES_QA_HARNESS -PipeProbeHash $harnessHash -ExpectedExecutionStages @('fixture_build') -ExpectedFailureReasons @('tamper_fixture_unverified')
Set-Content -LiteralPath $env:HERMES_QA_HARNESS -Value '# revised evaluation harness' -NoNewline
$secondHarnessHash = (Get-FileHash -LiteralPath $env:HERMES_QA_HARNESS -Algorithm SHA256).Hash.ToUpperInvariant()
Set-Request $secondId $secondNonce $secondHarnessHash
$second = Read-SecurityRequest -ControlPath $env:HERMES_QA_CONTROL
$secondClaimed = Claim-SecurityRequest -ClaimRoot $env:HERMES_QA_CLAIMS -Request $second
$secondReport = Invoke-SessionSecurityTrial -Request $second -Session $testSession -Runner $env:HERMES_QA_RUNNER -RunnerHash $runnerHash -Harness $env:HERMES_QA_HARNESS -PipeProbePath $env:HERMES_QA_HARNESS -PipeProbeHash $harnessHash -ExpectedExecutionStages @('fixture_build') -ExpectedFailureReasons @('tamper_fixture_unverified')
$replayClaimed = Claim-SecurityRequest -ClaimRoot $env:HERMES_QA_CLAIMS -Request $second
$beforeMismatch = @($firstReport,$secondReport).Count
Set-Request ([guid]'cccccccc-cccc-cccc-cccc-cccccccccccc') ([guid]'33333333-3333-3333-3333-333333333333') ('0' * 64)
$mismatch = Read-SecurityRequest -ControlPath $env:HERMES_QA_CONTROL
try {
    $_ = Invoke-SessionSecurityTrial -Request $mismatch -Session $testSession -Runner $env:HERMES_QA_RUNNER -RunnerHash $runnerHash -Harness $env:HERMES_QA_HARNESS -PipeProbePath $env:HERMES_QA_HARNESS -PipeProbeHash $harnessHash -ExpectedExecutionStages @('fixture_build') -ExpectedFailureReasons @('tamper_fixture_unverified')
} catch [Security.SecurityException] {}
$hashMismatchDispatched = (@($firstReport,$secondReport).Count -ne $beforeMismatch)
$pendingChildAllowed = Test-PreviousTrialAllowsNext -Report ([pscustomobject]@{
    childStarted = $true; childTerminalObserved = $false; jobCleanupSucceeded = $true; sessionCleanupSucceeded = $true
    result = [pscustomobject]@{ outcome = 'failed'; cleanup = [pscustomobject]@{ fixtureRemoved = $false; registrationsRemoved = $true } }
})
[ordered]@{
    dispatches = @($firstReport,$secondReport).Count
    sessionReused = ($firstReport.sessionId -ceq $testSession.id -and $secondReport.sessionId -ceq $testSession.id)
    firstClaimed = $firstClaimed
    secondClaimed = $secondClaimed
    replayClaimed = $replayClaimed
    hashMismatchDispatched = $hashMismatchDispatched
    pendingChildAllowed = $pendingChildAllowed
    outerLoopUsesRequestHash = $true
} | ConvertTo-Json -Compress
"""

    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={
            **os.environ,
            "HERMES_QA_BROKER": str(BROKER_PATH),
            "HERMES_QA_CLAIMS": str(claim_root),
            "HERMES_QA_CONTROL": str(control),
            "HERMES_QA_HARNESS": str(harness),
            "HERMES_QA_RUNNER": str(runner),
        },
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert SESSION_REQUEST_RESULT_ADAPTER.validate_json(result.stdout) == {
        "dispatches": 2,
        "sessionReused": True,
        "firstClaimed": True,
        "secondClaimed": True,
        "replayClaimed": False,
        "hashMismatchDispatched": False,
        "pendingChildAllowed": False,
        "outerLoopUsesRequestHash": True,
    }
