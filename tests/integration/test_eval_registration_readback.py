"""Evaluation broker registration-readback regressions."""

# ruff: noqa: E501

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Final, TypedDict

from pydantic import TypeAdapter

PROJECT_ROOT: Final = Path(__file__).resolve().parents[2]
BROKER_PATH: Final = (
    PROJECT_ROOT
    / ".omo"
    / "evidence"
    / "service-protection-eval-vm-20260908"
    / "security"
    / "hold-evaluation-session.ps1"
)
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None


class RegistrationReadbackResult(TypedDict):
    requestAccepted: bool
    rejectedRequests: int
    absenceVerified: bool
    servicePresentRejected: bool
    taskPresentRejected: bool
    serviceQueryErrorThrows: bool
    taskQueryErrorThrows: bool
    invalidReadbackRejected: bool
    sameSessionUsed: bool
    fixedQueriesUsed: bool
    readbackCreatesNoSession: bool
    outerLoopUsesFreshReadback: bool
    retainedRegistrationAllowed: bool
    retainedRegistrationBlockedByDefault: bool
    retainedRegistrationBlockedByPendingChild: bool
    retainedRegistrationBlockedByFailedCleanup: bool
    retainedRegistrationBlockedByMissingFields: bool


REGISTRATION_READBACK_RESULT_ADAPTER: Final = TypeAdapter(RegistrationReadbackResult)


def test_registration_request_and_readback_use_fixed_session_contract(tmp_path: Path) -> None:
    """등록 조회 요청은 좁게 파싱하고 고정 guest 조회만 같은 session에서 실행합니다."""
    control = tmp_path / "registration-request.json"
    command = r"""
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_BROKER, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) { throw 'BrokerParseFailed' }
$names = @('Read-RegistrationRequest', 'Invoke-SessionRegistrationReadback', 'Test-PreviousTrialAllowsNext')
foreach ($name in $names) {
    $definition = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $true))
    if ($definition.Count -ne 1) { throw ('BrokerFunctionMissing:' + $name) }
    . ([scriptblock]::Create($definition[0].Extent.Text))
}
$readbackDefinition = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Invoke-SessionRegistrationReadback'
}, $true))[0]
$forbiddenReadbackCommands = @($readbackDefinition.Body.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -in @('Get-Credential', 'New-PSSession', 'Set-Content', 'Add-Content')
}, $true))
if ($forbiddenReadbackCommands.Count -ne 0) { throw 'RegistrationReadbackHasMutationOrCredentialCommand' }
$brokerText = $ast.Extent.Text
$outerLoopUsesFreshReadback =
    $brokerText -match '\$registrationsAbsent\s*=\s*\$false' -and
    $brokerText -match 'Invoke-SessionRegistrationReadback\s+-Session\s+\$session' -and
    $brokerText -match 'Test-PreviousTrialAllowsNext\s+-Report\s+\$previousReport\s+-RegistrationsAbsent\s+\$registrationsAbsent'
$script:expectedSession = [pscustomobject]@{ id = 'held-session' }
$script:sameSessionUsed = $false
$script:queryCalls = [Collections.Generic.List[object]]::new()
$script:mode = 'absent'
function Invoke-Command {
    param($Session, [scriptblock]$ScriptBlock)
    $script:sameSessionUsed = ($Session -eq $script:expectedSession)
    if ($script:mode -eq 'invalid') { return [pscustomobject]@{ registrationsAbsent = 'false' } }
    & $ScriptBlock
}
function Get-CimInstance {
    param([string]$ClassName, [string]$Filter, $ErrorAction)
    [void]$script:queryCalls.Add([pscustomobject]@{ command = 'cim'; className = $ClassName; filter = $Filter; errorAction = [string]$ErrorAction })
    if ($script:mode -eq 'service_error') { throw [InvalidOperationException]::new('service query failed') }
    if ($script:mode -eq 'service') { return [pscustomobject]@{ Name = 'HermesWindowsBridgeGateway' } }
    return $null
}
function Get-ScheduledTask {
    param([string]$TaskPath, $ErrorAction)
    [void]$script:queryCalls.Add([pscustomobject]@{ command = 'task'; taskPath = $TaskPath; errorAction = [string]$ErrorAction })
    if ($script:mode -eq 'task_error') { throw [InvalidOperationException]::new('task query failed') }
    if ($script:mode -eq 'task') { return [pscustomobject]@{ TaskName = 'HermesWindowsBridgeWorker'; TaskPath = '\' } }
    return @()
}
function Set-RegistrationRequest([string]$Json) {
    [IO.File]::WriteAllText($env:HERMES_QA_CONTROL, $Json, [Text.UTF8Encoding]::new($false))
    return Read-RegistrationRequest -ControlPath $env:HERMES_QA_CONTROL
}
$valid = Set-RegistrationRequest '{"action":"registrations","id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","nonce":"11111111-1111-1111-1111-111111111111"}'
$rejected = 0
foreach ($invalid in @(
    '{"action":"security","id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","nonce":"11111111-1111-1111-1111-111111111111"}',
    '{"action":"registrations","id":"00000000-0000-0000-0000-000000000000","nonce":"11111111-1111-1111-1111-111111111111"}',
    '{"action":"registrations","id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","nonce":"11111111-1111-1111-1111-111111111111","path":"x.ps1"}',
    '{"action":"registrations","id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","nonce":"11111111-1111-1111-1111-111111111111","script":"x.ps1"}',
    '{"action":"registrations","id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","nonce":"11111111-1111-1111-1111-111111111111","hash":"deadbeef"}'
)) { if ($null -eq (Set-RegistrationRequest $invalid)) { $rejected++ } }
$script:mode = 'absent'
$absence = Invoke-SessionRegistrationReadback -Session $script:expectedSession
$script:mode = 'service'
$servicePresent = Invoke-SessionRegistrationReadback -Session $script:expectedSession
$script:mode = 'task'
$taskPresent = Invoke-SessionRegistrationReadback -Session $script:expectedSession
$script:mode = 'service_error'
$serviceQueryErrorThrows = $false
try { $_ = Invoke-SessionRegistrationReadback -Session $script:expectedSession }
catch [InvalidOperationException] { $serviceQueryErrorThrows = $true }
$script:mode = 'task_error'
$taskQueryErrorThrows = $false
try { $_ = Invoke-SessionRegistrationReadback -Session $script:expectedSession }
catch [InvalidOperationException] { $taskQueryErrorThrows = $true }
$script:mode = 'invalid'
$invalidReadbackRejected = $false
try { $_ = Invoke-SessionRegistrationReadback -Session $script:expectedSession }
catch [Security.SecurityException] { $invalidReadbackRejected = $true }
$terminal = [pscustomobject]@{
    childStarted = $true; childTerminalObserved = $true; jobCleanupSucceeded = $true; sessionCleanupSucceeded = $true
    result = [pscustomobject]@{ outcome = 'failed'; cleanup = [pscustomobject]@{ fixtureRemoved = $false; registrationsRemoved = $false } }
}
$pending = [pscustomobject]@{
    childStarted = $true; childTerminalObserved = $false; jobCleanupSucceeded = $true; sessionCleanupSucceeded = $true
    result = [pscustomobject]@{ outcome = 'failed'; cleanup = [pscustomobject]@{ fixtureRemoved = $false; registrationsRemoved = $false } }
}
$failedCleanup = [pscustomobject]@{
    childStarted = $true; childTerminalObserved = $true; jobCleanupSucceeded = $false; sessionCleanupSucceeded = $true
    result = [pscustomobject]@{ outcome = 'failed'; cleanup = [pscustomobject]@{ fixtureRemoved = $false; registrationsRemoved = $false } }
}
$missingFields = [pscustomobject]@{
    childStarted = $true; childTerminalObserved = $true; jobCleanupSucceeded = $true
    result = [pscustomobject]@{ outcome = 'failed'; cleanup = [pscustomobject]@{ fixtureRemoved = $false; registrationsRemoved = $false } }
}
$fixedQueriesUsed =
    @($script:queryCalls | Where-Object { $_.command -eq 'cim' -and $_.className -eq 'Win32_Service' -and $_.errorAction -eq 'Stop' -and $_.filter -in @("Name='HermesWindowsBridgeGateway'", "Name='HermesWindowsBridgePrivileged'") }).Count -ge 2 -and
    @($script:queryCalls | Where-Object { $_.command -eq 'task' -and $_.taskPath -eq '\' -and $_.errorAction -eq 'Stop' }).Count -ge 3
[ordered]@{
    requestAccepted = ($null -ne $valid -and $valid.id.Guid -ceq 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' -and $valid.nonce.Guid -ceq '11111111-1111-1111-1111-111111111111')
    rejectedRequests = $rejected
    absenceVerified = [bool]$absence.registrationsAbsent
    servicePresentRejected = -not [bool]$servicePresent.registrationsAbsent
    taskPresentRejected = -not [bool]$taskPresent.registrationsAbsent
    serviceQueryErrorThrows = $serviceQueryErrorThrows
    taskQueryErrorThrows = $taskQueryErrorThrows
    invalidReadbackRejected = $invalidReadbackRejected
    sameSessionUsed = $script:sameSessionUsed
    fixedQueriesUsed = $fixedQueriesUsed
    readbackCreatesNoSession = ($forbiddenReadbackCommands.Count -eq 0)
    outerLoopUsesFreshReadback = $outerLoopUsesFreshReadback
    retainedRegistrationAllowed = Test-PreviousTrialAllowsNext -Report $terminal -RegistrationsAbsent $true
    retainedRegistrationBlockedByDefault = -not (Test-PreviousTrialAllowsNext -Report $terminal)
    retainedRegistrationBlockedByPendingChild = -not (Test-PreviousTrialAllowsNext -Report $pending -RegistrationsAbsent $true)
    retainedRegistrationBlockedByFailedCleanup = -not (Test-PreviousTrialAllowsNext -Report $failedCleanup -RegistrationsAbsent $true)
    retainedRegistrationBlockedByMissingFields = -not (Test-PreviousTrialAllowsNext -Report $missingFields -RegistrationsAbsent $true)
} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={
            **os.environ,
            "HERMES_QA_BROKER": str(BROKER_PATH),
            "HERMES_QA_CONTROL": str(control),
        },
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert REGISTRATION_READBACK_RESULT_ADAPTER.validate_json(result.stdout) == {
        "requestAccepted": True,
        "rejectedRequests": 5,
        "absenceVerified": True,
        "servicePresentRejected": True,
        "taskPresentRejected": True,
        "serviceQueryErrorThrows": True,
        "taskQueryErrorThrows": True,
        "invalidReadbackRejected": True,
        "sameSessionUsed": True,
        "fixedQueriesUsed": True,
        "readbackCreatesNoSession": True,
        "outerLoopUsesFreshReadback": True,
        "retainedRegistrationAllowed": True,
        "retainedRegistrationBlockedByDefault": True,
        "retainedRegistrationBlockedByPendingChild": True,
        "retainedRegistrationBlockedByFailedCleanup": True,
        "retainedRegistrationBlockedByMissingFields": True,
    }
