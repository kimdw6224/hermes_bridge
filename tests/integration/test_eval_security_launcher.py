"""Evaluation-VM security launcher receipt boundary regressions."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Final, TypedDict

import pytest
from pydantic import TypeAdapter

PROJECT_ROOT: Final = Path(__file__).resolve().parents[2]
RUNNER_PATH: Final = (
    PROJECT_ROOT
    / ".omo"
    / "evidence"
    / "service-protection-eval-vm-20260908"
    / "security"
    / "run-security-checks.ps1"
)
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None
NONCE: Final = "8fb55a28-69e7-41f2-b449-df8148645bc0"


@pytest.mark.parametrize(
    "script_name",
    ["run-security-checks.ps1", "diagnose-security-gate.ps1", "launch-reviewed-security.ps1"],
)
def test_security_entrypoints_reject_apply_without_prompt_opt_in(script_name: str) -> None:
    arguments = [
        POWERSHELL_PATH,
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(RUNNER_PATH.with_name(script_name)),
        "-Apply",
    ]
    if script_name == "launch-reviewed-security.ps1":
        arguments.extend(["-HarnessSha256", "0" * 64, "-DeadlineUtc", "2026-09-09T00:00:00Z"])
    result = subprocess.run(
        arguments,
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
    )
    assert result.returncode != 0
    assert "credential_prompt_not_authorized" in result.stdout + result.stderr
    if script_name == "run-security-checks.ps1":
        assert '"credentialPrompted":false' in result.stdout
        assert '"vmConnectionCreated":false' in result.stdout


class ReceiptCaseResult(TypedDict):
    name: str
    accepted: bool


class EncodedArgumentResult(TypedDict):
    programRoot: str
    inputRoot: str
    inputBindingSha256: str
    fixtureSourceRoot: str
    trustedUvPath: str
    expectedUvSha256: str
    probePath: str
    pipeAclProbePath: str
    pipeAclProbeSha256: str


class ImmutableInventoryResult(TypedDict):
    inputFileCount: int
    uvSha256: str


class PipeAclProbeHashResult(TypedDict):
    initialAccepted: bool
    tamperRejected: bool


class DryRunResult(TypedDict):
    action: str
    applyRequired: bool
    guestMutation: bool
    credentialPrompted: bool
    vmConnectionCreated: bool
    blockedUntilHarnessHashAndSchema: bool


class GuestTransferResult(TypedDict):
    inputFileCount: int
    bindingCopied: bool
    runtimeCopied: bool
    inventoryAccepted: bool
    tamperRejected: bool


class VmBiosGuidResult(TypedDict):
    biosGuid: str


RECEIPT_CASE_RESULTS_ADAPTER: Final = TypeAdapter(list[ReceiptCaseResult])
ENCODED_ARGUMENT_RESULT_ADAPTER: Final = TypeAdapter(EncodedArgumentResult)
IMMUTABLE_INVENTORY_RESULT_ADAPTER: Final = TypeAdapter(ImmutableInventoryResult)
PIPE_ACL_PROBE_HASH_RESULT_ADAPTER: Final = TypeAdapter(PipeAclProbeHashResult)
DRY_RUN_RESULT_ADAPTER: Final = TypeAdapter(DryRunResult)
GUEST_TRANSFER_RESULT_ADAPTER: Final = TypeAdapter(GuestTransferResult)
VM_BIOS_GUID_RESULT_ADAPTER: Final = TypeAdapter(VmBiosGuidResult)


def test_security_launcher_vm_binding_accepts_one_associated_setting() -> None:
    """Get-HostVmBiosGuid는 singleton CIM association을 배열 한 건으로 취급합니다."""
    command = r"""
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_SECURITY_RUNNER, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) { throw 'SecurityRunnerParseFailed' }
$definition = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Get-HostVmBiosGuid'
}, $true))
if ($definition.Count -ne 1) { throw 'SecurityRunnerFunctionMissing:GetHostVmBiosGuid' }
Set-StrictMode -Version Latest
$vmId = [guid]'2275c148-f4ba-4f1e-85bb-2695c6439bb6'
$vmName = 'HermesBridge-Eval-20260908'
function Get-VM {
    param([guid]$Id)
    return [pscustomobject]@{ Name = $vmName; State = 'Running' }
}
function Get-CimInstance {
    return [pscustomobject]@{ Name = $vmId.Guid }
}
function Get-CimAssociatedInstance {
    return [pscustomobject]@{ BIOSGUID = 'ea687c09-159b-4942-bd0f-53d64f92ae16' }
}
. ([scriptblock]::Create($definition[0].Extent.Text))
[ordered]@{
    biosGuid = (Get-HostVmBiosGuid).Guid
} | ConvertTo-Json -Compress
"""

    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={**os.environ, "HERMES_QA_SECURITY_RUNNER": str(RUNNER_PATH)},
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert VM_BIOS_GUID_RESULT_ADAPTER.validate_json(result.stdout) == {
        "biosGuid": "ea687c09-159b-4942-bd0f-53d64f92ae16"
    }


def test_security_launcher_receipt_boundary_fails_closed_for_incomplete_success_and_reason_errors(
) -> None:
    """Get-SafeResult는 completed 조건과 failed 사유 enum을 실제 PS5에서 엄격히 강제합니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_SECURITY_RUNNER, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) { throw 'SecurityRunnerParseFailed' }
foreach ($name in @('Get-PropertyValue', 'Get-SafeResult')) {
    $definition = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true))
    if ($definition.Count -ne 1) { throw ('SecurityRunnerFunctionMissing:' + $name) }
    . ([scriptblock]::Create($definition[0].Extent.Text))
}
$securityNonce = [guid]$env:HERMES_QA_SECURITY_NONCE
$ExpectedExecutionStages = @('complete')
$ExpectedFailureReasons = @('fixture_failed')
function New-Receipt {
    param([string]$Outcome, $Reason)
    [pscustomobject]@{
        schemaVersion = 1; nonce = $securityNonce.Guid; outcome = $Outcome
        executionStage = 'complete'; failureReason = $Reason
        tokenGate = $true; immutableFileWriteDenied = $true
        immutableDirectoryWriteDenied = $true; pristineLaunchContractVerified = $true
        tamperedLaunchContractRejected = $true; pipeMetadataOpenConsumesConnection = $false
        livePipeDaclVerified = $true; gatewayRecoveryVerified = $true; receiptPersisted = $true
        cleanup = [pscustomobject]@{ fixtureRemoved = $true; registrationsRemoved = $true }
    }
}
$cases = @()
foreach ($entry in @(
    @('valid_passed', 'passed', '', $true),
    @('valid_allowlisted_failed', 'failed', 'fixture_failed', $true),
    @('failed_empty_reason', 'failed', '', $false),
    @('failed_null_reason', 'failed', $null, $false),
    @('passed_nonempty_reason', 'passed', 'fixture_failed', $false),
    @('passed_false_required_boolean', 'passed', '', $false),
    @('passed_null_required_boolean', 'passed', '', $false),
    @('passed_false_cleanup', 'passed', '', $false),
    @('passed_missing_gateway_recovery', 'passed', '', $false),
    @('passed_false_gateway_recovery', 'passed', '', $false),
    @('passed_null_gateway_recovery', 'passed', '', $false),
    @('passed_metadata_connection_consumed', 'passed', '', $true)
)) {
    $cases += [pscustomobject]@{
        name = $entry[0]; receipt = (New-Receipt $entry[1] $entry[2]); expected = $entry[3]
    }
}
$cases[5].receipt.tokenGate = $false
$cases[6].receipt.livePipeDaclVerified = $null
$cases[7].receipt.cleanup.registrationsRemoved = $false
$cases[8].receipt.PSObject.Properties.Remove('gatewayRecoveryVerified')
$cases[9].receipt.gatewayRecoveryVerified = $false
$cases[10].receipt.gatewayRecoveryVerified = $null
$cases[11].receipt.pipeMetadataOpenConsumesConnection = $true
$observed = foreach ($case in $cases) {
    $accepted = $true
    try { [void](Get-SafeResult $case.receipt) }
    catch [Security.SecurityException] { $accepted = $false }
    if ($accepted -ne $case.expected) { throw ('SecurityResultCaseFailed:' + $case.name) }
    [ordered]@{ name = [string]$case.name; accepted = [bool]$accepted }
}
$observed | ConvertTo-Json -Compress
"""

    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={
            **os.environ,
            "HERMES_QA_SECURITY_RUNNER": str(RUNNER_PATH),
            "HERMES_QA_SECURITY_NONCE": NONCE,
        },
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert RECEIPT_CASE_RESULTS_ADAPTER.validate_json(result.stdout) == [
        {"name": "valid_passed", "accepted": True},
        {"name": "valid_allowlisted_failed", "accepted": True},
        {"name": "failed_empty_reason", "accepted": False},
        {"name": "failed_null_reason", "accepted": False},
        {"name": "passed_nonempty_reason", "accepted": False},
        {"name": "passed_false_required_boolean", "accepted": False},
        {"name": "passed_null_required_boolean", "accepted": False},
        {"name": "passed_false_cleanup", "accepted": False},
        {"name": "passed_missing_gateway_recovery", "accepted": False},
        {"name": "passed_false_gateway_recovery", "accepted": False},
        {"name": "passed_null_gateway_recovery", "accepted": False},
        {"name": "passed_metadata_connection_consumed", "accepted": True},
    ]


def test_security_launcher_file_dry_run_resolves_default_harness_for_relative_and_absolute_paths(
) -> None:
    """PS5 -File 호출은 경로 형태와 무관하게 mutation 없는 dry-run을 반환합니다."""
    expected: DryRunResult = {
        "action": "dry_run",
        "applyRequired": True,
        "guestMutation": False,
        "credentialPrompted": False,
        "vmConnectionCreated": False,
        "blockedUntilHarnessHashAndSchema": True,
    }
    runner_paths = [
        str(RUNNER_PATH),
        str(RUNNER_PATH.relative_to(PROJECT_ROOT)),
    ]

    for runner_path in runner_paths:
        result = subprocess.run(
            [
                POWERSHELL_PATH,
                "-NoProfile",
                "-NonInteractive",
                "-File",
                runner_path,
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
        assert DRY_RUN_RESULT_ADAPTER.validate_json(result.stdout) == expected


def test_security_launcher_encoded_child_arguments_preserve_paths_with_spaces(
    tmp_path: Path,
) -> None:
    """실제 launcher guest-start block의 EncodedCommand가 공백 경로를 보존합니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_SECURITY_RUNNER, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) { throw 'SecurityRunnerParseFailed' }
$startCommands = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -ceq 'Start-Process'
}, $true))
if ($startCommands.Count -ne 1) { throw 'SecurityRunnerStartProcessMissing' }
$startBlock = $startCommands[0]
while ($startBlock -isnot [System.Management.Automation.Language.ScriptBlockAst]) {
    $startBlock = $startBlock.Parent
}
$convertFunction = @($startBlock.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'ConvertTo-SingleQuotedLiteral'
}, $true))
$childAssignment = @($startBlock.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -ceq '$childCommand'
}, $true))
$argumentAssignment = @($startBlock.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -ceq '$argumentList'
}, $true))
if ($convertFunction.Count -ne 1 -or $childAssignment.Count -ne 1 -or
    $argumentAssignment.Count -ne 1) {
    throw 'SecurityRunnerArgumentConstructionMissing'
}
$parameterBlock = 'param([string]$Harness,[guid]$ExpectedUuid,[guid]$Nonce,' +
    '[string]$ChildDeadline,[string]$ManifestHash,[string]$ExpectedInputRoot,' +
    '[string]$ExpectedInputBindingSha256,[string]$FixtureSourceRoot,' +
    '[string]$TrustedUvPath,[string]$ExpectedUvSha256,[string]$ProbePath,' +
    '[string]$ProbeHash,[string]$PipeAclProbePath,[string]$PipeAclProbeHash)'
$captureText = $parameterBlock + [Environment]::NewLine +
    $convertFunction[0].Extent.Text + [Environment]::NewLine +
    $childAssignment[0].Extent.Text + [Environment]::NewLine +
    $argumentAssignment[0].Extent.Text + [Environment]::NewLine +
    '$policyArgument = "-Execution" + "Policy"; ' +
    'if ($argumentList[0] -cne "-NoProfile" -or ' +
    '$argumentList[1] -cne "-EncodedCommand" -or $argumentList -contains $policyArgument) ' +
    '{ throw "SecurityChildPolicyInvalid" }; ' +
    '$env:HERMES_QA_CAPTURED_ENCODED = [string]$argumentList[2]'
$env:HERMES_QA_CAPTURED_ENCODED = $null
$_ = & ([scriptblock]::Create($captureText)) `
    $env:HERMES_QA_SECURITY_HARNESS `
    ([guid]'2275c148-f4ba-4f1e-85bb-2695c6439bb6') `
    ([guid]$env:HERMES_QA_SECURITY_NONCE) `
    '2026-09-08T12:00:00.0000000Z' `
    ('A' * 64) `
    $env:HERMES_QA_SECURITY_INPUT_ROOT `
    ('1595D52FE8A8C99A578CFA29777276D5C38A3BC251B9BE22989C5B8D2BA24260') `
    $env:HERMES_QA_SECURITY_FIXTURE_SOURCE_ROOT `
    $env:HERMES_QA_SECURITY_TRUSTED_UV `
    ('69A60E42E824019A3E97577670E58F76652ED98F0B16F75EC46981012459929E') `
    $env:HERMES_QA_SECURITY_PROBE `
    ('B' * 64) `
    $env:HERMES_QA_PIPE_ACL_PROBE `
    ('C' * 64)
if ([string]::IsNullOrEmpty($env:HERMES_QA_CAPTURED_ENCODED)) {
    throw 'SecurityRunnerEncodedCommandMissing'
}
& (Join-Path $PSHOME 'powershell.exe') -NoProfile -NonInteractive -EncodedCommand `
    $env:HERMES_QA_CAPTURED_ENCODED
"""

    harness_path = tmp_path / "guest security checks.ps1"
    _ = harness_path.write_text(
        """
param(
    [string]$ExpectedVmUuid,
    [string]$Nonce,
    [string]$DeadlineUtc,
    [string]$ExpectedProgramRoot,
    [string]$ExpectedReleaseManifestSha256,
    [string]$ExpectedInputRoot,
    [string]$ExpectedInputBindingSha256,
    [string]$FixtureSourceRoot,
    [string]$TrustedUvPath,
    [string]$ExpectedUvSha256,
    [string]$TokenProbePath,
    [string]$ExpectedTokenProbeSha256,
    [string]$PipeAclProbePath,
    [string]$ExpectedPipeAclProbeSha256,
    [switch]$Apply
)
[ordered]@{
    programRoot = $ExpectedProgramRoot
    inputRoot = $ExpectedInputRoot
    inputBindingSha256 = $ExpectedInputBindingSha256
    fixtureSourceRoot = $FixtureSourceRoot
    trustedUvPath = $TrustedUvPath
    expectedUvSha256 = $ExpectedUvSha256
    probePath = $TokenProbePath
    pipeAclProbePath = $PipeAclProbePath
    pipeAclProbeSha256 = $ExpectedPipeAclProbeSha256
} | ConvertTo-Json -Compress
""".strip(),
        encoding="utf-8",
    )
    probe_path = tmp_path / "token evidence.ps1"
    pipe_acl_probe_path = tmp_path / "pipe acl probe.py"
    input_root = r"C:\HermesTask6\69ecce43-c061-49ba-a91a-6b496455b490\input"
    fixture_source_root = input_root
    trusted_uv_path = input_root + r"\uv.exe"

    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={
            **os.environ,
            "HERMES_QA_SECURITY_RUNNER": str(RUNNER_PATH),
            "HERMES_QA_SECURITY_HARNESS": str(harness_path),
            "HERMES_QA_SECURITY_NONCE": NONCE,
            "HERMES_QA_SECURITY_INPUT_ROOT": input_root,
            "HERMES_QA_SECURITY_FIXTURE_SOURCE_ROOT": fixture_source_root,
            "HERMES_QA_SECURITY_TRUSTED_UV": trusted_uv_path,
            "HERMES_QA_SECURITY_PROBE": str(probe_path),
            "HERMES_QA_PIPE_ACL_PROBE": str(pipe_acl_probe_path),
        },
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert ENCODED_ARGUMENT_RESULT_ADAPTER.validate_json(result.stdout) == {
        "programRoot": r"C:\Program Files\HermesWindowsBridge",
        "inputRoot": input_root,
        "inputBindingSha256": (
            "1595D52FE8A8C99A578CFA29777276D5C38A3BC251B9BE22989C5B8D2BA24260"
        ),
        "fixtureSourceRoot": fixture_source_root,
        "trustedUvPath": trusted_uv_path,
        "expectedUvSha256": (
            "69A60E42E824019A3E97577670E58F76652ED98F0B16F75EC46981012459929E"
        ),
        "probePath": str(probe_path),
        "pipeAclProbePath": str(pipe_acl_probe_path),
        "pipeAclProbeSha256": "C" * 64,
    }


def test_security_launcher_immutable_inventory_accepts_the_bound_121_file_input(
) -> None:
    """실제 runner AST가 121개인 기존 immutable binding을 통과시킵니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_SECURITY_RUNNER, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) { throw 'SecurityRunnerParseFailed' }
Import-Module Microsoft.PowerShell.Utility -ErrorAction Stop
foreach ($name in @(
    'Get-HashUpper', 'Assert-RegularNoReparsePath', 'Assert-Hash',
    'Assert-ImmutableInventory'
)) {
    $definition = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true))
    if ($definition.Count -ne 1) { throw ('SecurityRunnerFunctionMissing:' + $name) }
    . ([scriptblock]::Create($definition[0].Extent.Text))
}
$immutableBundleRoot = $env:HERMES_QA_IMMUTABLE_BUNDLE
$immutableBindingPath = Join-Path $immutableBundleRoot 'task6-input-binding.json'
$immutableBindingSha256 = $env:HERMES_QA_IMMUTABLE_BINDING_SHA256
    $immutableNonce = [guid]'69ecce43-c061-49ba-a91a-6b496455b490'
$binding = Assert-ImmutableInventory
[ordered]@{
    inputFileCount = @($binding.inputFiles).Count
    uvSha256 = [string]$binding.uvSha256
} | ConvertTo-Json -Compress
"""
    bundle_root = (
        PROJECT_ROOT
        / ".omo"
        / "evidence"
        / "service-protection-eval-vm-20260908"
        / "lifecycle"
        / "bundles"
        / "69ecce43-c061-49ba-a91a-6b496455b490"
    )

    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={
            **os.environ,
            "HERMES_QA_SECURITY_RUNNER": str(RUNNER_PATH),
            "HERMES_QA_IMMUTABLE_BUNDLE": str(bundle_root),
            "HERMES_QA_IMMUTABLE_BINDING_SHA256": (
                "1595D52FE8A8C99A578CFA29777276D5C38A3BC251B9BE22989C5B8D2BA24260"
            ),
        },
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert IMMUTABLE_INVENTORY_RESULT_ADAPTER.validate_json(result.stdout) == {
        "inputFileCount": 121,
        "uvSha256": "69a60e42e824019a3e97577670e58f76652ed98f0b16f75ec46981012459929e",
    }


def test_security_launcher_pipe_acl_probe_hash_rejects_a_tampered_file(
    tmp_path: Path,
) -> None:
    """Pipe ACL probe는 실제 runner hash guard에서 변조된 source를 거부합니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_SECURITY_RUNNER, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) { throw 'SecurityRunnerParseFailed' }
Import-Module Microsoft.PowerShell.Utility -ErrorAction Stop
$pipeGuard = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -ceq 'Assert-Hash' -and
        $node.Extent.Text -match '\$PipeAclProbePath' -and
        $node.Extent.Text -match 'pipe_acl_probe_hash_mismatch'
}, $true))
if ($pipeGuard.Count -ne 1) { throw 'SecurityRunnerPipeAclProbeGuardMissing' }
foreach ($name in @('Get-HashUpper', 'Assert-RegularNoReparsePath', 'Assert-Hash')) {
    $definition = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true))
    if ($definition.Count -ne 1) { throw ('SecurityRunnerFunctionMissing:' + $name) }
    . ([scriptblock]::Create($definition[0].Extent.Text))
}
$expected = (Get-FileHash -LiteralPath $env:HERMES_QA_PIPE_ACL_PROBE `
    -Algorithm SHA256).Hash.ToUpperInvariant()
Assert-Hash -Path $env:HERMES_QA_PIPE_ACL_PROBE -Expected $expected `
    -Failure 'pipe_acl_probe_hash_mismatch'
Add-Content -LiteralPath $env:HERMES_QA_PIPE_ACL_PROBE -Value '# tampered' `
    -Encoding UTF8
$tamperRejected = $false
try {
    Assert-Hash -Path $env:HERMES_QA_PIPE_ACL_PROBE -Expected $expected `
        -Failure 'pipe_acl_probe_hash_mismatch'
} catch [Security.SecurityException] {
    $tamperRejected = $_.Exception.Message -ceq 'pipe_acl_probe_hash_mismatch'
}
if (-not $tamperRejected) { throw 'SecurityRunnerPipeAclProbeTamperAccepted' }
[ordered]@{ initialAccepted = $true; tamperRejected = $tamperRejected } |
    ConvertTo-Json -Compress
"""
    pipe_acl_probe_path = tmp_path / "pipe acl probe.py"
    _ = pipe_acl_probe_path.write_text("print('probe')\n", encoding="utf-8")

    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={
            **os.environ,
            "HERMES_QA_SECURITY_RUNNER": str(RUNNER_PATH),
            "HERMES_QA_PIPE_ACL_PROBE": str(pipe_acl_probe_path),
        },
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert PIPE_ACL_PROBE_HASH_RESULT_ADAPTER.validate_json(result.stdout) == {
        "initialAccepted": True,
        "tamperRejected": True,
    }


def test_security_launcher_copies_new_bound_input_to_guest_nonce_root(
    tmp_path: Path,
) -> None:
    """실제 AST copy helper가 최신 binding과 수정된 runtime을 함께 전송합니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_SECURITY_RUNNER, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) { throw 'SecurityRunnerParseFailed' }
Import-Module Microsoft.PowerShell.Utility -ErrorAction Stop
$definition = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Copy-ImmutableInputToGuest'
}, $true))
if ($definition.Count -ne 1) { throw 'SecurityRunnerFunctionMissing:CopyImmutable' }
$inventoryDefinition = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Test-GuestInputInventory'
}, $true))
if ($inventoryDefinition.Count -ne 1) {
    throw 'SecurityRunnerFunctionMissing:TestGuestInputInventory'
}
$inventoryBlock = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.ScriptBlockAst] -and
        $node.Parent -is [System.Management.Automation.Language.ScriptBlockExpressionAst] -and
        $node.Extent.Text -match 'security_guest_input_inventory_invalid'
}, $true))
if ($inventoryBlock.Count -ne 1) {
    throw 'SecurityRunnerGuestInventoryBlockMissing'
}
function Invoke-ShortGuestJob {
    param([scriptblock]$ScriptBlock, [object[]]$Arguments, [int]$MaximumSeconds)
    return @(& $ScriptBlock @Arguments)
}
function Get-RemainingSeconds { return 1200 }
function Copy-Item {
    [CmdletBinding()]
    param([string]$LiteralPath, [string]$Destination, $ToSession)
    Microsoft.PowerShell.Management\Copy-Item -LiteralPath $LiteralPath -Destination $Destination
}
. ([scriptblock]::Create($definition[0].Extent.Text))
$immutableBundleRoot = $env:HERMES_QA_IMMUTABLE_BUNDLE
$immutableBindingPath = Join-Path $immutableBundleRoot 'task6-input-binding.json'
$binding = Get-Content -LiteralPath $immutableBindingPath -Raw | ConvertFrom-Json
[void][IO.Directory]::CreateDirectory($env:HERMES_QA_GUEST_INPUT)
Copy-ImmutableInputToGuest -Binding $binding `
    -GuestInputRoot $env:HERMES_QA_GUEST_INPUT -Session 'local-test'
$runtime = Join-Path $env:HERMES_QA_GUEST_INPUT 'src\hermes_windows_bridge\privileged\runtime.py'
$bindingPath = Join-Path $env:HERMES_QA_GUEST_INPUT 'task6-input-binding.json'
$runtimeHash = (Get-FileHash -LiteralPath $runtime -Algorithm SHA256).Hash.ToUpperInvariant()
$harnessHash = (Get-FileHash -LiteralPath $env:HERMES_QA_GUEST_HARNESS `
    -Algorithm SHA256).Hash.ToUpperInvariant()
$probeHash = (Get-FileHash -LiteralPath $env:HERMES_QA_GUEST_PROBE `
    -Algorithm SHA256).Hash.ToUpperInvariant()
$pipeAclProbeHash = (Get-FileHash -LiteralPath $env:HERMES_QA_GUEST_PIPE_ACL_PROBE `
    -Algorithm SHA256).Hash.ToUpperInvariant()
$expectedEntries = @($binding.inputFiles | ForEach-Object {
    [ordered]@{
        relativePath = [string]$_.relativePath
        sha256 = ([string]$_.sha256).ToUpperInvariant()
        size = [int64]$_.size
    }
}) | ConvertTo-Json -Depth 4 -Compress
$inventoryArguments = @(
    $env:HERMES_QA_GUEST_HARNESS, $harnessHash,
    $env:HERMES_QA_GUEST_PROBE, $probeHash,
    $env:HERMES_QA_GUEST_PIPE_ACL_PROBE, $pipeAclProbeHash,
    $env:HERMES_QA_GUEST_INPUT, $env:HERMES_QA_IMMUTABLE_BINDING_SHA256,
    $expectedEntries, ([string]$binding.uvSha256).ToUpperInvariant(),
    $inventoryDefinition[0].Extent.Text
)
$inventoryText = $inventoryBlock[0].Extent.Text.Trim()
$remoteInventory = [scriptblock]::Create($inventoryText.Substring(1, $inventoryText.Length - 2))
$inventoryResult = @(& $remoteInventory @inventoryArguments)
if ($inventoryResult.Count -ne 1 -or -not $inventoryResult[0].copiesVerified `
    -or -not $inventoryResult[0].inputInventoryVerified) {
    throw 'SecurityRunnerGuestInventoryAcceptedWithoutVerifiedResult'
}
$bytes = [IO.File]::ReadAllBytes($runtime)
$bytes[0] = $bytes[0] -bxor 1
[IO.File]::WriteAllBytes($runtime, $bytes)
$tamperedHash = (Get-FileHash -LiteralPath $runtime -Algorithm SHA256).Hash.ToUpperInvariant()
if ($tamperedHash -ceq $runtimeHash) { throw 'SecurityRunnerTamperWriteFailed' }
$tamperRejected = $false
try {
    $null = @(& $remoteInventory @inventoryArguments)
} catch {
    $tamperRejected = $_.Exception.Message -ceq 'security_guest_input_inventory_invalid'
    if (-not $tamperRejected) { throw ('SecurityRunnerTamperFailure:' + $_.Exception.Message) }
}
if (-not $tamperRejected) { throw 'SecurityRunnerTamperUnexpectedSuccess' }
[ordered]@{
    inputFileCount = @(
        Get-ChildItem -LiteralPath $env:HERMES_QA_GUEST_INPUT -File -Recurse |
            Where-Object { $_.Name -cne 'task6-input-binding.json' }
    ).Count
    bindingCopied = Test-Path -LiteralPath $bindingPath -PathType Leaf
    runtimeCopied = ($runtimeHash -ceq
        '10BA34BE605E17E7741A9A853A344D77EF42A96357F2A244B09BD9DE4488E96C')
    inventoryAccepted = $true
    tamperRejected = $tamperRejected
} | ConvertTo-Json -Compress
"""
    bundle_root = (
        PROJECT_ROOT
        / ".omo"
        / "evidence"
        / "service-protection-eval-vm-20260908"
        / "lifecycle"
        / "bundles"
        / "69ecce43-c061-49ba-a91a-6b496455b490"
    )
    guest_input = tmp_path / "guest nonce" / "input"
    harness_path = tmp_path / "guest harness.ps1"
    probe_path = tmp_path / "token probe.ps1"
    pipe_acl_probe_path = tmp_path / "pipe acl probe.py"
    _ = harness_path.write_text("# test harness\n", encoding="utf-8")
    _ = probe_path.write_text("# test probe\n", encoding="utf-8")
    _ = pipe_acl_probe_path.write_text("print('probe')\n", encoding="utf-8")

    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={
            **os.environ,
            "HERMES_QA_SECURITY_RUNNER": str(RUNNER_PATH),
            "HERMES_QA_IMMUTABLE_BUNDLE": str(bundle_root),
            "HERMES_QA_IMMUTABLE_BINDING_SHA256": (
                "1595D52FE8A8C99A578CFA29777276D5C38A3BC251B9BE22989C5B8D2BA24260"
            ),
            "HERMES_QA_GUEST_INPUT": str(guest_input),
            "HERMES_QA_GUEST_HARNESS": str(harness_path),
            "HERMES_QA_GUEST_PROBE": str(probe_path),
            "HERMES_QA_GUEST_PIPE_ACL_PROBE": str(pipe_acl_probe_path),
        },
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=45,
    )

    assert result.returncode == 0, result.stderr
    assert GUEST_TRANSFER_RESULT_ADAPTER.validate_json(result.stdout) == {
        "inputFileCount": 121,
        "bindingCopied": True,
        "runtimeCopied": True,
        "inventoryAccepted": True,
        "tamperRejected": True,
    }
