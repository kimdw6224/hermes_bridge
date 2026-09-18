"""Todo9 local SCM fixture의 pre-Apply safety contract를 독립 검증합니다."""
# ruff: noqa: E501
# pyright: reportAny=false

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

PROJECT_ROOT: Final = Path(__file__).resolve().parents[2]
RUNNER_PATH: Final = (
    PROJECT_ROOT
    / ".omo"
    / "evidence"
    / "local-scm-20260910"
    / "run-local-scm-qa.ps1"
)
NATIVE_PATH: Final = (
    PROJECT_ROOT
    / ".omo"
    / "evidence"
    / "local-scm-20260910"
    / "local-scm-native.ps1"
)
PRESERVATION_PATH: Final = (
    PROJECT_ROOT
    / ".omo"
    / "evidence"
    / "local-scm-20260910"
    / "local-scm-preservation.ps1"
)
SUPERVISOR_BOUNDARY_PATH: Final = (
    PROJECT_ROOT
    / ".omo"
    / "evidence"
    / "local-scm-20260910"
    / "supervisor-boundary-d40c"
    / "actual-local-scm-supervisor.ps1"
)
SERVICE_HOST_PATH: Final = PROJECT_ROOT / "scripts" / "service-host.ps1"
TRANSACTION_PATH: Final = PROJECT_ROOT / "scripts" / "service-runtime-transaction.ps1"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None


def _powershell_environment(extra: dict[str, str]) -> dict[str, str]:
    """Windows PowerShell 5의 기본 모듈만 쓰도록 고정합니다."""
    environment = os.environ.copy()
    environment["PSModulePath"] = r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
    environment.update(extra)
    return environment


def _run_powershell(command: str, *, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _future_deadline() -> str:
    return (datetime.now(UTC) + timedelta(hours=2)).isoformat().replace("+00:00", "Z")


def test_supervisor_tracker_does_not_read_live_manifest_contents(tmp_path: Path) -> None:
    """실행 중 tracker는 writer와 경합할 수 있는 manifest 본문을 읽지 않아야 한다."""
    assert SUPERVISOR_BOUNDARY_PATH.is_file()
    manifest = tmp_path / "live-fixture-manifest.json"
    _ = manifest.write_text(
        json.dumps(
            {
                "createdServices": [{"name": "fixture-gateway"}],
                "nativeMutationJournal": [{"state": "applied"}],
            }
        ),
        encoding="utf-8",
    )
    command = r"""
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($env:HERMES_QA_SUPERVISOR, [ref]$tokens, [ref]$errors)
if (@($errors).Count -ne 0) { throw 'SupervisorAstInvalid' }
$definition = @($ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Get-ActualLocalScmManifestObservation'
}, $true))[0]
if ($null -eq $definition) { throw 'SupervisorManifestObservationFunctionMissing' }
. ([scriptblock]::Create($definition.Extent.Text))
$observation = Get-ActualLocalScmManifestObservation -ManifestPath $env:HERMES_QA_MANIFEST
[pscustomobject]@{
    present = $observation.present
    createdServiceCount = $observation.createdServiceCount
    journalCount = $observation.journalCount
} | ConvertTo-Json -Compress
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_SUPERVISOR": str(SUPERVISOR_BOUNDARY_PATH),
                "HERMES_QA_MANIFEST": str(manifest),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    observation = json.loads(result.stdout)
    assert observation == {
        "present": True,
        "createdServiceCount": None,
        "journalCount": None,
    }


def test_existing_user_owned_directory_fails_closed_without_acl_mutation(
    tmp_path: Path,
) -> None:
    """비관리자도 기존 user-owned directory를 helper가 바꾸지 않는지 검증합니다."""
    protected = tmp_path / "existing-protected-directory"
    protected.mkdir()
    command = r"""
. $env:HERMES_QA_SERVICE_HOST -LibraryMode
function Get-DescriptorSha256 {
    param([Parameter(Mandatory)][string]$Path)
    $descriptor = (Get-Acl -LiteralPath $Path -ErrorAction Stop).GetSecurityDescriptorBinaryForm()
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($descriptor))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}
$target = [IO.Path]::GetFullPath($env:HERMES_QA_PROTECTED_DIRECTORY)
$before = Get-DescriptorSha256 -Path $target
$validationFailure = $false
try {
    Set-BridgeHostProtectedDirectory -Path $target
} catch [Security.SecurityException] {
    $validationFailure = $_.Exception.Message -ceq 'BridgeServiceHostAclUnverified'
}
$afterFailure = Get-DescriptorSha256 -Path $target
[pscustomobject][ordered]@{
    before = $before
    afterFailure = $afterFailure
    validationFailure = $validationFailure
} | ConvertTo-Json -Compress
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_SERVICE_HOST": str(SERVICE_HOST_PATH),
                "HERMES_QA_PROTECTED_DIRECTORY": str(protected),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["validationFailure"] is True
    assert receipt["before"] == receipt["afterFailure"]


def test_transaction_core_restores_fixture_pointer_bytes_after_post_commit_failure(
    tmp_path: Path,
) -> None:
    """Todo9 adapter는 unchanged transaction core의 pointer compensation을 그대로 써야 합니다."""
    pointer = tmp_path / "fixture-selection.bin"
    before = b"fixture-pointer-before\x00\xff"
    _ = pointer.write_bytes(before)
    command = r"""
. $env:HERMES_QA_TRANSACTION
function Get-FileSha256 {
    param([Parameter(Mandatory)][string]$Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($Path)))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}
$pointer = $env:HERMES_QA_POINTER
$before = [IO.File]::ReadAllBytes($pointer)
$candidate = [byte[]]@(102, 105, 120, 116, 117, 114, 101, 45, 112, 111, 105, 110, 116, 101, 114, 45, 97, 102, 116, 101, 114)
$calls = [Collections.Generic.List[string]]::new()
$callback = {
    param([Parameter(Mandatory)][string]$Step)
    $calls.Add($Step)
    switch ($Step) {
        'pointer_commit' { [IO.File]::WriteAllBytes($pointer, $candidate); break }
        'pointer_restore' { [IO.File]::WriteAllBytes($pointer, $before); break }
        'post_commit_readback' { throw 'fixture-post-commit-readback-failure' }
        default { if ($Step -like '*_start') { return $true } }
    }
}
$receipt = Invoke-BridgeServiceSwitchTransaction -PreviousState safe-pair -InvokeStep $callback
[pscustomobject][ordered]@{
    receipt = $receipt
    calls = @($calls)
    pointerSha256 = Get-FileSha256 -Path $pointer
} | ConvertTo-Json -Depth 12 -Compress
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_TRANSACTION": str(TRANSACTION_PATH),
                "HERMES_QA_POINTER": str(pointer),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    receipt = report["receipt"]
    assert receipt["state"] == "rolled-back"
    assert receipt["failedStep"] == "post_commit_readback"
    assert receipt["pointerCommitted"] is False
    assert receipt["pointerCompensated"] is True
    assert receipt["rollbackFailures"] == []
    assert receipt["rollback"] == [
        "gateway_stop",
        "privileged_stop",
        "gateway_restore",
        "privileged_restore",
        "restore_readback",
        "pointer_restore",
        "privileged_start",
        "gateway_start",
        "restore_running_readback",
    ]
    assert report["pointerSha256"] == hashlib.sha256(before).hexdigest()


def test_transaction_core_fences_fixture_mutation_after_stop_failure(tmp_path: Path) -> None:
    """stop failure면 fixture adapter도 pointer와 definition mutation을 시도하면 안 됩니다."""
    pointer = tmp_path / "fixture-selection.bin"
    before = b"fixture-pointer-unchanged\x00\xff"
    _ = pointer.write_bytes(before)
    command = r"""
. $env:HERMES_QA_TRANSACTION
function Get-FileSha256 {
    param([Parameter(Mandatory)][string]$Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($Path)))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}
$calls = [Collections.Generic.List[string]]::new()
$callback = {
    param([Parameter(Mandatory)][string]$Step)
    $calls.Add($Step)
    if ($Step -ceq 'gateway_stop') { throw 'fixture-stop-failure' }
    throw 'mutation-after-stop-must-not-run'
}
$receipt = Invoke-BridgeServiceSwitchTransaction -PreviousState safe-pair -InvokeStep $callback
[pscustomobject][ordered]@{
    receipt = $receipt
    calls = @($calls)
    pointerSha256 = Get-FileSha256 -Path $env:HERMES_QA_POINTER
} | ConvertTo-Json -Depth 12 -Compress
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_TRANSACTION": str(TRANSACTION_PATH),
                "HERMES_QA_POINTER": str(pointer),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    receipt = report["receipt"]
    assert receipt["state"] == "manual-recovery-required"
    assert receipt["failedStep"] == "gateway_stop"
    assert receipt["pointerCommitted"] is False
    assert receipt["pointerCompensated"] is False
    assert receipt["rollback"] == []
    assert report["calls"] == ["gateway_stop"]
    assert report["pointerSha256"] == hashlib.sha256(before).hexdigest()


def test_local_scm_runner_does_not_exist_before_implementation() -> None:
    """Todo9 behavior guard가 구현 전에 명시적으로 RED가 되도록 artifact를 요구합니다."""
    assert RUNNER_PATH.is_file(), "Todo9 local SCM runner is not implemented yet"


def test_local_scm_runner_plan_contract_requires_no_apply_mutation() -> None:
    """구현 후 default plan은 fresh nonce의 immutable plan만 반환해야 합니다."""
    assert RUNNER_PATH.is_file(), "Todo9 local SCM runner is not implemented yet"
    nonce = uuid.uuid4()
    command = (
        "& $env:HERMES_QA_RUNNER -LocalScmQa -Nonce $env:HERMES_QA_NONCE "
        "-SourceRoot $env:HERMES_QA_SOURCE_ROOT -DeadlineUtc $env:HERMES_QA_DEADLINE "
        "| ConvertTo-Json -Depth 20 -Compress"
    )
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(RUNNER_PATH),
                "HERMES_QA_NONCE": str(nonce),
                "HERMES_QA_SOURCE_ROOT": str(PROJECT_ROOT),
                "HERMES_QA_DEADLINE": _future_deadline(),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    assert plan["state"] == "planned"
    assert plan["applied"] is False
    assert plan["nonce"] == str(nonce)
    assert plan["scmMutations"] == 0
    assert plan["externalCalls"] == []
    assert plan["canonicalParentTouched"] is False
    assert plan["serviceNames"] == [
        f"HermesBridgeLocalQa-{nonce}-Gateway",
        f"HermesBridgeLocalQa-{nonce}-Privileged",
    ]
    assert plan["sourceInventoryBefore"] == plan["sourceInventoryAfter"]
    assert plan["sourceDigestBefore"] == plan["sourceDigestAfter"]


def test_plan_binds_canonical_host_build_inputs_and_omits_generated_outputs() -> None:
    """source pin에는 fixture가 실제 build할 host project 입력이 포함되어야 합니다."""
    assert RUNNER_PATH.is_file(), "Todo9 local SCM runner is not implemented yet"
    command = r"""
& $env:HERMES_QA_RUNNER -LocalScmQa -Nonce $env:HERMES_QA_NONCE `
    -SourceRoot $env:HERMES_QA_SOURCE_ROOT -DeadlineUtc $env:HERMES_QA_DEADLINE |
    ConvertTo-Json -Depth 20 -Compress
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(RUNNER_PATH),
                "HERMES_QA_NONCE": str(uuid.uuid4()),
                "HERMES_QA_SOURCE_ROOT": str(PROJECT_ROOT),
                "HERMES_QA_DEADLINE": _future_deadline(),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    paths = {entry["relativePath"] for entry in plan["sourceInventory"]}
    assert {
        "service-host/global.json",
        "service-host/HermesBridge.ServiceHost/HermesBridge.ServiceHost.csproj",
        "service-host/HermesBridge.ServiceHost/ScmServiceHost.cs",
        "service-host/HermesBridge.ServiceHost/ReleaseVerification.cs",
    }.issubset(paths)
    assert not any("/bin/" in path or "/obj/" in path for path in paths)


def test_preflight_rejects_stateful_unsafe_conditions_without_mutation() -> None:
    """replay·lock·source drift·hardlink·비상승은 state adapter 조회 뒤 fail-closed여야 합니다."""
    assert RUNNER_PATH.is_file(), "Todo9 local SCM runner is not implemented yet"
    command = r"""
. $env:HERMES_QA_RUNNER | Out-Null
$plan = New-LocalScmQaPlan -Nonce ([guid]$env:HERMES_QA_NONCE) `
    -SourceRoot $env:HERMES_QA_SOURCE_ROOT -DeadlineUtc $env:HERMES_QA_DEADLINE
    $states = @(
    [pscustomobject]@{ fixtureRootExists=$true; nonceReplayed=$false; lockHeld=$false; sourceDrift=$false; sourceHardlinked=$false; elevated=$true; parentAclSha256Before='a'; parentAclSha256After='a'; existingLockPreserved=$true; existingStagingPreserved=$true },
    [pscustomobject]@{ gatewayServiceExists=$true; nonceReplayed=$false; lockHeld=$false; sourceDrift=$false; sourceHardlinked=$false; elevated=$true; parentAclSha256Before='a'; parentAclSha256After='a'; existingLockPreserved=$true; existingStagingPreserved=$true },
    [pscustomobject]@{ nonceReplayed=$true; lockHeld=$false; sourceDrift=$false; sourceHardlinked=$false; elevated=$true; parentAclSha256Before='a'; parentAclSha256After='a'; existingLockPreserved=$true; existingStagingPreserved=$true },
    [pscustomobject]@{ nonceReplayed=$false; lockHeld=$true; sourceDrift=$false; sourceHardlinked=$false; elevated=$true; parentAclSha256Before='a'; parentAclSha256After='a'; existingLockPreserved=$true; existingStagingPreserved=$true },
    [pscustomobject]@{ nonceReplayed=$false; lockHeld=$false; sourceDrift=$true; sourceHardlinked=$false; elevated=$true; parentAclSha256Before='a'; parentAclSha256After='a'; existingLockPreserved=$true; existingStagingPreserved=$true },
    [pscustomobject]@{ nonceReplayed=$false; lockHeld=$false; sourceDrift=$false; sourceHardlinked=$true; elevated=$true; parentAclSha256Before='a'; parentAclSha256After='a'; existingLockPreserved=$true; existingStagingPreserved=$true },
    [pscustomobject]@{ nonceReplayed=$false; lockHeld=$false; sourceDrift=$false; sourceHardlinked=$false; elevated=$false; parentAclSha256Before='a'; parentAclSha256After='a'; existingLockPreserved=$true; existingStagingPreserved=$true }
)
$blockedPredicates = @('fixtureRootExists','gatewayServiceExists','privilegedServiceExists','nonceReplayed','lockHeld','sourceDrift','sourceUnsafe','sourceHardlinked','sourceUntrusted','canonicalParentTouched')
foreach ($state in $states) {
    foreach ($predicate in $blockedPredicates) {
        if (-not ($state.PSObject.Properties.Name -contains $predicate)) { Add-Member -InputObject $state -NotePropertyName $predicate -NotePropertyValue $false }
    }
    Add-Member -InputObject $state -NotePropertyName processIs64Bit -NotePropertyValue $true
    Add-Member -InputObject $state -NotePropertyName windowsPowerShell5 -NotePropertyValue $true
}
$adapterCalls = 0
$index = 0
$adapter = @{ GetFixtureState = {
    param($ignoredPlan)
    $script:adapterCalls++
    $selected = $states[$script:index]
    $script:index++
    return $selected
} }
$receipts = foreach ($ignored in $states) {
    Assert-LocalScmQaPreflight -Plan $plan -Adapter $adapter
}
[pscustomobject]@{ adapterCalls=$adapterCalls; receipts=@($receipts) } | ConvertTo-Json -Depth 20 -Compress
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(RUNNER_PATH),
                "HERMES_QA_NONCE": str(uuid.uuid4()),
                "HERMES_QA_SOURCE_ROOT": str(PROJECT_ROOT),
                "HERMES_QA_DEADLINE": _future_deadline(),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["adapterCalls"] == 7
    assert [receipt["state"] for receipt in report["receipts"]] == ["rejected"] * 7
    assert [receipt["reason"] for receipt in report["receipts"]] == [
        "LocalScmQafixtureRootExists",
        "LocalScmQagatewayServiceExists",
        "LocalScmQanonceReplayed",
        "LocalScmQalockHeld",
        "LocalScmQasourceDrift",
        "LocalScmQasourceHardlinked",
        "LocalScmQaElevationRequired",
    ]
    for receipt in report["receipts"]:
        assert receipt["scmMutations"] == 0
        assert receipt["externalCalls"] == []
        assert receipt["canonicalParentTouched"] is False
        assert receipt["existingLockPreserved"] is True
        assert receipt["existingStagingPreserved"] is True


def test_preflight_rejects_production_service_selector_before_adapter_call() -> None:
    """운영 service name을 넣은 manifest는 state query조차 하지 않고 거부해야 합니다."""
    assert RUNNER_PATH.is_file(), "Todo9 local SCM runner is not implemented yet"
    command = r"""
. $env:HERMES_QA_RUNNER | Out-Null
$plan = New-LocalScmQaPlan -Nonce ([guid]$env:HERMES_QA_NONCE) `
    -SourceRoot $env:HERMES_QA_SOURCE_ROOT -DeadlineUtc $env:HERMES_QA_DEADLINE
$plan.serviceNames = @('HermesBridgeGateway', 'HermesBridgePrivileged')
$adapterCalls = 0
$adapter = @{ GetFixtureState = { param($ignoredPlan) $script:adapterCalls++; throw 'must-not-query' } }
$receipt = Assert-LocalScmQaPreflight -Plan $plan -Adapter $adapter
[pscustomobject]@{ adapterCalls=$adapterCalls; receipt=$receipt } | ConvertTo-Json -Depth 12 -Compress
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(RUNNER_PATH),
                "HERMES_QA_NONCE": str(uuid.uuid4()),
                "HERMES_QA_SOURCE_ROOT": str(PROJECT_ROOT),
                "HERMES_QA_DEADLINE": _future_deadline(),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["adapterCalls"] == 0
    assert report["receipt"]["state"] == "rejected"
    assert report["receipt"]["reason"] == "LocalScmQaIdentityInvalid"
    assert report["receipt"]["scmMutations"] == 0
    assert report["receipt"]["externalCalls"] == []


def test_native_fixture_state_replays_durable_ledger_or_lock_receipt_without_io(
    tmp_path: Path,
) -> None:
    """manifest가 없어도 nonce별 ledger 또는 lock receipt는 replay로 보고되어야 합니다."""
    stub = tmp_path / "scripts"
    stub.mkdir()
    _ = (stub / "service-runtime.ps1").write_text(
        "param([switch]$LibraryMode,$SourceRoot,$ProgramRoot)\n", encoding="utf-8"
    )
    command = r"""
. $env:HERMES_QA_RUNNER | Out-Null
$script:LocalScmQaBaseRoot=Join-Path $env:HERMES_QA_TEMP_ROOT 'fixture-base'
$script:LocalScmQaProgramRoot=Join-Path $env:HERMES_QA_TEMP_ROOT 'program-root'
$plan=New-LocalScmQaPlan -Nonce ([guid]$env:HERMES_QA_NONCE) -SourceRoot $env:HERMES_QA_SOURCE_ROOT -DeadlineUtc $env:HERMES_QA_DEADLINE
$script:LocalScmQaProjectRoot=$env:HERMES_QA_STUB_ROOT
$plan.programRoot=$script:LocalScmQaProgramRoot;$plan.hostRoot=Join-Path $script:LocalScmQaProgramRoot 'hosts'
$evidenceRoot=Split-Path -Parent $env:HERMES_QA_RUNNER
$ledger=Join-Path $evidenceRoot ('run-ledger-' + $plan.nonce + '.json')
$lockReceipt=Join-Path $evidenceRoot ('run-lock-' + $plan.nonce + '.json')
function Get-CimInstance { param($ClassName,$Filter,$ErrorAction) return $null }
function Test-Path { param($LiteralPath,$PathType) return ($LiteralPath -ceq $ledger -or $LiteralPath -ceq $lockReceipt) }
function Get-LocalScmQaSourceInventory { param($SourceRoot) return @($plan.sourceInventory | Where-Object { $_.relativePath -notlike 'service-host/*' }) }
function Get-LocalScmQaHostSourceInventory { param($SourceRoot) return @($plan.sourceInventory | Where-Object { $_.relativePath -like 'service-host/*' }) }
function Test-LocalScmQaReparseFree { param($Root,$Path) return $true }
function Get-BridgeFileLinkCount { param($Path) return 1 }
function Get-LocalScmQaAclSha256 { param($Path) return 'acl' }
$state=Get-LocalScmQaNativeFixtureState -Plan $plan
[pscustomobject]@{nonceReplayed=$state.nonceReplayed;fixtureRootExists=$state.fixtureRootExists;lockHeld=$state.lockHeld;sourceUnsafe=$state.sourceUnsafe;sourceDrift=$state.sourceDrift}|ConvertTo-Json -Compress
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(RUNNER_PATH),
                "HERMES_QA_TEMP_ROOT": str(tmp_path),
                "HERMES_QA_STUB_ROOT": str(tmp_path),
                "HERMES_QA_NONCE": str(uuid.uuid4()),
                "HERMES_QA_SOURCE_ROOT": str(PROJECT_ROOT),
                "HERMES_QA_DEADLINE": _future_deadline(),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["nonceReplayed"] is True
    assert report["fixtureRootExists"] is False
    assert report["lockHeld"] is False
    assert report["sourceUnsafe"] is False
    assert report["sourceDrift"] is False


def test_cleanup_rejects_foreign_path_even_when_service_names_match() -> None:
    """cleanup selector는 nonce 이름만으로 fixture root를 넓히면 안 됩니다."""
    assert RUNNER_PATH.is_file(), "Todo9 local SCM runner is not implemented yet"
    command = r"""
. $env:HERMES_QA_RUNNER | Out-Null
$plan = New-LocalScmQaPlan -Nonce ([guid]$env:HERMES_QA_NONCE) `
    -SourceRoot $env:HERMES_QA_SOURCE_ROOT -DeadlineUtc $env:HERMES_QA_DEADLINE
$plan.fixtureRoot = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'HermesBridgeLocalScmQa\foreign'
Complete-LocalScmQaCleanup -Manifest $plan | ConvertTo-Json -Depth 12 -Compress
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(RUNNER_PATH),
                "HERMES_QA_NONCE": str(uuid.uuid4()),
                "HERMES_QA_SOURCE_ROOT": str(PROJECT_ROOT),
                "HERMES_QA_DEADLINE": _future_deadline(),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["state"] == "rejected"
    assert receipt["reason"] == "LocalScmQaCleanupSelectorRejected"
    assert receipt["scmMutations"] == 0
    assert receipt["externalCalls"] == []


def test_plan_rejects_expired_deadline_and_alternative_source_without_adapter() -> None:
    """deadline·source identity 거부는 inventory나 external adapter 전에 끝나야 합니다."""
    assert RUNNER_PATH.is_file(), "Todo9 local SCM runner is not implemented yet"
    command = r"""
. $env:HERMES_QA_RUNNER | Out-Null
$expired = New-LocalScmQaPlan -Nonce ([guid]$env:HERMES_QA_NONCE) `
    -SourceRoot $env:HERMES_QA_SOURCE_ROOT -DeadlineUtc '2000-01-01T00:00:00Z'
$alternative = New-LocalScmQaPlan -Nonce ([guid]$env:HERMES_QA_NONCE) `
    -SourceRoot $env:HERMES_QA_ALTERNATIVE_SOURCE_ROOT -DeadlineUtc $env:HERMES_QA_DEADLINE
[pscustomobject]@{ expired=$expired; alternative=$alternative } | ConvertTo-Json -Depth 12 -Compress
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(RUNNER_PATH),
                "HERMES_QA_NONCE": str(uuid.uuid4()),
                "HERMES_QA_SOURCE_ROOT": str(PROJECT_ROOT),
                "HERMES_QA_ALTERNATIVE_SOURCE_ROOT": str(PROJECT_ROOT / "tests"),
                "HERMES_QA_DEADLINE": _future_deadline(),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert [report[key]["reason"] for key in ("expired", "alternative")] == [
        "LocalScmQaDeadlineInvalid",
        "LocalScmQaAlternativeSourceRootRejected",
    ]
    for key in ("expired", "alternative"):
        assert report[key]["state"] == "rejected"
        assert report[key]["scmMutations"] == 0
        assert report[key]["externalCalls"] == []


def test_plan_declares_protected_invalid_anchor_probe_separate_from_workspace() -> None:
    """Todo10의 pre-child rejection probe는 workspace binary를 서비스로 쓰면 안 됩니다."""
    assert RUNNER_PATH.is_file(), "Todo9 local SCM runner is not implemented yet"
    command = r"""
& $env:HERMES_QA_RUNNER -LocalScmQa -Nonce $env:HERMES_QA_NONCE `
    -SourceRoot $env:HERMES_QA_SOURCE_ROOT -DeadlineUtc $env:HERMES_QA_DEADLINE |
    ConvertTo-Json -Depth 20 -Compress
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(RUNNER_PATH),
                "HERMES_QA_NONCE": str(uuid.uuid4()),
                "HERMES_QA_SOURCE_ROOT": str(PROJECT_ROOT),
                "HERMES_QA_DEADLINE": _future_deadline(),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    probe = plan["invalidAnchorProbe"]
    probe_path = Path(probe["hostPath"])
    assert probe["requiresProtectedHost"] is True
    assert probe["candidateExecutionForbidden"] is True
    assert str(probe_path).lower().startswith(plan["hostRoot"].lower())
    assert not str(probe_path).lower().startswith(plan["fixtureWorkspace"].lower())


def test_native_boundary_contract_is_present_before_apply_wiring() -> None:
    """Apply orchestration은 SCM native boundary가 없으면 complete로 보이면 안 됩니다."""
    assert NATIVE_PATH.is_file(), "Todo9 native SCM boundary is not implemented yet"


def test_preservation_inventory_accepts_empty_owned_path_exclusions(tmp_path: Path) -> None:
    """첫 baseline은 아직 owned release/host path가 없어도 inventory를 만들 수 있어야 합니다."""
    assert PRESERVATION_PATH.is_file(), "Todo9 preservation helper is not implemented yet"
    command = r"""
. $env:HERMES_QA_PRESERVATION
$inventory = @(Get-LocalScmPreservationCanonicalInventory -Root $env:HERMES_QA_EMPTY_ROOT -ExcludedRoots @())
[pscustomobject]@{ count=$inventory.Count } | ConvertTo-Json -Compress
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_PRESERVATION": str(PRESERVATION_PATH),
                "HERMES_QA_EMPTY_ROOT": str(tmp_path),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["count"] == 0


def test_preservation_accepts_actual_builder_staging_name_shapes() -> None:
    """runtime 32-hex staging과 host `.staging-32hex`는 cleanup intent로 유효해야 합니다."""
    assert PRESERVATION_PATH.is_file()
    command = r"""
. $env:HERMES_QA_PRESERVATION
$nonce=[guid]::NewGuid(); $pf=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'HermesWindowsBridge'; $base=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'HermesBridgeLocalScmQa'
$release=Join-Path (Join-Path $pf 'releases') ('a'*64); $runtimeStage=Join-Path (Join-Path $pf 'staging') ('b'*32); $hostStage=Join-Path (Join-Path $pf 'hosts') ('.staging-' + ('c'*32))
$m=[pscustomobject]@{nonce=$nonce.ToString();fixtureBaseRoot=$base;fixtureRoot=(Join-Path $base $nonce.ToString());fixtureBaseOwned=$false;ownedCleanupRoots=@([pscustomobject]@{path=$release;category='release';absentBefore=$true;created=$true},[pscustomobject]@{path=$runtimeStage;category='staging';absentBefore=$true;created=$true},[pscustomobject]@{path=$hostStage;category='staging';absentBefore=$true;created=$true})}
@(Get-LocalScmPreservationOwnedCleanupPaths -Manifest $m -ProgramFilesRoot $pf).Count
"""
    result = _run_powershell(command, environment=_powershell_environment({"HERMES_QA_PRESERVATION": str(PRESERVATION_PATH)}))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "3"


def test_preservation_rejects_foreign_cleanup_root_before_any_delete(tmp_path: Path) -> None:
    """foreign manifest cleanup root는 native receipt나 deletion 전에 fail-closed여야 합니다."""
    assert PRESERVATION_PATH.is_file()
    command = r"""
. $env:HERMES_QA_PRESERVATION
$m=[pscustomobject]@{fixtureRoot=$env:HERMES_QA_FOREIGN;fixtureBaseRoot=$env:HERMES_QA_FOREIGN;nonce=([guid]::NewGuid()).ToString();ownedCleanupRoots=@();fixtureBaseOwned=$false}
Invoke-LocalScmQaOwnedFileCleanup -Manifest $m -NativeCleanupReceiptPath $env:HERMES_QA_NATIVE_RECEIPT -ProgramFilesRoot $env:HERMES_QA_FOREIGN -PreservationRoot $env:HERMES_QA_PRESERVE | ConvertTo-Json -Compress
"""
    receipt = tmp_path / "native.json"
    _ = receipt.write_text("{}", encoding="utf-8")
    preserve = tmp_path / "preserve"
    preserve.mkdir()
    result = _run_powershell(command, environment=_powershell_environment({"HERMES_QA_PRESERVATION": str(PRESERVATION_PATH), "HERMES_QA_FOREIGN": str(tmp_path / "foreign"), "HERMES_QA_NATIVE_RECEIPT": str(receipt), "HERMES_QA_PRESERVE": str(preserve)}))
    assert result.returncode == 0, result.stderr
    cleanup = json.loads(result.stdout)
    assert cleanup["state"] == "partial"
    assert cleanup["reconciliationRequired"] is True
    assert cleanup["deletedPathSha256"] == []


def test_persist_manifest_round_trip_keeps_later_mutable_schema_without_writes(tmp_path: Path) -> None:
    """actual Persist body는 protected creator mock 아래에서 complete mutable schema를 저장해야 합니다."""
    runner = RUNNER_PATH
    stub = tmp_path / "scripts"
    stub.mkdir()
    _ = (stub / "service-runtime.ps1").write_text(
        "param([switch]$LibraryMode,$SourceRoot,$ProgramRoot)\n", encoding="utf-8"
    )
    command = r"""
. $env:HERMES_QA_RUNNER | Out-Null
$script:LocalScmQaProjectRoot=$env:HERMES_QA_STUB_ROOT
$known=[Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$base=Join-Path $env:HERMES_QA_STUB_ROOT 'fixture-base';$nonce=([guid]::NewGuid()).ToString();$fixture=Join-Path $base $nonce;$pointerState=Join-Path $fixture 'state';$pointer=Join-Path $pointerState 'pointer'
[void][IO.Directory]::CreateDirectory($base)
function Test-Path { param([string]$LiteralPath,[string]$PathType) if($LiteralPath -ceq $base){return $true};if($LiteralPath -in @($fixture,$pointerState,$pointer)){return $false};throw "unexpected:$LiteralPath" }
function Test-LocalScmQaReparseFree { param($Root,$Path) if($Path -in @($known,$base,$fixture,$pointerState,$pointer)){return $true};throw "unexpected:$Path" }
function Test-BridgeTreeAcl { param($Path,$RequireTrustedOwner) return $null }
function New-BridgeProtectedDirectory { param($Path) $script:created+=@($Path);[void][IO.Directory]::CreateDirectory($Path) }
function Get-LocalScmQaAclSha256 { param($Path) 'a' }
function Write-LocalScmQaManifest { param($Manifest) $script:captured=$Manifest|ConvertTo-Json -Depth 20 -Compress }
$script:created=@();$script:captured=$null
$p=[pscustomobject]@{fixtureRoot=$fixture;fixtureBaseRoot=$base;fixtureWorkspace=(Join-Path $fixture 'source');manifestPath=(Join-Path $fixture 'manifest.json');nonce=$nonce;serviceNames=@("HermesBridgeLocalQa-$nonce-Gateway","HermesBridgeLocalQa-$nonce-Privileged");serviceAccounts=@('a','b');immutableContext=@{};sourceRoot='C:\source';sourceDigest='d';sourceInventory=@();deadlineUtc='2030-01-01T00:00:00Z';fixtureChildPatchSha256ByMode=@{};runnerSha256='r';nativeHelperPath='n';nativeHelperSha256='n';preservationHelperPath='p';preservationHelperSha256='p';fixtureOwnedPaths=@($fixture);fixturePointerPath=$pointer;fixtureChildPath='x';invalidAnchorProbe=[pscustomobject]@{candidateReleaseRoot=$null;candidateChildExecutablePath=$null;basePythonExecutablePath=$null;sourceHostRoot=$null};programRoot='C:\Program Files\HermesWindowsBridge'}
$m=Invoke-LocalScmQaPersistOwnershipIntent -Plan $p -ApplyAuthorized
$round=$m|ConvertTo-Json -Depth 20|ConvertFrom-Json
$round.runtimeBuildLock=[pscustomobject]@{};$round.scenarioContracts=[pscustomobject]@{};$round.trustedUvPath='u';$round.trustedDotnetPath='d';$round.nativeMutationJournal=@();$round.productionPreservationSummary=[pscustomobject]@{};$round.invalidAnchorProbe.candidateReleaseRoot='r';$round.invalidAnchorProbe.basePythonExecutablePath='b'
[pscustomobject]@{created=@($script:created);captured=($null -ne $script:captured);pointerSeed=$round.fixturePointerSeed;ok=($null -ne $round.invalidAnchorProbe)}|ConvertTo-Json -Compress
"""
    result = _run_powershell(command, environment=_powershell_environment({"HERMES_QA_RUNNER": str(runner), "HERMES_QA_STUB_ROOT": str(tmp_path)}))
    assert result.returncode == 0, result.stderr
    report=json.loads(result.stdout)
    assert len(report["created"]) == 2
    assert report["captured"] is True
    assert report["ok"] is True
    assert report["pointerSeed"]["created"] is True
    assert report["pointerSeed"]["length"] > 0


def test_apply_uses_only_explicit_stateful_adapter_sequence(tmp_path: Path) -> None:
    """full Apply orchestration은 disposable adapter boundary에서만 순서대로 진행해야 합니다."""
    assert RUNNER_PATH.is_file(), "Todo9 local SCM runner is not implemented yet"
    command = r"""
. $env:HERMES_QA_RUNNER | Out-Null
$script:LocalScmQaBaseRoot = Join-Path $env:HERMES_QA_TEMP_ROOT 'fixture-base'
$script:LocalScmQaProgramRoot = Join-Path $env:HERMES_QA_TEMP_ROOT 'program-root'
[void][IO.Directory]::CreateDirectory($script:LocalScmQaBaseRoot)
[void][IO.Directory]::CreateDirectory((Join-Path $script:LocalScmQaProgramRoot 'releases'))
[void][IO.Directory]::CreateDirectory((Join-Path $script:LocalScmQaProgramRoot 'hosts'))
$plan = New-LocalScmQaPlan -Nonce ([guid]$env:HERMES_QA_NONCE) `
    -SourceRoot $env:HERMES_QA_SOURCE_ROOT -DeadlineUtc $env:HERMES_QA_DEADLINE
$calls = [Collections.Generic.List[string]]::new()
$adapter = @{
    GetFixtureState = { param($ignored) [pscustomobject]@{ fixtureRootExists=$false;gatewayServiceExists=$false;privilegedServiceExists=$false;nonceReplayed=$false;lockHeld=$false;sourceDrift=$false;sourceUnsafe=$false;sourceHardlinked=$false;sourceUntrusted=$false;canonicalParentTouched=$false;elevated=$true;processIs64Bit=$true;windowsPowerShell5=$true;parentAclSha256Before='a';parentAclSha256After='a';existingLockPreserved=$true;existingStagingPreserved=$true } }
    PersistOwnershipIntent = { param($providedPlan) [void]$calls.Add('persist'); [void][IO.Directory]::CreateDirectory($providedPlan.fixtureRoot); [pscustomobject]@{ nonce=$providedPlan.nonce; manifestPath=$providedPlan.manifestPath; fixtureRoot=$providedPlan.fixtureRoot; serviceNames=@($providedPlan.serviceNames); fixtureOwnedPaths=@($providedPlan.fixtureRoot); ownershipIntent=@([pscustomobject]@{path=$providedPlan.fixtureRoot;absentBefore=$true;created=$true}); releaseRoot=@(); hostDigestRoots=@(); scenarioContracts=[pscustomobject]@{healthy=[pscustomobject]@{hosts=@()}}; fixtureBaseOwned=$false } }
    AcquireFixtureLock = { param($manifest) [void]$calls.Add('lock'); [pscustomobject]@{ acquired=$true; manifest=$manifest } }
    BuildFixtureArtifacts = { param($manifest) [void]$calls.Add('build'); [pscustomobject]@{ state='built'; manifest=$manifest } }
    RunInvalidAnchorProbe = { param($ignoredManifest,$ignoredHosts) [void]$calls.Add('probe'); [pscustomobject]@{ scmMutations=1; state='completed'; gatewayRemoved=$true } }
    ComparePreservationBaseline = { param($ignoredManifest,$phase) [void]$calls.Add("baseline:$phase"); [pscustomobject]@{ equal=$true } }
    RegisterFixtureServices = { param($ignoredManifest,$ignoredHosts) [void]$calls.Add('register'); [pscustomobject]@{ scmMutations=2 } }
    RunLifecycleScenarios = { param($ignoredManifest,$ignoredRegistration) [void]$calls.Add('scenarios'); [pscustomobject]@{ scmMutations=4; state='completed'; partial=$false } }
    CleanupFixture = { param($ignoredManifest) [void]$calls.Add('cleanup'); [pscustomobject]@{ state='completed'; reconciliationRequired=$false; native=[pscustomobject]@{state='completed';reconciliationRequired=$false}; files=[pscustomobject]@{state='completed';reconciliationRequired=$false} } }
    ReleaseFixtureLock = { param($lock) [void]$calls.Add('unlock'); [pscustomobject]@{ released=$true; emptyOwnedFixtureBaseRemoved=$false } }
}
$receipt = Invoke-LocalScmQaApply -Plan $plan -Adapter $adapter
[pscustomobject]@{ calls=@($calls); receipt=$receipt } | ConvertTo-Json -Depth 20 -Compress
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(RUNNER_PATH),
                "HERMES_QA_TEMP_ROOT": str(tmp_path),
                "HERMES_QA_NONCE": str(uuid.uuid4()),
                "HERMES_QA_SOURCE_ROOT": str(PROJECT_ROOT),
                "HERMES_QA_DEADLINE": _future_deadline(),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["calls"] == [
        "persist", "lock", "build", "probe", "baseline:after-invalid-anchor-probe", "register", "scenarios", "baseline:after-lifecycle", "cleanup", "baseline:after-cleanup", "unlock"
    ], json.dumps(report, indent=2)
    assert report["receipt"]["state"] == "completed"
    assert report["receipt"]["scmMutations"] == 7
    assert report["receipt"]["cleanup"]["state"] == "completed"


def test_apply_preserves_failure_receipts_when_fixture_lock_release_is_partial(
    tmp_path: Path,
) -> None:
    """cleanup 또는 lock-base release가 실패해도 원래 apply 결과를 구조화해 반환해야 합니다."""
    command = r"""
. $env:HERMES_QA_RUNNER | Out-Null
$script:LocalScmQaBaseRoot = Join-Path $env:HERMES_QA_TEMP_ROOT 'fixture-base'
$script:LocalScmQaProgramRoot = Join-Path $env:HERMES_QA_TEMP_ROOT 'program-root'
[void][IO.Directory]::CreateDirectory($script:LocalScmQaBaseRoot)
[void][IO.Directory]::CreateDirectory((Join-Path $script:LocalScmQaProgramRoot 'releases'))
[void][IO.Directory]::CreateDirectory((Join-Path $script:LocalScmQaProgramRoot 'hosts'))
$plan = New-LocalScmQaPlan -Nonce ([guid]$env:HERMES_QA_NONCE) -SourceRoot $env:HERMES_QA_SOURCE_ROOT -DeadlineUtc $env:HERMES_QA_DEADLINE
function New-ReleaseFailureAdapter {
    param([Parameter(Mandatory)][ValidateSet('prior-failure','nominal-success')][string]$Mode)
    @{
        GetFixtureState = { param($ignored) [pscustomobject]@{ fixtureRootExists=$false;gatewayServiceExists=$false;privilegedServiceExists=$false;nonceReplayed=$false;lockHeld=$false;sourceDrift=$false;sourceUnsafe=$false;sourceHardlinked=$false;sourceUntrusted=$false;canonicalParentTouched=$false;elevated=$true;processIs64Bit=$true;windowsPowerShell5=$true;parentAclSha256Before='a';parentAclSha256After='a';existingLockPreserved=$true;existingStagingPreserved=$true } }
        PersistOwnershipIntent = { param($providedPlan) [pscustomobject]@{ nonce=$providedPlan.nonce;manifestPath=$providedPlan.manifestPath;fixtureRoot=$providedPlan.fixtureRoot;serviceNames=@($providedPlan.serviceNames);fixtureOwnedPaths=@($providedPlan.fixtureRoot);ownershipIntent=@([pscustomobject]@{path=$providedPlan.fixtureRoot;absentBefore=$true;created=$true});releaseRoot=@();hostDigestRoots=@();scenarioContracts=[pscustomobject]@{healthy=[pscustomobject]@{hosts=@()}};fixtureBaseOwned=$true;createdServices=@();nativeMutationJournal=@() } }
        AcquireFixtureLock = { param($manifest) [pscustomobject]@{acquired=$true;manifest=$manifest} }
        BuildFixtureArtifacts = { param($manifest) if($Mode -ceq 'prior-failure'){return [pscustomobject]@{state='failed';manifest=$manifest}};[pscustomobject]@{state='built';manifest=$manifest} }
        ComparePreservationBaseline = { param($manifest,$checkpoint) [pscustomobject]@{equal=$true;checkpoint=$checkpoint} }
        CleanupFixture = { param($manifest) if($Mode -ceq 'prior-failure'){return [pscustomobject]@{state='partial';reconciliationRequired=$true;native=[pscustomobject]@{state='partial';reconciliationRequired=$true};files=[pscustomobject]@{state='partial';reconciliationRequired=$true}}};[pscustomobject]@{state='completed';reconciliationRequired=$false;native=[pscustomobject]@{state='completed';reconciliationRequired=$false;scmMutations=0};files=[pscustomobject]@{state='completed';reconciliationRequired=$false}} }
        ReleaseFixtureLock = { param($lock) [pscustomobject]@{released=$true;emptyOwnedFixtureBaseRemoved=$false} }
        RunInvalidAnchorProbe = { throw 'must-not-probe' }
        RegisterFixtureServices = { throw 'must-not-register' }
        RunLifecycleScenarios = { throw 'must-not-scenarios' }
    }
}
function Invoke-ReleaseFailureCase {
    param([Parameter(Mandatory)][string]$Mode)
    try { return [pscustomobject]@{threw=$false;receipt=(Invoke-LocalScmQaApply -Plan $plan -Adapter (New-ReleaseFailureAdapter -Mode $Mode) -BuildOnly)} }
    catch { return [pscustomobject]@{threw=$true;message=$_.Exception.Message} }
}
[pscustomobject]@{priorFailure=(Invoke-ReleaseFailureCase -Mode 'prior-failure');nominalSuccess=(Invoke-ReleaseFailureCase -Mode 'nominal-success')} | ConvertTo-Json -Depth 20 -Compress
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(RUNNER_PATH),
                "HERMES_QA_TEMP_ROOT": str(tmp_path),
                "HERMES_QA_NONCE": str(uuid.uuid4()),
                "HERMES_QA_SOURCE_ROOT": str(PROJECT_ROOT),
                "HERMES_QA_DEADLINE": _future_deadline(),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    prior_failure = report["priorFailure"]
    assert prior_failure["threw"] is False
    assert prior_failure["receipt"]["state"] == "failed"
    assert prior_failure["receipt"]["phase"] == "build-fixture-artifacts"
    assert "LocalScmQaFixtureArtifactsUnverified" in prior_failure["receipt"]["reason"]
    assert prior_failure["receipt"]["cleanup"]["state"] == "partial"
    assert prior_failure["receipt"]["lockRelease"]["reconciliationRequired"] is True
    assert prior_failure["receipt"]["reconciliationRequired"] is True
    nominal_success = report["nominalSuccess"]
    assert nominal_success["threw"] is False
    assert nominal_success["receipt"]["state"] == "failed"
    assert nominal_success["receipt"]["phase"] == "release-fixture-lock"
    assert nominal_success["receipt"]["reason"] == "LocalScmQaOwnedFixtureBaseCleanupUnverified"
    assert nominal_success["receipt"]["cleanup"]["state"] == "completed"
    assert nominal_success["receipt"]["lockRelease"]["reconciliationRequired"] is True
    assert nominal_success["receipt"]["reconciliationRequired"] is True


def test_apply_failure_counts_valid_durable_journal_without_merging_cleanup_mutations(
    tmp_path: Path,
) -> None:
    """실패 receipt는 검증된 journal의 applied 수를 쓰고 cleanup native 수와 합치지 않아야 한다."""
    command = r"""
. $env:HERMES_QA_RUNNER | Out-Null
$script:LocalScmQaBaseRoot = Join-Path $env:HERMES_QA_TEMP_ROOT 'fixture-base'
$script:LocalScmQaProgramRoot = Join-Path $env:HERMES_QA_TEMP_ROOT 'program-root'
[void][IO.Directory]::CreateDirectory($script:LocalScmQaBaseRoot)
[void][IO.Directory]::CreateDirectory((Join-Path $script:LocalScmQaProgramRoot 'releases'))
[void][IO.Directory]::CreateDirectory((Join-Path $script:LocalScmQaProgramRoot 'hosts'))
$plan = New-LocalScmQaPlan -Nonce ([guid]$env:HERMES_QA_NONCE) -SourceRoot $env:HERMES_QA_SOURCE_ROOT -DeadlineUtc $env:HERMES_QA_DEADLINE
function Write-TestManifest {
    param([Parameter(Mandatory)]$Manifest)
    [IO.File]::WriteAllText($Manifest.manifestPath, ($Manifest | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
}
function New-MutationCountAdapter {
    param([Parameter(Mandatory)][ValidateSet('durable','unavailable')][string]$Mode)
    @{
        GetFixtureState = { param($ignored) [pscustomobject]@{ fixtureRootExists=$false;gatewayServiceExists=$false;privilegedServiceExists=$false;nonceReplayed=$false;lockHeld=$false;sourceDrift=$false;sourceUnsafe=$false;sourceHardlinked=$false;sourceUntrusted=$false;canonicalParentTouched=$false;elevated=$true;processIs64Bit=$true;windowsPowerShell5=$true;parentAclSha256Before='a';parentAclSha256After='a';existingLockPreserved=$true;existingStagingPreserved=$true } }
        PersistOwnershipIntent = {
            param($providedPlan)
            [void][IO.Directory]::CreateDirectory($providedPlan.fixtureRoot)
            $manifest = [pscustomobject]@{
                nonce=$providedPlan.nonce;manifestPath=$providedPlan.manifestPath;fixtureRoot=$providedPlan.fixtureRoot;sourceRoot=$providedPlan.sourceRoot
                immutableContext=$providedPlan.immutableContext;serviceNames=@($providedPlan.serviceNames);fixtureOwnedPaths=@($providedPlan.fixtureRoot)
                ownershipIntent=@([pscustomobject]@{path=$providedPlan.fixtureRoot;absentBefore=$true;created=$true});releaseRoot=@();hostDigestRoots=@()
                scenarioContracts=[pscustomobject]@{healthy=[pscustomobject]@{hosts=@()}};fixtureBaseOwned=$false;createdServices=@();nativeMutationJournal=@()
            }
            Write-TestManifest -Manifest $manifest
            return $manifest
        }
        AcquireFixtureLock = { param($manifest) [pscustomobject]@{acquired=$true;manifest=$manifest} }
        BuildFixtureArtifacts = { param($manifest) [pscustomobject]@{state='built';manifest=$manifest} }
        RunInvalidAnchorProbe = {
            param($manifest,$hosts)
            [pscustomobject]@{scmMutations=if($Mode -ceq 'durable'){0}else{1};state='completed';gatewayRemoved=$true}
        }
        ComparePreservationBaseline = { param($manifest,$checkpoint) [pscustomobject]@{equal=$true;checkpoint=$checkpoint} }
        RegisterFixtureServices = {
            param($manifest,$hosts)
            [pscustomobject]@{scmMutations=if($Mode -ceq 'durable'){0}else{1}}
        }
        RunLifecycleScenarios = {
            param($manifest,$registration)
            $manifest.nativeMutationJournal = @(
                [pscustomobject]@{action='create';state='applied';serviceName='fixture-gateway'},
                [pscustomobject]@{action='start';state='unknown';serviceName='fixture-gateway'},
                [pscustomobject]@{action='delete';state='applied';serviceName='fixture-gateway'}
            )
            Write-TestManifest -Manifest $manifest
            if ($Mode -ceq 'unavailable') { Remove-Item -LiteralPath $manifest.manifestPath -Force }
            throw [InvalidOperationException]::new('LocalScmNativeHealthyChildObservationMissing')
        }
        CleanupFixture = {
            param($manifest)
            [pscustomobject]@{
                state='completed';reconciliationRequired=$false
                native=[pscustomobject]@{state='completed';reconciliationRequired=$false;scmMutations=2}
                files=[pscustomobject]@{state='completed';reconciliationRequired=$false}
            }
        }
        ReleaseFixtureLock = { param($lock) [pscustomobject]@{released=$true;emptyOwnedFixtureBaseRemoved=$false} }
    }
}
function Invoke-MutationCountCase {
    param([Parameter(Mandatory)][string]$Mode)
    Invoke-LocalScmQaApply -Plan $plan -Adapter (New-MutationCountAdapter -Mode $Mode)
}
[pscustomobject]@{durable=(Invoke-MutationCountCase -Mode 'durable');unavailable=(Invoke-MutationCountCase -Mode 'unavailable')} | ConvertTo-Json -Depth 20 -Compress
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(RUNNER_PATH),
                "HERMES_QA_TEMP_ROOT": str(tmp_path),
                "HERMES_QA_NONCE": str(uuid.uuid4()),
                "HERMES_QA_SOURCE_ROOT": str(PROJECT_ROOT),
                "HERMES_QA_DEADLINE": _future_deadline(),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    durable = report["durable"]
    assert durable["state"] == "failed"
    assert durable["phase"] == "lifecycle-scenarios"
    assert durable["reason"] == "LocalScmNativeHealthyChildObservationMissing"
    assert durable["scmMutations"] == 2
    assert durable["scmMutationsConfirmed"] == 2
    assert durable["scmMutationAttemptCount"] == 3
    assert [entry["state"] for entry in durable["scmMutationJournal"]] == [
        "applied",
        "unknown",
        "applied",
    ]
    assert durable["cleanup"]["native"]["scmMutations"] == 2
    assert durable["cleanup"]["state"] == "completed"
    unavailable = report["unavailable"]
    assert unavailable["state"] == "failed"
    assert unavailable["phase"] == "lifecycle-scenarios"
    assert unavailable["reason"] == "LocalScmNativeHealthyChildObservationMissing"
    assert unavailable["scmMutations"] == 2
    assert unavailable["scmMutationsConfirmed"] == 2
    assert unavailable["scmMutationAttemptCount"] == 0
    assert unavailable["scmMutationJournal"] == []
    assert unavailable["cleanup"]["native"]["scmMutations"] == 2


def test_build_only_runs_artifact_and_preservation_flow_without_scm_callbacks(
    tmp_path: Path,
) -> None:
    """BuildOnly는 build·보존·cleanup만 수행하고 SCM adapter를 조회조차 하지 않아야 합니다."""
    command = r"""
. $env:HERMES_QA_RUNNER | Out-Null
$script:LocalScmQaBaseRoot = Join-Path $env:HERMES_QA_TEMP_ROOT 'fixture-base'
$script:LocalScmQaProgramRoot = Join-Path $env:HERMES_QA_TEMP_ROOT 'program-root'
[void][IO.Directory]::CreateDirectory($script:LocalScmQaBaseRoot)
[void][IO.Directory]::CreateDirectory((Join-Path $script:LocalScmQaProgramRoot 'releases'))
[void][IO.Directory]::CreateDirectory((Join-Path $script:LocalScmQaProgramRoot 'hosts'))
$plan = New-LocalScmQaPlan -Nonce ([guid]$env:HERMES_QA_NONCE) -SourceRoot $env:HERMES_QA_SOURCE_ROOT -DeadlineUtc $env:HERMES_QA_DEADLINE
function Invoke-BuildOnlyCase {
    param([Parameter(Mandatory)][string]$Mode)
    $script:calls = [Collections.Generic.List[string]]::new()
    $adapter = @{
        GetFixtureState = { param($ignored) [pscustomobject]@{ fixtureRootExists=$false;gatewayServiceExists=$false;privilegedServiceExists=$false;nonceReplayed=$false;lockHeld=$false;sourceDrift=$false;sourceUnsafe=$false;sourceHardlinked=$false;sourceUntrusted=$false;canonicalParentTouched=$false;elevated=$true;processIs64Bit=$true;windowsPowerShell5=$true;parentAclSha256Before='a';parentAclSha256After='a';existingLockPreserved=$true;existingStagingPreserved=$true } }
        PersistOwnershipIntent = { param($providedPlan) [void]$script:calls.Add('persist'); [pscustomobject]@{ nonce=$providedPlan.nonce;manifestPath=$providedPlan.manifestPath;fixtureRoot=$providedPlan.fixtureRoot;serviceNames=@($providedPlan.serviceNames);fixtureOwnedPaths=@($providedPlan.fixtureRoot);ownershipIntent=@([pscustomobject]@{path=$providedPlan.fixtureRoot;absentBefore=$true;created=$true});releaseRoot=@();hostDigestRoots=@();scenarioContracts=[pscustomobject]@{healthy=[pscustomobject]@{hosts=@()}};fixtureBaseOwned=$false;createdServices=@();nativeMutationJournal=@() } }
        AcquireFixtureLock = { param($manifest) [void]$script:calls.Add('lock'); [pscustomobject]@{acquired=$true;manifest=$manifest} }
        BuildFixtureArtifacts = { param($manifest) [void]$script:calls.Add('build'); if($Mode -ceq 'build-failure'){return [pscustomobject]@{state='failed';manifest=$manifest}}; return [pscustomobject]@{state='built';manifest=$manifest} }
        ComparePreservationBaseline = { param($manifest,$checkpoint) [void]$script:calls.Add("baseline:$checkpoint"); if($Mode -ceq 'compare-failure'){return [pscustomobject]@{equal=$false}};return [pscustomobject]@{equal=$true} }
        CleanupFixture = { param($manifest) [void]$script:calls.Add('cleanup'); if($Mode -ceq 'cleanup-failure'){return [pscustomobject]@{state='partial';reconciliationRequired=$true;native=$null;files=$null}};return [pscustomobject]@{state='completed';reconciliationRequired=$false;native=[pscustomobject]@{state='completed';reconciliationRequired=$false;scmMutations=0};files=[pscustomobject]@{state='completed';reconciliationRequired=$false}} }
        ReleaseFixtureLock = { param($lock) [void]$script:calls.Add('unlock'); [pscustomobject]@{released=$true;emptyOwnedFixtureBaseRemoved=$false} }
        RunInvalidAnchorProbe = { throw 'SCM callback must not be looked up: probe' }
        RegisterFixtureServices = { throw 'SCM callback must not be looked up: register' }
        RunLifecycleScenarios = { throw 'SCM callback must not be looked up: scenarios' }
    }
    $receipt = Invoke-LocalScmQaApply -Plan $plan -Adapter $adapter -BuildOnly
    return [pscustomobject]@{receipt=$receipt;calls=@($script:calls)}
}
[pscustomobject]@{success=(Invoke-BuildOnlyCase -Mode 'success');buildFailure=(Invoke-BuildOnlyCase -Mode 'build-failure');compareFailure=(Invoke-BuildOnlyCase -Mode 'compare-failure');cleanupFailure=(Invoke-BuildOnlyCase -Mode 'cleanup-failure')} | ConvertTo-Json -Depth 20 -Compress
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(RUNNER_PATH),
                "HERMES_QA_TEMP_ROOT": str(tmp_path),
                "HERMES_QA_NONCE": str(uuid.uuid4()),
                "HERMES_QA_SOURCE_ROOT": str(PROJECT_ROOT),
                "HERMES_QA_DEADLINE": _future_deadline(),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    success = report["success"]
    assert success["calls"] == [
        "persist",
        "lock",
        "build",
        "baseline:after-build-only",
        "cleanup",
        "baseline:after-build-only-cleanup",
        "unlock",
    ]
    assert success["receipt"]["state"] == "completed"
    assert success["receipt"]["verificationScope"] == "build-only"
    assert success["receipt"]["actualScmVerified"] is False
    assert success["receipt"]["scmMutations"] == 0
    failure_reasons = {
        "buildFailure": "LocalScmQaFixtureArtifactsUnverified",
        "compareFailure": "LocalScmQaProductionBaselineChangedAfterBuildOnly",
        "cleanupFailure": "LocalScmQaBuildOnlyCleanupUnverified",
    }
    for failure_name, expected_reason in failure_reasons.items():
        failure = report[failure_name]
        assert failure["receipt"]["state"] == "failed"
        assert expected_reason in failure["receipt"]["reason"]
        assert failure["receipt"]["scmMutations"] == 0
        assert not any(
            call in {"probe", "register", "scenarios"} for call in failure["calls"]
        )


def test_apply_marks_fresh_fixture_unverified_when_persist_fails_before_durability(
    tmp_path: Path,
) -> None:
    """durable manifest가 없으면 cleanup adapter가 새 fixture를 지우지 않아야 합니다."""
    command = r"""
. $env:HERMES_QA_RUNNER | Out-Null
$script:LocalScmQaBaseRoot = Join-Path $env:HERMES_QA_TEMP_ROOT 'fixture-base'
$script:LocalScmQaProgramRoot = Join-Path $env:HERMES_QA_TEMP_ROOT 'program-root'
[void][IO.Directory]::CreateDirectory($script:LocalScmQaBaseRoot)
$plan = New-LocalScmQaPlan -Nonce ([guid]$env:HERMES_QA_NONCE) -SourceRoot $env:HERMES_QA_SOURCE_ROOT -DeadlineUtc $env:HERMES_QA_DEADLINE
$script:cleanupCalls=0
$adapter = @{
    GetFixtureState = { param($ignored) [pscustomobject]@{ fixtureRootExists=$false;gatewayServiceExists=$false;privilegedServiceExists=$false;nonceReplayed=$false;lockHeld=$false;sourceDrift=$false;sourceUnsafe=$false;sourceHardlinked=$false;sourceUntrusted=$false;canonicalParentTouched=$false;elevated=$true;processIs64Bit=$true;windowsPowerShell5=$true;parentAclSha256Before='a';parentAclSha256After='a';existingLockPreserved=$true;existingStagingPreserved=$true } }
    PersistOwnershipIntent = { param($providedPlan) [void][IO.Directory]::CreateDirectory($providedPlan.fixtureRoot); throw 'persist-before-manifest' }
    AcquireFixtureLock = { throw 'must-not-lock' }
    BuildFixtureArtifacts = { throw 'must-not-build' }
    RegisterFixtureServices = { throw 'must-not-register' }
    RunInvalidAnchorProbe = { throw 'must-not-probe' }
    RunLifecycleScenarios = { throw 'must-not-scenarios' }
    ComparePreservationBaseline = { throw 'must-not-baseline' }
    CleanupFixture = { $script:cleanupCalls++; throw 'must-not-cleanup' }
    ReleaseFixtureLock = { throw 'must-not-unlock' }
}
$receipt = Invoke-LocalScmQaApply -Plan $plan -Adapter $adapter
[pscustomobject]@{ receipt=$receipt; cleanupCalls=$script:cleanupCalls; fixturePresent=(Test-Path -LiteralPath $plan.fixtureRoot) } | ConvertTo-Json -Depth 12 -Compress
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(RUNNER_PATH),
                "HERMES_QA_TEMP_ROOT": str(tmp_path),
                "HERMES_QA_NONCE": str(uuid.uuid4()),
                "HERMES_QA_SOURCE_ROOT": str(PROJECT_ROOT),
                "HERMES_QA_DEADLINE": _future_deadline(),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["cleanupCalls"] == 0
    assert report["fixturePresent"] is True
    assert report["receipt"]["state"] == "failed"
    assert report["receipt"]["cleanup"]["state"] == "unverified"
    assert report["receipt"]["cleanup"]["reason"] == "LocalScmQaInitialManifestUnavailable"
    assert report["receipt"]["cleanup"]["fixtureRootPresent"] is True
    assert len(report["receipt"]["cleanup"]["expectedFixtureRootSha256"]) == 64
    assert report["receipt"]["exceptionType"] == "System.Management.Automation.RuntimeException"
    assert report["receipt"]["exceptionMessage"] == "persist-before-manifest"
    assert report["receipt"]["exceptionLine"]
    assert "Invoke-LocalScmQaApply" in report["receipt"]["exceptionStackTrace"]


def test_bounded_worker_failure_records_durable_sanitized_evidence_pointer(
    tmp_path: Path,
) -> None:
    """nonzero와 timeout worker는 raw output 없이 durable evidence pointer를 남겨야 합니다."""
    stub = tmp_path / "scripts"
    stub.mkdir()
    _ = (stub / "service-runtime.ps1").write_text(
        "param([switch]$LibraryMode,$SourceRoot,$ProgramRoot)\n", encoding="utf-8"
    )
    command = r"""
. $env:HERMES_QA_RUNNER | Out-Null
$script:LocalScmQaProjectRoot=$env:HERMES_QA_STUB_ROOT
$script:LocalScmQaProgramRoot=Join-Path $env:HERMES_QA_TEMP_ROOT 'program-root'
$fixture=Join-Path $env:HERMES_QA_TEMP_ROOT 'fixture'
[void][IO.Directory]::CreateDirectory($fixture)
[void][IO.Directory]::CreateDirectory($script:LocalScmQaProgramRoot)
$lock=Join-Path $script:LocalScmQaProgramRoot 'runtime-build.lock'
[IO.File]::WriteAllText($lock,'lock',[Text.UTF8Encoding]::new($false))
$uvFirst=Join-Path $env:HERMES_QA_TEMP_ROOT 'uv-first.exe'
[IO.File]::WriteAllText($uvFirst,'uv',[Text.UTF8Encoding]::new($false))
$manifestPath=Join-Path $fixture 'manifest.json'
$manifest=[pscustomobject]@{nonce=([guid]::NewGuid()).ToString();fixtureRoot=$fixture;manifestPath=$manifestPath;sourceRoot=$env:HERMES_QA_SOURCE_ROOT;deadlineUtc=$env:HERMES_QA_DEADLINE;runtimeBuildLock=$null;trustedUvPath=$null;trustedUvSha256=$null;trustedDotnetPath=$null;trustedDotnetSha256=$null;buildWorkerEvidencePath=$null}
function Test-LocalScmQaReparseFree { param($Root,$Path) return $true }
function Test-BridgeTreeAcl { param($Path,$RequireTrustedOwner) return $null }
function Get-BridgeFileLinkCount { param($Path) return 1 }
function Get-LocalScmQaFileSha256 { param($Path) return 'hash' }
function Get-LocalScmQaAclSha256 { param($Path) return 'acl' }
function Get-LocalScmQaExistingFileId { param($Path) return 'file-id' }
function Get-Command { param($Name,$CommandType,$ErrorAction) if($Name -ceq 'dotnet.exe'){return [pscustomobject]@{Source=(Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'dotnet\dotnet.exe')}};return @([pscustomobject]@{Source=$uvFirst},[pscustomobject]@{Source=(Join-Path $env:HERMES_QA_TEMP_ROOT 'uv-second.exe')}) }
function Get-BridgeBuildEnvironment { param($ProtectedRoot) return @{SystemRoot='C:\Windows';PATH='C:\Windows\System32'} }
function Write-LocalScmQaManifest { param($Manifest) [IO.File]::WriteAllText($Manifest.manifestPath,($Manifest|ConvertTo-Json -Depth 16),[Text.UTF8Encoding]::new($false)) }
$script:captured=@();$script:attempt=0
function Invoke-BridgeBoundedProcess { param($FilePath,$Arguments,$WorkingDirectory,$Environment,$TimeoutSeconds) $script:attempt++;if($script:attempt -eq 1){return [pscustomobject]@{exitCode=23;stdout='token=raw-worker-token';stderr='Authorization: Bearer raw-worker-secret'}};throw [TimeoutException]::new('worker-timeout') }
function Write-LocalScmQaBuildWorkerEvidence { param($Manifest,$Process,$FailureKind,$FailureDetail) $path=Join-Path $env:HERMES_QA_TEMP_ROOT ($FailureKind + '.json');$script:captured+=@([pscustomobject]@{kind=$FailureKind;exitCode=if($null -eq $Process){$null}else{$Process.exitCode};path=$path});return [pscustomobject]@{evidencePath=$path;stdoutEvidencePath=($path+'.stdout');stderrEvidencePath=($path+'.stderr');failureEvidencePath=($path+'.failure')} }
$nonzero=Invoke-LocalScmQaBoundedBuildWorker -Manifest $manifest
$timeout=Invoke-LocalScmQaBoundedBuildWorker -Manifest $manifest
$durable=[IO.File]::ReadAllText($manifestPath,[Text.UTF8Encoding]::new($false,$true))|ConvertFrom-Json
$summary=Get-LocalScmQaSanitizedProcessOutputSummary -Text 'token=raw-worker-token Authorization: Bearer raw-worker-secret'
[pscustomobject]@{nonzero=$nonzero;timeout=$timeout;captured=@($script:captured);durable=$durable;summary=$summary;expectedUvPath=$uvFirst}|ConvertTo-Json -Depth 16 -Compress
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(RUNNER_PATH),
                "HERMES_QA_STUB_ROOT": str(tmp_path),
                "HERMES_QA_TEMP_ROOT": str(tmp_path),
                "HERMES_QA_SOURCE_ROOT": str(PROJECT_ROOT),
                "HERMES_QA_DEADLINE": _future_deadline(),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["nonzero"]["state"] == "failed"
    assert report["nonzero"]["workerExitCode"] == 23
    assert report["nonzero"]["reason"] == "LocalScmQaBuildWorkerExitNonZero"
    assert report["nonzero"]["manifest"]["trustedUvPath"] == report["expectedUvPath"]
    assert report["nonzero"]["manifest"]["trustedUvSha256"] == "hash"
    assert report["timeout"]["state"] == "failed"
    assert report["timeout"]["workerExitCode"] is None
    assert report["timeout"]["reason"] == "TimeoutException"
    assert report["durable"]["buildWorkerEvidencePath"] == report["timeout"]["evidencePath"]
    assert [entry["kind"] for entry in report["captured"]] == [
        "LocalScmQaBuildWorkerExitNonZero",
        "TimeoutException",
    ]
    assert report["summary"]["redactionsApplied"] == 2
    assert "raw-worker-token" not in report["summary"]["excerpt"]
    assert "raw-worker-secret" not in report["summary"]["excerpt"]


def test_bounded_worker_empty_streams_keep_nonzero_exit_and_durable_evidence(
    tmp_path: Path,
) -> None:
    """빈 worker stdout/stderr도 exit와 evidence를 보존하고 binding 오류로 가리지 않아야 합니다."""
    runner_copy = tmp_path / "runner-copy.ps1"
    _ = runner_copy.write_bytes(RUNNER_PATH.read_bytes())
    stub = tmp_path / "scripts"
    stub.mkdir()
    _ = (stub / "service-runtime.ps1").write_text(
        "param([switch]$LibraryMode,$SourceRoot,$ProgramRoot)\n", encoding="utf-8"
    )
    command = r"""
. $env:HERMES_QA_RUNNER | Out-Null
$script:LocalScmQaProjectRoot=$env:HERMES_QA_STUB_ROOT
$script:LocalScmQaProgramRoot=Join-Path $env:HERMES_QA_TEMP_ROOT 'program-root'
$fixture=Join-Path $env:HERMES_QA_TEMP_ROOT 'fixture'
[void][IO.Directory]::CreateDirectory($fixture)
[void][IO.Directory]::CreateDirectory($script:LocalScmQaProgramRoot)
$lock=Join-Path $script:LocalScmQaProgramRoot 'runtime-build.lock'
[IO.File]::WriteAllText($lock,'lock',[Text.UTF8Encoding]::new($false))
$uv=Join-Path $env:HERMES_QA_TEMP_ROOT 'uv.exe'
[IO.File]::WriteAllText($uv,'uv',[Text.UTF8Encoding]::new($false))
$manifestPath=Join-Path $fixture 'manifest.json'
$manifest=[pscustomobject]@{nonce=([guid]::NewGuid()).ToString();fixtureRoot=$fixture;manifestPath=$manifestPath;sourceRoot=$env:HERMES_QA_SOURCE_ROOT;deadlineUtc=$env:HERMES_QA_DEADLINE;runtimeBuildLock=$null;trustedUvPath=$null;trustedUvSha256=$null;trustedDotnetPath=$null;trustedDotnetSha256=$null;buildWorkerEvidencePath=$null}
function Test-LocalScmQaReparseFree { param($Root,$Path) return $true }
function Test-BridgeTreeAcl { param($Path,$RequireTrustedOwner) return $null }
function Get-BridgeFileLinkCount { param($Path) return 1 }
function Get-LocalScmQaFileSha256 { param($Path) return 'hash' }
function Get-LocalScmQaAclSha256 { param($Path) return 'acl' }
function Get-LocalScmQaExistingFileId { param($Path) return 'file-id' }
function Get-Command { param($Name,$CommandType,$ErrorAction) if($Name -ceq 'uv.exe'){return [pscustomobject]@{Source=$uv}};throw "unexpected:$Name" }
function Get-BridgeBuildEnvironment { param($ProtectedRoot) return @{SystemRoot='C:\Windows';PATH='C:\Windows\System32'} }
function Write-LocalScmQaManifest { param($Manifest) [IO.File]::WriteAllText($Manifest.manifestPath,($Manifest|ConvertTo-Json -Depth 16),[Text.UTF8Encoding]::new($false)) }
$script:boundedCall=$null
function Invoke-BridgeBoundedProcess { param($FilePath,$Arguments,$WorkingDirectory,$Environment,$TimeoutSeconds) $script:boundedCall=[pscustomobject]@{filePath=$FilePath;arguments=@($Arguments);workingDirectory=$WorkingDirectory;timeoutSeconds=$TimeoutSeconds};return [pscustomobject]@{exitCode=1;stdout='';stderr=''} }
$result=Invoke-LocalScmQaBoundedBuildWorker -Manifest $manifest
$evidence=Get-Content -LiteralPath $result.evidencePath -Raw|ConvertFrom-Json
$durable=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
[pscustomobject]@{result=$result;evidence=$evidence;durable=$durable;boundedCall=$script:boundedCall;stdoutLogExists=(Test-Path -LiteralPath $result.stdoutEvidencePath -PathType Leaf);stderrLogExists=(Test-Path -LiteralPath $result.stderrEvidencePath -PathType Leaf);failureLogExists=(Test-Path -LiteralPath $result.failureEvidencePath -PathType Leaf)}|ConvertTo-Json -Depth 20 -Compress
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(runner_copy),
                "HERMES_QA_STUB_ROOT": str(tmp_path),
                "HERMES_QA_TEMP_ROOT": str(tmp_path),
                "HERMES_QA_SOURCE_ROOT": str(PROJECT_ROOT),
                "HERMES_QA_DEADLINE": _future_deadline(),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["result"]["state"] == "failed"
    assert report["result"]["workerExitCode"] == 1
    assert report["result"]["reason"] == "LocalScmQaBuildWorkerExitNonZero"
    assert report["result"]["reconciliationRequired"] is True
    assert report["durable"]["buildWorkerEvidencePath"] == report["result"]["evidencePath"]
    for stream_name in ("stdout", "stderr"):
        stream = report["evidence"][stream_name]
        assert stream["available"] is True
        assert stream["utf8Length"] == 0
        assert stream["sha256"] == hashlib.sha256(b"").hexdigest()
    assert report["stdoutLogExists"] is True
    assert report["stderrLogExists"] is True
    assert report["failureLogExists"] is True
    assert report["boundedCall"]["filePath"].endswith("powershell.exe")
    assert "-BuildWorker" in report["boundedCall"]["arguments"]
    assert "-ManifestPath" in report["boundedCall"]["arguments"]


def test_bounded_worker_uses_fixture_owned_dotnet_environment(
    tmp_path: Path,
) -> None:
    """.NET restore child는 user cache 대신 fixture-owned shell/cache paths를 받아야 합니다."""
    runner_copy = tmp_path / "runner-copy.ps1"
    _ = runner_copy.write_bytes(RUNNER_PATH.read_bytes())
    stub = tmp_path / "scripts"
    stub.mkdir()
    _ = (stub / "service-runtime.ps1").write_text(
        "param([switch]$LibraryMode,$SourceRoot,$ProgramRoot)\n", encoding="utf-8"
    )
    command = r"""
. $env:HERMES_QA_RUNNER | Out-Null
$script:LocalScmQaProjectRoot=$env:HERMES_QA_STUB_ROOT
$script:LocalScmQaProgramRoot=Join-Path $env:HERMES_QA_TEMP_ROOT 'program-root'
$fixture=Join-Path $env:HERMES_QA_TEMP_ROOT 'fixture'
[void][IO.Directory]::CreateDirectory($fixture)
[void][IO.Directory]::CreateDirectory($script:LocalScmQaProgramRoot)
$lock=Join-Path $script:LocalScmQaProgramRoot 'runtime-build.lock'
[IO.File]::WriteAllText($lock,'lock',[Text.UTF8Encoding]::new($false))
$uv=Join-Path $env:HERMES_QA_TEMP_ROOT 'uv.exe'
[IO.File]::WriteAllText($uv,'uv',[Text.UTF8Encoding]::new($false))
$manifestPath=Join-Path $fixture 'manifest.json'
$manifest=[pscustomobject]@{nonce=([guid]::NewGuid()).ToString();fixtureRoot=$fixture;manifestPath=$manifestPath;sourceRoot=$env:HERMES_QA_SOURCE_ROOT;deadlineUtc=$env:HERMES_QA_DEADLINE;runtimeBuildLock=$null;trustedUvPath=$null;trustedUvSha256=$null;trustedDotnetPath=$null;trustedDotnetSha256=$null;buildWorkerEvidencePath=$null}
function Test-LocalScmQaReparseFree { param($Root,$Path) return $true }
function Test-BridgeTreeAcl { param($Path,$RequireTrustedOwner) return $null }
function Get-BridgeFileLinkCount { param($Path) return 1 }
function Get-LocalScmQaFileSha256 { param($Path) return 'hash' }
function Get-LocalScmQaAclSha256 { param($Path) return 'acl' }
function Get-LocalScmQaExistingFileId { param($Path) return 'file-id' }
function Get-Command { param($Name,$CommandType,$ErrorAction) if($Name -ceq 'uv.exe'){return [pscustomobject]@{Source=$uv}};throw "unexpected:$Name" }
function Get-BridgeBuildEnvironment { param($ProtectedRoot) return @{SystemRoot='C:\Windows';PATH='C:\Windows\System32'} }
function Write-LocalScmQaManifest { param($Manifest) [IO.File]::WriteAllText($Manifest.manifestPath,($Manifest|ConvertTo-Json -Depth 16),[Text.UTF8Encoding]::new($false)) }
function Write-LocalScmQaBuildWorkerEvidence { param($Manifest,$Process,$FailureKind,$FailureDetail) $path=Join-Path $env:HERMES_QA_TEMP_ROOT 'evidence.json';return [pscustomobject]@{evidencePath=$path;stdoutEvidencePath=($path+'.stdout');stderrEvidencePath=($path+'.stderr');failureEvidencePath=($path+'.failure')} }
$script:boundedCall=$null
function Invoke-BridgeBoundedProcess { param($FilePath,$Arguments,$WorkingDirectory,$Environment,$TimeoutSeconds) $script:boundedCall=[pscustomobject]@{environment=$Environment};return [pscustomobject]@{exitCode=1;stdout='';stderr=''} }
$result=Invoke-LocalScmQaBoundedBuildWorker -Manifest $manifest
[pscustomobject]@{result=$result;fixtureRoot=$fixture;environment=$script:boundedCall.environment}|ConvertTo-Json -Depth 20 -Compress
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(runner_copy),
                "HERMES_QA_TEMP_ROOT": str(tmp_path),
                "HERMES_QA_STUB_ROOT": str(tmp_path),
                "HERMES_QA_SOURCE_ROOT": str(PROJECT_ROOT),
                "HERMES_QA_DEADLINE": _future_deadline(),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    environment = report["environment"]
    fixture_root = Path(report["fixtureRoot"])
    assert report["result"]["state"] == "failed"
    assert environment["APPDATA"] == str(fixture_root / "appdata")
    assert environment["LOCALAPPDATA"] == str(fixture_root / "localappdata")
    assert environment["DOTNET_CLI_HOME"] == str(fixture_root / "dotnet-cli")
    assert environment["NUGET_PACKAGES"] == str(fixture_root / "nuget-packages")
    assert environment["DOTNET_CLI_TELEMETRY_OPTOUT"] == "true"
    assert environment["DOTNET_NOLOGO"] == "true"
    assert environment["DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE"] == "true"
    assert environment["DOTNET_GENERATE_ASPNET_CERTIFICATE"] == "false"
    assert environment["DOTNET_ADD_GLOBAL_TOOLS_TO_PATH"] == "false"
    assert environment["ProgramFiles"] == r"C:\Program Files"
    assert environment["ProgramFiles(x86)"] == r"C:\Program Files (x86)"
    assert r"\.nuget\packages" not in environment["NUGET_PACKAGES"].lower()


def test_host_builder_failure_bridges_verbose_restore_diagnostic_to_stderr(
    tmp_path: Path,
) -> None:
    """canonical builder가 숨긴 restore 진단은 worker stderr로 남아야 합니다."""
    stub = tmp_path / "scripts"
    stub.mkdir()
    _ = (stub / "service-host.ps1").write_text(
        """param([switch]$LibraryMode)
function Set-BridgeHostProtectedDirectory { param($Path) }
function Invoke-BridgeServiceHostBuild {
    [CmdletBinding()]
    param($SourceRoot,$ProgramRoot,$ReleaseRoot,$ExpectedManifestSha256)
    Write-Verbose 'host-restore-output-sentinel'
    throw [ComponentModel.Win32Exception]::new('BridgeServiceHostRestoreFailed')
}
""",
        encoding="utf-8",
    )
    command = r"""
. $env:HERMES_QA_RUNNER | Out-Null
$script:LocalScmQaProjectRoot=$env:HERMES_QA_STUB_ROOT
$script:LocalScmQaProgramRoot=Join-Path $env:HERMES_QA_TEMP_ROOT 'program-root'
[void][IO.Directory]::CreateDirectory($script:LocalScmQaProgramRoot)
$source=Join-Path $env:HERMES_QA_TEMP_ROOT 'source'
$releaseRoot=Join-Path $env:HERMES_QA_TEMP_ROOT 'release'
[void][IO.Directory]::CreateDirectory($source)
[void][IO.Directory]::CreateDirectory($releaseRoot)
$releaseManifest=Join-Path $releaseRoot 'release-manifest.json'
[IO.File]::WriteAllText($releaseManifest,'{}',[Text.UTF8Encoding]::new($false))
$manifestPath=Join-Path $env:HERMES_QA_TEMP_ROOT 'fixture-manifest.json'
$manifest=[pscustomobject]@{nonce=([guid]::NewGuid()).ToString();sourceRoot=$source;manifestPath=$manifestPath;ownershipIntent=@();hostBuildDiagnosticPath=$null;hostBuildDiagnostics=@();scenarios=[pscustomobject]@{verifierTamper=[pscustomobject]@{paths=@()}}}
$release=[pscustomobject]@{releaseRoot=$releaseRoot;manifestPath=$releaseManifest}
function Get-LocalScmQaFileSha256 { param($Path) return 'hash' }
function Write-LocalScmQaHostBuildDiagnostics { param($Manifest,$Records,$State) $text=@($Records|ForEach-Object{[string]$_.Message})-join "`n";return [pscustomobject]@{entry=[pscustomobject]@{verboseRecordCount=@($Records).Count;output=[pscustomobject]@{excerpt=$text}}} }
try {
    Invoke-LocalScmQaBuildFixtureHosts -Manifest $manifest -Release $release
} catch {
    [pscustomobject]@{caught=$_.Exception.Message}|ConvertTo-Json -Compress
}
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(RUNNER_PATH),
                "HERMES_QA_TEMP_ROOT": str(tmp_path),
                "HERMES_QA_STUB_ROOT": str(tmp_path),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["caught"] == "BridgeServiceHostRestoreFailed"
    assert "host-restore-output-sentinel" in result.stderr


def test_host_builder_failure_without_verbose_preserves_original_error(
    tmp_path: Path,
) -> None:
    """빈 verbose stream도 원래 host builder 오류를 가리면 안 됩니다."""
    stub = tmp_path / "scripts"
    stub.mkdir()
    _ = (stub / "service-host.ps1").write_text(
        """param([switch]$LibraryMode)
function Set-BridgeHostProtectedDirectory { param($Path) }
function Invoke-BridgeServiceHostBuild {
    [CmdletBinding()]
    param($SourceRoot,$ProgramRoot,$ReleaseRoot,$ExpectedManifestSha256)
    throw [ComponentModel.Win32Exception]::new('BridgeServiceHostRestoreFailed')
}
""",
        encoding="utf-8",
    )
    command = r"""
. $env:HERMES_QA_RUNNER | Out-Null
$script:LocalScmQaProjectRoot=$env:HERMES_QA_STUB_ROOT
$script:LocalScmQaProgramRoot=Join-Path $env:HERMES_QA_TEMP_ROOT 'program-root'
[void][IO.Directory]::CreateDirectory($script:LocalScmQaProgramRoot)
$source=Join-Path $env:HERMES_QA_TEMP_ROOT 'source'
$releaseRoot=Join-Path $env:HERMES_QA_TEMP_ROOT 'release'
[void][IO.Directory]::CreateDirectory($source)
[void][IO.Directory]::CreateDirectory($releaseRoot)
$releaseManifest=Join-Path $releaseRoot 'release-manifest.json'
[IO.File]::WriteAllText($releaseManifest,'{}',[Text.UTF8Encoding]::new($false))
$manifestPath=Join-Path $env:HERMES_QA_TEMP_ROOT 'fixture-manifest.json'
$manifest=[pscustomobject]@{nonce=([guid]::NewGuid()).ToString();sourceRoot=$source;manifestPath=$manifestPath;ownershipIntent=@();hostBuildDiagnosticPath=$null;hostBuildDiagnostics=@();scenarios=[pscustomobject]@{verifierTamper=[pscustomobject]@{paths=@()}}}
$release=[pscustomobject]@{releaseRoot=$releaseRoot;manifestPath=$releaseManifest}
function Get-LocalScmQaFileSha256 { param($Path) return 'hash' }
function Write-LocalScmQaHostBuildDiagnostics { param($Manifest,$Records,$State) return [pscustomobject]@{entry=[pscustomobject]@{verboseRecordCount=0;output=[pscustomobject]@{excerpt=''}}} }
try {
    Invoke-LocalScmQaBuildFixtureHosts -Manifest $manifest -Release $release
} catch {
    [pscustomobject]@{caught=$_.Exception.Message}|ConvertTo-Json -Compress
}
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(RUNNER_PATH),
                "HERMES_QA_TEMP_ROOT": str(tmp_path),
                "HERMES_QA_STUB_ROOT": str(tmp_path),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["caught"] == "BridgeServiceHostRestoreFailed"


def test_host_builder_diagnostic_writer_failure_preserves_original_error(
    tmp_path: Path,
) -> None:
    """진단 영수증 쓰기 실패는 host builder의 실패 원인을 덮으면 안 됩니다."""
    stub = tmp_path / "scripts"
    stub.mkdir()
    _ = (stub / "service-host.ps1").write_text(
        """param([switch]$LibraryMode)
function Set-BridgeHostProtectedDirectory { param($Path) }
function Invoke-BridgeServiceHostBuild {
    [CmdletBinding()]
    param($SourceRoot,$ProgramRoot,$ReleaseRoot,$ExpectedManifestSha256)
    Write-Verbose 'host-restore-output-sentinel'
    throw [ComponentModel.Win32Exception]::new('BridgeServiceHostRestoreFailed')
}
""",
        encoding="utf-8",
    )
    command = r"""
. $env:HERMES_QA_RUNNER | Out-Null
$script:LocalScmQaProjectRoot=$env:HERMES_QA_STUB_ROOT
$script:LocalScmQaProgramRoot=Join-Path $env:HERMES_QA_TEMP_ROOT 'program-root'
[void][IO.Directory]::CreateDirectory($script:LocalScmQaProgramRoot)
$source=Join-Path $env:HERMES_QA_TEMP_ROOT 'source'
$releaseRoot=Join-Path $env:HERMES_QA_TEMP_ROOT 'release'
[void][IO.Directory]::CreateDirectory($source)
[void][IO.Directory]::CreateDirectory($releaseRoot)
$releaseManifest=Join-Path $releaseRoot 'release-manifest.json'
[IO.File]::WriteAllText($releaseManifest,'{}',[Text.UTF8Encoding]::new($false))
$manifestPath=Join-Path $env:HERMES_QA_TEMP_ROOT 'fixture-manifest.json'
$manifest=[pscustomobject]@{nonce=([guid]::NewGuid()).ToString();sourceRoot=$source;manifestPath=$manifestPath;ownershipIntent=@();hostBuildDiagnosticPath=$null;hostBuildDiagnostics=@();scenarios=[pscustomobject]@{verifierTamper=[pscustomobject]@{paths=@()}}}
$release=[pscustomobject]@{releaseRoot=$releaseRoot;manifestPath=$releaseManifest}
function Get-LocalScmQaFileSha256 { param($Path) return 'hash' }
function Write-LocalScmQaHostBuildDiagnostics { param($Manifest,$Records,$State) throw [InvalidOperationException]::new('diagnostic-write-failure') }
try {
    Invoke-LocalScmQaBuildFixtureHosts -Manifest $manifest -Release $release
} catch {
    [pscustomobject]@{caught=$_.Exception.Message}|ConvertTo-Json -Compress
}
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(RUNNER_PATH),
                "HERMES_QA_TEMP_ROOT": str(tmp_path),
                "HERMES_QA_STUB_ROOT": str(tmp_path),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["caught"] == "BridgeServiceHostRestoreFailed"
    assert "[LocalScmQaHostBuildDiagnosticWriteFailed]" in result.stderr


def test_host_builder_success_keeps_one_result_separate_from_verbose(
    tmp_path: Path,
) -> None:
    """성공 경로의 verbose record는 단일 host build 결과와 분리해야 합니다."""
    stub = tmp_path / "scripts"
    stub.mkdir()
    _ = (stub / "service-host.ps1").write_text(
        """param([switch]$LibraryMode)
function Set-BridgeHostProtectedDirectory { param($Path) }
function Invoke-BridgeServiceHostBuild {
    [CmdletBinding()]
    param($SourceRoot,$ProgramRoot,$ReleaseRoot,$ExpectedManifestSha256)
    Write-Verbose 'host-build-success-sentinel'
    [pscustomobject]@{state='failed';hosts=@();stagingRoot='staging'}
}
""",
        encoding="utf-8",
    )
    command = r"""
. $env:HERMES_QA_RUNNER | Out-Null
$script:LocalScmQaProjectRoot=$env:HERMES_QA_STUB_ROOT
$script:LocalScmQaProgramRoot=Join-Path $env:HERMES_QA_TEMP_ROOT 'program-root'
[void][IO.Directory]::CreateDirectory($script:LocalScmQaProgramRoot)
$source=Join-Path $env:HERMES_QA_TEMP_ROOT 'source'
$releaseRoot=Join-Path $env:HERMES_QA_TEMP_ROOT 'release'
[void][IO.Directory]::CreateDirectory($source)
[void][IO.Directory]::CreateDirectory($releaseRoot)
$releaseManifest=Join-Path $releaseRoot 'release-manifest.json'
[IO.File]::WriteAllText($releaseManifest,'{}',[Text.UTF8Encoding]::new($false))
$manifestPath=Join-Path $env:HERMES_QA_TEMP_ROOT 'fixture-manifest.json'
$manifest=[pscustomobject]@{nonce=([guid]::NewGuid()).ToString();sourceRoot=$source;manifestPath=$manifestPath;ownershipIntent=@();hostBuildDiagnosticPath=$null;hostBuildDiagnostics=@();scenarios=[pscustomobject]@{verifierTamper=[pscustomobject]@{paths=@()}}}
$release=[pscustomobject]@{releaseRoot=$releaseRoot;manifestPath=$releaseManifest}
function Get-LocalScmQaFileSha256 { param($Path) return 'hash' }
$script:diagnostic=$null
function Write-LocalScmQaHostBuildDiagnostics {
    param($Manifest,$Records,$State)
    $script:diagnostic=[pscustomobject]@{state=$State;recordCount=@($Records).Count;verbose=$Records[0].Message}
    return [pscustomobject]@{entry=[pscustomobject]@{verboseRecordCount=1;output=[pscustomobject]@{excerpt=$Records[0].Message}}}
}
try {
    Invoke-LocalScmQaBuildFixtureHosts -Manifest $manifest -Release $release
} catch {
    [pscustomobject]@{caught=$_.Exception.Message;diagnostic=$script:diagnostic}|ConvertTo-Json -Depth 8 -Compress
}
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(RUNNER_PATH),
                "HERMES_QA_TEMP_ROOT": str(tmp_path),
                "HERMES_QA_STUB_ROOT": str(tmp_path),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["caught"] == "LocalScmQaHostBuildUnverified"
    assert report["diagnostic"]["state"] == "success"
    assert report["diagnostic"]["recordCount"] == 2
    assert report["diagnostic"]["verbose"] == "host-build-success-sentinel"


def test_workspace_fixture_child_has_exact_ready_bytes_and_matches_plan_hash(
    tmp_path: Path,
) -> None:
    """copied fixture template은 LF protocol bytes와 plan의 immutable patch hash를 함께 지켜야 합니다."""
    assert RUNNER_PATH.is_file(), "Todo9 local SCM runner is not implemented yet"
    stub = tmp_path / "scripts"
    stub.mkdir()
    _ = (stub / "service-runtime.ps1").write_text(
        "param([switch]$LibraryMode,$SourceRoot,$ProgramRoot)\n", encoding="utf-8"
    )
    command = r"""
. $env:HERMES_QA_RUNNER | Out-Null
$script:LocalScmQaBaseRoot = Join-Path $env:HERMES_QA_TEMP_ROOT 'fixture-base'
$script:LocalScmQaProgramRoot = Join-Path $env:HERMES_QA_TEMP_ROOT 'program-root'
[void][IO.Directory]::CreateDirectory($script:LocalScmQaBaseRoot)
[void][IO.Directory]::CreateDirectory($script:LocalScmQaProgramRoot)
function Test-BridgeTreeAcl { param($Path,$RequireTrustedOwner) return $null }
function Test-LocalScmQaReparseFree { param($Root,$Path) return $true }
function Get-BridgeFileLinkCount { param($Path) return 1 }
$plan = New-LocalScmQaPlan -Nonce ([guid]$env:HERMES_QA_NONCE) `
    -SourceRoot $env:HERMES_QA_SOURCE_ROOT -DeadlineUtc $env:HERMES_QA_DEADLINE
$script:LocalScmQaProjectRoot=$env:HERMES_QA_STUB_ROOT
[void][IO.Directory]::CreateDirectory($plan.fixtureRoot)
$workspace = Invoke-LocalScmQaCreateFixtureWorkspace -Manifest $plan
$childPath = Join-Path $workspace.sourceRoot 'src\hermes_windows_bridge\service_child.py'
[pscustomobject]@{
    childPath = $childPath
    planPatchSha256 = $plan.fixtureChildPatchSha256
    actualPatchSha256 = Get-LocalScmQaFileSha256 -Path $childPath
    workspace = $workspace
} | ConvertTo-Json -Depth 12 -Compress
"""
    result = _run_powershell(
        command,
        environment=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(RUNNER_PATH),
                "HERMES_QA_TEMP_ROOT": str(tmp_path),
                "HERMES_QA_STUB_ROOT": str(tmp_path),
                "HERMES_QA_NONCE": str(uuid.uuid4()),
                "HERMES_QA_SOURCE_ROOT": str(PROJECT_ROOT),
                "HERMES_QA_DEADLINE": _future_deadline(),
            }
        ),
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    child = Path(report["childPath"])
    process = subprocess.run(
        [sys.executable, str(child), "--profile", "gateway"],
        input=b"STOP\n",
        cwd=child.parent,
        check=False,
        capture_output=True,
        timeout=10,
    )

    assert process.returncode == 0, process.stderr.decode("utf-8", errors="replace")
    assert process.stdout == b"READY 1\n"
    assert report["actualPatchSha256"] == report["planPatchSha256"]
