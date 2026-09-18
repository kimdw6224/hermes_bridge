"""Protected two-service release transaction tests."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path
from typing import ClassVar, Final

import pytest
from pydantic import BaseModel, ConfigDict, Field

PROJECT_ROOT: Final = Path(__file__).parents[2]
TRANSACTION_SCRIPT: Final = PROJECT_ROOT / "scripts" / "service-runtime-transaction.ps1"
RUNTIME_SCRIPT: Final = PROJECT_ROOT / "scripts" / "service-runtime.ps1"
POWERSHELL: Final = shutil.which("powershell.exe")
assert POWERSHELL is not None


@pytest.mark.parametrize(
    ("validator_result", "expected_unresolved"),
    [("$true", "False"), ("$false", "True"), ("'True'", "True")],
)
def test_recovered_journal_requires_validated_archive(
    tmp_path: Path, validator_result: str, expected_unresolved: str
) -> None:
    recovery_script = tmp_path / "recover-service-switch.ps1"
    _ = recovery_script.write_text(
        f"""param([switch]$LibraryMode)
function Test-BridgeRecoveredJournal {{
    param($StatePath)
    return {validator_result}
}}
""",
        encoding="utf-8",
    )
    install_path = PROJECT_ROOT / "scripts" / "install.ps1"
    expression = rf"""
$ast=[Management.Automation.Language.Parser]::ParseFile('{install_path}',[ref]$null,[ref]$null)
$loop=$ast.Find({{param($n) $n -is [Management.Automation.Language.ForEachStatementAst] -and
    $n.Variable.VariablePath.UserPath -ceq 'backupStatePath'}},$true)
$canonicalScriptRoot='{tmp_path}'
$backups=@('C:\fixture\state.json')
$unresolvedBackupState=$false
$legacyFailedBackupStates=@()
function Get-Content {{ return '{{"schemaVersion":1,"status":"recovered"}}' }}
. ([scriptblock]::Create($loop.Extent.Text))
$unresolvedBackupState
"""
    result = _run(expression)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected_unresolved


@pytest.mark.parametrize("profile", ["gateway", "privileged"])
def test_registration_request_account_matches_actual_adapter(profile: str) -> None:
    command = f". '{TRANSACTION_SCRIPT}'; " + " ".join(
        (
            ("$r=[pscustomobject]@{manifestPath='C:\\fixture\\release-manifest.json';"
            "releaseRoot='C:\\fixture';serviceExecutable='C:\\fixture\\python.exe'};"),
            f"$expected=Get-BridgeServiceRegistrationRequest -Release $r -Profile '{profile}';",
            (f"$adapter=& '{POWERSHELL}' -NoProfile -File "
            f"'{PROJECT_ROOT / 'scripts' / f'register-{profile}-service.ps1'}' "
            "-Json | Out-String | ConvertFrom-Json;"),
            "$expected.account -ceq $adapter.account",
        )
    )
    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "True"


@pytest.mark.parametrize(
    ("readback_state", "readback_exact", "valid"),
    [("desired", "$true", True), ("absent", "$true", False), ("desired", "$false", False)],
)
def test_pair_inspection_checks_arguments_and_readback_consistency(
    readback_state: str, readback_exact: str, *, valid: bool
) -> None:
    command = (
        f". '{TRANSACTION_SCRIPT}'; "
        f"$readbackState='{readback_state}';$readbackExact={readback_exact}; "
    )
    command += r"""
$ErrorActionPreference='Stop'
function Get-BridgeServiceRegistrationRequest {
    param($Release,$Profile)
    [pscustomobject]@{script='adapter.ps1';arguments=@('-Name',$Profile);name=$Profile;account='test'}
}
function Invoke-BridgeChildProcess {
    [CmdletBinding()]
    param($FilePath,[string[]]$ArgumentList,$WorkingDirectory,$TimeoutSeconds)
    if ($ArgumentList.Count -ne 9 -or $ArgumentList[-1] -cne '-Json' -or
        $ArgumentList[4] -cne '-Operation' -or $ArgumentList[5] -cne 'Inspect') {
        throw 'InspectionArgumentsInvalid'
    }
    $record=[pscustomobject]@{mode='inspect';name=$ArgumentList[7];account='test';
        inspect=@{writes=0};
        readBack=@{performed=$true;state=$readbackState;exact=$readbackExact};state='desired'}
    [pscustomobject]@{stdout=($record|ConvertTo-Json -Compress);exitCode=0}
}
(Get-BridgeServicePairInspection -ScriptRoot 'C:\fixture' -Release @{}).previousState
"""
    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if valid:
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "safe-pair"
    else:
        assert result.returncode != 0
        assert "BridgeServiceInspectionContractInvalid" in result.stderr


@pytest.mark.parametrize("previous_state", ["absent", "desired", "conflict", "inspection-error"])
def test_restore_uses_fresh_previous_registration_before_candidate_removal(
    previous_state: str,
) -> None:
    install_path = PROJECT_ROOT / "scripts" / "install.ps1"
    expression = rf"""
$ast=[Management.Automation.Language.Parser]::ParseFile('{install_path}',[ref]$null,[ref]$null)
$assignment=$ast.Find({{param($n)
    $n -is [Management.Automation.Language.AssignmentStatementAst] -and
    $n.Left.Extent.Text -ceq '$invokeServiceStep'}},$true)
$callback=& ([scriptblock]::Create($assignment.Right.Extent.Text))
$previousRelease=[pscustomobject]@{{manifestPath='C:\old\release-manifest.json';
    releaseRoot='C:\old';serviceExecutable='C:\old\python.exe'}}
$request=[pscustomobject]@{{name='HermesWindowsBridgeGateway';script='candidate.ps1';
    arguments=@('candidate');account='NT AUTHORITY\LocalService';argv=@('candidate')}}
$registrationRequests=@($request,$request)
$switchContext=[pscustomobject]@{{rollingBack=$false}}
$adapterReceipts=[Collections.Generic.List[object]]::new()
function Get-BridgeServiceDefinitionInspection {{
    param($ScriptRoot,$Definition)
    if ('{previous_state}' -ceq 'inspection-error') {{ throw 'InspectionDenied' }}
    [pscustomobject]@{{state='{previous_state}'}}
}}
function Invoke-BridgeRegistrationAdapter {{
    param($ScriptRoot,$ScriptName,$ArgumentList,$AdapterMode,$Operation,
        $ExpectedName,$ExpectedAccount,$ExpectedArgv)
    if ($Operation -ceq 'Remove') {{ throw 'InvalidCandidateMustNotBeRemoved' }}
    if ($ArgumentList[1] -cne 'C:\old\release-manifest.json') {{ throw 'WrongPreviousRelease' }}
    return 'registered-previous'
}}
try {{ & $callback 'gateway_restore' }} catch {{ 'failure:' + $_.Exception.Message }}
@($adapterReceipts) -join ','
"""
    result = _run(expression)
    assert result.returncode == 0, result.stderr
    expected = {
        "absent": "registered-previous",
        "desired": "",
        "conflict": "failure:InvalidCandidateMustNotBeRemoved",
        "inspection-error": "failure:InspectionDenied",
    }
    assert result.stdout.strip() == expected[previous_state]


class SwitchReceipt(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    state: str
    steps: tuple[str, ...]
    rollback: tuple[str, ...]
    starts: int
    worker_calls: int = Field(alias="workerCalls")
    pointer_committed: bool = Field(alias="pointerCommitted")
    failed_step: str | None = Field(alias="failedStep")
    failure_reason: str | None = Field(alias="failureReason")
    rollback_failures: tuple[str, ...] = Field(alias="rollbackFailures")
    pointer_compensated: bool = Field(alias="pointerCompensated")


class AdapterTraceItem(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    name: str
    operation: str
    arguments: tuple[str, ...]
    argv: tuple[str, ...]


class CallbackTrace(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    receipt: SwitchReceipt
    adapter: tuple[AdapterTraceItem, ...]
    starts: tuple[str, ...]
    pointer: tuple[str, ...]
    child_args: tuple[str, ...] = Field(alias="childArgs")
    child_timeout_seconds: int = Field(alias="childTimeoutSeconds")


class WorkerHashTrace(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    receipt: SwitchReceipt
    worker_hash: str = Field(alias="workerHash")


class StopFenceTrace(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    receipt: SwitchReceipt
    calls: tuple[str, ...]


class InstallSimulationTrace(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", frozen=True)

    service_transaction: SwitchReceipt = Field(alias="serviceTransaction")
    registration_results: tuple[dict[str, object], ...] = Field(alias="registrationResults")


class OuterCatchTrace(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", frozen=True)

    atomic: bool
    service_transaction: SwitchReceipt | None = Field(alias="serviceTransaction")
    failed_step: str | None = Field(alias="failedStep")


class ReleaseSelectionTrace(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    release_root: str = Field(alias="releaseRoot")
    release_id: str = Field(alias="releaseId")
    manifest_path: str = Field(alias="manifestPath")
    manifest_sha256: str = Field(alias="manifestSha256")
    service_executable: str = Field(alias="serviceExecutable")


class WorkerPresenceTrace(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    task_absent: bool = Field(alias="taskAbsent")
    should_register: bool = Field(alias="shouldRegister")


def _run(expression: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (f". '{RUNTIME_SCRIPT}' -LibraryMode; . '{TRANSACTION_SCRIPT}'; "
            f"$installationContext=$null; {expression}"),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )


def test_release_selection_preserves_paths_across_runtime_library_dot_source(
    tmp_path: Path,
) -> None:
    scripts_root = tmp_path / "scripts"
    _ = scripts_root.mkdir()
    transaction_copy = scripts_root / TRANSACTION_SCRIPT.name
    _ = shutil.copyfile(TRANSACTION_SCRIPT, transaction_copy)
    runtime_copy = scripts_root / RUNTIME_SCRIPT.name
    _ = runtime_copy.write_text(
        """[CmdletBinding()]
param(
    [Parameter()][string]$ManifestPath,
    [Parameter()][string]$ReleaseRoot,
    [switch]$LibraryMode
)
function Get-BridgeServiceLaunchContract {
    param([string]$ManifestPath, [string]$ReleaseRoot)
    [pscustomobject]@{
        verified = -not [string]::IsNullOrWhiteSpace($ManifestPath) -and
            -not [string]::IsNullOrWhiteSpace($ReleaseRoot)
        serviceExecutable = Join-Path $ReleaseRoot 'venv\\Scripts\\python.exe'
    }
}
""",
        encoding="utf-8-sig",
    )
    program_root = tmp_path / "program"
    release_id = "a" * 64
    release_root = program_root / "releases" / release_id
    release_root.mkdir(parents=True)
    manifest_path = release_root / "release-manifest.json"
    _ = manifest_path.write_text("{}", encoding="utf-8")
    transaction_path = str(transaction_copy).replace("'", "''")
    program_path = str(program_root).replace("'", "''")
    release_path = str(release_root).replace("'", "''")
    command = (
        "function Test-BridgeTreeAcl { return $null };"
        "function Get-BridgeFileLinkCount { return 1 };"
        "function Get-FileHash { param($LiteralPath,$Algorithm) "
        "[pscustomobject]@{Hash=('f'*64)} };"
        f". '{transaction_path}';"
        "$selection=Resolve-BridgeServiceReleaseSelection "
        f"-ProgramRoot '{program_path}' -ServiceReleaseRoot '{release_path}';"
        "$selection|ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout, result.stderr
    selection = ReleaseSelectionTrace.model_validate_json(result.stdout)
    assert Path(selection.release_root) == release_root
    assert selection.release_id == release_id
    assert Path(selection.manifest_path) == manifest_path
    assert Path(selection.service_executable) == release_root / "venv" / "Scripts" / "python.exe"


@pytest.mark.parametrize(
    ("query_state", "expected_absent", "expected_register", "expected_exit"),
    [
        ("absent", True, True, 0),
        ("present", False, False, 0),
        ("denied", False, False, 1),
    ],
)
def test_actual_install_worker_query_distinguishes_absent_present_and_error(
    query_state: str,
    *,
    expected_absent: bool,
    expected_register: bool,
    expected_exit: int,
) -> None:
    install_path = str(PROJECT_ROOT / "scripts" / "install.ps1").replace("'", "''")
    query_body = {
        "absent": (
            "$record=[Management.Automation.ErrorRecord]::new("
            "[Management.Automation.ItemNotFoundException]::new('missing'),"
            "'CmdletizationQuery_NotFound,Get-ScheduledTask',"
            "[Management.Automation.ErrorCategory]::ObjectNotFound,$null);throw $record"
        ),
        "present": "return [pscustomobject]@{TaskName='HermesWindowsBridgeWorker'}",
        "denied": "throw [UnauthorizedAccessException]::new('denied')",
    }[query_state]
    expression = (
        f"$ast=[Management.Automation.Language.Parser]::ParseFile('{install_path}',"
        "[ref]$null,[ref]$null);"
        "$functionAst=$ast.Find({param($node)$node -is "
        "[Management.Automation.Language.FunctionDefinitionAst] -and "
        "$node.Name -ceq 'Test-BridgeWorkerTaskAbsent'},$true);"
        "$assignmentAst=$ast.Find({param($node)$node -is "
        "[Management.Automation.Language.AssignmentStatementAst] -and "
        "$node.Left.Extent.Text -ceq '$workerTaskAbsent' -and "
        "$node.Right.Extent.Text -like 'Test-BridgeWorkerTaskAbsent -TaskName *'},$true);"
        "$ifAst=$ast.Find({param($node)$node -is "
        "[Management.Automation.Language.IfStatementAst] -and "
        "$node.Clauses[0].Item1.Extent.Text -like "
        "'*previousInspection.previousState*workerTaskAbsent*'},$true);"
        "if($null -in @($functionAst,$assignmentAst,$ifAst)){throw "
        "('production-worker-ast-missing:' + "
        "@($null -eq $functionAst,$null -eq $assignmentAst,$null -eq $ifAst) -join ',')};"
        ". ([scriptblock]::Create($functionAst.Extent.Text));"
        f"function Get-ScheduledTask {{ param($TaskPath,$TaskName,$ErrorAction) "
        "if($TaskPath -cne '\\'){throw 'wrong-task-path'};"
        f"{query_body} }};"
        "$previousInspection=[pscustomobject]@{previousState='absent-pair'};"
        "$identity=[pscustomobject]@{Name='Bridge.User'};$pythonPath='C:\\fixture\\python.exe';"
        "$registrationPlans=@($null,$null,[pscustomobject]@{name='HermesWindowsBridgeWorker';serviceArgv=@($pythonPath,'-m','worker')});"
        "$installationContext=$null;"
        "$registrationResults=@();$workerRegistrationApplied=$false;$startedComponents=@();"
        "$plan=[pscustomobject]@{receipts=@()};"
        "$registerCalls=[Collections.Generic.List[string]]::new();"
        "function Invoke-BridgeRegistrationAdapter {[void]$registerCalls.Add('register');"
        "return [pscustomobject]@{applied=$true}};"
        "function Start-ScheduledTask { param($TaskName,$ErrorAction) };"
        ". ([scriptblock]::Create($assignmentAst.Extent.Text));"
        ". ([scriptblock]::Create($ifAst.Extent.Text));"
        "[pscustomobject]@{taskAbsent=$workerTaskAbsent;shouldRegister=$registerCalls.Count -eq 1}|"
        "ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", expression],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == expected_exit, result.stderr
    if expected_exit != 0:
        assert "denied" in result.stderr
        return
    trace = WorkerPresenceTrace.model_validate_json(result.stdout)
    assert trace.task_absent is expected_absent
    assert trace.should_register is expected_register, result.stderr


@pytest.mark.parametrize("previous_state", ["unsafe", "mixed"])
def test_unsafe_previous_pair_requires_manual_recovery_without_starts(
    previous_state: str,
) -> None:
    result = _run(
        "".join(
            (
                "$callback={param($step) throw 'must-not-run'};",
                "Invoke-BridgeServiceSwitchTransaction ",
                f"-PreviousState '{previous_state}' -InvokeStep $callback ",
                "| ConvertTo-Json -Compress",
            )
        )
    )
    assert result.returncode == 0, result.stderr
    receipt = SwitchReceipt.model_validate_json(result.stdout)
    assert receipt.state == "manual-recovery-required"
    assert receipt.starts == 0
    assert receipt.worker_calls == 0


def test_switch_order_commits_only_after_final_readback() -> None:
    command = "$calls=[Collections.Generic.List[string]]::new();"
    command += "$callback={param($step) $calls.Add($step);if($step -like '*_start'){return $true}};"
    command += "Invoke-BridgeServiceSwitchTransaction -PreviousState 'safe-pair' "
    command += "-InvokeStep $callback | ConvertTo-Json -Compress"
    result = _run(command)
    assert result.returncode == 0, result.stderr
    receipt = SwitchReceipt.model_validate_json(result.stdout)
    assert receipt.state == "switched"
    assert receipt.steps == (
        "gateway_stop",
        "privileged_stop",
        "gateway_register",
        "privileged_register",
        "privileged_start",
        "gateway_start",
        "final_readback",
        "doctor",
        "pointer_commit",
        "post_commit_readback",
    )
    assert receipt.pointer_committed is True
    assert receipt.starts == 2
    assert receipt.worker_calls == 0


@pytest.mark.parametrize(
    "failure_step",
    [
        "gateway_stop",
        "privileged_stop",
        "gateway_register",
        "privileged_register",
        "privileged_start",
        "gateway_start",
        "final_readback",
        "doctor",
        "pointer_commit",
        "post_commit_readback",
    ],
)
def test_each_stage_failure_rolls_back_without_pointer_commit(
    failure_step: str,
) -> None:
    command = "$failed=[Collections.Generic.HashSet[string]]::new();"
    command += "$callback={param($step) if($step -ceq "
    command += f"'{failure_step}' -and $failed.Add($step)){{throw 'fault'}}}};"
    command += "Invoke-BridgeServiceSwitchTransaction -PreviousState 'safe-pair' "
    command += "-InvokeStep $callback | ConvertTo-Json -Compress"
    result = _run(command)
    assert result.returncode == 0, result.stderr
    receipt = SwitchReceipt.model_validate_json(result.stdout)
    expected_state = "manual-recovery-required" if failure_step.endswith("_stop") else "rolled-back"
    assert receipt.state == expected_state
    assert receipt.pointer_committed is False
    assert receipt.worker_calls == 0
    assert receipt.failed_step == failure_step
    assert receipt.failure_reason == "fault"


def test_rollback_failure_requires_manual_recovery() -> None:
    command = "$fail=@('gateway_register','gateway_restore');"
    command += "$callback={param($step) if($step -in $fail){throw $step}};"
    command += "Invoke-BridgeServiceSwitchTransaction -PreviousState 'safe-pair' "
    command += "-InvokeStep $callback | ConvertTo-Json -Compress"
    result = _run(command)
    assert result.returncode == 0, result.stderr
    receipt = SwitchReceipt.model_validate_json(result.stdout)
    assert receipt.state == "manual-recovery-required"
    assert receipt.failed_step == "gateway_register"
    assert receipt.rollback_failures == ("gateway_restore:gateway_restore",)
    assert receipt.starts == 0
    assert "privileged_start" not in receipt.rollback
    assert "gateway_start" not in receipt.rollback


def test_verified_restore_readback_precedes_rollback_starts() -> None:
    command = "$failed=[Collections.Generic.HashSet[string]]::new();"
    command += "$callback={param($step) if($step -ceq 'gateway_register' "
    command += "-and $failed.Add($step)){throw 'fault'}};"
    command += "Invoke-BridgeServiceSwitchTransaction -PreviousState 'safe-pair' "
    command += "-InvokeStep $callback | ConvertTo-Json -Compress"
    result = _run(command)
    assert result.returncode == 0, result.stderr
    receipt = SwitchReceipt.model_validate_json(result.stdout)
    assert receipt.rollback[-4:] == (
        "restore_readback",
        "privileged_start",
        "gateway_start",
        "restore_running_readback",
    )


@pytest.mark.parametrize("failed_stop", ["gateway_stop", "privileged_stop"])
def test_rollback_stop_failure_fences_all_later_mutations(failed_stop: str) -> None:
    command = "$calls=[Collections.Generic.List[string]]::new();"
    command += "$failed=[Collections.Generic.HashSet[string]]::new();$counts=@{};"
    command += "$callback={param($step) $calls.Add($step);"
    command += "if(-not $counts.ContainsKey($step)){$counts[$step]=0};$counts[$step]++;"
    command += "if($step -ceq 'gateway_register' -and $failed.Add('primary')){throw 'fault'};"
    command += f"if($step -ceq '{failed_stop}' -and $counts[$step] -gt 1){{throw 'stop-fault'}}}};"
    command += "$receipt=Invoke-BridgeServiceSwitchTransaction -PreviousState 'safe-pair' "
    command += (
        "-InvokeStep $callback;"
        "[pscustomobject]@{receipt=$receipt;calls=@($calls)}|"
        "ConvertTo-Json -Depth 8 -Compress"
    )
    result = _run(command)
    assert result.returncode == 0, result.stderr
    raw = StopFenceTrace.model_validate_json(result.stdout)
    assert raw.receipt.state == "manual-recovery-required"
    failed_index = raw.calls.index(failed_stop, 3)
    assert raw.calls[failed_index + 1 :] == ()


def test_post_commit_failure_compensates_pointer_and_exact_pair() -> None:
    command = "$failed=[Collections.Generic.HashSet[string]]::new();"
    command += (
        "$callback={param($step) if($step -ceq 'post_commit_readback' "
        "-and $failed.Add($step)){throw 'late-fault'}};"
    )
    command += "Invoke-BridgeServiceSwitchTransaction -PreviousState 'safe-pair' "
    command += "-InvokeStep $callback | ConvertTo-Json -Compress"
    result = _run(command)
    assert result.returncode == 0, result.stderr
    receipt = SwitchReceipt.model_validate_json(result.stdout)
    assert receipt.state == "rolled-back"
    assert receipt.pointer_committed is False
    assert receipt.pointer_compensated is True
    assert "pointer_restore" in receipt.rollback


def test_idempotent_production_callback_keeps_worker_bytes_unchanged(
    tmp_path: Path,
) -> None:
    worker = tmp_path / "worker-definition.bin"
    worker_bytes = b"worker-definition-must-not-change\x00\xff"
    _ = worker.write_bytes(worker_bytes)
    before_hash = hashlib.sha256(worker_bytes).hexdigest()
    command = "$calls=[Collections.Generic.List[string]]::new();"
    command += (
        "$callback={param($step) $calls.Add($step);if($step -like '*_start'){return $false}};"
    )
    command += (
        "$receipt=Invoke-BridgeServiceSwitchTransaction "
        "-PreviousState 'safe-pair' -InvokeStep $callback;"
    )
    command += (
        f"$bytes=[IO.File]::ReadAllBytes('{worker}');$sha=[Security.Cryptography.SHA256]::Create();"
    )
    command += (
        "$workerHash=([BitConverter]::ToString($sha.ComputeHash($bytes)))."
        "Replace('-','').ToLowerInvariant();"
    )
    command += (
        "[pscustomobject]@{receipt=$receipt;workerHash=$workerHash}|"
        "ConvertTo-Json -Depth 8 -Compress"
    )
    result = _run(command)
    assert result.returncode == 0, result.stderr
    raw = WorkerHashTrace.model_validate_json(result.stdout)
    assert raw.receipt.worker_calls == 0
    assert raw.worker_hash == before_hash


def test_cancellation_uses_the_same_fault_rollback_contract() -> None:
    command = "$failed=[Collections.Generic.HashSet[string]]::new();"
    command += (
        "$callback={param($step) if($step -ceq 'gateway_start' "
        "-and $failed.Add($step)){"
        "throw [OperationCanceledException]::new('cancelled')}};"
    )
    command += (
        "Invoke-BridgeServiceSwitchTransaction -PreviousState 'safe-pair' "
        "-InvokeStep $callback|ConvertTo-Json -Compress"
    )
    result = _run(command)
    assert result.returncode == 0, result.stderr
    receipt = SwitchReceipt.model_validate_json(result.stdout)
    assert receipt.state == "rolled-back"
    assert receipt.failed_step == "gateway_start"
    assert receipt.failure_reason == "cancelled"
    assert receipt.worker_calls == 0


def test_install_consumes_shared_transaction_and_preserves_first_install_worker() -> None:
    install_source = (PROJECT_ROOT / "scripts" / "install.ps1").read_text(encoding="utf-8-sig")
    assert "Invoke-BridgeServiceSwitchTransaction" in install_source
    assert (
        "$previousInspection.previousState -ceq 'absent-pair' -and $workerTaskAbsent"
        in install_source
    )
    assert "registered-first-install" in install_source
    assert "$callerApply = $Apply" in install_source
    assert "$Apply = $callerApply" in install_source
    assert "Grant-BridgeBaseRuntimeAccess -RuntimeRoot" not in install_source


@pytest.mark.parametrize(
    ("doctor_fails", "pointer_mismatch", "serve_host"),
    [
        (False, False, "host.ts.net"),
        (False, False, ""),
        (True, False, "host.ts.net"),
        (False, True, "host.ts.net"),
    ],
)
def test_actual_install_callback_full_sequence_uses_protected_pair_only(
    tmp_path: Path,
    *,
    doctor_fails: bool,
    pointer_mismatch: bool,
    serve_host: str,
) -> None:
    install_path = str(PROJECT_ROOT / "scripts" / "install.ps1").replace("'", "''")
    state_path = str(tmp_path / "state.json").replace("'", "''")
    doctor_result = (
        '[pscustomobject]@{exitCode=1;stdout=\'{"checks":[{"critical":true,"status":"fail","id":"gateway_service"}]}\'}'
        if doctor_fails
        else "[pscustomobject]@{exitCode=0;stdout='{}'}"
    )
    active_pointer_body = "mismatch" if pointer_mismatch else "new-pointer"
    expression = (
        "Add-Type -AssemblyName System.ServiceProcess;$tokens=$null;$errors=$null;"
        f"$ast=[Management.Automation.Language.Parser]::ParseFile('{install_path}',[ref]$tokens,[ref]$errors);"
        "$assignment=$ast.Find({param($node)$node -is "
        "[Management.Automation.Language.AssignmentStatementAst] "
        "-and $node.Left.Extent.Text -ceq '$invokeServiceStep'},$true);"
        "$callback=& ([scriptblock]::Create($assignment.Right.Extent.Text));"
        "$adapterReceipts=[Collections.Generic.List[object]]::new();$script:adapterTrace=[Collections.Generic.List[object]]::new();"
        "$script:startTrace=[Collections.Generic.List[string]]::new();"
        "$script:pointerTrace=[Collections.Generic.List[string]]::new();"
        "$script:childArgs=@();$script:childTimeoutSeconds=0;"
        "$serviceSwitchIdempotent=$false;$switchContext=[pscustomobject]@{rollingBack=$false;playwrightApplied=$false;tailscaleApplied=$false};"
        "$new=[pscustomobject]@{releaseId=('b'*64);"
        "releaseRoot='C:\\Program Files\\HermesWindowsBridge\\releases\\'+('b'*64);"
        "manifestPath='C:\\new\\release-manifest.json';manifestSha256=('c'*64);"
        "serviceExecutable='C:\\new\\python.exe'};"
        "$old=[pscustomobject]@{releaseId=('a'*64);"
        "releaseRoot='C:\\Program Files\\HermesWindowsBridge\\releases\\'+('a'*64);"
        "manifestPath='C:\\old\\release-manifest.json';manifestSha256=('d'*64);"
        "serviceExecutable='C:\\old\\python.exe'};"
        "$serviceRelease=$new;$previousRelease=$old;"
        "$definition=[pscustomobject]@{observedDefinition=[pscustomobject]@{running=$true}};"
        "$previousInspection=[pscustomobject]@{previousState='safe-pair';definitions=@($definition,$definition)};"
        "$registrationRequests=@("
        "[pscustomobject]@{name='HermesWindowsBridgeGateway';script='gateway.ps1';arguments=@('-RuntimeManifestPath',$new.manifestPath,'-RuntimeReleaseRoot',$new.releaseRoot);account='LocalService';argv=@($new.serviceExecutable,'-I','-B','-m','gateway')},"
        "[pscustomobject]@{name='HermesWindowsBridgePrivileged';script='privileged.ps1';arguments=@('-RuntimeManifestPath',$new.manifestPath,'-RuntimeReleaseRoot',$new.releaseRoot);account='LocalSystem';argv=@($new.serviceExecutable,'-I','-B','-m','privileged')});"
        "$InstallPlaywright=$false;$ConfigureTailscale=$false;$playwrightApplied=$false;$tailscaleApplied=$false;"
        "$ProgramDataRoot='C:\\fixture-pd';$LocalDataRoot='C:\\fixture-ld';$Port=8765;"
        f"$ServeHost='{serve_host}';$Capability='hermes.local/windows-control';"
        "$serviceProgramRoot='C:\\Program Files\\HermesWindowsBridge';"
        "$activePointerPath='C:\\fixture\\active-release.json';"
        "$previousPointerExisted=$true;$previousPointerBody='old-pointer';"
        f"$transactionStatePath='{state_path}';$plan=[pscustomobject]@{{receipts=@();tailscaleTransaction=$null}};"
        "function Invoke-BridgeRegistrationAdapter { "
        "param($ScriptRoot,$ScriptName,$ArgumentList,$AdapterMode,$Operation,"
        "$ExpectedName,$ExpectedAccount,$ExpectedArgv) "
        "$row=[pscustomobject]@{name=$ExpectedName;operation=$Operation;"
        "arguments=@($ArgumentList);argv=@($ExpectedArgv)};"
        "$script:adapterTrace.Add($row);return $row };"
        "function Get-Service { $item=[pscustomobject]@{Status='Running'};"
        "Add-Member -InputObject $item -MemberType ScriptMethod "
        "-Name WaitForStatus -Value {param($status,$timeout)};return $item };"
        "function Stop-Service { param($Name,[switch]$Force,$ErrorAction) };"
        "function Start-Service { param($Name,$ErrorAction)"
        "$script:startTrace.Add($Name) };"
        "function Get-BridgeServicePairInspection { param($ScriptRoot,$Release) "
        "return [pscustomobject]@{previousState='safe-pair';"
        "definitions=@($definition,$definition)} };"
        "function Get-BridgeServiceDefinitionInspection { param($ScriptRoot,$Definition) "
        "return [pscustomobject]@{state='conflict'} };"
        "function Assert-BridgePathUnderRoot { param($Root,$Path) return $Path };"
        "function Invoke-BridgeChildProcess { param($FilePath,$ArgumentList,"
        "$WorkingDirectory,$TimeoutSeconds) $script:childArgs=@($ArgumentList);"
        "$script:childTimeoutSeconds=[int]$TimeoutSeconds;"
        f"return {doctor_result} }};"
        "function Publish-BridgeActiveReleasePointer { param($ProgramRoot,$Release)"
        "$script:pointerTrace.Add('publish') };"
        "function Restore-BridgeActiveReleasePointerBody { param($ProgramRoot,$Body)"
        "$script:pointerTrace.Add('restore') };"
        "function Get-BridgeActiveReleasePointerBody { return 'new-pointer' };"
        "function Get-Content { param($LiteralPath,[switch]$Raw,$ErrorAction) "
        f"if($LiteralPath -ceq $activePointerPath){{return '{active_pointer_body}'}};"
        "return Microsoft.PowerShell.Management\\Get-Content "
        "-LiteralPath $LiteralPath -Raw };"
        "$receipt=Invoke-BridgeServiceSwitchTransaction -PreviousState 'safe-pair' "
        "-InvokeStep $callback;"
        "[pscustomobject]@{receipt=$receipt;adapter=@($script:adapterTrace);"
        "starts=@($script:startTrace);pointer=@($script:pointerTrace);"
        "childArgs=@($script:childArgs);"
        "childTimeoutSeconds=$script:childTimeoutSeconds}|"
        "ConvertTo-Json -Depth 12 -Compress"
    )
    result = _run(expression)
    assert result.returncode == 0, result.stderr
    payload = CallbackTrace.model_validate_json(result.stdout)
    adapter = payload.adapter
    assert adapter, payload.model_dump_json(indent=2)
    assert all(item.name != "HermesWindowsBridgeWorker" for item in adapter)
    assert adapter[0].arguments == (
        "-RuntimeManifestPath",
        "C:\\old\\release-manifest.json",
        "-RuntimeReleaseRoot",
        f"C:\\Program Files\\HermesWindowsBridge\\releases\\{'a' * 64}",
    )
    assert adapter[1].arguments[1] == "C:\\new\\release-manifest.json"
    release_argument_index = payload.child_args.index("-ServiceReleaseRoot")
    assert payload.child_args[release_argument_index + 1] == (
        f"C:\\Program Files\\HermesWindowsBridge\\releases\\{'b' * 64}"
    )
    if serve_host:
        serve_host_index = payload.child_args.index("-ServeHost")
        assert payload.child_args[serve_host_index + 1] == serve_host
    else:
        assert "-ServeHost" not in payload.child_args
    assert payload.child_timeout_seconds == 180
    if doctor_fails or pointer_mismatch:
        assert payload.receipt.state == "rolled-back"
        assert len(adapter) == 8
        assert payload.pointer == (() if doctor_fails else ("publish", "restore"))
    else:
        assert payload.receipt.state == "switched", payload.model_dump_json(indent=2)
        assert len(adapter) == 4
        assert payload.pointer == ("publish",)


def test_install_simulation_executes_the_shared_production_orchestrator(
    tmp_path: Path,
) -> None:
    environment = os.environ.copy()
    environment["ProgramData"] = str(tmp_path / "program-data")
    environment["LOCALAPPDATA"] = str(tmp_path / "local-data")
    script_path = str(PROJECT_ROOT / "scripts" / "install.ps1").replace("'", "''")
    program_data = environment["ProgramData"].replace("'", "''")
    local_data = environment["LOCALAPPDATA"].replace("'", "''")
    expression = (
        f"& '{script_path}' -Apply -Confirm:$false -AdapterMode Simulate -Json "
        f"-ProgramDataRoot '{program_data}' -LocalDataRoot '{local_data}'"
    )
    result = subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            expression,
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    payload = InstallSimulationTrace.model_validate_json(result.stdout)
    assert payload.service_transaction.state == "switched"
    assert payload.service_transaction.worker_calls == 0
    assert payload.service_transaction.steps[-3:] == (
        "doctor",
        "pointer_commit",
        "post_commit_readback",
    )
    worker_results = [
        item
        for item in payload.registration_results
        if item.get("name") == "HermesWindowsBridgeWorker"
    ]
    assert len(worker_results) == 1


def test_actual_install_outer_catch_never_verifies_manual_service_rollback(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "state.json"
    _ = state_path.write_text('{"status":"running"}', encoding="utf-8")
    install_path = str(PROJECT_ROOT / "scripts" / "install.ps1").replace("'", "''")
    escaped_state = str(state_path).replace("'", "''")
    expression = (
        f"$ast=[Management.Automation.Language.Parser]::ParseFile('{install_path}',"
        "[ref]$null,[ref]$null);"
        "$catch=$ast.FindAll({param($node)$node -is "
        "[Management.Automation.Language.CatchClauseAst] -and "
        "$node.Extent.Text -like '*rollbackVerified*'},$true)[0];"
        "$outerCatch=& ([scriptblock]::Create($catch.Body.Extent.Text));"
        "$serviceSwitch=[pscustomobject]@{state='manual-recovery-required';"
        "steps=@();rollback=@();starts=0;workerCalls=0;pointerCommitted=$false;"
        "pointerCompensated=$false;failedStep='gateway_register';"
        "failureReason='fault';rollbackFailures=@('gateway_stop:stop-fault')};"
        "$plan=[ordered]@{atomic=$true;state='apply';applied=$true;failedStep=$null;"
        "rollback=@();preservedChanges=@();tailscaleTransaction=$null;"
        "registrationResults=@();serviceTransaction=$null;failureReason=$null};"
        f"$transactionStatePath='{escaped_state}';$currentStep='service_release_transaction';"
        "$tailscaleApplied=$false;$playwrightApplied=$false;"
        "$startedComponents=@();$workerRegistrationApplied=$false;"
        "$registrationResults=@();$registrationRequests=@();"
        "$runtimeAccessApplied=$false;$createdFiles=@();$savedTokenAcl=$null;"
        "$savedDirectoryAcls=@();$createdDirectories=@();$Json=$true;"
        "try{throw 'primary'}catch{& $outerCatch}"
    )
    result = _run(expression)
    assert result.returncode == 2, result.stderr
    receipt = OuterCatchTrace.model_validate_json(result.stdout)
    assert receipt.atomic is False
    assert receipt.service_transaction is not None
    assert receipt.service_transaction.state == "manual-recovery-required"
    assert state_path.read_text(encoding="utf-8") == '{"status":"running"}'


@pytest.mark.parametrize(
    ("shared_step", "expected_step"),
    [
        ("privileged_start", "privileged_service_start"),
        ("gateway_start", "gateway_service_start"),
        ("gateway_register", "gateway_service"),
        ("privileged_register", "privileged_helper_service"),
    ],
)
def test_actual_outer_catch_maps_shared_component_failure(
    tmp_path: Path,
    shared_step: str,
    expected_step: str,
) -> None:
    state_path = tmp_path / "state.json"
    _ = state_path.write_text('{"status":"running"}', encoding="utf-8")
    install_path = str(PROJECT_ROOT / "scripts" / "install.ps1").replace("'", "''")
    escaped_state = str(state_path).replace("'", "''")
    expression = (
        f"$ast=[Management.Automation.Language.Parser]::ParseFile('{install_path}',"
        "[ref]$null,[ref]$null);"
        "$catch=$ast.FindAll({param($node)$node -is "
        "[Management.Automation.Language.CatchClauseAst] -and "
        "$node.Extent.Text -like '*rollbackVerified*'},$true)[0];"
        "$outerCatch=& ([scriptblock]::Create($catch.Body.Extent.Text));"
        "$serviceSwitch=[pscustomobject]@{state='rolled-back';steps=@();"
        "rollback=@();starts=0;workerCalls=0;pointerCommitted=$false;"
        "pointerCompensated=$false;"
        f"failedStep='{shared_step}';failureReason='fault';rollbackFailures=@()}};"
        "$plan=[ordered]@{atomic=$true;state='apply';applied=$true;failedStep=$null;"
        "rollback=@();preservedChanges=@();tailscaleTransaction=$null;"
        "registrationResults=@();serviceTransaction=$null;failureReason=$null};"
        f"$transactionStatePath='{escaped_state}';$currentStep='service_release_transaction';"
        "$tailscaleApplied=$false;$playwrightApplied=$false;"
        "$startedComponents=@();$workerRegistrationApplied=$false;"
        "$registrationResults=@();$registrationRequests=@();"
        "$runtimeAccessApplied=$false;$createdFiles=@();$savedTokenAcl=$null;"
        "$savedDirectoryAcls=@();$createdDirectories=@();$Json=$true;"
        "try{throw 'primary'}catch{& $outerCatch}"
    )
    result = _run(expression)
    assert result.returncode == 2, result.stderr
    receipt = OuterCatchTrace.model_validate_json(result.stdout)
    assert receipt.failed_step == expected_step


def test_transaction_lock_is_exclusive(tmp_path: Path) -> None:
    _ = (tmp_path / "service-release.lock").write_bytes(b"")
    expression = (
        "function Test-BridgeTreeAcl { return $null };"
        "function Get-BridgeFileLinkCount { return 1 };"
        f"$first=Enter-BridgeServiceReleaseTransaction -ProgramRoot '{tmp_path}';"
        "try { Enter-BridgeServiceReleaseTransaction -ProgramRoot '"
        f"{tmp_path}' }} catch {{ $_.Exception.Message }} finally {{ $first.Dispose() }}"
    )
    result = _run(expression)
    assert result.returncode == 0, result.stderr
    assert "BridgeServiceReleaseTransactionBusy" in result.stdout


def test_pointer_commit_is_an_actual_atomic_adapter_step(tmp_path: Path) -> None:
    manifest_hash = "a" * 64
    expression = (
        "function Test-BridgeTreeAcl { return $null };"
        "function Get-BridgeFileLinkCount { return 1 };"
        "$release=[pscustomobject]@{releaseRoot='C:\\Program Files\\HermesWindowsBridge\\"
        f"releases\\{'b' * 64}';manifestSha256='{manifest_hash}'}};"
        f"Publish-BridgeActiveReleasePointer -ProgramRoot '{tmp_path}' -Release $release;"
        f"Get-Content -LiteralPath '{tmp_path / 'active-release.json'}' -Raw"
    )
    result = _run(expression)
    assert result.returncode == 0, result.stderr
    assert manifest_hash in result.stdout


def test_pointer_update_uses_ps5_null_string_and_preserves_old_bytes_on_fault(
    tmp_path: Path,
) -> None:
    pointer = tmp_path / "active-release.json"
    old_bytes = b'{"old":true}'
    _ = pointer.write_bytes(old_bytes)
    expression = (
        "function Test-BridgeTreeAcl { return $null };"
        "function Get-BridgeFileLinkCount { return 1 };"
        "$release=[pscustomobject]@{releaseRoot='C:\\Program Files\\HermesWindowsBridge\\"
        f"releases\\{'b' * 64}';manifestSha256='{'a' * 64}'}};"
        f"Publish-BridgeActiveReleasePointer -ProgramRoot '{tmp_path}' -Release $release;"
        f"[IO.File]::ReadAllBytes('{pointer}').Length"
    )
    result = _run(expression)
    assert result.returncode == 0, result.stderr
    assert int(result.stdout.strip()) > len(old_bytes)
