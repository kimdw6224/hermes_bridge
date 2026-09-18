"""수동 서비스 복구 journal의 fail-closed 경계를 검증합니다."""

# ruff: noqa: E501

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import ClassVar, Final

import pytest
from pydantic import BaseModel, ConfigDict, Field

ROOT: Final = Path(__file__).parents[2]
RECOVERY_SCRIPT: Final = ROOT / "scripts" / "recover-service-switch.ps1"
POWERSHELL: Final = shutil.which("powershell.exe")
assert POWERSHELL is not None
RELEASE_ID: Final = "a" * 64
MANIFEST_SHA: Final = "b" * 64


class RecoveryReceipt(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)
    applied: bool


class RecoveryTerminal(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)
    status: str
    recovery_verified: bool = Field(alias="recoveryVerified")


def _write_json(path: Path, value: dict[str, object]) -> bytes:
    body = json.dumps(value, separators=(",", ":")).encode("utf-8")
    _ = path.write_bytes(body)
    return body


def _new_fixture(tmp_path: Path, *, recovered: bool = False) -> tuple[Path, Path]:
    data_root = tmp_path / "program-data"
    journal = data_root / "HermesWindowsBridge" / "backups" / ("install-" + "c" * 32)
    journal.mkdir(parents=True)
    _ = (data_root / "HermesWindowsBridge" / "config.yaml").write_text(
        "gateway: fixture\n", encoding="utf-8"
    )
    _ = (data_root / "HermesWindowsBridge" / "policy.yaml").write_text(
        "policy: fixture\n", encoding="utf-8"
    )
    original = json.dumps(
        {"schemaVersion": 1, "status": "running", "startedUtc": "2026-09-09T00:00:00.0000000Z"},
        separators=(",", ":"),
    ).encode("utf-8")
    if recovered:
        _ = (journal / "original-state.json").write_bytes(original)
    else:
        _ = _write_json(
            journal / "state.json",
            {"schemaVersion": 1, "status": "running", "startedUtc": "2026-09-09T00:00:00.0000000Z"},
        )
    definition_bytes = _write_json(
        journal / "service-definitions.json",
        {
            "schemaVersion": 1,
            "releaseId": RELEASE_ID,
            "manifestSha256": MANIFEST_SHA,
            "pairState": "safe-pair",
            "definitions": [
                {
                    "name": "HermesWindowsBridgeGateway",
                    "pathName": "gateway-path",
                    "account": "NT AUTHORITY\\LocalService",
                    "startMode": "Auto",
                    "running": True,
                    "recoveryExact": True,
                },
                {
                    "name": "HermesWindowsBridgePrivileged",
                    "pathName": "privileged-path",
                    "account": "LocalSystem",
                    "startMode": "Auto",
                    "running": True,
                    "recoveryExact": True,
                },
            ],
        },
    )
    service_root = tmp_path / "program-files" / "HermesWindowsBridge"
    service_root.mkdir(parents=True)
    pointer_bytes = _write_json(
        service_root / "active-release.json",
        {
            "schemaVersion": 1,
            "releaseRoot": str(service_root / "releases" / RELEASE_ID),
            "manifestSha256": MANIFEST_SHA,
        },
    )
    if recovered:
        _ = _write_json(
            journal / "state.json",
            {
                "schemaVersion": 1,
                "status": "recovered",
                "recoveryVerified": True,
                "previousReleaseId": RELEASE_ID,
                "previousManifestSha256": MANIFEST_SHA,
                "originalStateFile": "original-state.json",
                "originalStateSha256": hashlib.sha256(original).hexdigest(),
                "recoveredUtc": "2026-09-09T00:01:00.0000000Z",
                "verification": {
                    "activePointerSha256": hashlib.sha256(pointer_bytes).hexdigest(),
                    "serviceDefinitionsSha256": hashlib.sha256(definition_bytes).hexdigest(),
                    "configFingerprint": "f" * 64,
                    "configTrust": "runtime-localservice-modify",
                    "requiredDoctorChecks": [
                        "gateway_service", "privileged_helper_service", "backend_listener", "bearer_auth",
                        "interactive_worker", "token_acl", "tailscale", "protected_service_runtime",
                        "gateway_service_object_acl", "gateway_service_registry_acl",
                        "privileged_service_object_acl", "privileged_service_registry_acl", "privileged_tool_surface",
                    ],
                    "unverifiedCriticalWarnings": ["worker_pipe_acl"],
                },
            },
        )
    return data_root, journal


def _run(command: str, *, data_root: Path) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["ProgramData"] = str(data_root)
    return subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        check=False,
        encoding="utf-8",
        timeout=30,
        env=environment,
    )


def _library_preamble(*, service_root: Path) -> str:
    return rf"""
. '{RECOVERY_SCRIPT}' -LibraryMode
function Test-BridgeRecoveryProtectedPath {{ param($Path) return $true }}
function Test-BridgeRecoveryDataRootBoundary {{ param($DataRoot) return $true }}
function Test-BridgeRecoveryJournalParentBoundary {{ param($Path) return $true }}
function Test-BridgeRecoveryRuntimeFile {{ param($Path,$Paths) return $true }}
function Test-BridgeRecoveryAdministrator {{ return $true }}
function Get-BridgeRecoveryServiceProgramRoot {{ return '{service_root}' }}
function Enter-BridgeRecoveryReadLock {{
    $lock=[pscustomobject]@{{}}; $lock | Add-Member ScriptMethod Dispose {{}}; return $lock
}}
function Get-BridgeRecoveryWorkerFingerprint {{ return 'worker-stable' }}
function Get-BridgeRecoveryServicePairInspection {{
    $defs=@(
        [pscustomobject]@{{name='HermesWindowsBridgeGateway';observedDefinition=[pscustomobject]@{{pathName='gateway-path';account='NT AUTHORITY\LocalService';startMode='Auto';running=$true;recoveryExact=$true}}}},
        [pscustomobject]@{{name='HermesWindowsBridgePrivileged';observedDefinition=[pscustomobject]@{{pathName='privileged-path';account='LocalSystem';startMode='Auto';running=$true;recoveryExact=$true}}}}
    )
    return [pscustomobject]@{{previousState='safe-pair';definitions=$defs}}
}}
function Get-BridgeRecoveryDoctorReport {{
    $ids=@('gateway_service','privileged_helper_service','backend_listener','bearer_auth','interactive_worker','token_acl','tailscale','protected_service_runtime','gateway_service_object_acl','gateway_service_registry_acl','privileged_service_object_acl','privileged_service_registry_acl','privileged_tool_surface')
    $checks=@($ids | ForEach-Object {{ [pscustomobject]@{{id=$_;status='pass';critical=$true}} }})
    $checks += @([pscustomobject]@{{id='transport_policy';status='warn';critical=$true}},[pscustomobject]@{{id='worker_pipe_acl';status='warn';critical=$true}},[pscustomobject]@{{id='privileged_pipe_acl';status='warn';critical=$true}})
    return [pscustomobject]@{{schemaVersion=1;kind='hermes-windows-bridge-doctor';readOnly=$true;securityMode=$true;healthy=$true;checks=$checks}}
}}
"""


def test_validator_accepts_only_protected_recovered_journal(tmp_path: Path) -> None:
    data_root, journal = _new_fixture(tmp_path, recovered=True)
    command = rf"""
. '{RECOVERY_SCRIPT}' -LibraryMode
function Test-BridgeRecoveryProtectedPath {{ param($Path) return $true }}
function Test-BridgeRecoveryDataRootBoundary {{ param($DataRoot) return $true }}
function Test-BridgeRecoveryJournalParentBoundary {{ param($Path) return $true }}
function Test-BridgeRecoveryRuntimeFile {{ param($Path,$Paths) return $true }}
function Get-BridgeRecoveryServiceProgramRoot {{ return '{tmp_path / "program-files" / "HermesWindowsBridge"}' }}
Test-BridgeRecoveredJournal -StatePath '{journal / "state.json"}'
"""
    result = _run(command, data_root=data_root)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "True"


@pytest.mark.parametrize(
    ("identity", "rights", "expected"),
    [
        ("NT AUTHORITY\\LOCAL SERVICE", "Modify", "True"),
        ("BUILTIN\\Users", "WriteData", "False"),
        ("BUILTIN\\Users", "DeleteSubdirectoriesAndFiles", "False"),
        ("BUILTIN\\Users", "ChangePermissions", "False"),
        ("BUILTIN\\Users", "TakeOwnership", "False"),
    ],
)
def test_runtime_parent_boundary_allows_modify_but_rejects_replacement_rights(
    identity: str, rights: str, expected: str
) -> None:
    command = rf"""
. '{RECOVERY_SCRIPT}' -LibraryMode
function Get-Acl {{
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner([Security.Principal.NTAccount]::new('BUILTIN\Administrators'))
    $acl.SetAccessRuleProtection($true,$false)
    $rule=[Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.NTAccount]::new('{identity}'),
        [Security.AccessControl.FileSystemRights]::{rights},
        [Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
    return $acl
}}
Test-BridgeRecoveryJournalParentBoundary -Path 'C:\fixture'
"""
    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        check=False,
        encoding="utf-8",
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected


@pytest.mark.parametrize("scenario", ["wrong-pointer", "inconsistent-baseline", "failed-health"])
def test_recovery_refuses_unverified_live_state(tmp_path: Path, scenario: str) -> None:
    data_root, journal = _new_fixture(tmp_path)
    service_root = tmp_path / "program-files" / "HermesWindowsBridge"
    preamble = _library_preamble(service_root=service_root)
    if scenario == "wrong-pointer":
        pointer = service_root / "active-release.json"
        _ = _write_json(
            pointer,
            {
                "schemaVersion": 1,
                "releaseRoot": str(service_root / "releases" / ("f" * 64)),
                "manifestSha256": MANIFEST_SHA,
            },
        )
    if scenario == "inconsistent-baseline":
        preamble += "function Get-BridgeRecoveryServicePairInspection { return [pscustomobject]@{previousState='mixed';definitions=@()} }\n"
    if scenario == "failed-health":
        preamble += "function Get-BridgeRecoveryDoctorReport { return [pscustomobject]@{schemaVersion=1;kind='hermes-windows-bridge-doctor';readOnly=$true;securityMode=$true;healthy=$true;checks=@()} }\n"
    command = (
        preamble
        + rf"""
try {{ Invoke-BridgeServiceSwitchRecovery -TransactionDirectory '{journal}' -ServeHost 'fixture.ts.net' -Apply | Out-Null; 'unexpected' }} catch {{ $_.Exception.Message }}
"""
    )
    result = _run(command, data_root=data_root)
    assert result.returncode == 0, result.stderr
    assert "unexpected" not in result.stdout
    assert b'"status":"running"' in (journal / "state.json").read_bytes()
    assert not (journal / "original-state.json").exists()


def test_recovery_apply_archives_original_and_atomically_records_terminal_state(
    tmp_path: Path,
) -> None:
    data_root, journal = _new_fixture(tmp_path)
    service_root = tmp_path / "program-files" / "HermesWindowsBridge"
    before = (journal / "state.json").read_bytes()
    command = (
        _library_preamble(service_root=service_root)
        + rf"""
Invoke-BridgeServiceSwitchRecovery -TransactionDirectory '{journal}' -ServeHost 'fixture.ts.net' -Apply | ConvertTo-Json -Compress
"""
    )
    result = _run(command, data_root=data_root)
    assert result.returncode == 0, result.stderr
    receipt = RecoveryReceipt.model_validate_json(result.stdout)
    assert receipt.applied is True
    assert (journal / "original-state.json").read_bytes() == before
    terminal = RecoveryTerminal.model_validate_json((journal / "state.json").read_bytes())
    assert terminal.status == "recovered"
    assert terminal.recovery_verified is True


def test_recovery_read_only_mode_writes_nothing(tmp_path: Path) -> None:
    data_root, journal = _new_fixture(tmp_path)
    service_root = tmp_path / "program-files" / "HermesWindowsBridge"
    before = (journal / "state.json").read_bytes()
    command = (
        _library_preamble(service_root=service_root)
        + rf"""
Invoke-BridgeServiceSwitchRecovery -TransactionDirectory '{journal}' -ServeHost 'fixture.ts.net' | ConvertTo-Json -Compress
"""
    )
    result = _run(command, data_root=data_root)
    assert result.returncode == 0, result.stderr
    assert RecoveryReceipt.model_validate_json(result.stdout).applied is False
    assert (journal / "state.json").read_bytes() == before
    assert not (journal / "original-state.json").exists()


def test_recovery_rejects_changed_journal_and_unsafe_archive_path(tmp_path: Path) -> None:
    data_root, journal = _new_fixture(tmp_path)
    service_root = tmp_path / "program-files" / "HermesWindowsBridge"
    command = (
        _library_preamble(service_root=service_root)
        + rf"""
$validDoctor=${{function:Get-BridgeRecoveryDoctorReport}}
function Get-BridgeRecoveryDoctorReport {{
    [IO.File]::WriteAllText('{journal / "state.json"}','{{"schemaVersion":1,"status":"running","startedUtc":"2026-09-09T00:00:01.0000000Z"}}')
    & $validDoctor
}}
try {{ Invoke-BridgeServiceSwitchRecovery -TransactionDirectory '{journal}' -ServeHost 'fixture.ts.net' -Apply | Out-Null; 'unexpected' }} catch {{ $_.Exception.Message }}
"""
    )
    result = _run(command, data_root=data_root)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "BridgeRecoveryConcurrentStateChanged"
    assert not (journal / "original-state.json").exists()
    unsafe = journal.parent.parent / "outside" / "state.json"
    unsafe.parent.mkdir(parents=True)
    _ = unsafe.write_text("{}", encoding="utf-8")
    validator = rf"""
. '{RECOVERY_SCRIPT}' -LibraryMode
function Test-BridgeRecoveryProtectedPath {{ param($Path) return $false }}
function Test-BridgeRecoveryDataRootBoundary {{ param($DataRoot) return $true }}
function Test-BridgeRecoveryJournalParentBoundary {{ param($Path) return $true }}
function Test-BridgeRecoveryRuntimeFile {{ param($Path,$Paths) return $true }}
Test-BridgeRecoveredJournal -StatePath '{unsafe}'
"""
    invalid = _run(validator, data_root=data_root)
    assert invalid.returncode == 0, invalid.stderr
    assert invalid.stdout.strip() == "False"


def test_directory_pins_block_move_until_disposed(tmp_path: Path) -> None:
    data_root, journal = _new_fixture(tmp_path)
    target = journal.with_name(journal.name + "-moved")
    command = rf"""
. '{RECOVERY_SCRIPT}' -LibraryMode
$paths=[pscustomobject]@{{
    dataRoot='{data_root}'; bridgeRoot='{data_root / "HermesWindowsBridge"}'
    backupsRoot='{journal.parent}'; transactionDirectory='{journal}'
}}
$pins=@(Enter-BridgeRecoveryDirectoryPins -Paths $paths)
try {{
    try {{ [IO.Directory]::Move('{journal}','{target}'); 'moved' }} catch [IO.IOException] {{ 'blocked' }}
}} finally {{
    for($index=$pins.Count-1;$index -ge 0;$index--) {{ $pins[$index].Dispose() }}
}}
[IO.Directory]::Move('{journal}','{target}')
Test-Path -LiteralPath '{target}' -PathType Container
"""
    result = _run(command, data_root=data_root)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["blocked", "True"]


def test_directory_pin_rejects_preexisting_delete_handle(tmp_path: Path) -> None:
    data_root, journal = _new_fixture(tmp_path)
    command = rf"""
. '{RECOVERY_SCRIPT}' -LibraryMode
Initialize-BridgeRecoveryDirectoryPinApi
$native=[HermesBridge.RecoveryDirectoryPin].GetMethod('CreateFile',[Reflection.BindingFlags]'Static,NonPublic')
$arguments=@('{journal}',[uint32]0x10000,[uint32]7,[IntPtr]::Zero,[uint32]3,[uint32]0x02200000,[IntPtr]::Zero)
$existing=$native.Invoke($null,$arguments)
if ($existing.IsInvalid) {{ throw 'DeleteHandleOpenFailed' }}
try {{
    try {{ $unexpected=[HermesBridge.RecoveryDirectoryPin]::Open('{journal}'); $unexpected.Dispose(); 'unexpected' }}
    catch {{ $_.Exception.InnerException.NativeErrorCode }}
}} finally {{ $existing.Dispose() }}
$pin=[HermesBridge.RecoveryDirectoryPin]::Open('{journal}')
try {{ -not $pin.IsInvalid }} finally {{ $pin.Dispose() }}
"""
    result = _run(command, data_root=data_root)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["32", "True"]


def test_archive_and_publish_require_directory_pins(tmp_path: Path) -> None:
    data_root, journal = _new_fixture(tmp_path)
    command = rf"""
. '{RECOVERY_SCRIPT}' -LibraryMode
$paths=[pscustomobject]@{{dataRoot='{data_root}';transactionDirectory='{journal}';originalStatePath='{journal / "original-state.json"}';statePath='{journal / "state.json"}'}}
try {{ Save-BridgeRecoveryOriginalState -Paths $paths -StateBytes ([byte[]](1)) -StateSha256 ('a'*64) -Pins @(); 'unexpected' }} catch {{ $_.Exception.Message }}
try {{ Publish-BridgeRecoveryTerminalState -Paths $paths -Snapshot @{{}} -Body '{{}}' -Pins @(); 'unexpected' }} catch {{ $_.Exception.Message }}
"""
    result = _run(command, data_root=data_root)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "BridgeRecoveryDirectoryPinsRequired",
        "BridgeRecoveryDirectoryPinsRequired",
    ]


def test_runtime_dot_source_preserves_selected_program_root() -> None:
    selected_root = r"C:\Program Files\HermesWindowsBridge"
    command = rf"""
& {{
    param($RuntimePath,$SelectedProgramRoot)
    . $RuntimePath -LibraryMode
    function Resolve-BridgeServiceReleaseSelection {{ param([string]$ProgramRoot) return $ProgramRoot }}
    Resolve-BridgeServiceReleaseSelection -ProgramRoot $SelectedProgramRoot
}} '{ROOT / "scripts" / "service-runtime.ps1"}' '{selected_root}'
"""
    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        check=False,
        encoding="utf-8",
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == selected_root
