"""실제 uninstall 제어흐름의 보호된 제거 경계를 검증합니다."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import ClassVar, Final

import pytest
from pydantic import BaseModel, ConfigDict

ROOT: Final = Path(__file__).parents[2]
POWERSHELL: Final = shutil.which("powershell.exe")
assert POWERSHELL is not None


class RollbackStep(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)
    step: str
    state: str


class UninstallReceipt(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)
    atomic: bool
    state: str
    rollback: tuple[RollbackStep, ...]


@pytest.mark.parametrize(
    "scenario", [
        "safe-pair", "absent-pair", "unsafe", "mixed", "unreadable", "remove-failure",
        "readback-conflict", "rollback-failure", "rollback-inexact",
    ],
)
def test_production_uninstall_authorizes_before_any_removal(
    tmp_path: Path, scenario: str,
) -> None:
    environment = os.environ.copy()
    environment.update(
        HERMES_UNINSTALL_ROOT=str(ROOT / "scripts"),
        HERMES_UNINSTALL_DATA=str(tmp_path),
        HERMES_UNINSTALL_SCENARIO=scenario,
    )
    command = r"""
$source=Get-Content ($env:HERMES_UNINSTALL_ROOT+'/uninstall.ps1') -Raw
$source=$source.Replace('$PSScriptRoot','$env:HERMES_UNINSTALL_ROOT')
$boundary=@'
function Test-BridgeAdministrator {return $true}
function Get-Service {return [pscustomobject]@{Status='Stopped'}}
function Get-ScheduledTask {return [pscustomobject]@{TaskName='HermesWindowsBridgeWorker'}}
function Enter-BridgeServiceReleaseTransaction {
 [Console]::Error.WriteLine('LOCK-ENTER')
 $lock=[pscustomobject]@{}
 $lock | Add-Member ScriptMethod Dispose {[Console]::Error.WriteLine('LOCK-DISPOSE')}
 return $lock
}
function Resolve-BridgeServiceReleaseSelection {
 [Console]::Error.WriteLine('AUTHORITY')
 if($env:HERMES_UNINSTALL_SCENARIO -eq 'unreadable'){throw 'authority-unreadable'}
 return [pscustomobject]@{manifestPath='C:\Protected\release-manifest.json';
 releaseRoot='C:\Protected';serviceExecutable='C:\Protected\python.exe'}
}
function Get-BridgeServicePairInspection {
 [Console]::Error.WriteLine('INSPECT')
 if($script:removals -ge 3){
  $state=if($env:HERMES_UNINSTALL_SCENARIO -eq 'readback-conflict'){
   'mixed'}else{'absent-pair'}
  return [pscustomobject]@{previousState=$state}
 }
 $state=if($env:HERMES_UNINSTALL_SCENARIO -in @(
 'remove-failure','readback-conflict','rollback-failure','rollback-inexact')){
 'safe-pair'}else{$env:HERMES_UNINSTALL_SCENARIO}
 return [pscustomobject]@{previousState=$state}
}
function Invoke-BridgeRegistrationAdapter {
 param($ScriptRoot,$ScriptName,$ArgumentList,$AdapterMode,$Operation,$ExpectedName,$ExpectedAccount,$ExpectedArgv)
 $trace=$Operation.ToUpperInvariant()+':'+$ExpectedName+':'+($ExpectedArgv -join '|')+
 ':'+($ArgumentList -join '|')+':'+$AdapterMode+':'+$ExpectedAccount+':'+$ScriptName
 [Console]::Error.WriteLine($trace)
 if($Operation -eq 'Remove'){
  if($script:removals -eq 2 -and $env:HERMES_UNINSTALL_SCENARIO -in @(
   'remove-failure','rollback-failure','rollback-inexact')){throw 'injected-third-remove-failure'}
  $script:removals++
 }
 if($Operation -eq 'Register' -and $ExpectedName -eq 'HermesWindowsBridgeGateway'){
  if($env:HERMES_UNINSTALL_SCENARIO -eq 'rollback-failure'){throw 'injected-register-failure'}
  if($env:HERMES_UNINSTALL_SCENARIO -eq 'rollback-inexact'){
   return [pscustomobject]@{applied=$true;readBack=[pscustomobject]@{exact=$false}}
  }
 }
 return [pscustomobject]@{applied=$true;readBack=[pscustomobject]@{exact=$true}}
}
function Set-Acl {throw 'unexpected-acl-write'}
function Start-Service {throw 'unexpected-start'}
function Stop-Service {throw 'unexpected-stop'}
$script:removals=0
'@
$marker='$installationContext = Resolve-UninstallInstallationContext'
$source=$source.Replace($marker,$boundary+"`r`n"+$marker)
& ([scriptblock]::Create($source)) -Apply -Confirm:$false -Json `
 -ProgramDataRoot $env:HERMES_UNINSTALL_DATA -LocalDataRoot $env:HERMES_UNINSTALL_DATA
"""
    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command],
        env=environment, capture_output=True, text=True, check=False, timeout=20,
    )
    assert "LOCK-ENTER" in result.stderr
    assert "LOCK-DISPOSE" in result.stderr
    assert result.stderr.index("LOCK-ENTER") < result.stderr.index("AUTHORITY")
    if scenario in {"remove-failure", "readback-conflict", "rollback-failure", "rollback-inexact"}:
        assert result.returncode == 2, result.stderr
        assert result.stderr.index("REMOVE:") < result.stderr.index("LOCK-DISPOSE")
        lines = result.stderr.splitlines()
        removed = [line.removeprefix("REMOVE:") for line in lines if line.startswith("REMOVE:")]
        restored = [
            line.removeprefix("REGISTER:") for line in lines if line.startswith("REGISTER:")
        ]
        successful = removed if scenario == "readback-conflict" else removed[:2]
        assert restored == list(reversed(successful))
        assert result.stderr.rindex("REGISTER:") < result.stderr.index("LOCK-DISPOSE")
        receipt = UninstallReceipt.model_validate_json(result.stdout)
        assert receipt.state == "failed"
        assert len(receipt.rollback) == len(successful)
        failed_restore = scenario in {"rollback-failure", "rollback-inexact"}
        assert receipt.atomic is not failed_restore
        assert [step.state for step in receipt.rollback] == (
            ["rollback-failed", "restored"] if failed_restore else ["restored"] * len(successful)
        )
    elif scenario in {"unsafe", "mixed", "unreadable"}:
        assert result.returncode == 2, result.stderr
        assert "REMOVE:" not in result.stderr
    else:
        assert result.returncode == 0, result.stderr
        assert "REMOVE:HermesWindowsBridgeWorker:" in result.stderr
        assert "|-m|hermes_windows_bridge.worker.main" in result.stderr
        if scenario == "safe-pair":
            assert result.stderr.count("INSPECT") >= 2
            assert "C:\\Protected\\python.exe|-I|-B|-m|" in result.stderr
            assert "-RuntimeManifestPath|C:\\Protected\\release-manifest.json" in result.stderr
        else:
            assert "REMOVE:HermesWindowsBridgeGateway:" not in result.stderr
            assert "REMOVE:HermesWindowsBridgePrivileged:" not in result.stderr
