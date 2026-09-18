"""서비스 등록의 공백 경로와 SCM readback 계약을 검증합니다."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import ClassVar, Final

import pytest
from pydantic import BaseModel, ConfigDict, Field

_PROJECT_ROOT: Final = Path(__file__).parents[2]
_POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert _POWERSHELL_PATH is not None
_GATEWAY_MODULE: Final = "hermes_windows_bridge.gateway.windows_service"
_PRIVILEGED_MODULE: Final = "hermes_windows_bridge.privileged.main"


class ServiceReadback(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)
    binary_path: str = Field(alias="binaryPath")
    state: str


class ServiceInspection(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)
    state: str
    path_name: str = Field(alias="pathName")
    account: str
    start_mode: str = Field(alias="startMode")
    running: bool
    recovery_exact: bool = Field(alias="recoveryExact")
    snapshot_stable: bool = Field(alias="snapshotStable")


@pytest.mark.parametrize(
    ("script_name", "module", "account"),
    [
        ("register-gateway-service.ps1", _GATEWAY_MODULE, "NT AUTHORITY\\LocalService"),
        ("register-privileged-service.ps1", _PRIVILEGED_MODULE, "LocalSystem"),
    ],
)
@pytest.mark.parametrize("observed", ["exact", "legacy", "unquoted", "extra-argument"])
def test_service_readback_checks_quoted_isolated_definition(
    script_name: str,
    module: str,
    account: str,
    observed: str,
) -> None:
    # Given: 공백이 있는 실행경로와 SCM을 대체하는 고정 조회 결과입니다.
    executable = r"C:\Program Files\Hermes Bridge\venv\Scripts\python.exe"
    expected = f'"{executable}" -I -B -m {module}'
    definitions = {
        "exact": expected,
        "legacy": f'"{executable}" -m {module}',
        "unquoted": f"{executable} -I -B -m {module}",
        "extra-argument": expected + " --unexpected",
    }
    environment = os.environ.copy()
    environment.update(
        HERMES_TEST_SCRIPT=str(_PROJECT_ROOT / "scripts" / script_name),
        HERMES_TEST_EXECUTABLE=executable,
        HERMES_TEST_MODULE=module,
        HERMES_TEST_ACCOUNT=account,
        HERMES_TEST_OBSERVED=definitions[observed],
    )
    command = r"""
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:HERMES_TEST_SCRIPT,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'parse failed'}
$definition=$ast.Find({param($node)
 $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
 $node.Name -eq 'Get-ServiceDefinitionState'
},$true)
. ([scriptblock]::Create($definition.Extent.Text))
Add-Type 'namespace HermesBridge {
 public static class ServiceRegistrationApi {
  public static bool RecoveryIsExact(string name) { return true; }
 }
 public static class ServiceRecoveryApi {
  public static bool IsExact(string name) { return true; }
 }
}'
    function Get-CimInstance {
 param($ClassName,$Filter,$ErrorAction)
 [pscustomobject]@{PathName=$env:HERMES_TEST_OBSERVED;
 StartName=$env:HERMES_TEST_ACCOUNT; StartMode='Auto'}
    }
    function Get-BridgeServiceObjectSecurityState { return $true }
$resolvedExecutable=$env:HERMES_TEST_EXECUTABLE; $runtimeModule=$env:HERMES_TEST_MODULE
$assignments=@($ast.FindAll({param($node)
 $node -is [Management.Automation.Language.AssignmentStatementAst] -and
 $node.Left.Extent.Text -eq '$binaryPath'
},$true))
    if($assignments.Count -ne 3){throw 'inspect/register/remove binary definitions missing'}
foreach($assignment in $assignments){
 . ([scriptblock]::Create($assignment.Extent.Text))
 $state=Get-ServiceDefinitionState -Name 'HermesTest' -BinaryPath $binaryPath `
  -Account $env:HERMES_TEST_ACCOUNT
 [pscustomobject]@{binaryPath=$binaryPath; state=$state} | ConvertTo-Json -Compress
}
"""
    # When: 제품 함수와 Register/Remove의 실제 binaryPath 식을 fake 조회에 적용합니다.
    result = subprocess.run(
        [_POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )

    # Then: 정확한 5항만 desired이며 인자 변조와 잘못된 quoting은 거부됩니다.
    assert result.returncode == 0, result.stderr
    records = [ServiceReadback.model_validate_json(line) for line in result.stdout.splitlines()]
    assert len(records) == 3
    for record in records:
        assert record.binary_path == expected
        assert record.state == ("desired" if observed == "exact" else "conflict")


@pytest.mark.parametrize(
    "script_name",
    ["register-gateway-service.ps1", "register-privileged-service.ps1"],
)
def test_inspect_seam_reads_exact_definition_without_mutation(script_name: str) -> None:
    environment = os.environ.copy()
    environment["HERMES_TEST_SCRIPT"] = str(_PROJECT_ROOT / "scripts" / script_name)
    command = r"""
$ast=[Management.Automation.Language.Parser]::ParseFile($env:HERMES_TEST_SCRIPT,[ref]$null,[ref]$null)
$definition=$ast.Find({param($node)
 $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
 $node.Name -eq 'Get-ServiceDefinitionInspection'
},$true)
. ([scriptblock]::Create($definition.Extent.Text))
Add-Type 'namespace HermesBridge {
 public static class ServiceRegistrationApi {
  public static bool RecoveryIsExact(string n){return true;}
 }
 public static class ServiceRecoveryApi {public static bool IsExact(string n){return true;}}
}'
function Initialize-ServiceRegistrationApi {}
function Initialize-ServiceRecoveryApi {}
    function Get-CimInstance {
 param($ClassName,$Filter,$ErrorAction)
 [pscustomobject]@{PathName='"C:\Program Files\Bridge\python.exe" -I -B -m fixed';
 StartName='LocalSystem';StartMode='Auto';State='Running'}
    }
    function Get-BridgeServiceObjectSecurityState { return $true }
function Stop-Service { throw 'mutation-called' }
function Start-Service { throw 'mutation-called' }
function Invoke-CimMethod { throw 'mutation-called' }
$binary='"C:\Program Files\Bridge\python.exe" -I -B -m fixed'
Get-ServiceDefinitionInspection -Name 'HermesTest' -BinaryPath $binary -Account 'LocalSystem' |
 ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [_POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    inspection = ServiceInspection.model_validate_json(result.stdout)
    assert inspection.state == "desired"
    assert inspection.running is True
    assert inspection.recovery_exact is True
    assert inspection.snapshot_stable is True


@pytest.mark.parametrize(
    "script_name",
    ["register-gateway-service.ps1", "register-privileged-service.ps1"],
)
def test_inspect_rejects_changed_snapshot_binding(script_name: str) -> None:
    environment = os.environ.copy()
    environment["HERMES_TEST_SCRIPT"] = str(_PROJECT_ROOT / "scripts" / script_name)
    command = r"""
$ast=[Management.Automation.Language.Parser]::ParseFile($env:HERMES_TEST_SCRIPT,[ref]$null,[ref]$null)
$definition=$ast.Find({param($node)
 $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
 $node.Name -eq 'Get-ServiceDefinitionInspection'
},$true)
. ([scriptblock]::Create($definition.Extent.Text))
Add-Type 'namespace HermesBridge {
 public static class ServiceRegistrationApi {
  public static bool RecoveryIsExact(string n){return true;}
 }
 public static class ServiceRecoveryApi {public static bool IsExact(string n){return true;}}
}'
function Initialize-ServiceRegistrationApi {}
function Initialize-ServiceRecoveryApi {}
$script:calls=0
function Get-CimInstance { $script:calls++; [pscustomobject]@{
 PathName=if($script:calls -eq 1){'untrusted'}else{'expected'};
 StartName='LocalSystem';StartMode='Auto';State='Running'} }
Get-ServiceDefinitionInspection -Name 'HermesTest' -BinaryPath 'expected' -Account 'LocalSystem' |
 ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [_POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    inspection = ServiceInspection.model_validate_json(result.stdout)
    assert inspection.state == "conflict"
    assert inspection.path_name == "untrusted"
    assert inspection.snapshot_stable is False


@pytest.mark.parametrize(
    "script_name",
    ["register-gateway-service.ps1", "register-privileged-service.ps1"],
)
def test_inspect_propagates_cim_query_failure(script_name: str) -> None:
    environment = os.environ.copy()
    environment["HERMES_TEST_SCRIPT"] = str(_PROJECT_ROOT / "scripts" / script_name)
    command = r"""
$ast=[Management.Automation.Language.Parser]::ParseFile($env:HERMES_TEST_SCRIPT,[ref]$null,[ref]$null)
$definition=$ast.Find({param($node)
 $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
 $node.Name -eq 'Get-ServiceDefinitionInspection'
},$true)
. ([scriptblock]::Create($definition.Extent.Text))
function Initialize-ServiceRegistrationApi {}
function Initialize-ServiceRecoveryApi {}
function Get-CimInstance { [CmdletBinding()]param($ClassName,$Filter) Write-Error 'query-failed' }
try { Get-ServiceDefinitionInspection -Name 'HermesTest' -BinaryPath 'expected' `
 -Account 'LocalSystem' }
catch { $_.Exception.Message; exit 7 }
"""
    result = subprocess.run(
        [_POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 7
    assert "query-failed" in result.stdout
