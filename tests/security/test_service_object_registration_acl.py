"""Created-service object ACL registration contract."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Final

PROJECT_ROOT: Final = Path(__file__).parents[2]
SCRIPTS_ROOT: Final = PROJECT_ROOT / "scripts"
SECURITY_HELPER: Final = SCRIPTS_ROOT / "service-object-security.ps1"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None


def _evaluate_descriptor(sddl: str) -> bool:
    """Run the shared pure descriptor policy without opening SCM."""
    environment = os.environ.copy()
    environment["HERMES_TEST_SERVICE_SECURITY"] = str(SECURITY_HELPER)
    command = r"""
. $env:HERMES_TEST_SERVICE_SECURITY
$descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($env:HERMES_TEST_SDDL)
[bool](Test-BridgeServiceObjectSecurityDescriptor -Descriptor $descriptor) |
 ConvertTo-Json -Compress
"""
    environment["HERMES_TEST_SDDL"] = sddl
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip() == "true"


def test_service_object_policy_rejects_default_user_defined_control() -> None:
    # Given: SCM 기본 ACL처럼 local authenticated users에 SERVICE_USER_DEFINED_CONTROL을 허용합니다.
    default_like = "O:BAG:BAD:(A;;0x00000100;;;AU)(A;;0x000F01FF;;;SY)(A;;0x000F01FF;;;BA)"

    # When: shared registration policy를 순수 descriptor boundary로 평가합니다.
    actual = _evaluate_descriptor(default_like)

    # Then: doctor와 같은 0x100 change right를 fail closed 합니다.
    assert actual is False


def test_service_object_policy_accepts_canonical_system_administrator_dacl() -> None:
    # Given: 등록기가 새 service에 적용할 SYSTEM/Administrators 전용 DACL입니다.
    canonical = "O:BAG:BAD:(A;;0x000F01FF;;;SY)(A;;0x000F01FF;;;BA)"

    # When: shared registration policy를 순수 descriptor boundary로 평가합니다.
    actual = _evaluate_descriptor(canonical)

    # Then: trusted owner와 exact canonical DACL만 허용합니다.
    assert actual is True


def test_service_object_policy_rejects_untrusted_owner() -> None:
    # Given: DACL은 canonical이어도 object owner가 비신뢰 SID입니다.
    untrusted_owner = "O:ANG:BAD:(A;;0x000F01FF;;;SY)(A;;0x000F01FF;;;BA)"

    # When: shared registration policy를 순수 descriptor boundary로 평가합니다.
    actual = _evaluate_descriptor(untrusted_owner)

    # Then: DACL-only hardening으로 owner failure를 숨기지 않습니다.
    assert actual is False


def test_registration_adapters_set_only_newly_created_service_and_compensate() -> None:
    # Given: production adapters의 source contract를 SCM을 열지 않고 검토합니다.
    gateway = (SCRIPTS_ROOT / "register-gateway-service.ps1").read_text(encoding="utf-8")
    privileged = (SCRIPTS_ROOT / "register-privileged-service.ps1").read_text(encoding="utf-8")

    # When: each create branch and its failure compensation boundary are selected.
    gateway_create = gateway[gateway.index("if ($state -eq 'absent') {") :]
    privileged_create = privileged[privileged.index("if ($state -eq 'absent') {") :]

    # Then: setters are create-only; existing desired services are inspected, never mutated.
    for create_branch in (gateway_create, privileged_create):
        assert "Set-BridgeCreatedServiceObjectProtection" in create_branch
        assert "BridgeCreatedServiceSecurityCleanupFailed" in create_branch
        assert create_branch.index(
            "Set-BridgeCreatedServiceObjectProtection"
        ) < create_branch.index("$manifest.applied = $true")
    assert gateway.count("Set-BridgeCreatedServiceObjectProtection") == 1
    assert privileged.count("Set-BridgeCreatedServiceObjectProtection") == 1


def test_existing_service_security_mismatch_returns_conflict_without_setter() -> None:
    # Given: existing service의 path/account/recovery는 정확하지만 security reader가 false입니다.
    environment = os.environ.copy()
    environment["HERMES_TEST_SCRIPTS"] = str(SCRIPTS_ROOT)
    command = r"""
$scripts=@('register-gateway-service.ps1','register-privileged-service.ps1')
$records=@()
foreach($scriptName in $scripts){
 $path=Join-Path $env:HERMES_TEST_SCRIPTS $scriptName
 $tokens=$null; $errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
 $definition=$ast.Find({param($node)
  $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
  $node.Name -eq 'Get-ServiceDefinitionState'
 },$true)
 . ([scriptblock]::Create($definition.Extent.Text))
 if($scriptName -eq 'register-gateway-service.ps1'){
  Add-Type @'
namespace HermesBridge {
 public static class ServiceRegistrationApi {
  public static bool RecoveryIsExact(string n){return true;}
 }
}
'@
  $account='NT AUTHORITY\LocalService'
 } else {
  Add-Type @'
namespace HermesBridge {
 public static class ServiceRecoveryApi {
  public static bool IsExact(string n){return true;}
 }
}
'@
  $account='LocalSystem'
 }
 function Get-CimInstance {
  [pscustomobject]@{PathName='expected';StartName=$account;StartMode='Auto'}
 }
 function Get-BridgeServiceObjectSecurityState { return $false }
 function Set-BridgeCreatedServiceObjectProtection { throw 'setter-called-for-existing-service' }
 $stateResult=Get-ServiceDefinitionState -Name 'HermesTest' -BinaryPath 'expected' -Account $account
 $records += [pscustomobject]@{script=$scriptName;state=$stateResult}
}
$records | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    # When: normal Register/Inspect state evaluator가 security mismatch를 관찰합니다.
    # Then: setter 없이 양쪽 existing service를 conflict로 fail closed 합니다.
    assert result.returncode == 0, result.stderr
    assert '"state":"conflict"' in result.stdout
    assert result.stdout.count('"state":"conflict"') == 2


def test_created_service_protection_failure_runs_only_created_service_compensation() -> None:
    # Given: actual adapter AST의 create branch에서 protection setter가 실패합니다.
    environment = os.environ.copy()
    environment["HERMES_TEST_SCRIPTS"] = str(SCRIPTS_ROOT)
    command = r"""
$records=@()
$gatewayPath=Join-Path $env:HERMES_TEST_SCRIPTS 'register-gateway-service.ps1'
$gatewayAst=[Management.Automation.Language.Parser]::ParseFile($gatewayPath,[ref]$null,[ref]$null)
$gatewayBranch=@($gatewayAst.FindAll({param($node)
 $node -is [Management.Automation.Language.IfStatementAst] -and
 $node.Clauses[0].Item1.Extent.Text -eq '$state -eq ''absent'''
},$true))[0]
Add-Type @'
namespace HermesBridge {
 public static class ServiceRegistrationApi {
  public static int RemoveCalls;
  public static void Install(string n,string b,string a){}
  public static void Remove(string n){RemoveCalls++;}
 }
}
'@
$state='absent';$binaryPath='expected'
$manifest=[pscustomobject]@{name='HermesTest';account='LocalSystem';applied=$false}
function Set-BridgeCreatedServiceObjectProtection {
 throw [Security.SecurityException]::new('protection-failed')
}
try { . ([scriptblock]::Create($gatewayBranch.Extent.Text)) }
catch { $gatewayError=$_.Exception.Message }
$records += [pscustomobject]@{
 script='gateway';error=$gatewayError;cleanupCalls=[HermesBridge.ServiceRegistrationApi]::RemoveCalls
}

$privilegedPath=Join-Path $env:HERMES_TEST_SCRIPTS 'register-privileged-service.ps1'
$privilegedAst=[Management.Automation.Language.Parser]::ParseFile($privilegedPath,[ref]$null,[ref]$null)
$privilegedBranch=@($privilegedAst.FindAll({param($node)
 $node -is [Management.Automation.Language.IfStatementAst] -and
 $node.Clauses[0].Item1.Extent.Text -eq '$state -eq ''absent'''
},$true))[0]
$script:cleanupCalls=0;$state='absent';$binaryPath='expected'
$manifest=[pscustomobject]@{name='HermesTest';account='LocalSystem';applied=$false}
function Initialize-ServiceRecoveryApi {}
Add-Type @'
namespace HermesBridge {
 public static class ServiceRecoveryApi {
  public static void Configure(string n){}
 }
}
'@
function Set-BridgeCreatedServiceObjectProtection {
 throw [Security.SecurityException]::new('protection-failed')
}
function Get-CimInstance { [pscustomobject]@{Name='HermesTest'} }
function Invoke-CimMethod {
 param($ClassName,$MethodName,$Arguments,$InputObject,$ErrorAction)
 if($MethodName -eq 'Create'){return [pscustomobject]@{ReturnValue=0}}
 $script:cleanupCalls++
 return [pscustomobject]@{ReturnValue=0}
}
try { . ([scriptblock]::Create($privilegedBranch.Extent.Text)) }
catch { $privilegedError=$_.Exception.Message }
$records += [pscustomobject]@{
 script='privileged';error=$privilegedError;cleanupCalls=$script:cleanupCalls
}
$records | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    # When: each production create branch runs with only creation/cleanup seams faked.
    # Then: protection failure calls exactly one cleanup for the newly-created name.
    assert result.returncode == 0, result.stderr
    assert result.stdout.count('"cleanupCalls":1') == 2
    assert result.stdout.count('"error":"protection-failed"') == 2
