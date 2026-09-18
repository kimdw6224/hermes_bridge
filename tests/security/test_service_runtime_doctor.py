"""Read-only SCM service-object and registry ACL doctor sensor contract."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import ClassVar, Final, Literal

import pytest
from pydantic import BaseModel, ConfigDict, Field

PROJECT_ROOT: Final = Path(__file__).parents[2]
DOCTOR_PATH: Final = PROJECT_ROOT / "scripts" / "doctor.ps1"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None
_SERVICE_MASKS: Final = (
    "0x00000002", "0x00000010", "0x00000020", "0x00000040", "0x00000100",
    "0x00010000",
    "0x00040000", "0x00080000", "0x20000000", "0x40000000", "0x10000000",
)
_REGISTRY_MASKS: Final = (
    "0x00000002", "0x00000004", "0x00000020", "0x00010000", "0x00040000",
    "0x00080000", "0x40000000", "0x10000000",
)


class CheckResult(BaseModel):
    """Sanitized doctor sensor output parsed at the PowerShell JSON boundary."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    id: str
    status: Literal["pass", "warn", "fail"]
    critical: bool
    detail: str


class AclSensorReport(BaseModel):
    """Independent service-object and registry sensor results."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    service: CheckResult
    registry: CheckResult


class NativeDescriptorRead(BaseModel):
    """Read-only native SCM descriptor-query boundary result."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    result: Literal["verified", "unverified"]
    descriptor_type: str = Field(default="", alias="descriptorType")


class RuntimeDoctorReport(BaseModel):
    """Minimal doctor CLI boundary needed to inspect an explicit candidate result."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    security_mode: bool = Field(alias="securityMode")
    checks: list[CheckResult]


class RuntimeHelperComposition(BaseModel):
    """Current-checkout runtime helper composition observed in PowerShell 5.1."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    child_process_invoker_loaded: bool = Field(alias="childProcessInvokerLoaded")
    release_selection_loaded: bool = Field(alias="releaseSelectionLoaded")
    pair_inspection_loaded: bool = Field(alias="pairInspectionLoaded")


def _run_runtime_sensor(state: str, failure: str = "") -> CheckResult:
    """Execute the protected runtime sensor through its public read-only seams."""
    environment = os.environ.copy()
    environment.update(
        HERMES_TEST_DOCTOR=str(DOCTOR_PATH),
        HERMES_TEST_PAIR_STATE=state,
        HERMES_TEST_RUNTIME_FAILURE=failure,
    )
    command = r"""
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:HERMES_TEST_DOCTOR,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'doctor-parse-failed'}
foreach($name in @('New-CheckResult','Get-ProtectedServiceRuntimeCheck')){
 $definition=$ast.Find({param($node)
  $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
 },$true)
 if($null -eq $definition){throw "required-runtime-sensor-missing:$name"}
 . ([scriptblock]::Create($definition.Extent.Text))
}
function Set-Acl { throw 'unexpected-acl-mutation' }
function Start-Service { throw 'unexpected-service-start' }
function Stop-Service { throw 'unexpected-service-stop' }
function Invoke-BridgeChildProcess { throw 'unexpected-runtime-execution' }
function Resolve-BridgeServiceReleaseSelection {
 param($ProgramRoot,$ServiceReleaseRoot)
 if($env:HERMES_TEST_RUNTIME_FAILURE){
  if($env:HERMES_TEST_RUNTIME_FAILURE -in @('AccessDenied','UnauthorizedAccessException')){
   throw [UnauthorizedAccessException]::new($env:HERMES_TEST_RUNTIME_FAILURE)
  }
  throw [Security.SecurityException]::new($env:HERMES_TEST_RUNTIME_FAILURE)
 }
 $root='C:\Program Files\HermesWindowsBridge\releases\' + ('a' * 64)
 return [pscustomobject]@{releaseRoot=$root;manifestPath=($root + '\release-manifest.json')}
}
function Get-BridgeServicePairInspection {
 param($ScriptRoot,$Release)
 return [pscustomobject]@{previousState=$env:HERMES_TEST_PAIR_STATE;definitions=@()}
}
$root='C:\Program Files\HermesWindowsBridge'
Get-ProtectedServiceRuntimeCheck -Id 'protected_service_runtime_fixture' `
 -ProgramRoot $root -ServiceReleaseRoot '' | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    return CheckResult.model_validate_json(result.stdout)


def test_runtime_sensor_passes_explicit_candidate_without_active_pointer() -> None:
    # Given: install pre-commit 경로의 protected explicit candidate release입니다.
    environment = os.environ.copy()
    environment.update(HERMES_TEST_DOCTOR=str(DOCTOR_PATH))
    command = r"""
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:HERMES_TEST_DOCTOR,[ref]$tokens,[ref]$errors)
foreach($name in @('New-CheckResult','Get-ProtectedServiceRuntimeCheck')){
 $definition=$ast.Find({param($node)
  $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
 },$true)
 . ([scriptblock]::Create($definition.Extent.Text))
}
$script:receivedCandidate=''
function Resolve-BridgeServiceReleaseSelection {
 param($ProgramRoot,$ServiceReleaseRoot)
 $script:receivedCandidate=$ServiceReleaseRoot
 [pscustomobject]@{releaseRoot=$ServiceReleaseRoot;manifestPath='safe-manifest'}
}
function Get-BridgeServicePairInspection { [pscustomobject]@{previousState='safe-pair'} }
$candidate='C:\Program Files\HermesWindowsBridge\releases\' + ('a' * 64)
$root='C:\Program Files\HermesWindowsBridge'
$check=Get-ProtectedServiceRuntimeCheck -Id 'runtime' -ProgramRoot $root `
 -ServiceReleaseRoot $candidate
[pscustomobject]@{candidate=$script:receivedCandidate;check=$check}|ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    # When/Then: candidate는 그대로 public resolver에 전달되고 pointer fallback 없이 pass입니다.
    assert result.returncode == 0, result.stderr
    payload = result.stdout
    assert "active-release.json" not in payload
    assert '"status":"pass"' in payload


@pytest.mark.parametrize("security_mode", [False, True])
def test_doctor_candidate_mode_preserves_json_after_library_helper_load(
    *,
    security_mode: bool,
) -> None:
    # Given: active pointer가 없는 install-precommit candidate CLI invocation입니다.
    sentinel = "SENSITIVE_DOCTOR_SENTINEL_7f3f3a5b"
    candidate = rf"C:\\{sentinel}-outside-protected-release"
    environment = os.environ.copy()
    environment.update(
        HERMES_BRIDGE_TAILSCALE_SERVE_HOST=sentinel,
        HERMES_BRIDGE_ALLOWED_HOSTS=sentinel,
        HERMES_BRIDGE_ALLOWED_ORIGINS=sentinel,
        HERMES_BRIDGE_TOKEN=sentinel,
    )

    # When: 존재하지 않는 candidate와 선택적 Security readback을 요청합니다.
    arguments = [
        POWERSHELL_PATH,
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(DOCTOR_PATH),
        "-ServiceReleaseRoot",
        candidate,
    ]
    if security_mode:
        arguments.append("-Security")
    arguments.append("-Json")
    result = subprocess.run(
        arguments,
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    # Then: 두 경로 모두 JSON과 protected runtime failure를 유지합니다.
    # Sentinel은 stdout/stderr 어느 쪽에도 나타나지 않습니다.
    report = RuntimeDoctorReport.model_validate_json(result.stdout)
    assert report.security_mode is security_mode
    assert "protected_service_runtime" in {check.id for check in report.checks}
    assert candidate not in result.stdout
    assert sentinel not in result.stdout
    assert sentinel not in result.stderr


def test_doctor_runtime_helper_composition_loads_current_checkout_child_invoker() -> None:
    # Given: doctor의 runtime 검증은 현재 checkout helper만 조합해야 합니다.
    environment = os.environ.copy()
    environment["HERMES_TEST_DOCTOR"] = str(DOCTOR_PATH)
    command = r"""
$doctorPath=$env:HERMES_TEST_DOCTOR
$source=[IO.File]::ReadAllText($doctorPath)
$scriptRoot=Split-Path -Parent $doctorPath
$commonPath=Join-Path $scriptRoot 'lifecycle-common.ps1'
$runtimePath=Join-Path $scriptRoot 'service-runtime.ps1'
$transactionPath=Join-Path $scriptRoot 'service-runtime-transaction.ps1'
$expectedCommonPath=@'
$commonHelperPath = Join-Path $PSScriptRoot 'lifecycle-common.ps1'
'@.Trim()
if($source -notmatch [regex]::Escape($expectedCommonPath)){
 throw 'doctor-common-helper-path-missing'
}
if($source -notmatch [regex]::Escape('. $commonHelperPath')){
 throw 'doctor-common-helper-load-missing'
}
. $commonPath
. $runtimePath -LibraryMode
. $transactionPath
$childInvoker=Get-Command Invoke-BridgeChildProcess -ErrorAction SilentlyContinue
$releaseSelector=Get-Command Resolve-BridgeServiceReleaseSelection -ErrorAction SilentlyContinue
$pairInspector=Get-Command Get-BridgeServicePairInspection -ErrorAction SilentlyContinue
[pscustomobject]@{
 childProcessInvokerLoaded=($null -ne $childInvoker)
 releaseSelectionLoaded=($null -ne $releaseSelector)
 pairInspectionLoaded=($null -ne $pairInspector)
}|ConvertTo-Json -Compress
"""

    # When: actual Windows PowerShell 5.1에서 동일한 current-checkout helper chain을 load합니다.
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    # Then: Inspect child seam은 존재하고 candidate code는 load하지 않습니다.
    assert result.returncode == 0, result.stderr
    composition = RuntimeHelperComposition.model_validate_json(result.stdout)
    assert composition.child_process_invoker_loaded is True
    assert composition.release_selection_loaded is True
    assert composition.pair_inspection_loaded is True


def test_host_child_sensor_preserves_contract_values_after_library_dot_source(
    tmp_path: Path,
) -> None:
    # Given: LibraryMode helper가 outer contract parameter와 같은 이름을 선언합니다.
    helper_path = tmp_path / "service-host.ps1"
    _ = helper_path.write_text(
        r"""
param(
  [string]$HostRoot,
  [ValidateSet('gateway','privileged')][string]$Profile,
 [string]$ReleaseRoot,
 [switch]$LibraryMode
)
function Get-BridgeServiceHostContract {
 param(
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$HostRoot,
  [Parameter(Mandatory)][ValidateSet('gateway','privileged')][string]$Profile,
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ReleaseRoot
 )
 [IO.File]::AppendAllText(
  $env:HERMES_TEST_CONTRACT_TRACE,
  ('{0}|{1}|{2}' -f $HostRoot,$Profile,$ReleaseRoot) + [Environment]::NewLine
 )
 $hostExecutable='C:\fixture\host\HermesBridge.ServiceHost.exe'
 $releaseExecutable='C:\fixture\release\venv\Scripts\python.exe'
 [pscustomobject]@{schemaVersion=1;verified=$true;state='verified';hostExecutable=$hostExecutable;releaseExecutable=$releaseExecutable}
}
Set-Content -LiteralPath $env:HERMES_TEST_HELPER_LOAD -Value 'loaded' -NoNewline
""",
        encoding="utf-8",
    )
    command = r"""
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:HERMES_TEST_DOCTOR,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'doctor-parse-failed'}
foreach($name in @('New-CheckResult','Get-ProtectedServiceHostChildCheck')){
 $definition=$ast.Find({param($node)
  $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
 },$true)
 if($null -eq $definition){throw "doctor-function-missing:$name"}
 $source=$definition.Extent.Text
 if($name -eq 'Get-ProtectedServiceHostChildCheck'){
  $expected='$hostHelperPath = Join-Path $PSScriptRoot ''service-host.ps1'''
  if(-not $source.Contains($expected)){throw 'host-helper-binding-anchor-missing'}
  $source=$source.Replace($expected,'$hostHelperPath = $env:HERMES_TEST_HOST_HELPER')
 }
 . ([scriptblock]::Create($source))
}
function Get-CimInstance {
 param([string]$ClassName,[string]$Filter)
 $hostExecutable='C:\fixture\host\HermesBridge.ServiceHost.exe'
 $releaseExecutable='C:\fixture\release\venv\Scripts\python.exe'
 $gatewayHostCommand='"{0}" --profile gateway' -f $hostExecutable
 $privilegedHostCommand='"{0}" --profile privileged' -f $hostExecutable
 $gatewayChildCommand=(
  '"{0}" -I -B -m hermes_windows_bridge.service_child --profile gateway' -f $releaseExecutable
 )
 $privilegedChildCommand=(
  '"{0}" -I -B -m hermes_windows_bridge.service_child --profile privileged' -f $releaseExecutable
 )
 if($ClassName -eq 'Win32_Service'){
  if($Filter -match 'Gateway'){return [pscustomobject]@{State='Running';ProcessId=101}}
  return [pscustomobject]@{State='Running';ProcessId=102}
 }
 if($Filter -eq 'ProcessId=101'){
  return [pscustomobject]@{
   ExecutablePath=$hostExecutable
   CommandLine=$gatewayHostCommand
  }
 }
 if($Filter -eq 'ProcessId=102'){
  return [pscustomobject]@{
   ExecutablePath=$hostExecutable
   CommandLine=$privilegedHostCommand
  }
 }
 if($Filter -eq 'ParentProcessId=101'){
  return [pscustomobject]@{
   ExecutablePath=$releaseExecutable
   CommandLine=$gatewayChildCommand
  }
 }
 if($Filter -eq 'ParentProcessId=102'){
  return [pscustomobject]@{
   ExecutablePath=$releaseExecutable
   CommandLine=$privilegedChildCommand
  }
 }
 throw "unexpected-cim-filter:$Filter"
}
$release=[pscustomobject]@{
 releaseRoot='C:\fixture\release'
 gatewayServiceHostRoot='C:\fixture\host'
 privilegedServiceHostRoot='C:\fixture\host'
}
Get-ProtectedServiceHostChildCheck -Id 'host_child' -Release $release | ConvertTo-Json -Compress
"""
    helper_load_path = tmp_path / "helper-load.txt"
    contract_trace_path = tmp_path / "contract-trace.txt"
    environment = os.environ.copy()
    environment.update(
        HERMES_TEST_DOCTOR=str(DOCTOR_PATH),
        HERMES_TEST_HOST_HELPER=str(helper_path),
        HERMES_TEST_HELPER_LOAD=str(helper_load_path),
        HERMES_TEST_CONTRACT_TRACE=str(contract_trace_path),
    )

    # When: corrected production sensor가 fake helper를 LibraryMode로 dot-source합니다.
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    # Then: helper call input and host-child observation both verify successfully.
    assert result.returncode == 0, result.stderr
    check = CheckResult.model_validate_json(result.stdout)
    assert check.status == "pass", check.detail
    assert check.critical is True
    assert helper_load_path.read_text(encoding="utf-8") == "loaded"
    assert contract_trace_path.read_text(encoding="utf-8").splitlines() == [
        r"C:\fixture\host|gateway|C:\fixture\release",
        r"C:\fixture\host|privileged|C:\fixture\release",
    ]


@pytest.mark.parametrize("state", ["safe-pair"])
def test_protected_runtime_sensor_passes_only_for_verified_desired_pair(state: str) -> None:
    # Given: 공개 transaction helper가 검증한 protected release와 exact desired pair입니다.
    # When: doctor runtime sensor가 read-only public seams를 호출합니다.
    result = _run_runtime_sensor(state)

    # Then: runtime proof가 critical pass가 되며 SCM path나 runtime 실행이 발생하지 않습니다.
    assert result.status == "pass"
    assert result.critical is True


@pytest.mark.parametrize("state", ["absent-pair", "mixed", "unsafe"])
def test_protected_runtime_sensor_fails_for_non_desired_pair(state: str) -> None:
    # Given: absent, mixed, 또는 legacy/conflict SCM pair 상태입니다.
    # When: same protected release로 doctor sensor를 실행합니다.
    result = _run_runtime_sensor(state)

    # Then: 원시 SCM PathName을 노출하거나 후보로 채택하지 않고 fail closed 합니다.
    assert result.status == "fail"
    assert "C:\\Program Files" not in result.detail


@pytest.mark.parametrize(
    "failure",
    [
        "BridgeActiveReleasePointerMissing",
        "BridgeActiveReleaseManifestMismatch",
        "BridgeServiceReleaseUnverified",
    ],
)
def test_protected_runtime_sensor_fails_for_pointer_digest_or_closure_failure(failure: str) -> None:
    # Given: protected pointer, manifest digest, 또는 launch closure 검증이 실패합니다.
    # When: default active-pointer sensor를 실행합니다.
    result = _run_runtime_sensor("safe-pair", failure)

    # Then: details는 fixed category만 포함하고 security proof를 fail closed 합니다.
    assert result.status == "fail"
    assert failure not in result.detail


@pytest.mark.parametrize("failure", ["AccessDenied", "UnauthorizedAccessException"])
def test_protected_runtime_sensor_warns_for_access_or_query_unverified(failure: str) -> None:
    # Given: read-only pointer/SCM query 권한이 없는 상태입니다.
    # When: doctor sensor를 실행합니다.
    result = _run_runtime_sensor("safe-pair", failure)

    # Then: pass를 가정하지 않고 stable unverified category를 반환합니다.
    assert result.status == "warn"
    assert "unverified" in result.detail
    assert failure not in result.detail


def _run_acl_sensor(
    service_sddl: str, registry_sddl: str, outcome: str = "verified"
) -> AclSensorReport:
    """Execute doctor functions through a PowerShell 5.1 fake OS-reader boundary."""
    environment = os.environ.copy()
    environment.update(
        HERMES_TEST_DOCTOR=str(DOCTOR_PATH),
        HERMES_TEST_SERVICE_SDDL=service_sddl,
        HERMES_TEST_REGISTRY_SDDL=registry_sddl,
        HERMES_TEST_ACL_OUTCOME=outcome,
    )
    command = r"""
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:HERMES_TEST_DOCTOR,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'doctor-parse-failed'}
$names=@(
 'New-CheckResult', 'Test-BridgeDangerousServiceAccessMask',
 'Test-BridgeDangerousRegistryAccessMask', 'Get-BridgeAclDescriptorAssessment',
 'Get-BridgeServiceObjectAclCheck', 'Get-BridgeServiceRegistryAclCheck'
)
foreach($name in $names){
 $definition=$ast.Find({param($node)
  $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
 },$true)
 if($null -eq $definition){throw "required-acl-sensor-missing:$name"}
 . ([scriptblock]::Create($definition.Extent.Text))
}
function Set-Acl { throw 'unexpected-acl-mutation' }
function Start-Service { throw 'unexpected-service-start' }
function Stop-Service { throw 'unexpected-service-stop' }
function New-Service { throw 'unexpected-service-registration' }
function Get-BridgeServiceSecurityDescriptor {
 param([string]$Name)
 if($env:HERMES_TEST_ACL_OUTCOME -eq 'unverified'){
  return [pscustomobject]@{result='unverified';descriptor=$null}
 }
 if($env:HERMES_TEST_ACL_OUTCOME -eq 'malformed'){
  return [pscustomobject]@{result='verified';descriptor='malformed-descriptor'}
 }
 $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($env:HERMES_TEST_SERVICE_SDDL)
 return [pscustomobject]@{result='verified';descriptor=$descriptor}
}
function Get-BridgeServiceRegistrySecurityDescriptor {
 param([string]$Name)
 if($env:HERMES_TEST_ACL_OUTCOME -eq 'unverified'){
  return [pscustomobject]@{result='unverified';descriptor=$null}
 }
 if($env:HERMES_TEST_ACL_OUTCOME -eq 'malformed'){
  return [pscustomobject]@{result='verified';descriptor='malformed-descriptor'}
 }
 $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($env:HERMES_TEST_REGISTRY_SDDL)
 return [pscustomobject]@{result='verified';descriptor=$descriptor}
}
[pscustomobject]@{
 service=Get-BridgeServiceObjectAclCheck -Id 'service_acl_fixture' `
  -Name 'HermesWindowsBridgeGateway'
 registry=Get-BridgeServiceRegistryAclCheck -Id 'registry_acl_fixture' `
  -Name 'HermesWindowsBridgeGateway'
}|ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    return AclSensorReport.model_validate_json(result.stdout)


def _descriptor(owner: str = "BA", ace: str = "") -> str:
    return f"O:{owner}G:BAD:{ace}"


def test_native_service_descriptor_reader_requests_only_read_control() -> None:
    # Given: 항상 존재하는 Windows EventLog service와 제품의 native reader입니다.
    command = r"""
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:HERMES_TEST_DOCTOR,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'doctor-parse-failed'}
foreach($name in @(
 'Initialize-BridgeDoctorServiceSecurityApi',
 'Get-BridgeServiceSecurityDescriptor'
)){
 $definition=$ast.Find({param($node)
  $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
 },$true)
 if($null -eq $definition){throw "required-native-reader-missing:$name"}
 . ([scriptblock]::Create($definition.Extent.Text))
}
$read=Get-BridgeServiceSecurityDescriptor -Name 'EventLog'
[pscustomobject]@{
 result=[string]$read.result
 descriptorType=if($null -eq $read.descriptor){''}else{$read.descriptor.GetType().FullName}
}|ConvertTo-Json -Compress
"""
    environment = os.environ.copy()
    environment["HERMES_TEST_DOCTOR"] = str(DOCTOR_PATH)

    # When: 실제 Windows PowerShell 5.1 native boundary에서 READ_CONTROL query를 실행합니다.
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    # Then: Windows PowerShell 5.1에서도 READ_CONTROL descriptor를 실제로 읽습니다.
    assert result.returncode == 0, result.stderr
    read = NativeDescriptorRead.model_validate_json(result.stdout)
    assert read.result == "verified"
    assert read.descriptor_type == "System.Security.AccessControl.RawSecurityDescriptor"
    source = DOCTOR_PATH.read_text(encoding="utf-8")
    assert "OpenService($scManager, $Name, [uint32]0x00020000)" in source
    assert "SetServiceObjectSecurity" not in source


def test_acl_sensors_pass_for_trusted_read_only_descriptors() -> None:
    # Given: SYSTEM/Administrators만 허용한 empty read-only DACL입니다.
    trusted = _descriptor(ace="(A;;0x00000001;;;SY)(A;;0x00000001;;;BA)")

    # When: 실제 doctor 함수가 fake read-only OS reader를 통과합니다.
    report = _run_acl_sensor(trusted, trusted)

    # Then: 두 독립 surface가 critical pass이며 등록/ACL 변경은 호출되지 않습니다.
    assert report.service.status == "pass"
    assert report.registry.status == "pass"
    assert report.service.critical is True
    assert report.registry.critical is True


@pytest.mark.parametrize("mask", _SERVICE_MASKS)
def test_service_acl_sensor_fails_for_each_untrusted_dangerous_allow(mask: str) -> None:
    # Given: 비신뢰 principal에 각 서비스 변경 권한을 허용한 DACL입니다.
    dangerous = _descriptor(ace=f"(A;;{mask};;;BU)")

    # When: service-object sensor를 실행합니다.
    report = _run_acl_sensor(dangerous, _descriptor())

    # Then: raw SDDL 없이 critical failure로 판정합니다.
    assert report.service.status == "fail"
    assert report.service.critical is True
    assert dangerous not in report.service.detail


@pytest.mark.parametrize("mask", _REGISTRY_MASKS)
def test_registry_acl_sensor_fails_for_each_untrusted_dangerous_allow(mask: str) -> None:
    # Given: 비신뢰 principal에 각 Registry 변경 권한을 허용한 DACL입니다.
    dangerous = _descriptor(ace=f"(A;;{mask};;;BU)")

    # When: Registry-key sensor를 실행합니다.
    report = _run_acl_sensor(_descriptor(), dangerous)

    # Then: fixed Registry surface만 critical failure가 됩니다.
    assert report.registry.status == "fail"
    assert report.registry.critical is True


@pytest.mark.parametrize(
    ("service_sddl", "registry_sddl", "expected"),
    [
        ("O:BAG:BAD:NO_ACCESS_CONTROL", _descriptor(), "service"),
        (_descriptor(), "O:BAG:BAD:NO_ACCESS_CONTROL", "registry"),
        (_descriptor(owner="WD"), _descriptor(), "service"),
        (_descriptor(), _descriptor(owner="WD"), "registry"),
    ],
)
def test_acl_sensors_fail_for_null_dacl_or_untrusted_owner(
    service_sddl: str,
    registry_sddl: str,
    expected: Literal["service", "registry"],
) -> None:
    # Given: null DACL 또는 신뢰되지 않은 owner가 포함된 descriptor입니다.
    # When: 두 sensor를 실행합니다.
    report = _run_acl_sensor(service_sddl, registry_sddl)

    # Then: 해당 surface만 security proof를 fail closed 합니다.
    result = report.service if expected == "service" else report.registry
    assert result.status == "fail"
    assert result.critical is True


def test_acl_sensor_ignores_inherit_only_allow_but_not_inherited_effective_allow() -> None:
    # Given: INHERIT_ONLY ACE와 현재 object에 effective인 inherited ACE입니다.
    inherit_only = _descriptor(ace="(A;IO;0x00000002;;;BU)")
    inherited_effective = _descriptor(ace="(A;ID;0x00000002;;;BU)")

    # When: service-object sensor를 각각 실행합니다.
    ignored = _run_acl_sensor(inherit_only, _descriptor())
    effective = _run_acl_sensor(inherited_effective, _descriptor())

    # Then: 현재 object에 적용되지 않는 ACE만 허용하고 inherited effective ACE는 거부합니다.
    assert ignored.service.status == "pass"
    assert effective.service.status == "fail"


def test_acl_sensor_deny_ace_does_not_grant_write_access() -> None:
    # Given: dangerous right를 deny만 하는 비신뢰 principal ACE입니다.
    denied = _descriptor(ace="(D;;0x00000002;;;BU)")

    # When: service-object sensor를 실행합니다.
    report = _run_acl_sensor(denied, _descriptor())

    # Then: deny ACE는 권한 부여가 아니므로 false-positive fail을 만들지 않습니다.
    assert report.service.status == "pass"


@pytest.mark.parametrize(
    ("outcome", "status"),
    [("unverified", "warn"), ("malformed", "fail")],
)
def test_acl_sensor_reports_query_or_malformed_descriptor_without_leaking_error_material(
    outcome: str,
    status: Literal["warn", "fail"],
) -> None:
    # Given: access/query failure 또는 malformed descriptor를 나타내는 fake reader입니다.
    marker = "TOP_SECRET_SDDL_OR_PATH"

    # When: doctor sensor를 실행합니다.
    report = _run_acl_sensor(marker, marker, outcome)

    # Then: query failure는 unverified, malformed descriptor는 fail closed로 반환합니다.
    assert report.service.status == status
    assert report.registry.status == status
    if status == "warn":
        assert "unverified" in report.service.detail
        assert "unverified" in report.registry.detail
    assert marker not in report.service.detail
    assert marker not in report.registry.detail
