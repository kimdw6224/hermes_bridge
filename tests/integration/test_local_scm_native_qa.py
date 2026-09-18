"""Native SCM helper의 격리된 사전 적용 동작 회귀를 실행합니다."""
# ruff: noqa: E501
# pyright: reportAny=false

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Final

PROJECT_ROOT: Final = Path(__file__).resolve().parents[2]
NATIVE_PATH: Final = (
    PROJECT_ROOT
    / ".omo"
    / "evidence"
    / "local-scm-20260910"
    / "local-scm-native.ps1"
)
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None


def _run_native(
    command: str,
    *,
    temp_root: Path,
    native_path: Path = NATIVE_PATH,
    extra_environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Windows PowerShell 5에서 helper를 격리된 native fake와 실행합니다."""
    environment = os.environ.copy()
    environment["PSModulePath"] = r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
    environment["HERMES_NATIVE_QA_PATH"] = str(native_path)
    environment["HERMES_NATIVE_QA_ROOT"] = str(temp_root)
    if extra_environment is not None:
        environment.update(extra_environment)
    return subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        cwd=PROJECT_ROOT,
        encoding="utf-8",
        env=environment,
        errors="replace",
        text=True,
        timeout=30,
    )


def test_native_probe_accepts_absent_digest_path_and_leaves_durable_single_receipt(
    tmp_path: Path,
) -> None:
    """실제 probe orchestration이 존재하지 않는 안전 digest 경로와 foreign SCM을 구분합니다."""
    command = r"""
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
namespace HermesBridge.LocalScm {
  public sealed class Snapshot {
    public bool Exists { get; set; } public uint ServiceType { get; set; }
    public uint StartType { get; set; } public string Account { get; set; }
    public string BinaryPath { get; set; } public uint State { get; set; }
    public uint Win32ExitCode { get; set; } public uint ServiceSpecificExitCode { get; set; }
    public uint ProcessId { get; set; } public bool RecoveryEnabled { get; set; }
    public Snapshot() { ServiceType=16; StartType=3; Account=""; BinaryPath=""; State=1; Win32ExitCode=1066; ServiceSpecificExitCode=1001; ProcessId=0; RecoveryEnabled=false; }
  }
  public static class Native {
    static readonly Dictionary<string, Snapshot> Values = new Dictionary<string, Snapshot>();
    public static readonly List<string> Calls = new List<string>(); public static bool ExistingInitially;
    public static void Reset(bool existing) { Values.Clear(); Calls.Clear(); ExistingInitially = existing; }
    public static Snapshot Query(string name) {
      Snapshot value; if (Values.TryGetValue(name, out value)) return value;
      return new Snapshot { Exists = ExistingInitially };
    }
    public static void CreateDemandOwnProcess(string name, string binary, string account) {
      Calls.Add("create:" + name); Values[name] = new Snapshot { Exists=true, Account=account, BinaryPath=binary };
    }
    public static void Start(string name) { Calls.Add("start:" + name); }
    public static void Delete(string name) { Calls.Add("delete:" + name); Values[name] = new Snapshot { Exists=false }; }
    public static void Stop(string name) { Calls.Add("stop:" + name); }
    public static void SetRecovery(string name, bool enabled) { Calls.Add("recovery:" + name); }
  }
}
'@
. $env:HERMES_NATIVE_QA_PATH
$script:LocalScmNativeProgramRoot = $env:HERMES_NATIVE_QA_ROOT
$programRoot = $script:LocalScmNativeProgramRoot
$hostsRoot = Join-Path $programRoot 'hosts'
$digestRoot = Join-Path $hostsRoot ('a' * 64)
$profileRoot = Join-Path $digestRoot 'gateway'
$releaseRoot = Join-Path (Join-Path $programRoot 'releases') ('b' * 64)
$null = New-Item -ItemType Directory -Path $profileRoot -Force
$null = New-Item -ItemType Directory -Path $releaseRoot -Force
$hostExecutable = Join-Path $profileRoot 'HermesBridge.ServiceHost.exe'
$candidate = Join-Path $releaseRoot 'candidate.exe'
[IO.File]::WriteAllBytes($hostExecutable,[byte[]](1,2,3)); [IO.File]::WriteAllBytes($candidate,[byte[]](4,5,6))
$nonce = '11111111-1111-1111-1111-111111111111'
$gateway = "HermesBridgeLocalQa-$nonce-Gateway"; $privileged = "HermesBridgeLocalQa-$nonce-Privileged"
$manifestPath = Join-Path $env:HERMES_NATIVE_QA_ROOT 'manifest.json'
$manifest = [pscustomobject]@{
  nonce=$nonce; serviceNames=@($gateway,$privileged); serviceAccounts=@('NT AUTHORITY\LocalService','LocalSystem');
  manifestPath=$manifestPath; fixtureRoot=$env:HERMES_NATIVE_QA_ROOT; applyAuthorized=$true;
  createdServices=@(); ownershipIntent=@(); ownedCleanupRoots=@(); fixtureOwnedPaths=@(); createdPaths=@(); nativeMutationJournal=@();
  hostDigestRoots=@($digestRoot); releaseRoot=$releaseRoot
}
$manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
$contract = Assert-LocalScmNativeContract -Manifest $manifest -HostContract ([pscustomobject]@{profile='gateway';hostRoot=$profileRoot;hostExecutable=$hostExecutable;releaseRoot=$releaseRoot}) -Identity ([pscustomobject]@{profile='gateway';serviceName=$gateway;account='NT AUTHORITY\LocalService'})
function Assert-LocalScmNativeManifest { param($Manifest,[switch]$Mutation,[switch]$AllowCleanupAfterDeadline) if($Mutation){$script:LocalScmNativeCurrentManifest=$Manifest} }
function Initialize-LocalScmNativeInvalidAnchorPackage { param($Manifest,$Probe) [pscustomobject]@{hostRoot=$Probe.hostPath;hostDigest=('a' * 64);hostExecutable=$hostExecutable} }
function New-LocalScmNativeProcessObserver { param($Manifest,$ChildPath,$ReleaseRoot) [pscustomobject]@{ watcher=$null; records=[Collections.Generic.List[object]]::new(); childHandles=[Collections.Generic.List[object]]::new() } }
function Receive-LocalScmNativeAnyProcessObservation { param($Observer,[int]$TimeoutMilliseconds) @() }
function Close-LocalScmNativeProcessObserver { param($Observer) @() }
$probeHostPath = Join-Path (Join-Path $hostsRoot ('c' * 64)) 'invalid-profile'
$manifest | Add-Member NoteProperty invalidAnchorProbe ([pscustomobject]@{requiresProtectedHost=$true;candidateExecutionForbidden=$true;hostPath=$probeHostPath;candidateChildExecutablePath=$candidate;candidateReleaseRoot=$releaseRoot})
[HermesBridge.LocalScm.Native]::Reset($false)
$receipt = RunInvalidAnchorProbe -Manifest $manifest -Hosts ([pscustomobject]@{})
$durable = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
[HermesBridge.LocalScm.Native]::Reset($true)
$foreignRejected = $false
try { [void](RunInvalidAnchorProbe -Manifest $manifest -Hosts ([pscustomobject]@{})) } catch [Security.SecurityException] { $foreignRejected = $_.Exception.Message -ceq 'LocalScmNativeProbeAlreadyExists' }
[pscustomobject][ordered]@{
  contractProfile=$contract.profile; receiptCount=@($receipt).Count; state=$receipt.state; gatewayRemoved=$receipt.gatewayRemoved;
  calls=@([HermesBridge.LocalScm.Native]::Calls); durableJournal=@($durable.nativeMutationJournal | ForEach-Object { $_.state }); foreignRejected=$foreignRejected
} | ConvertTo-Json -Compress
"""
    result = _run_native(command, temp_root=tmp_path)

    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["contractProfile"] == "gateway"
    assert receipt["receiptCount"] == 1
    assert receipt["state"] == "completed"
    assert receipt["gatewayRemoved"] is True
    assert receipt["durableJournal"] == ["applied", "applied", "applied"]
    assert receipt["foreignRejected"] is True


def test_native_registration_failure_tracks_creation_and_cleanup_preserves_foreign_service(
    tmp_path: Path,
) -> None:
    """등록의 두 번째 native 실패와 cleanup ownership fence를 실제 helper 함수로 확인합니다."""
    command = r"""
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
namespace HermesBridge.LocalScm {
  public sealed class Snapshot {
    public bool Exists { get; set; } public uint ServiceType { get; set; } public uint StartType { get; set; }
    public string Account { get; set; } public string BinaryPath { get; set; } public uint State { get; set; }
    public uint Win32ExitCode { get; set; } public uint ServiceSpecificExitCode { get; set; } public uint ProcessId { get; set; } public bool RecoveryEnabled { get; set; }
    public Snapshot() { ServiceType=16; StartType=3; Account=""; BinaryPath=""; State=1; Win32ExitCode=0; ServiceSpecificExitCode=0; }
  }
  public static class Native {
    static readonly Dictionary<string, Snapshot> Values = new Dictionary<string, Snapshot>();
    public static readonly List<string> Calls = new List<string>(); public static int CreateNumber; public static int FailAt;
    public static void Reset(int failAt) { Values.Clear(); Calls.Clear(); CreateNumber=0; FailAt=failAt; }
    public static void ClearCalls() { Calls.Clear(); }
    public static Snapshot Query(string name) { Snapshot value; return Values.TryGetValue(name, out value) ? value : new Snapshot { Exists=false }; }
    public static void CreateDemandOwnProcess(string name, string binary, string account) { CreateNumber++; Calls.Add("create:" + name); if (CreateNumber == FailAt) throw new InvalidOperationException("fake-second-create"); Values[name]=new Snapshot { Exists=true, Account=account, BinaryPath=binary }; }
    public static void Delete(string name) { Calls.Add("delete:" + name); Values[name]=new Snapshot { Exists=false }; }
    public static void Start(string name) { Calls.Add("start:" + name); } public static void Stop(string name) { Calls.Add("stop:" + name); }
    public static void SetRecovery(string name, bool enabled) { Calls.Add("recovery:" + name); }
    public static void SetForeign(string name) { Values[name].BinaryPath="foreign-binary"; }
  }
}
'@
. $env:HERMES_NATIVE_QA_PATH
$script:LocalScmNativeProgramRoot = $env:HERMES_NATIVE_QA_ROOT
$programRoot=$script:LocalScmNativeProgramRoot; $hostsRoot=Join-Path $programRoot 'hosts'; $releaseRoot=Join-Path (Join-Path $programRoot 'releases') ('d' * 64)
$digestRoot=Join-Path $hostsRoot ('e' * 64); $gatewayRoot=Join-Path $digestRoot 'gateway'; $privilegedRoot=Join-Path $digestRoot 'privileged'
$null=New-Item -ItemType Directory -Path $gatewayRoot,$privilegedRoot,$releaseRoot -Force
$gatewayExe=Join-Path $gatewayRoot 'HermesBridge.ServiceHost.exe'; $privilegedExe=Join-Path $privilegedRoot 'HermesBridge.ServiceHost.exe'
[IO.File]::WriteAllBytes($gatewayExe,[byte[]](1)); [IO.File]::WriteAllBytes($privilegedExe,[byte[]](2))
$nonce='22222222-2222-2222-2222-222222222222'; $gateway="HermesBridgeLocalQa-$nonce-Gateway"; $privileged="HermesBridgeLocalQa-$nonce-Privileged"; $manifestPath=Join-Path $programRoot 'manifest.json'
$gatewayHost=[pscustomobject]@{profile='gateway';hostRoot=$gatewayRoot;hostExecutable=$gatewayExe;releaseRoot=$releaseRoot}; $privilegedHost=[pscustomobject]@{profile='privileged';hostRoot=$privilegedRoot;hostExecutable=$privilegedExe;releaseRoot=$releaseRoot}; $hosts=[pscustomobject]@{hosts=@($gatewayHost,$privilegedHost)}
$childPath=Join-Path $releaseRoot 'child.exe'; [IO.File]::WriteAllBytes($childPath,[byte[]](3))
$scenario=[pscustomobject]@{hosts=@($gatewayHost,$privilegedHost);expectedChildExecutablePath=$childPath;expectedChildPath=$childPath}
$noReady=[pscustomobject]@{hosts=@([pscustomobject]@{profile='gateway';hostExecutable=($gatewayExe + '.noready')},[pscustomobject]@{profile='privileged';hostExecutable=($privilegedExe + '.noready')});expectedChildExecutablePath=$childPath;expectedChildPath=$childPath}
$uncooperative=[pscustomobject]@{hosts=@([pscustomobject]@{profile='gateway';hostExecutable=($gatewayExe + '.uncooperative')},[pscustomobject]@{profile='privileged';hostExecutable=($privilegedExe + '.uncooperative')});expectedChildExecutablePath=$childPath;expectedChildPath=$childPath}
$manifest=[pscustomobject]@{nonce=$nonce;serviceNames=@($gateway,$privileged);serviceAccounts=@('NT AUTHORITY\LocalService','LocalSystem');manifestPath=$manifestPath;fixtureRoot=$programRoot;applyAuthorized=$true;createdServices=@();nativeMutationJournal=@();hostDigestRoots=@($digestRoot);releaseRoot=$releaseRoot;invalidAnchorProbe=[pscustomobject]@{hostPath=$gatewayRoot};scenarioContracts=[pscustomobject]@{healthy=$scenario;noReady=$noReady;uncooperative=$uncooperative}}
$manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
function Assert-LocalScmNativeManifest { param($Manifest,[switch]$Mutation,[switch]$AllowCleanupAfterDeadline) if($Mutation){$script:LocalScmNativeCurrentManifest=$Manifest} }
function Get-CimInstance { param([string]$ClassName,[string]$Filter) if($ClassName -ceq 'Win32_Process'){ return @() } throw "unexpected-cim" }
[HermesBridge.LocalScm.Native]::Reset(0)
$registered=RegisterFixtureServices -Manifest $manifest -Hosts $hosts
$registeredIntents=@($manifest.createdServices | ForEach-Object { [bool]$_.confirmed })
[HermesBridge.LocalScm.Native]::ClearCalls(); [HermesBridge.LocalScm.Native]::SetForeign($gateway)
$privIdentity=Get-LocalScmNativeExpectedServices -Manifest $manifest | Where-Object { $_.profile -ceq 'privileged' }
$privOwned=Test-LocalScmNativeCreatedServiceOwnership -Manifest $manifest -Identity $privIdentity -Snapshot ([HermesBridge.LocalScm.Native]::Query($privileged))
$cleanup=CleanupFixture -Manifest $manifest
$cleanupCalls=@([HermesBridge.LocalScm.Native]::Calls)
$failedManifest=[pscustomobject]@{nonce=$nonce;serviceNames=@($gateway,$privileged);serviceAccounts=@('NT AUTHORITY\LocalService','LocalSystem');manifestPath=(Join-Path $programRoot 'failed-manifest.json');fixtureRoot=$programRoot;applyAuthorized=$true;createdServices=@();nativeMutationJournal=@();hostDigestRoots=@($digestRoot);releaseRoot=$releaseRoot}
$failedManifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $failedManifest.manifestPath -Encoding UTF8
[void]$script:LocalScmNativeMutationJournal.Clear()
[HermesBridge.LocalScm.Native]::Reset(2); $secondFailed=$false
try { [void](RegisterFixtureServices -Manifest $failedManifest -Hosts $hosts) } catch { $secondFailed=$_.Exception.Message -match 'fake-second-create' }
$failureIntents=@($failedManifest.createdServices | ForEach-Object { [pscustomobject]@{attempted=[bool]$_.createAttempted;confirmed=[bool]$_.confirmed} })
$failureJournal=@($failedManifest.nativeMutationJournal | ForEach-Object { $_.state })
[pscustomobject][ordered]@{registeredCount=@($registered.registrations).Count;registeredIntents=$registeredIntents;privOwned=$privOwned;cleanupState=$cleanup.state;cleanupReconciliation=$cleanup.reconciliationRequired;cleanupCalls=$cleanupCalls;cleanupErrors=@($cleanup.errors);secondFailed=$secondFailed;failureIntents=$failureIntents;failureJournal=$failureJournal} | ConvertTo-Json -Compress
"""
    result = _run_native(command, temp_root=tmp_path)

    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["registeredCount"] == 2
    assert receipt["registeredIntents"] == [True, True]
    assert receipt["privOwned"] is True
    assert receipt["cleanupState"] == "partial"
    assert receipt["cleanupReconciliation"] is True
    assert receipt["cleanupCalls"] == [
        "recovery:HermesBridgeLocalQa-22222222-2222-2222-2222-222222222222-Privileged",
        "delete:HermesBridgeLocalQa-22222222-2222-2222-2222-222222222222-Privileged",
    ], json.dumps(receipt, indent=2)
    assert receipt["secondFailed"] is True
    assert receipt["failureIntents"] == [
        {"attempted": True, "confirmed": True},
        {"attempted": True, "confirmed": False},
    ]
    assert receipt["failureJournal"] == ["applied", "unknown"]


def test_native_observer_buffers_out_of_order_children_and_fails_closed_for_wmi_errors(
    tmp_path: Path,
) -> None:
    """두 host 자식의 역순 WMI event와 관련 event 관찰 오류를 helper가 안전히 처리하는지 확인합니다."""
    command = r"""
. $env:HERMES_NATIVE_QA_PATH
$childPath=Join-Path $env:HERMES_NATIVE_QA_ROOT 'candidate.exe'; [IO.File]::WriteAllBytes($childPath,[byte[]](1))
$processId=$PID; $script:events=[Collections.Queue]::new()
function Add-Event([int]$EventProcessId,[int]$Parent,[string]$Name='candidate.exe') { $script:events.Enqueue([pscustomobject]@{Properties=@{ProcessID=[pscustomobject]@{Value=$EventProcessId};ParentProcessID=[pscustomobject]@{Value=$Parent};ProcessName=[pscustomobject]@{Value=$Name}}}) }
$watcher=[pscustomobject]@{}
$watcher | Add-Member ScriptMethod WaitForNextEvent { if($script:events.Count -eq 0){throw [Management.ManagementException]::new([Management.ManagementStatus]::Timedout)}; return $script:events.Dequeue() }
function Get-CimInstance { param([string]$ClassName,[string]$Filter) if($Filter -match '900'){return [pscustomobject]@{ExecutablePath='other.exe'}}; [pscustomobject]@{ExecutablePath=$childPath} }
$observer=[pscustomobject]@{watcher=$watcher;childPath=$childPath;knownParentIds=@(101,202);records=[Collections.Generic.List[object]]::new();pendingRecords=[Collections.Generic.List[object]]::new();ignoredEvents=[Collections.Generic.List[object]]::new();childHandles=[Collections.Generic.List[object]]::new()}
Add-Event -EventProcessId 900 -Parent 909 -Name 'other.exe'; Add-Event -EventProcessId 900 -Parent 101 -Name 'powershell.exe'; Add-Event -EventProcessId $processId -Parent 202; Add-Event -EventProcessId $processId -Parent 101
$gateway=Receive-LocalScmNativeProcessObservation -Observer $observer -ExpectedParentIds @(101) -TimeoutSeconds 1
$privileged=Receive-LocalScmNativeProcessObservation -Observer $observer -ExpectedParentIds @(202) -TimeoutSeconds 1
$script:events=[Collections.Queue]::new(); $deniedWatcher=[pscustomobject]@{}
$deniedWatcher | Add-Member ScriptMethod WaitForNextEvent { throw [Management.ManagementException]::new([Management.ManagementStatus]::AccessDenied) }
$deniedObserver=[pscustomobject]@{watcher=$deniedWatcher;childPath=$childPath;records=[Collections.Generic.List[object]]::new();ignoredEvents=[Collections.Generic.List[object]]::new();childHandles=[Collections.Generic.List[object]]::new()}
$accessDenied=$false
try { [void](Receive-LocalScmNativeAnyProcessObservation -Observer $deniedObserver -TimeoutMilliseconds 1) } catch { $accessDenied=$true }
$script:events=[Collections.Queue]::new(); Add-Event -EventProcessId $processId -Parent 303
function Get-CimInstance { param([string]$ClassName,[string]$Filter) $null }
$unresolvedObserver=[pscustomobject]@{watcher=$watcher;childPath=$childPath;records=[Collections.Generic.List[object]]::new();ignoredEvents=[Collections.Generic.List[object]]::new();childHandles=[Collections.Generic.List[object]]::new()}
$unresolved=$false
try { [void](Receive-LocalScmNativeAnyProcessObservation -Observer $unresolvedObserver -TimeoutMilliseconds 1) } catch [Security.SecurityException] { $unresolved=$_.Exception.Message -ceq 'LocalScmNativeCandidateStartUnresolved' }
foreach($handle in @($observer.childHandles)){ $handle.process.Dispose() }
[pscustomobject][ordered]@{gatewayParent=$gateway.parentProcessId;privilegedParent=$privileged.parentProcessId;recordParents=@($observer.records | ForEach-Object { $_.parentProcessId });pendingCount=$observer.pendingRecords.Count;accessDenied=$accessDenied;unresolved=$unresolved} | ConvertTo-Json -Compress
"""
    result = _run_native(command, temp_root=tmp_path)

    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["gatewayParent"] == 101
    assert receipt["privilegedParent"] == 202
    assert receipt["recordParents"] == [202, 101]
    assert receipt["pendingCount"] == 0
    assert receipt["accessDenied"] is True, receipt
    assert receipt["unresolved"] is True


def test_native_observer_initializes_synchronously_and_releases_prearm_resources(
    tmp_path: Path,
) -> None:
    """Observer 초기화가 sync prearm·ambient 해제·오류 fail-closed 순서를 지키는지 확인합니다."""
    command = r"""
$nativeCopy=Join-Path $env:HERMES_NATIVE_QA_ROOT 'native-with-watcher-seam.ps1'
$source=Get-Content -LiteralPath $env:HERMES_NATIVE_QA_PATH -Raw
$needle='$watcher = [Management.ManagementEventWatcher]::new([Management.WqlEventQuery]::new(''SELECT * FROM Win32_ProcessStartTrace''))'
if(-not $source.Contains($needle)){throw 'NativeWatcherConstructorSeamNotFound'}
$source=$source.Replace($needle,'$watcher = New-LocalScmNativeTestWatcher')
$source | Set-Content -LiteralPath $nativeCopy -Encoding UTF8
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Management;
using System.Reflection;
namespace HermesBridge {
  public sealed class QaWatcherOptions { public TimeSpan Timeout { get; set; } }
  public sealed class QaAmbientEvent : IDisposable { public bool Disposed { get; private set; } public void Dispose() { Disposed = true; } }
  public sealed class QaWatcher {
    public QaWatcherOptions Options { get; private set; }
    public List<string> Calls { get; private set; }
    public string Mode { get; private set; }
    public QaAmbientEvent AmbientEvent { get; private set; }
    public QaWatcher(string mode) { Options = new QaWatcherOptions(); Calls = new List<string>(); Mode = mode; if (mode == "ambient") AmbientEvent = new QaAmbientEvent(); }
    public void Start() { Calls.Add("start"); }
    public void Stop() { Calls.Add("stop"); if (Mode.Contains("stop-throws")) throw new InvalidOperationException("stop-teardown-error"); }
    public void Dispose() { Calls.Add("dispose"); if (Mode.Contains("dispose-throws")) throw new InvalidOperationException("dispose-teardown-error"); }
    private static ManagementException ManagementError(ManagementStatus status, string message) {
      ConstructorInfo constructor = typeof(ManagementException).GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic, null, new Type[] { typeof(ManagementStatus), typeof(string), typeof(ManagementBaseObject) }, null);
      return (ManagementException)constructor.Invoke(new object[] { status, message, null });
    }
    public object WaitForNextEvent() {
      Calls.Add("wait");
      if (Mode == "timeout") throw ManagementError(ManagementStatus.Timedout, "timeout");
      if (Mode == "ambient") return AmbientEvent;
      if (Mode.StartsWith("provider")) throw ManagementError(ManagementStatus.AccessDenied, "provider-error");
      if (Mode.StartsWith("ordinary")) throw new InvalidOperationException("ordinary-prearm-error");
      throw new InvalidOperationException("UnknownObserverMode");
    }
  }
  public static class QaWatcherFactory { public static QaWatcher Create(string mode) { return new QaWatcher(mode); } }
}
'@ -ReferencedAssemblies ([Management.ManagementEventWatcher].Assembly.Location)
$script:LastWatcher=$null
function New-LocalScmNativeTestWatcher { $script:LastWatcher=[HermesBridge.QaWatcherFactory]::Create($script:ObserverMode); return $script:LastWatcher }
. $nativeCopy
function Assert-LocalScmNativeManifest { param($Manifest) }
function Test-LocalScmNativePathUnderRoot { param($Root,$Path) $true }
function Test-LocalScmNativeReparseFree { param($Root,$Path) $true }
$releaseRoot=Join-Path $env:HERMES_NATIVE_QA_ROOT 'release'; $null=New-Item -ItemType Directory -Path $releaseRoot -Force
$childPath=Join-Path $releaseRoot 'candidate.exe'; [IO.File]::WriteAllBytes($childPath,[byte[]](1))
$manifest=[pscustomobject]@{releaseRoot=$releaseRoot}
function Invoke-ObserverInit {
  param([string]$Mode)
  $script:ObserverMode=$Mode; $threw=$false; $message=$null; $observer=$null
  $exceptionType=$null; $innerExceptionType=$null; $innerExceptionMessage=$null
  try { $observer=New-LocalScmNativeProcessObserver -Manifest $manifest -ChildPath $childPath -ReleaseRoot $releaseRoot } catch { $threw=$true; $message=$_.Exception.Message; $exceptionType=$_.Exception.GetType().FullName; if($null -ne $_.Exception.InnerException){$innerExceptionType=$_.Exception.InnerException.GetType().FullName;$innerExceptionMessage=$_.Exception.InnerException.Message} }
  $timeoutMilliseconds=$null
  if($null -ne $script:LastWatcher.Options.Timeout){ $timeoutMilliseconds=[int]$script:LastWatcher.Options.Timeout.TotalMilliseconds }
  $ambientDisposed=$null
  if($null -ne $script:LastWatcher.AmbientEvent){ $ambientDisposed=[bool]$script:LastWatcher.AmbientEvent.Disposed }
  [pscustomobject][ordered]@{
    mode=$Mode; threw=$threw; message=$message; exceptionType=$exceptionType; innerExceptionType=$innerExceptionType; innerExceptionMessage=$innerExceptionMessage; returned=($null -ne $observer); timeoutMilliseconds=$timeoutMilliseconds; calls=@($script:LastWatcher.Calls); ambientDisposed=$ambientDisposed
  }
}
[pscustomobject][ordered]@{timeout=(Invoke-ObserverInit timeout);ambient=(Invoke-ObserverInit ambient);provider=(Invoke-ObserverInit provider);ordinary=(Invoke-ObserverInit ordinary);providerStopThrows=(Invoke-ObserverInit provider-stop-throws);providerDisposeThrows=(Invoke-ObserverInit provider-dispose-throws);providerBothTeardownsThrow=(Invoke-ObserverInit provider-stop-throws-dispose-throws);ordinaryStopThrows=(Invoke-ObserverInit ordinary-stop-throws);ordinaryDisposeThrows=(Invoke-ObserverInit ordinary-dispose-throws)} | ConvertTo-Json -Depth 8 -Compress
"""
    result = _run_native(command, temp_root=tmp_path)

    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["timeout"] == {
        "mode": "timeout",
        "threw": False,
        "message": None,
        "exceptionType": None,
        "innerExceptionType": None,
        "innerExceptionMessage": None,
        "returned": True,
        "timeoutMilliseconds": 250,
        "calls": ["wait"],
        "ambientDisposed": None,
    }, json.dumps(receipt, indent=2)
    assert receipt["ambient"] == {
        "mode": "ambient",
        "threw": False,
        "message": None,
        "exceptionType": None,
        "innerExceptionType": None,
        "innerExceptionMessage": None,
        "returned": True,
        "timeoutMilliseconds": 250,
        "calls": ["wait"],
        "ambientDisposed": True,
    }
    expected_inner_exception_types = {
        "provider": "System.Management.ManagementException",
        "providerStopThrows": "System.Management.ManagementException",
        "providerDisposeThrows": "System.Management.ManagementException",
        "providerBothTeardownsThrow": "System.Management.ManagementException",
        "ordinary": "System.InvalidOperationException",
        "ordinaryStopThrows": "System.InvalidOperationException",
        "ordinaryDisposeThrows": "System.InvalidOperationException",
    }
    for mode, expected_inner_exception_type in expected_inner_exception_types.items():
        outcome = receipt[mode]
        assert outcome["threw"] is True
        assert outcome["returned"] is False
        assert outcome["timeoutMilliseconds"] == 250
        assert outcome["calls"] == ["wait", "stop", "dispose"]
        assert outcome["ambientDisposed"] is None
        assert outcome["exceptionType"] == "System.Management.Automation.MethodInvocationException"
        assert outcome["innerExceptionType"] == expected_inner_exception_type
        expected_message = "provider-error" if mode.startswith("provider") else "ordinary-prearm-error"
        assert outcome["innerExceptionMessage"] == expected_message
        assert "start" not in outcome["calls"]


def test_native_probe_preserves_release_binding_and_partial_digest_ownership(tmp_path: Path) -> None:
    """실제 probe package 함수가 library dot-source 뒤에도 release binding과 생성 digest intent를 보존합니다."""
    command = r"""
$copyRoot=Join-Path $env:HERMES_NATIVE_QA_ROOT 'copied-source'; $nativeCopy=Join-Path $copyRoot '.omo\evidence\local-scm-20260910\local-scm-native.ps1'; $scriptDir=Join-Path $copyRoot 'scripts'
$null=New-Item -ItemType Directory -Path (Split-Path -Parent $nativeCopy),$scriptDir -Force; Copy-Item -LiteralPath $env:HERMES_NATIVE_QA_PATH -Destination $nativeCopy
@'
param([switch]$LibraryMode,[string]$ReleaseRoot)
function Get-BridgeServiceHostContract { param($HostRoot,$Profile,$ReleaseRoot) if([string]::IsNullOrWhiteSpace($ReleaseRoot)){throw [Security.SecurityException]::new('ProbeReleaseRootLost')}; [pscustomobject]@{verified=$true;releaseRoot=$ReleaseRoot} }
function Test-BridgeHostManifest { param($HostRoot,$Profile) $true }
function Get-BridgeHostDigest { param($HostRoot) 'source-digest' }
function Set-BridgeHostProtectedDirectory { param($Path) $null=[IO.Directory]::CreateDirectory($Path); if($env:HERMES_NATIVE_QA_FAIL_TARGET -ceq $Path){throw [IO.IOException]::new('ProbeCopyInjectedFailure')} }
function Test-BridgeHostReparseFree { param($Path) $true }
function Test-BridgeHostAcl { param($Path) $true }
function Get-BridgeHostFileSha256 { param($Path) (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
'@ | Set-Content -LiteralPath (Join-Path $scriptDir 'service-host.ps1') -Encoding UTF8
. $nativeCopy
$script:LocalScmNativeProgramRoot=Join-Path $env:HERMES_NATIVE_QA_ROOT 'program-root'; $hostsRoot=Join-Path $script:LocalScmNativeProgramRoot 'hosts'; $releaseRoot=Join-Path (Join-Path $script:LocalScmNativeProgramRoot 'releases') ('f' * 64); $sourceRoot=Join-Path (Join-Path $hostsRoot ('a' * 64)) 'gateway'
$null=New-Item -ItemType Directory -Path $sourceRoot,$releaseRoot -Force; [IO.File]::WriteAllBytes((Join-Path $sourceRoot 'HermesBridge.ServiceHost.exe'),[byte[]](1,2,3))
function New-Manifest([string]$Name) { $path=Join-Path $env:HERMES_NATIVE_QA_ROOT ($Name + '.json'); $m=[pscustomobject]@{manifestPath=$path;ownershipIntent=@();ownedCleanupRoots=@();fixtureOwnedPaths=@();createdPaths=@()}; $m | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8; return $m }
$target=Join-Path (Join-Path $hostsRoot ('b' * 64)) 'invalid-profile'; $manifest=New-Manifest -Name normal
$probe=[pscustomobject]@{sourceHostRoot=$sourceRoot;hostPath=$target;candidateReleaseRoot=$releaseRoot}
$normal=Initialize-LocalScmNativeInvalidAnchorPackage -Manifest $manifest -Probe $probe
$partialTarget=Join-Path (Join-Path $hostsRoot ('c' * 64)) 'invalid-profile'; $partialManifest=New-Manifest -Name partial; $partialProbe=[pscustomobject]@{sourceHostRoot=$sourceRoot;hostPath=$partialTarget;candidateReleaseRoot=$releaseRoot}; $env:HERMES_NATIVE_QA_FAIL_TARGET=$partialTarget; $partialRejected=$false
try { [void](Initialize-LocalScmNativeInvalidAnchorPackage -Manifest $partialManifest -Probe $partialProbe) } catch [IO.IOException] { $partialRejected=$_.Exception.Message -ceq 'ProbeCopyInjectedFailure' } finally { Remove-Item Env:HERMES_NATIVE_QA_FAIL_TARGET }
$partialParent=Split-Path -Parent $partialTarget; $created=@($partialManifest.ownedCleanupRoots | Where-Object { $_.path -ceq $partialParent -and $_.created -and $_.absentBefore }).Count -eq 1
[pscustomobject][ordered]@{normalHostRoot=$normal.hostRoot;normalDigest=$normal.hostDigest;partialRejected=$partialRejected;partialParentExists=(Test-Path -LiteralPath $partialParent);partialCreatedIntent=$created} | ConvertTo-Json -Compress
"""
    result = _run_native(command, temp_root=tmp_path)

    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["normalHostRoot"].endswith(r"invalid-profile")
    assert receipt["normalDigest"] == "source-digest"
    assert receipt["partialRejected"] is True
    assert receipt["partialParentExists"] is True
    assert receipt["partialCreatedIntent"] is True


def test_native_lifecycle_reuses_healthy_pair_after_absent_branch_and_propagates_callback(
    tmp_path: Path,
) -> None:
    """Lifecycle orchestration이 no-ready 등록과 absent rollback 뒤 healthy post-commit 기준선을 구분합니다."""
    command = r"""
. $env:HERMES_NATIVE_QA_PATH
$nonce='33333333-3333-3333-3333-333333333333'; $gateway="HermesBridgeLocalQa-$nonce-Gateway"; $privileged="HermesBridgeLocalQa-$nonce-Privileged"
$manifest=[pscustomobject]@{nonce=$nonce;serviceNames=@($gateway,$privileged);serviceAccounts=@('NT AUTHORITY\LocalService','LocalSystem');deadlineUtc=([DateTimeOffset]::UtcNow.AddMinutes(3).ToString('o'));nativeMutationJournal=@()}
$gatewayName=[string]$manifest.serviceNames[0]; $privilegedName=[string]$manifest.serviceNames[1]
$events=[Collections.Generic.List[string]]::new()
function Assert-LocalScmNativeManifest { param($Manifest,[switch]$Mutation) }
function Get-LocalScmNativeScenarioContract { param($Manifest,[string]$Mode) [pscustomobject]@{mode=$Mode;releaseRoot=($Mode + '-release');expectedChildPath=($Mode + '-child');expectedChildExecutablePath=($Mode + '-python');hosts=@([pscustomobject]@{profile='gateway';hostRoot='gateway-host'},[pscustomobject]@{profile='privileged';hostRoot='privileged-host'})} }
function Set-LocalScmNativeScenarioRegistration { param($Manifest,$Scenario) $events.Add(('register:' + $Scenario.mode)); [pscustomobject]@{mode=$Scenario.mode} }
function Start-LocalScmNativeFixturePair { param($Manifest,$Hosts,$ChildPath,$ReleaseRoot) $events.Add(('start:' + $Hosts.mode)); [pscustomobject]@{handles=@();childHandles=@();observations=@()} }
function Stop-LocalScmNativeFixturePair { param($Manifest) $events.Add('stop'); [pscustomobject]@{profile='gateway';win32ExitCode=1066;serviceSpecificExitCode=1007} }
function Invoke-LocalScmNativeMutation { param($Action,$ServiceName,$Operation) $events.Add(('mutation:' + $Action)) }
function Wait-LocalScmNativeState { param($Manifest,$ServiceName,$WantedStates,[int]$TimeoutSeconds) [pscustomobject]@{Exists=$true;ServiceType=16;StartType=3;Account='NT AUTHORITY\LocalService';State=1;Win32ExitCode=1066;ServiceSpecificExitCode=1004;ProcessId=0;RecoveryEnabled=$false} }
function Invoke-LocalScmNativeStartFailureScenario { param($Manifest,$Scenario,$Path,$Name) [pscustomobject]@{name=$Name} }
function Invoke-LocalScmNativeCrashRecoveryScenario { param($Manifest,$Scenario,$Hosts) [pscustomobject]@{recoveryEnabled=$true} }
function Get-LocalScmNativeOwnedChildSamples { param($ChildExecutablePath) @([pscustomobject]@{processIds=@()}) }
function Get-LocalScmNativeSnapshot { param($Manifest,$ServiceName) [pscustomobject]@{Exists=$false;State=1;ServiceType=16;StartType=3;Account='';BinaryPath='';Win32ExitCode=0;ServiceSpecificExitCode=0;ProcessId=0;RecoveryEnabled=$false} }
function Invoke-LocalScmNativeTransactionCore { param($Manifest,$Hosts,[string]$PreviousState,[string]$FailureStep,$RestoreHosts,[switch]$PostCommitFailure,[switch]$StopFailure)
  $hostMode=if($null -eq $Hosts.PSObject.Properties['mode']){'wrapped'}else{[string]$Hosts.mode}; $events.Add(('core:' + $PreviousState + ':' + $hostMode + ':' + [bool]$PostCommitFailure + ':' + [bool]$StopFailure))
  if($StopFailure){return [pscustomobject]@{coreReceipt=[pscustomobject]@{state='manual-recovery-required';failedStep='stop'};pointerBytesExact=$true}}
  if($PostCommitFailure){return [pscustomobject]@{coreReceipt=[pscustomobject]@{state='rolled-back';failedStep='post';pointerCompensated=$true;pointerCommitted=$false};pointerBytesExact=$true}}
  if($PreviousState -ceq 'absent-pair'){
    foreach($entry in @(
      [pscustomobject]@{action='create';serviceName=$gatewayName;state='applied'},[pscustomobject]@{action='create';serviceName=$privilegedName;state='applied'},
      [pscustomobject]@{action='delete';serviceName=$gatewayName;state='applied'},[pscustomobject]@{action='delete';serviceName=$privilegedName;state='applied'}
    )){[void](New-LocalScmNativeMutationRecord -Action $entry.action -ServiceName $entry.serviceName -State $entry.state)}
    return [pscustomobject]@{coreReceipt=[pscustomobject]@{state='rolled-back';failedStep='privileged_start';steps=@('gateway_stop','privileged_stop','gateway_register','privileged_register');rollback=@('gateway_stop','privileged_stop','gateway_remove','privileged_remove','remove_readback');rollbackFailures=@()};pointerBytesExact=$true}
  }
  return [pscustomobject]@{coreReceipt=[pscustomobject]@{state='rolled-back';failedStep=if($PreviousState -ceq 'safe-pair'){'privileged_start'}else{'gateway_register'}};pointerBytesExact=$true}
}
$run=RunLifecycleScenarios -Manifest $manifest -Registration ([pscustomobject]@{})
$callbackFailed=$false
try { Invoke-LocalScmNativeAfterScenario -AfterScenario { param($Name,$Receipt) throw [InvalidOperationException]::new('callback-failure') } -ScenarioName healthy -ScenarioReceipt ([pscustomobject]@{}) -Receipts ([Collections.Generic.List[object]]::new()) } catch [InvalidOperationException] { $callbackFailed=$_.Exception.Message -ceq 'callback-failure' }
[pscustomobject][ordered]@{state=$run.state;events=@($events);callbackFailed=$callbackFailed} | ConvertTo-Json -Compress
"""
    result = _run_native(command, temp_root=tmp_path)

    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["state"] == "completed"
    assert "register:noReady" in receipt["events"]
    assert "core:absent-pair:healthy:False:False" in receipt["events"]
    assert "core:safe-pair:healthy:True:False" in receipt["events"]
    assert receipt["callbackFailed"] is True


def _absent_pair_transaction_command() -> str:
    """실제 transaction core를 stateful fake SCM 경계에서 실행하는 PowerShell을 만듭니다."""
    return r"""
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
namespace HermesBridge.LocalScm {
  public sealed class Snapshot {
    public bool Exists { get; set; } public uint ServiceType { get; set; } public uint StartType { get; set; }
    public string Account { get; set; } public string BinaryPath { get; set; } public uint State { get; set; }
    public uint Win32ExitCode { get; set; } public uint ServiceSpecificExitCode { get; set; } public uint ProcessId { get; set; } public bool RecoveryEnabled { get; set; }
    public Snapshot() { ServiceType=16; StartType=3; Account=""; BinaryPath=""; State=1; }
  }
  public static class Native {
    static readonly Dictionary<string, Snapshot> Values = new Dictionary<string, Snapshot>();
    public static readonly List<string> Calls = new List<string>();
    public static void Reset() { Values.Clear(); Calls.Clear(); }
    public static Snapshot Query(string name) { Calls.Add("query:"+name); Snapshot value; return Values.TryGetValue(name,out value) ? value : new Snapshot { Exists=false }; }
    public static void Seed(string name, string binary, string account) { Values[name]=new Snapshot { Exists=true, BinaryPath=binary, Account=account, State=1 }; }
    public static void CreateDemandOwnProcess(string name, string binary, string account) { Calls.Add("create:"+name); Values[name]=new Snapshot { Exists=true, BinaryPath=binary, Account=account, State=1 }; }
    public static void Delete(string name) { Calls.Add("delete:"+name); Values[name]=new Snapshot { Exists=false }; }
    public static void Start(string name) { Calls.Add("start:"+name); Snapshot value=Query(name); value.State=4; Values[name]=value; }
    public static void Stop(string name) { Calls.Add("stop:"+name); Snapshot value=Query(name); value.State=1; Values[name]=value; }
    public static void SetRecovery(string name, bool enabled) { Calls.Add("recovery:"+name); Snapshot value=Query(name); value.RecoveryEnabled=enabled; Values[name]=value; }
  }
}
'@
$isolatedNative=Join-Path $env:HERMES_NATIVE_QA_ROOT '.omo\evidence\local-scm-20260910\local-scm-native.ps1'
$isolatedCore=Join-Path $env:HERMES_NATIVE_QA_ROOT 'scripts\service-runtime-transaction.ps1'
$null=New-Item -ItemType Directory -Path (Split-Path -Parent $isolatedNative),(Split-Path -Parent $isolatedCore) -Force
Copy-Item -LiteralPath $env:HERMES_NATIVE_QA_PATH -Destination $isolatedNative
Copy-Item -LiteralPath (Join-Path (Get-Location) 'scripts\service-runtime-transaction.ps1') -Destination $isolatedCore
. $isolatedNative
$nonce='44444444-4444-4444-4444-444444444444'; $gateway="HermesBridgeLocalQa-$nonce-Gateway"; $privileged="HermesBridgeLocalQa-$nonce-Privileged"
$fixtureRoot=$env:HERMES_NATIVE_QA_ROOT; $releaseRoot=Join-Path $fixtureRoot 'release'; $pointerPath=Join-Path $fixtureRoot 'active-release.json'; $manifestPath=Join-Path $fixtureRoot 'manifest.json'
$null=New-Item -ItemType Directory -Path $releaseRoot -Force; [IO.File]::WriteAllText($pointerPath,'{"baseline":true}',[Text.UTF8Encoding]::new($false))
$gatewayHost=[pscustomobject]@{profile='gateway';hostRoot=(Join-Path $fixtureRoot 'gateway-host');hostExecutable=(Join-Path $fixtureRoot 'gateway-host\host.exe');releaseRoot=$releaseRoot}
$privilegedHost=[pscustomobject]@{profile='privileged';hostRoot=(Join-Path $fixtureRoot 'privileged-host');hostExecutable=(Join-Path $fixtureRoot 'privileged-host\host.exe');releaseRoot=$releaseRoot}
$hosts=[pscustomobject]@{hosts=@($gatewayHost,$privilegedHost)}
$manifest=[pscustomobject]@{nonce=$nonce;serviceNames=@($gateway,$privileged);serviceAccounts=@('NT AUTHORITY\LocalService','LocalSystem');fixtureRoot=$fixtureRoot;manifestPath=$manifestPath;pointerPath=$pointerPath;deadlineUtc=([DateTimeOffset]::UtcNow.AddMinutes(5).ToString('o'));applyAuthorized=$true;createdServices=@();nativeMutationJournal=@()}
$manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
function Assert-LocalScmNativeManifest { param($Manifest,[switch]$Mutation) if($Mutation){$script:LocalScmNativeCurrentManifest=$Manifest} }
function Assert-LocalScmNativeContract { param($Manifest,$HostContract,$Identity,$ExpectedReleaseRoot) [pscustomobject]@{profile=$Identity.profile;hostExecutable=$HostContract.hostExecutable;releaseRoot=$ExpectedReleaseRoot} }
function Wait-LocalScmNativeState { param($Manifest,$ServiceName,$WantedStates) [pscustomobject]@{Exists=$true;ServiceType=16;StartType=3;Account='NT AUTHORITY\LocalService';BinaryPath='';State=1;Win32ExitCode=1066;ServiceSpecificExitCode=1004;ProcessId=0;RecoveryEnabled=$false} }
function Wait-LocalScmNativeServiceAbsent { param($Manifest,$ServiceName) $true }
function Set-LocalScmNativeScenarioRegistration { param($Manifest,$Scenario) [HermesBridge.LocalScm.Native]::Seed($gateway,('"' + $gatewayHost.hostExecutable + '" --profile gateway'),'NT AUTHORITY\LocalService'); [HermesBridge.LocalScm.Native]::Seed($privileged,('"' + $privilegedHost.hostExecutable + '" --profile privileged'),'LocalSystem'); $hosts }
function Get-LocalScmNativeScenarioContract { param($Manifest,[string]$Mode) [pscustomobject]@{mode=$Mode;releaseRoot=$releaseRoot;expectedChildPath=(Join-Path $fixtureRoot 'candidate.exe');expectedChildExecutablePath=(Join-Path $fixtureRoot 'candidate.exe');hosts=@($gatewayHost,$privilegedHost)} }
function Start-LocalScmNativeFixturePair { param($Manifest,$Hosts,$ChildPath,$ReleaseRoot) [pscustomobject]@{handles=@();childHandles=@();observations=@()} }
function Stop-LocalScmNativeFixturePair { param($Manifest) @([pscustomobject]@{win32ExitCode=1066;serviceSpecificExitCode=1007},[pscustomobject]@{win32ExitCode=1066;serviceSpecificExitCode=1007}) }
function Invoke-LocalScmNativeStartFailureScenario { param($Manifest,$Scenario,$Path,$Name) [pscustomobject]@{name=$Name} }
function Invoke-LocalScmNativeCrashRecoveryScenario { param($Manifest,$Scenario,$Hosts) [pscustomobject]@{recoveryEnabled=$true} }
function Get-LocalScmNativeOwnedChildSamples { param($ChildExecutablePath) @([pscustomobject]@{processIds=@()}) }
function Close-LocalScmNativeHostExitHandle { param($Handle) }
function Close-LocalScmNativeChildHandle { param($Handle) }
$script:ActualTransactionCore=${function:Invoke-LocalScmNativeTransactionCore}; $script:AbsentCore=$null; $script:AbsentCalls=@(); $script:AbsentFinal=@()
    function Invoke-LocalScmNativeTransactionCore {
  param($Manifest,$Hosts,[string]$PreviousState,[string]$FailureStep,$RestoreHosts=$Hosts,[switch]$PostCommitFailure,[switch]$StopFailure)
  if($PreviousState -ceq 'absent-pair'){
    $start=[HermesBridge.LocalScm.Native]::Calls.Count
    $transactionJournalStart=$script:LocalScmNativeMutationJournal.Count
    $script:AbsentCore=& $script:ActualTransactionCore -Manifest $Manifest -Hosts $Hosts -PreviousState $PreviousState -FailureStep $FailureStep -RestoreHosts $RestoreHosts -PostCommitFailure:$PostCommitFailure -StopFailure:$StopFailure
    $transactionJournal=@($script:LocalScmNativeMutationJournal | Select-Object -Skip $transactionJournalStart)
    $fault=[string]$env:HERMES_NATIVE_QA_ABSENT_FAULT
    if($fault -ceq 'missing'){ $record=@($transactionJournal | Where-Object {$_.action -ceq 'create' -and $_.serviceName -ceq $Manifest.serviceNames[0] -and $_.state -ceq 'applied'}) | Select-Object -First 1; [void]$script:LocalScmNativeMutationJournal.Remove($record) }
    if($fault -ceq 'unknown'){ $record=@($transactionJournal | Where-Object {$_.action -ceq 'create' -and $_.serviceName -ceq $Manifest.serviceNames[0] -and $_.state -ceq 'applied'}) | Select-Object -First 1; $record.state='unknown' }
    if($fault -ceq 'reverse'){ $create=@($transactionJournal | Where-Object {$_.action -ceq 'create' -and $_.serviceName -ceq $Manifest.serviceNames[0] -and $_.state -ceq 'applied'}) | Select-Object -First 1; $delete=@($transactionJournal | Where-Object {$_.action -ceq 'delete' -and $_.serviceName -ceq $Manifest.serviceNames[0] -and $_.state -ceq 'applied'}) | Select-Object -First 1; $createIndex=$script:LocalScmNativeMutationJournal.IndexOf($create); $deleteIndex=$script:LocalScmNativeMutationJournal.IndexOf($delete); $swap=$script:LocalScmNativeMutationJournal[$createIndex]; $script:LocalScmNativeMutationJournal[$createIndex]=$script:LocalScmNativeMutationJournal[$deleteIndex]; $script:LocalScmNativeMutationJournal[$deleteIndex]=$swap }
    if($fault -ceq 'residual'){ [HermesBridge.LocalScm.Native]::Seed([string]$Manifest.serviceNames[0],('"' + $gatewayHost.hostExecutable + '" --profile gateway'),'NT AUTHORITY\LocalService') }
    $script:AbsentCalls=@([HermesBridge.LocalScm.Native]::Calls | Select-Object -Skip $start)
    $script:AbsentFinal=@([bool]([HermesBridge.LocalScm.Native]::Query([string]$Manifest.serviceNames[0]).Exists),[bool]([HermesBridge.LocalScm.Native]::Query([string]$Manifest.serviceNames[1]).Exists))
    return $script:AbsentCore
  }
  if($StopFailure){return [pscustomobject]@{coreReceipt=[pscustomobject]@{state='manual-recovery-required';failedStep='gateway_stop'};pointerBytesExact=$true}}
  if($PostCommitFailure){return [pscustomobject]@{coreReceipt=[pscustomobject]@{state='rolled-back';failedStep='post';pointerCompensated=$true;pointerCommitted=$false};pointerBytesExact=$true}}
  return [pscustomobject]@{coreReceipt=[pscustomobject]@{state='rolled-back';failedStep='privileged_start'};pointerBytesExact=$true}
}
[HermesBridge.LocalScm.Native]::Reset()
$run=RunLifecycleScenarios -Manifest $manifest -Registration ([pscustomobject]@{})
$absentJournal=@((Get-LocalScmNativeProperty -Object $script:AbsentCore -Name 'mutationJournal') | Where-Object {$null -ne $_}); $rollbackProof=@((Get-LocalScmNativeProperty -Object $script:AbsentCore -Name 'rollbackProof') | Where-Object {$null -ne $_})
[pscustomobject][ordered]@{runState=$run.state;failedStep=$script:AbsentCore.coreReceipt.failedStep;coreState=$script:AbsentCore.coreReceipt.state;steps=@($script:AbsentCore.coreReceipt.steps);rollback=@($script:AbsentCore.coreReceipt.rollback);rollbackFailures=@($script:AbsentCore.coreReceipt.rollbackFailures);calls=$script:AbsentCalls;appliedJournal=@($absentJournal | Where-Object {$_.state -ceq 'applied' -and $_.action -in @('create','delete')} | ForEach-Object {[pscustomobject]@{action=$_.action;serviceName=$_.serviceName}});rollbackProof=$rollbackProof;finalExists=$script:AbsentFinal} | ConvertTo-Json -Depth 12 -Compress
"""


def test_native_lifecycle_absent_pair_executes_real_transaction_and_proves_rollback(
    tmp_path: Path,
) -> None:
    """실제 transaction core가 두 nonce 등록 뒤 absent rollback을 수행하는지 확인합니다."""
    command = _absent_pair_transaction_command()
    result = _run_native(command, temp_root=tmp_path)

    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["runState"] == "completed"
    assert receipt["coreState"] == "rolled-back"
    assert receipt["failedStep"] == "privileged_start"
    assert receipt["steps"] == ["gateway_stop", "privileged_stop", "gateway_register", "privileged_register"]
    assert receipt["rollback"] == ["gateway_stop", "privileged_stop", "gateway_remove", "privileged_remove", "remove_readback"]
    assert receipt["rollbackFailures"] == []
    assert receipt["finalExists"] == [False, False]
    assert receipt["appliedJournal"] == [
        {"action": "create", "serviceName": "HermesBridgeLocalQa-44444444-4444-4444-4444-444444444444-Gateway"},
        {"action": "create", "serviceName": "HermesBridgeLocalQa-44444444-4444-4444-4444-444444444444-Privileged"},
        {"action": "delete", "serviceName": "HermesBridgeLocalQa-44444444-4444-4444-4444-444444444444-Gateway"},
        {"action": "delete", "serviceName": "HermesBridgeLocalQa-44444444-4444-4444-4444-444444444444-Privileged"},
    ]
    for proof in receipt["rollbackProof"]:
        assert proof["createIndex"] < proof["deleteIndex"]
        assert proof["finalAbsent"] is True
    for service_name in (
        "HermesBridgeLocalQa-44444444-4444-4444-4444-444444444444-Gateway",
        "HermesBridgeLocalQa-44444444-4444-4444-4444-444444444444-Privileged",
    ):
        create_index = receipt["calls"].index(f"create:{service_name}")
        delete_index = receipt["calls"].index(f"delete:{service_name}")
        assert create_index < delete_index
        assert any(
            call == f"query:{service_name}"
            for call in receipt["calls"][create_index + 1 : delete_index]
        )


def test_native_lifecycle_absent_pair_rejects_corrupt_transaction_proof(
    tmp_path: Path,
) -> None:
    """실제 lifecycle proof가 누락·unknown·역순 journal과 잔존 nonce 서비스를 거부하는지 확인합니다."""
    command = _absent_pair_transaction_command()

    for fault in ("missing", "unknown", "reverse", "residual"):
        result = _run_native(
            command,
            temp_root=tmp_path / fault,
            extra_environment={"HERMES_NATIVE_QA_ABSENT_FAULT": fault},
        )
        assert result.returncode != 0
        assert "LocalScmNativeAbsentPairRollbackProofInvalid" in result.stderr


def _set_recovery_boundary_command() -> str:
    """선택한 helper의 SetRecovery 본문을 fake handle 경계에서 컴파일합니다."""
    return r"""
$source=[IO.File]::ReadAllText($env:HERMES_NATIVE_QA_PATH)
$start=$source.IndexOf('    public static void SetRecovery(')
$end=$source.IndexOf('    public static void Start(', $start)
if($start -lt 0 -or $end -le $start){throw [InvalidOperationException]::new('LocalScmNativeSetRecoveryBodyMissing')}
$setRecovery=$source.Substring($start,$end-$start)
$harness=@"
using System;
using System.Collections.Generic;
namespace HermesBridge.LocalScmRecoveryBoundary {
  public sealed class Result {
    public uint ServiceAccess { get; set; }
    public string Error { get; set; }
    public string[] Calls { get; set; }
  }
  public static class RecoveryBoundary {
    const uint SC_MANAGER_CONNECT=0x0001;
    const uint SERVICE_QUERY_CONFIG=0x0001, SERVICE_CHANGE_CONFIG=0x0002, SERVICE_START=0x0010;
    static readonly List<string> Calls=new List<string>();
    static uint serviceAccess; static int failureMode;
    static IntPtr Manager(uint access) { Calls.Add("manager:"+access); return new IntPtr(1); }
    static IntPtr Service(IntPtr scm,string name,uint access) { Calls.Add("service:"+access); serviceAccess=access; if(failureMode==1) throw new InvalidOperationException("service-failure"); return new IntPtr(2); }
    static void ConfigureRecovery(IntPtr service,bool enabled) { Calls.Add("configure:"+enabled); if(failureMode==2) throw new InvalidOperationException("configure-failure"); }
    static bool CloseServiceHandle(IntPtr handle) { Calls.Add("close:"+handle.ToInt64()); return true; }
$setRecovery
    public static Result Execute(bool enabled,int failure) {
      Calls.Clear(); serviceAccess=0; failureMode=failure; string error=null;
      try { SetRecovery("HermesBridgeLocalQa-recovery-boundary",enabled); }
      catch(Exception exception) { error=exception.Message; }
      return new Result { ServiceAccess=serviceAccess, Error=error, Calls=Calls.ToArray() };
    }
  }
}
"@
Add-Type -TypeDefinition $harness
$enabled=[HermesBridge.LocalScmRecoveryBoundary.RecoveryBoundary]::Execute($true,0)
$disabled=[HermesBridge.LocalScmRecoveryBoundary.RecoveryBoundary]::Execute($false,0)
$serviceFailure=[HermesBridge.LocalScmRecoveryBoundary.RecoveryBoundary]::Execute($true,1)
$configureFailure=[HermesBridge.LocalScmRecoveryBoundary.RecoveryBoundary]::Execute($true,2)
[pscustomobject][ordered]@{
  enabled=[pscustomobject]@{serviceAccess=$enabled.ServiceAccess;error=$enabled.Error;calls=@($enabled.Calls)}
  disabled=[pscustomobject]@{serviceAccess=$disabled.ServiceAccess;error=$disabled.Error;calls=@($disabled.Calls)}
  serviceFailure=[pscustomobject]@{serviceAccess=$serviceFailure.ServiceAccess;error=$serviceFailure.Error;calls=@($serviceFailure.Calls)}
  configureFailure=[pscustomobject]@{serviceAccess=$configureFailure.ServiceAccess;error=$configureFailure.Error;calls=@($configureFailure.Calls)}
} | ConvertTo-Json -Compress -Depth 6
"""


def test_native_set_recovery_compiled_boundary_requests_restart_access_only_when_enabled(
    tmp_path: Path,
) -> None:
    """실제 SetRecovery 본문이 enabled restart와 readback에 필요한 handle 권한만 요청합니다."""
    command = _set_recovery_boundary_command()
    result = _run_native(command, temp_root=tmp_path)

    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["enabled"] == {
        "serviceAccess": 0x0013,
        "error": None,
        "calls": ["manager:1", "service:19", "configure:True", "close:2", "close:1"],
    }
    assert receipt["disabled"] == {
        "serviceAccess": 0x0003,
        "error": None,
        "calls": ["manager:1", "service:3", "configure:False", "close:2", "close:1"],
    }
    assert receipt["serviceFailure"] == {
        "serviceAccess": 0x0013,
        "error": "service-failure",
        "calls": ["manager:1", "service:19", "close:1"],
    }
    assert receipt["configureFailure"] == {
        "serviceAccess": 0x0013,
        "error": "configure-failure",
        "calls": ["manager:1", "service:19", "configure:True", "close:2", "close:1"],
    }


def _absent_stop_transition_command() -> str:
    """실제 fixture transition을 bounded sleep과 stateful fake native API에서 실행합니다."""
    return r"""
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
namespace HermesBridge.LocalScm {
  public sealed class Snapshot {
    public bool Exists { get; set; } public uint ServiceType { get; set; } public uint StartType { get; set; }
    public string Account { get; set; } public string BinaryPath { get; set; } public uint State { get; set; }
    public uint Win32ExitCode { get; set; } public uint ServiceSpecificExitCode { get; set; } public uint ProcessId { get; set; } public bool RecoveryEnabled { get; set; }
    public Snapshot() { ServiceType=16; StartType=3; Account=""; BinaryPath=""; State=0; }
  }
  public static class Native {
    static readonly Dictionary<string,Snapshot> Values=new Dictionary<string,Snapshot>();
    public static readonly List<string> Calls=new List<string>(); static int Behavior;
    public static void Reset(int behavior) { Values.Clear(); Calls.Clear(); Behavior=behavior; }
    public static void ClearCalls() { Calls.Clear(); }
    public static Snapshot Query(string name) { Snapshot value; Calls.Add("query:"+name); return Values.TryGetValue(name,out value) ? value : new Snapshot { Exists=false, State=0 }; }
    public static void Seed(string name,string binary,string account,uint state) { Values[name]=new Snapshot { Exists=true, BinaryPath=binary, Account=account, State=state, RecoveryEnabled=true }; }
    public static void CreateDemandOwnProcess(string name,string binary,string account) { Calls.Add("create:"+name); Values[name]=new Snapshot { Exists=true, BinaryPath=binary, Account=account, State=1, RecoveryEnabled=false }; }
    public static void Delete(string name) { Calls.Add("delete:"+name); Values[name]=new Snapshot { Exists=false, State=0 }; }
    public static void SetRecovery(string name,bool enabled) { Calls.Add("recovery:"+name+":"+enabled); Snapshot value=Query(name); value.RecoveryEnabled=enabled; Values[name]=value; }
    public static void Stop(string name) { Calls.Add("stop:"+name); if(Behavior==1) throw new InvalidOperationException("fake-stop-failure"); Snapshot value=Query(name); if(Behavior==3) { Values[name]=new Snapshot { Exists=false, State=0 }; return; } if(Behavior==2) return; value.State=1; Values[name]=value; }
    public static void Start(string name) { Calls.Add("start:"+name); Snapshot value=Query(name); value.State=4; Values[name]=value; }
  }
}
'@
$isolatedNative=Join-Path $env:HERMES_NATIVE_QA_ROOT '.omo\evidence\local-scm-20260910\local-scm-native.ps1'
$isolatedCore=Join-Path $env:HERMES_NATIVE_QA_ROOT 'scripts\service-runtime-transaction.ps1'
$null=New-Item -ItemType Directory -Force -Path (Split-Path -Parent $isolatedNative),(Split-Path -Parent $isolatedCore)
Copy-Item -LiteralPath $env:HERMES_NATIVE_QA_PATH -Destination $isolatedNative
Copy-Item -LiteralPath (Join-Path (Get-Location) 'scripts\service-runtime-transaction.ps1') -Destination $isolatedCore
. $isolatedNative
function Assert-LocalScmNativeManifest { param($Manifest,[switch]$Mutation,[switch]$AllowCleanupAfterDeadline) if($Mutation){$script:LocalScmNativeCurrentManifest=$Manifest} }
function Assert-LocalScmNativeContract { param($Manifest,$HostContract,$Identity,$ExpectedReleaseRoot) [pscustomobject]@{profile=$Identity.profile;hostRoot=$HostContract.hostRoot;hostExecutable=$HostContract.hostExecutable;releaseRoot=$ExpectedReleaseRoot} }
function Start-Sleep { param([int]$Milliseconds) $script:BoundedWaitCalls++; throw [TimeoutException]::new('LocalScmNativeBoundedWait') }
function New-TransitionFixture {
  param([string]$Name)
  $nonce='55555555-5555-5555-5555-555555555555'; $gateway="HermesBridgeLocalQa-$nonce-Gateway"; $privileged="HermesBridgeLocalQa-$nonce-Privileged"
  $root=Join-Path $env:HERMES_NATIVE_QA_ROOT $Name; $release=Join-Path $root 'release'; $pointer=Join-Path $root 'active-release.json'; $manifestPath=Join-Path $root 'manifest.json'
  $null=New-Item -ItemType Directory -Force -Path $root,$release; [IO.File]::WriteAllText($pointer,'{"baseline":true}',[Text.UTF8Encoding]::new($false))
  $gatewayHost=[pscustomobject]@{profile='gateway';hostRoot=(Join-Path $root 'gateway');hostExecutable=(Join-Path $root 'gateway\host.exe');releaseRoot=$release}
  $privilegedHost=[pscustomobject]@{profile='privileged';hostRoot=(Join-Path $root 'privileged');hostExecutable=(Join-Path $root 'privileged\host.exe');releaseRoot=$release}
  $manifest=[pscustomobject]@{nonce=$nonce;serviceNames=@($gateway,$privileged);serviceAccounts=@('NT AUTHORITY\LocalService','LocalSystem');fixtureRoot=$root;manifestPath=$manifestPath;pointerPath=$pointer;deadlineUtc=([DateTimeOffset]::UtcNow.AddMinutes(5).ToString('o'));applyAuthorized=$true;createdServices=@();nativeMutationJournal=@()}
  $manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
  Assert-LocalScmNativeManifest -Manifest $manifest -Mutation
  return [pscustomobject]@{manifest=$manifest;hosts=[pscustomobject]@{hosts=@($gatewayHost,$privilegedHost)};scenario=[pscustomobject]@{hosts=@($gatewayHost,$privilegedHost);releaseRoot=$release};gateway=$gateway;privileged=$privileged;gatewayHost=$gatewayHost;privilegedHost=$privilegedHost}
}
function Invoke-RegistrationCase {
  param([string]$Name,[string]$Mode)
  $fixture=New-TransitionFixture -Name $Name; [HermesBridge.LocalScm.Native]::Reset(0); $script:LocalScmNativeMutationJournal.Clear(); $script:BoundedWaitCalls=0
  if($Mode -ceq 'mixed'){[HermesBridge.LocalScm.Native]::Seed($fixture.gateway,('"' + $fixture.gatewayHost.hostExecutable + '" --profile gateway'),'NT AUTHORITY\LocalService',4)}
  $error=$null; try { $hosts=Set-LocalScmNativeScenarioRegistration -Manifest $fixture.manifest -Scenario $fixture.scenario } catch { $error=$_.Exception.Message }
  return [pscustomobject]@{error=$error;waitCalls=$script:BoundedWaitCalls;calls=@([HermesBridge.LocalScm.Native]::Calls);gatewayExists=[HermesBridge.LocalScm.Native]::Query($fixture.gateway).Exists;privilegedExists=[HermesBridge.LocalScm.Native]::Query($fixture.privileged).Exists}
}
function Invoke-StopCase {
  param([string]$Name,[int]$Behavior)
  $fixture=New-TransitionFixture -Name $Name; [HermesBridge.LocalScm.Native]::Reset($Behavior); $script:LocalScmNativeMutationJournal.Clear(); $script:BoundedWaitCalls=0
  [HermesBridge.LocalScm.Native]::Seed($fixture.gateway,('"' + $fixture.gatewayHost.hostExecutable + '" --profile gateway'),'NT AUTHORITY\LocalService',4)
  $error=$null; try { [void](Stop-LocalScmNativeFixturePair -Manifest $fixture.manifest) } catch { $error=$_.Exception.Message }
  return [pscustomobject]@{error=$error;waitCalls=$script:BoundedWaitCalls;calls=@([HermesBridge.LocalScm.Native]::Calls)}
}
$both=Invoke-RegistrationCase -Name both -Mode absent
$mixed=Invoke-RegistrationCase -Name mixed -Mode mixed
$nonconvergent=Invoke-StopCase -Name nonconvergent -Behavior 2
$disappeared=Invoke-StopCase -Name disappeared -Behavior 3
$stopFailure=Invoke-StopCase -Name stopFailure -Behavior 1
$chainFixture=New-TransitionFixture -Name chain; [HermesBridge.LocalScm.Native]::Reset(0); $script:LocalScmNativeMutationJournal.Clear(); $script:BoundedWaitCalls=0
$absentCore=Invoke-LocalScmNativeTransactionCore -Manifest $chainFixture.manifest -Hosts $chainFixture.hosts -PreviousState absent-pair -FailureStep privileged_start
[HermesBridge.LocalScm.Native]::ClearCalls(); $script:BoundedWaitCalls=0; $chainError=$null
$postCommit=$null; $stopFence=$null
try {
  $registered=Set-LocalScmNativeScenarioRegistration -Manifest $chainFixture.manifest -Scenario $chainFixture.scenario
  $registrationCalls=@([HermesBridge.LocalScm.Native]::Calls)
  $postCommit=Invoke-LocalScmNativeTransactionCore -Manifest $chainFixture.manifest -Hosts $registered -PreviousState safe-pair -FailureStep '__never__' -PostCommitFailure
  $beforeFence=$script:LocalScmNativeMutationJournal.Count
  $stopFence=Invoke-LocalScmNativeTransactionCore -Manifest $chainFixture.manifest -Hosts $registered -PreviousState safe-pair -FailureStep '__never__' -StopFailure
  $afterFence=$script:LocalScmNativeMutationJournal.Count
} catch { $chainError=$_.Exception.Message; $registrationCalls=@([HermesBridge.LocalScm.Native]::Calls); $beforeFence=-1; $afterFence=-1 }
[pscustomobject][ordered]@{
  both=$both;mixed=$mixed;nonconvergent=$nonconvergent;disappeared=$disappeared;stopFailure=$stopFailure
  chain=[pscustomobject]@{error=$chainError;waitCalls=$script:BoundedWaitCalls;absentFailedStep=$absentCore.coreReceipt.failedStep;absentState=$absentCore.coreReceipt.state;registrationCalls=$registrationCalls;postState=if($null -eq $postCommit){$null}else{$postCommit.coreReceipt.state};pointerCompensated=if($null -eq $postCommit){$null}else{$postCommit.coreReceipt.pointerCompensated};pointerCommitted=if($null -eq $postCommit){$null}else{$postCommit.coreReceipt.pointerCommitted};pointerBytesExact=if($null -eq $postCommit){$null}else{$postCommit.pointerBytesExact};postRollbackFailureCount=if($null -eq $postCommit){-1}else{@($postCommit.coreReceipt.rollbackFailures).Count};stopFenceState=if($null -eq $stopFence){$null}else{$stopFence.coreReceipt.state};beforeFence=$beforeFence;afterFence=$afterFence}
} | ConvertTo-Json -Compress -Depth 12
"""


def test_native_absent_stop_transition_keeps_existing_waits_strict_and_rebuilds_next_scenarios(
    tmp_path: Path,
) -> None:
    """부재 서비스만 StopPair의 stopped 대기를 건너뛰고 기존 서비스 전이는 엄격한 실패 경로를 유지합니다."""
    result = _run_native(_absent_stop_transition_command(), temp_root=tmp_path)

    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["both"]["error"] is None
    assert receipt["both"]["waitCalls"] == 0
    assert receipt["both"]["gatewayExists"] is True
    assert receipt["both"]["privilegedExists"] is True
    assert receipt["mixed"]["error"] is None
    assert receipt["mixed"]["waitCalls"] == 0
    assert any(call.startswith("recovery:HermesBridgeLocalQa-55555555") for call in receipt["mixed"]["calls"])
    assert any(call.startswith("stop:HermesBridgeLocalQa-55555555") for call in receipt["mixed"]["calls"])
    for rejected in (receipt["nonconvergent"], receipt["disappeared"]):
        assert rejected["error"] == "LocalScmNativeBoundedWait"
        assert rejected["waitCalls"] == 1
    assert "fake-stop-failure" in receipt["stopFailure"]["error"]
    assert receipt["stopFailure"]["waitCalls"] == 0
    assert receipt["chain"]["error"] is None
    assert receipt["chain"]["waitCalls"] == 0
    assert receipt["chain"]["absentState"] == "rolled-back"
    assert receipt["chain"]["absentFailedStep"] == "privileged_start"
    registration_calls = receipt["chain"]["registrationCalls"]
    assert all(not call.startswith(("recovery:", "stop:")) for call in registration_calls)
    assert registration_calls.count(
        "create:HermesBridgeLocalQa-55555555-5555-5555-5555-555555555555-Gateway"
    ) == 1
    assert registration_calls.count(
        "create:HermesBridgeLocalQa-55555555-5555-5555-5555-555555555555-Privileged"
    ) == 1
    assert receipt["chain"]["postState"] == "rolled-back"
    assert receipt["chain"]["pointerCompensated"] is True
    assert receipt["chain"]["pointerCommitted"] is False
    assert receipt["chain"]["pointerBytesExact"] is True
    assert receipt["chain"]["postRollbackFailureCount"] == 0
    assert receipt["chain"]["stopFenceState"] == "manual-recovery-required"
    assert receipt["chain"]["beforeFence"] == receipt["chain"]["afterFence"]
