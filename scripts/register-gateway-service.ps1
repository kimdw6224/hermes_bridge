[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[^\r\n]+$')]
    [string]$ExecutablePath = 'python.exe',

    [string]$ExistingManifestPath = '',

    [string]$RuntimeManifestPath = '',

    [string]$RuntimeReleaseRoot = '',

    [string]$ServiceHostRoot = '',

    [string]$InstallationContextPath = '',

    [string]$InstallationContextSha256 = '',

    [switch]$Apply,

    [ValidateSet('Register', 'Remove', 'Inspect')]
    [string]$Operation = 'Register',

    [ValidateSet('Production', 'Simulate')]
    [string]$AdapterMode = 'Production',

    [switch]$Json
)

$ErrorActionPreference = 'Stop'
$runtimeModule = 'hermes_windows_bridge.gateway.windows_service'
$serviceHostRequested = $PSBoundParameters.ContainsKey('ServiceHostRoot')
$installationContextPathProvided = $PSBoundParameters.ContainsKey('InstallationContextPath')
$installationContextHashProvided = $PSBoundParameters.ContainsKey('InstallationContextSha256')
$serviceHostLaunch = $null
$installationContext = $null
. (Join-Path $PSScriptRoot 'service-object-security.ps1')

if ($installationContextPathProvided -or $installationContextHashProvided) {
    if ($installationContextPathProvided -xor $installationContextHashProvided) {
        throw [ArgumentException]::new('BridgeInstallationContextPairRequired')
    }
    $installationContextScriptPath = Join-Path $PSScriptRoot 'installation-context.ps1'
    if (-not (Test-Path -LiteralPath $installationContextScriptPath -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new('BridgeInstallationContextContractMissing')
    }
    . $installationContextScriptPath -LibraryMode
}

function Resolve-AdapterInstallationContext {
    if (-not $installationContextPathProvided) { return $null }
    $requestedContextPath = $InstallationContextPath
    $requestedContextSha256 = $InstallationContextSha256
    return Get-BridgeInstallationContext -Path $requestedContextPath -Sha256 $requestedContextSha256
}

function New-ServiceRuntimeArgv {
    param([Parameter(Mandatory)][string]$PythonPath)
    return @($PythonPath, '-I', '-B', '-m', $runtimeModule)
}

function Resolve-VerifiedServiceExecutable {
    if ([string]::IsNullOrWhiteSpace($RuntimeManifestPath) -or [string]::IsNullOrWhiteSpace($RuntimeReleaseRoot)) {
        throw [Security.SecurityException]::new('BridgeServiceLaunchAuthorityRequired')
    }
    $runtimeContract = Join-Path $PSScriptRoot 'service-runtime.ps1'
    if (-not (Test-Path -LiteralPath $runtimeContract -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new('BridgeServiceRuntimeContractMissing')
    }
    . $runtimeContract -LibraryMode
    $launch = Get-BridgeServiceLaunchContract -ManifestPath $RuntimeManifestPath -ReleaseRoot $RuntimeReleaseRoot
    if (-not $launch.verified -or [string]::IsNullOrWhiteSpace([string]$launch.serviceExecutable)) {
        throw [Security.SecurityException]::new('BridgeServiceLaunchAuthorityUnverified')
    }
    return [string]$launch.serviceExecutable
}

function Resolve-VerifiedServiceHostLaunch {
    param([Parameter(Mandatory)][ValidateSet('gateway')][string]$Profile)

    if ([string]::IsNullOrWhiteSpace($ServiceHostRoot) -or [string]::IsNullOrWhiteSpace($RuntimeReleaseRoot)) {
        throw [Security.SecurityException]::new('BridgeServiceHostAuthorityRequired')
    }
    $hostContract = Join-Path $PSScriptRoot 'service-host.ps1'
    if (-not (Test-Path -LiteralPath $hostContract -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new('BridgeServiceHostContractMissing')
    }
    . $hostContract -LibraryMode -Profile $Profile
    $hostArguments = @{ HostRoot = $ServiceHostRoot; Profile = $Profile; ReleaseRoot = $RuntimeReleaseRoot }
    if ($null -ne $installationContext) {
        $hostArguments.InstallationContextPath = [string]$installationContext.contextPath
        $hostArguments.InstallationContextSha256 = [string]$installationContext.contextSha256
    }
    $hostLaunch = Get-BridgeServiceHostContract @hostArguments
    $expectedArgv = @([string]$hostLaunch.hostExecutable, '--profile', $Profile)
    $expectedHostRoot = [IO.Path]::GetFullPath($ServiceHostRoot).TrimEnd('\', '/')
    $expectedReleaseRoot = [IO.Path]::GetFullPath($RuntimeReleaseRoot).TrimEnd('\', '/')
    if (-not $hostLaunch.verified -or
        [string]$hostLaunch.profile -cne $Profile -or
        ([string]$hostLaunch.hostRoot).TrimEnd('\', '/') -ine $expectedHostRoot -or
        ([string]$hostLaunch.releaseRoot).TrimEnd('\', '/') -ine $expectedReleaseRoot -or
        [string]::IsNullOrWhiteSpace([string]$hostLaunch.hostExecutable) -or
        [string]::IsNullOrWhiteSpace([string]$hostLaunch.releaseExecutable) -or
        [string]$hostLaunch.hostDigest -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$hostLaunch.manifestSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        ((@($hostLaunch.argv) | ConvertTo-Json -Compress) -cne ($expectedArgv | ConvertTo-Json -Compress))) {
        throw [Security.SecurityException]::new('BridgeServiceHostAuthorityUnverified')
    }
    if ($null -ne $installationContext -and (
        [int]$hostLaunch.schemaVersion -ne 2 -or
        [string]$hostLaunch.contextNonce -cne [string]$installationContext.nonce -or
        [string]$hostLaunch.serviceName -cne [string]$installationContext.gatewayServiceName -or
        [string]$hostLaunch.runtimeBindingPath -cne [string]$expectedBinding.path -or
        [string]$hostLaunch.runtimeBindingSha256 -cne [string]$expectedBinding.sha256
    )) {
        throw [Security.SecurityException]::new('BridgeContextServiceHostAuthorityUnverified')
    }
    return [pscustomobject][ordered]@{ argv = $expectedArgv }
}

function ConvertTo-ServiceBinaryPath {
    param([Parameter(Mandatory)][string[]]$Argv)
    if ($Argv.Count -ne 3 -or $Argv[1] -cne '--profile' -or $Argv[2] -cne 'gateway') {
        throw [Security.SecurityException]::new('BridgeServiceHostArgvInvalid')
    }
    return ('"{0}" {1} {2}' -f $Argv[0], $Argv[1], $Argv[2])
}

if ($AdapterMode -eq 'Simulate' -and (-not $Apply -or $WhatIfPreference)) {
    throw 'AdapterMode Simulate requires -Apply and cannot be combined with -WhatIf.'
}

$installationContext = Resolve-AdapterInstallationContext
if ($null -ne $installationContext -and (-not $serviceHostRequested -or [string]::IsNullOrWhiteSpace($RuntimeReleaseRoot))) {
    throw [ArgumentException]::new('BridgeContextServiceHostAuthorityRequired')
}
if ($null -ne $installationContext -and $AdapterMode -eq 'Simulate') {
    throw [ArgumentException]::new('BridgeContextSimulationForbidden')
}
$expectedBinding = $null
if ($null -ne $installationContext) {
    $expectedBinding = Get-BridgeInstallationContextBinding -Context $installationContext -Profile 'gateway'
    if ([string]$expectedBinding.path -cne (Join-Path $installationContext.bindingsDirectory 'gateway.json') -or
        [string]$expectedBinding.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$expectedBinding.contextNonce -cne [string]$installationContext.nonce) {
        throw [Security.SecurityException]::new('BridgeContextServiceBindingUnverified')
    }
}

function Resolve-RuntimeExecutable {
    param([Parameter(Mandatory)][string]$Path)

    if ([IO.Path]::GetFileName($Path) -ine 'python.exe') { throw 'ExecutablePath must identify python.exe.' }
    if ([IO.Path]::IsPathRooted($Path)) {
        if ($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path -match '^(\\\\|//|\\\\[?.]\\)') {
            throw 'ExecutablePath must be a rooted local file path.'
        }
        $candidate = $Path
    } else {
        if ($Path -notmatch '^[A-Za-z0-9_.-]+\.exe$') {
            throw 'ExecutablePath must be an executable name or rooted local path.'
        }
        $command = @(Get-Command -Name $Path -CommandType Application -All -ErrorAction Stop)[0]
        $candidate = $command.Source
    }
    $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'ExecutablePath must name a regular local file.'
    }
    return $item.FullName
}

function Test-RuntimeModuleImport {
    param([Parameter(Mandatory)][string]$PythonPath)

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $PythonPath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.Arguments = '-c "import importlib,sys; importlib.import_module(''hermes_windows_bridge.gateway.windows_service''); print(sys.executable)"'
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start() -or -not $process.WaitForExit(10000)) {
            if (-not $process.HasExited) { $process.Kill() }
            return $false
        }
        $reportedExecutable = $process.StandardOutput.ReadToEnd().Trim()
        $null = $process.StandardError.ReadToEnd()
        return $process.ExitCode -eq 0 -and $reportedExecutable.Equals($PythonPath, [StringComparison]::OrdinalIgnoreCase)
    } finally {
        $process.Dispose()
    }
}

function Initialize-ServiceRegistrationApi {
    if ('HermesBridge.ServiceRegistrationApi' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;

namespace HermesBridge {
    public static class ServiceRegistrationApi {
        const uint SC_MANAGER_CONNECT = 0x0001, SC_MANAGER_CREATE_SERVICE = 0x0002;
        const uint SERVICE_QUERY_CONFIG = 0x0001, SERVICE_CHANGE_CONFIG = 0x0002, SERVICE_QUERY_STATUS = 0x0004, SERVICE_START = 0x0010, SERVICE_STOP = 0x0020, DELETE = 0x00010000;
        const uint SERVICE_WIN32_OWN_PROCESS = 0x10, SERVICE_AUTO_START = 2, SERVICE_ERROR_NORMAL = 1;
        const uint SERVICE_CONFIG_FAILURE_ACTIONS = 2, SERVICE_CONFIG_DELAYED_AUTO_START_INFO = 3, SC_ACTION_RESTART = 1;
        const uint SERVICE_CONTROL_STOP = 1, SERVICE_STOPPED = 1;

        [StructLayout(LayoutKind.Sequential)] struct SERVICE_DELAYED_AUTO_START_INFO { [MarshalAs(UnmanagedType.Bool)] public bool delayed; }
        [StructLayout(LayoutKind.Sequential)] struct SC_ACTION { public uint Type; public uint Delay; }
        [StructLayout(LayoutKind.Sequential)] struct SERVICE_FAILURE_ACTIONS { public uint ResetPeriod; public IntPtr RebootMsg; public IntPtr Command; public uint ActionsCount; public IntPtr Actions; }
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct QUERY_SERVICE_CONFIG { public uint ServiceType, StartType, ErrorControl; public IntPtr BinaryPathName, LoadOrderGroup; public uint TagId; public IntPtr Dependencies, ServiceStartName, DisplayName; }
        [StructLayout(LayoutKind.Sequential)] struct SERVICE_STATUS { public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint; }

        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr OpenSCManagerW(string machine, string database, uint access);
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateServiceW(IntPtr manager, string name, string display, uint access, uint type, uint start, uint error, string binary, string group, IntPtr tag, string deps, string account, string password);
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr OpenServiceW(IntPtr manager, string name, uint access);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool ChangeServiceConfig2W(IntPtr service, uint level, IntPtr info);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool QueryServiceConfigW(IntPtr service, IntPtr config, uint size, out uint needed);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool QueryServiceConfig2W(IntPtr service, uint level, IntPtr buffer, uint size, out uint needed);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool ControlService(IntPtr service, uint control, out SERVICE_STATUS status);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool QueryServiceStatus(IntPtr service, out SERVICE_STATUS status);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool DeleteService(IntPtr service);
        [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr handle);

        static void ThrowLast(string operation) { throw new Win32Exception(Marshal.GetLastWin32Error(), operation); }
        static IntPtr Manager(uint access) { var h = OpenSCManagerW(null, null, access); if (h == IntPtr.Zero) ThrowLast("OpenSCManagerW"); return h; }
        static IntPtr Service(IntPtr manager, string name, uint access) { var h = OpenServiceW(manager, name, access); if (h == IntPtr.Zero) ThrowLast("OpenServiceW"); return h; }

        static void Configure(IntPtr service) {
            var delayed = new SERVICE_DELAYED_AUTO_START_INFO { delayed = true };
            IntPtr delayedPtr = Marshal.AllocHGlobal(Marshal.SizeOf(delayed));
            var actions = new[] { new SC_ACTION { Type=SC_ACTION_RESTART, Delay=5000 }, new SC_ACTION { Type=SC_ACTION_RESTART, Delay=15000 }, new SC_ACTION { Type=SC_ACTION_RESTART, Delay=60000 } };
            IntPtr actionsPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SC_ACTION)) * actions.Length);
            IntPtr failurePtr = IntPtr.Zero;
            try {
                Marshal.StructureToPtr(delayed, delayedPtr, false);
                if (!ChangeServiceConfig2W(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, delayedPtr)) ThrowLast("ChangeServiceConfig2W(delayed)");
                for (int i=0; i<actions.Length; i++) Marshal.StructureToPtr(actions[i], IntPtr.Add(actionsPtr, i * Marshal.SizeOf(typeof(SC_ACTION))), false);
                var failure = new SERVICE_FAILURE_ACTIONS { ResetPeriod=86400, ActionsCount=(uint)actions.Length, Actions=actionsPtr };
                failurePtr = Marshal.AllocHGlobal(Marshal.SizeOf(failure)); Marshal.StructureToPtr(failure, failurePtr, false);
                if (!ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, failurePtr)) ThrowLast("ChangeServiceConfig2W(failure)");
            } finally { if (failurePtr != IntPtr.Zero) Marshal.FreeHGlobal(failurePtr); Marshal.FreeHGlobal(actionsPtr); Marshal.FreeHGlobal(delayedPtr); }
        }

        public static bool RecoveryIsExact(string name) {
            IntPtr manager = Manager(SC_MANAGER_CONNECT), service = IntPtr.Zero, delayedPtr = IntPtr.Zero, failurePtr = IntPtr.Zero;
            try {
                service = Service(manager, name, SERVICE_QUERY_CONFIG);
                uint needed;
                delayedPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SERVICE_DELAYED_AUTO_START_INFO)));
                if (!QueryServiceConfig2W(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, delayedPtr, (uint)Marshal.SizeOf(typeof(SERVICE_DELAYED_AUTO_START_INFO)), out needed)) ThrowLast("QueryServiceConfig2W(delayed)");
                var delayed = (SERVICE_DELAYED_AUTO_START_INFO)Marshal.PtrToStructure(delayedPtr, typeof(SERVICE_DELAYED_AUTO_START_INFO));
                QueryServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, IntPtr.Zero, 0, out needed);
                if (needed == 0) return false;
                failurePtr = Marshal.AllocHGlobal((int)needed);
                if (!QueryServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, failurePtr, needed, out needed)) ThrowLast("QueryServiceConfig2W(failure)");
                var failure = (SERVICE_FAILURE_ACTIONS)Marshal.PtrToStructure(failurePtr, typeof(SERVICE_FAILURE_ACTIONS));
                if (!delayed.delayed || failure.ResetPeriod != 86400 || failure.ActionsCount != 3 || failure.Actions == IntPtr.Zero) return false;
                uint[] delays = { 5000, 15000, 60000 }; int size = Marshal.SizeOf(typeof(SC_ACTION));
                for (int i=0; i<delays.Length; i++) { var action = (SC_ACTION)Marshal.PtrToStructure(IntPtr.Add(failure.Actions, i*size), typeof(SC_ACTION)); if (action.Type != SC_ACTION_RESTART || action.Delay != delays[i]) return false; }
                return true;
            } finally { if (failurePtr != IntPtr.Zero) Marshal.FreeHGlobal(failurePtr); if (delayedPtr != IntPtr.Zero) Marshal.FreeHGlobal(delayedPtr); if (service != IntPtr.Zero) CloseServiceHandle(service); CloseServiceHandle(manager); }
        }

        public static void Install(string name, string binary, string account) {
            IntPtr manager = Manager(SC_MANAGER_CREATE_SERVICE), service = IntPtr.Zero;
            try {
                service = CreateServiceW(manager, name, name, SERVICE_QUERY_CONFIG|SERVICE_CHANGE_CONFIG|SERVICE_START|SERVICE_STOP|DELETE, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, binary, null, IntPtr.Zero, null, account, null);
                if (service == IntPtr.Zero) ThrowLast("CreateServiceW");
                try { Configure(service); } catch { DeleteService(service); throw; }
            } finally { if (service != IntPtr.Zero) CloseServiceHandle(service); CloseServiceHandle(manager); }
        }

        public static void Remove(string name) {
            IntPtr manager = Manager(SC_MANAGER_CONNECT), service = IntPtr.Zero;
            try {
                service = Service(manager, name, SERVICE_STOP|SERVICE_QUERY_STATUS|DELETE);
                SERVICE_STATUS status;
                if (QueryServiceStatus(service, out status) && status.CurrentState != SERVICE_STOPPED) {
                    ControlService(service, SERVICE_CONTROL_STOP, out status);
                    for (int i=0; i<100 && QueryServiceStatus(service, out status) && status.CurrentState != SERVICE_STOPPED; i++) Thread.Sleep(100);
                    if (status.CurrentState != SERVICE_STOPPED) throw new InvalidOperationException("Service did not stop before removal.");
                }
                if (!DeleteService(service)) ThrowLast("DeleteService");
            } finally { if (service != IntPtr.Zero) CloseServiceHandle(service); CloseServiceHandle(manager); }
        }
    }
}
'@
}

function Get-ServiceDefinitionState {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$BinaryPath,
        [Parameter(Mandatory)][string]$Account,
        [switch]$SkipServiceObjectProtection
    )

    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
    if ($null -eq $service) { return 'absent' }
    $recoveryMatches = [HermesBridge.ServiceRegistrationApi]::RecoveryIsExact($Name)
    $securityMatches = $SkipServiceObjectProtection -or (Get-BridgeServiceObjectSecurityState -Name $Name)
    if ($service.PathName -ceq $BinaryPath -and $service.StartName -ieq $Account -and $service.StartMode -eq 'Auto' -and $recoveryMatches -and $securityMatches) { return 'desired' }
    return 'conflict'
}

function Get-ExistingManifest {
    param([string]$Path)

    if (-not [System.IO.Path]::IsPathRooted($Path) -or $Path -notmatch '^[A-Za-z]:[\\/]') {
        throw 'ExistingManifestPath must be a rooted local file path.'
    }
    if ($Path -match '^(\\\\|//|\\\\[?.]\\)') {
        throw 'ExistingManifestPath must not be a UNC or device path.'
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'ExistingManifestPath must name an existing local file.'
    }

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSProvider.Name -ne 'FileSystem' -or $item.PSIsContainer) {
        throw 'ExistingManifestPath must name a local filesystem file.'
    }
    $resolvedPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    if ($resolvedPath -notmatch '^[A-Za-z]:\\') {
        throw 'ExistingManifestPath did not resolve to a local filesystem path.'
    }

    try {
        $existing = Get-Content -LiteralPath $resolvedPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw 'ExistingManifestPath must contain valid JSON.'
    }
    if ($existing -isnot [System.Management.Automation.PSCustomObject]) {
        throw 'ExistingManifestPath must contain a JSON object.'
    }
    return $existing
}

function Test-SameDefinition {
    param(
        [object]$Existing,
        [System.Collections.Specialized.OrderedDictionary]$Desired
    )

    $definitionFields = @(
        'schemaVersion', 'kind', 'name', 'account', 'startupType', 'delayedStart',
        'restartOnFailure', 'interactive', 'argv', 'typedApis'
    )
    foreach ($field in $definitionFields) {
        $property = $Existing.PSObject.Properties[$field]
        if ($null -eq $property) {
            return $false
        }
        $actual = $property.Value | ConvertTo-Json -Compress -Depth 8
        $expected = $Desired[$field] | ConvertTo-Json -Compress -Depth 8
        if ($actual -cne $expected) {
            return $false
        }
    }
    return $true
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ServiceDefinitionInspection {
    param([string]$Name, [string]$BinaryPath, [string]$Account)
    Initialize-ServiceRegistrationApi
    $service = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $Name) -ErrorAction Stop
    if ($null -eq $service) { $recoveryMatches = $false } else { $recoveryMatches = [HermesBridge.ServiceRegistrationApi]::RecoveryIsExact($Name) }
    $second = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $Name) -ErrorAction Stop
    $stable = ($null -eq $service) -eq ($null -eq $second)
    if ($stable -and $null -ne $service) {
        $stable = $service.PathName -ceq $second.PathName -and $service.StartName -ceq $second.StartName -and
            $service.StartMode -ceq $second.StartMode -and $service.State -ceq $second.State
    }
    $securityMatches = $null -ne $service -and (Get-BridgeServiceObjectSecurityState -Name $Name)
    $state = if (-not $stable) { 'conflict' } elseif ($null -eq $service) { 'absent' } elseif (
        $service.PathName -ceq $BinaryPath -and $service.StartName -ieq $Account -and
        $service.StartMode -eq 'Auto' -and $recoveryMatches -and $securityMatches
    ) { 'desired' } else { 'conflict' }
    return [pscustomobject][ordered]@{
        state = $state
        pathName = if ($null -eq $service) { $null } else { [string]$service.PathName }
        account = if ($null -eq $service) { $null } else { [string]$service.StartName }
        startMode = if ($null -eq $service) { $null } else { [string]$service.StartMode }
        running = $null -ne $service -and [string]$service.State -ceq 'Running'
        recoveryExact = $recoveryMatches
        snapshotStable = $stable
    }
}

$manifest = [ordered]@{
    schemaVersion = 1
    kind = 'windows-service-registration-plan'
    mode = 'dry-run'
    installed = $false
    applied = $false
    state = 'planned'
    atomic = $true
    applyRequiresAdministrator = $true
    name = if ($null -ne $installationContext) { [string]$installationContext.gatewayServiceName } else { 'HermesWindowsBridgeGateway' }
    account = 'NT AUTHORITY\LocalService'
    startupType = 'Automatic'
    delayedStart = $true
    restartOnFailure = $true
    interactive = $false
    operation = $Operation
    argv = New-ServiceRuntimeArgv -PythonPath $ExecutablePath
    typedApis = @('CreateServiceW', 'ChangeServiceConfig2W', 'DeleteService')
    recovery = [ordered]@{
        atomic = $true
        resumeSafe = $true
        definitionComparison = 'exact-security-definition'
        mutation = 'fixed-win32-service-api'
        failureActions = @('restart/5000', 'restart/15000', 'restart/60000')
    }
    receipt = [ordered]@{ operation = $Operation; target = if ($null -ne $installationContext) { [string]$installationContext.gatewayServiceName } else { 'HermesWindowsBridgeGateway' }; changed = $false; before = 'not-read'; after = 'not-read' }
    readBack = [ordered]@{ performed = $false; state = 'not-read'; exact = $false }
    rollback = [ordered]@{ supported = $true; inverseOperation = if ($Operation -eq 'Register') { 'Remove' } else { 'Register' }; attempted = $false; succeeded = $null }
}

if ($WhatIfPreference) {
    $manifest.mode = 'what-if'
}

if ($serviceHostRequested) {
    try {
        $serviceHostLaunch = Resolve-VerifiedServiceHostLaunch -Profile 'gateway'
        $manifest.argv = $serviceHostLaunch.argv
    }
    catch {
        $manifest.state = 'conflict'
        $manifest.failureReason = 'runtime-entrypoint-unverified'
        $manifest | ConvertTo-Json -Depth 8
        exit 3
    }
}

if ($ExistingManifestPath) {
    try {
        $existing = Get-ExistingManifest -Path $ExistingManifestPath
        if (Test-SameDefinition -Existing $existing -Desired $manifest) {
            $manifest.state = 'unchanged'
        }
        else {
            $manifest.state = 'conflict'
            $manifest.failureReason = 'definition-mismatch'
            $manifest | ConvertTo-Json -Depth 8
            exit 2
        }
    }
    catch {
        $manifest.state = 'conflict'
        $manifest.failureReason = 'invalid-existing-manifest'
        $manifest | ConvertTo-Json -Depth 8
        exit 2
    }
}

if ($Operation -eq 'Inspect') {
    if ($null -eq $serviceHostLaunch) {
        try { $resolvedExecutable = Resolve-VerifiedServiceExecutable }
        catch { $manifest.state = 'conflict'; $manifest.failureReason = 'runtime-entrypoint-unverified'; $manifest | ConvertTo-Json -Depth 8; exit 3 }
        $manifest.argv = New-ServiceRuntimeArgv -PythonPath $resolvedExecutable
    }
    $binaryPath = if ($null -ne $serviceHostLaunch) { ConvertTo-ServiceBinaryPath -Argv $serviceHostLaunch.argv } else { '"{0}" -I -B -m {1}' -f $resolvedExecutable, $runtimeModule }
    try { $inspection = Get-ServiceDefinitionInspection -Name $manifest.name -BinaryPath $binaryPath -Account $manifest.account }
    catch { $manifest.state = 'conflict'; $manifest.failureReason = 'service-inspection-unverified'; $manifest.inspect = [ordered]@{ scmReads = $null; writes = 0 }; $manifest | ConvertTo-Json -Depth 8; exit 3 }
    $manifest.mode = 'inspect'; $manifest.state = [string]$inspection.state
    $manifest.observedDefinition = $inspection
    $manifest.receipt.before = $inspection.state; $manifest.receipt.after = $inspection.state
    $manifest.readBack.performed = $true; $manifest.readBack.state = $inspection.state
    $manifest.readBack.exact = $inspection.state -in @('desired', 'absent')
    $manifest.inspect = [ordered]@{ scmReads = 2; writes = 0 }
    $manifest | ConvertTo-Json -Depth 8
    if ($inspection.state -eq 'conflict') { exit 2 }
    exit 0
}

if ($Apply -and -not $WhatIfPreference) {
    $manifest.mode = 'apply'
    $manifest.dispatch = [ordered]@{ adapterMode = $AdapterMode; operation = $Operation; typedApis = $manifest.typedApis; argv = $manifest.argv; externalCalls = 0 }
    if ($AdapterMode -eq 'Simulate') {
        if ($null -eq $serviceHostLaunch -and [IO.Path]::GetFileName($ExecutablePath) -ine 'python.exe') {
            $manifest.state = 'conflict'; $manifest.failureReason = 'runtime-entrypoint-unverified'; $manifest | ConvertTo-Json -Depth 8; exit 3
        }
        $manifest.state = 'simulated'
        $manifest | ConvertTo-Json -Depth 8
        exit 0
    }
    if ($null -eq $serviceHostLaunch) {
        try {
            $resolvedExecutable = Resolve-VerifiedServiceExecutable
        } catch {
            $manifest.state = 'conflict'; $manifest.failureReason = 'runtime-entrypoint-unverified'; $manifest | ConvertTo-Json -Depth 8; exit 3
        }
        $manifest.argv = New-ServiceRuntimeArgv -PythonPath $resolvedExecutable
    }
    $manifest.dispatch.argv = $manifest.argv
    if (-not (Test-Administrator)) {
        $manifest.state = 'conflict'
        $manifest.failureReason = 'administrator-required'
        $manifest | ConvertTo-Json -Depth 8
        exit 3
    }
    Initialize-ServiceRegistrationApi
    if ($Operation -eq 'Remove') {
        $binaryPath = if ($null -ne $serviceHostLaunch) { ConvertTo-ServiceBinaryPath -Argv $serviceHostLaunch.argv } else { '"{0}" -I -B -m {1}' -f $resolvedExecutable, $runtimeModule }
        $existingState = Get-ServiceDefinitionState -Name $manifest.name -BinaryPath $binaryPath -Account $manifest.account -SkipServiceObjectProtection
        $manifest.receipt.before = $existingState
        if ($existingState -eq 'absent') {
            $manifest.state = 'unchanged'
            $manifest.receipt.after = 'absent'; $manifest.readBack.performed = $true; $manifest.readBack.state = 'absent'; $manifest.readBack.exact = $true
        } elseif ($existingState -eq 'conflict') {
            $manifest.state='conflict'; $manifest.failureReason='installed-definition-mismatch'; $manifest.receipt.after='conflict'; $manifest | ConvertTo-Json -Depth 8; exit 2
        } else {
            [HermesBridge.ServiceRegistrationApi]::Remove($manifest.name)
            $removed = $false
            for ($attempt = 0; $attempt -lt 100; $attempt++) { if ($null -eq (Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $manifest.name) -ErrorAction SilentlyContinue)) { $removed = $true; break }; Start-Sleep -Milliseconds 100 }
            $manifest.readBack.performed = $true; $manifest.readBack.state = if ($removed) { 'absent' } else { 'present' }; $manifest.readBack.exact = $removed
            if (-not $removed) { $manifest.state='conflict'; $manifest.failureReason='post-remove-verification-failed'; $manifest.receipt.after='present'; $manifest | ConvertTo-Json -Depth 8; exit 3 }
            $manifest.state = 'removed'; $manifest.applied = $true; $manifest.receipt.changed = $true; $manifest.receipt.after = 'absent'
        }
    } else {
        $binaryPath = if ($null -ne $serviceHostLaunch) { ConvertTo-ServiceBinaryPath -Argv $serviceHostLaunch.argv } else { '"{0}" -I -B -m {1}' -f $resolvedExecutable, $runtimeModule }
        $state = Get-ServiceDefinitionState -Name $manifest.name -BinaryPath $binaryPath -Account $manifest.account
        $manifest.receipt.before = $state
        if ($state -eq 'conflict') {
            $manifest.state = 'conflict'; $manifest.failureReason = 'installed-definition-mismatch'; $manifest | ConvertTo-Json -Depth 8; exit 2
        }
        if ($state -eq 'absent') {
            [HermesBridge.ServiceRegistrationApi]::Install($manifest.name, $binaryPath, $manifest.account)
            try {
                Set-BridgeCreatedServiceObjectProtection -Name $manifest.name
            } catch {
                $protectionError = $_
                try { [HermesBridge.ServiceRegistrationApi]::Remove($manifest.name) }
                catch { throw [InvalidOperationException]::new('BridgeCreatedServiceSecurityCleanupFailed', $_.Exception) }
                throw $protectionError
            }
            $manifest.applied = $true
        }
        $verifiedState = Get-ServiceDefinitionState -Name $manifest.name -BinaryPath $binaryPath -Account $manifest.account
        $manifest.readBack.performed = $true; $manifest.readBack.state = $verifiedState; $manifest.readBack.exact = $verifiedState -eq 'desired'; $manifest.receipt.after = $verifiedState; $manifest.receipt.changed = $manifest.applied
        if ($verifiedState -ne 'desired') {
            $manifest.state = 'conflict'; $manifest.failureReason = 'post-apply-verification-failed'; $manifest.applied = $false; $manifest | ConvertTo-Json -Depth 8; exit 3
        }
        $manifest.installed = $true
        $manifest.state = if ($manifest.applied) { 'applied' } else { 'unchanged' }
    }
}

$manifest | ConvertTo-Json -Depth 8
