[CmdletBinding()]
param(
    [switch]$Json,
    [switch]$Security,
    [ValidateRange(1, 65535)][int]$GatewayPort = 8765,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]*\.ts\.net$')][string]$ServeHost,
    [ValidateNotNullOrEmpty()][string]$Capability = 'hermes.local/windows-control',
    [string]$ServiceReleaseRoot = '',
    [string]$GatewayServiceHostRoot = '',
    [string]$PrivilegedServiceHostRoot = '',
    [string]$InstallationContextPath = '',
    [string]$InstallationContextSha256 = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$jsonOutput = [bool]$Json
$securityMode = [bool]$Security
$selectedServiceReleaseRoot = [string]$ServiceReleaseRoot
$selectedGatewayServiceHostRoot = [string]$GatewayServiceHostRoot
$selectedPrivilegedServiceHostRoot = [string]$PrivilegedServiceHostRoot
$installationContext = $null
$installationContextMode = $false
$externalCommandTimeoutSeconds = 5
$gatewayPort = $GatewayPort
$programDataRoot = if ([string]::IsNullOrWhiteSpace($env:ProgramData)) { [Environment]::GetFolderPath('CommonApplicationData') } else { $env:ProgramData }
$localDataRoot = if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { [Environment]::GetFolderPath('LocalApplicationData') } else { $env:LOCALAPPDATA }
$tokenPath = [IO.Path]::Combine($programDataRoot, 'HermesWindowsBridge', 'secrets', 'token')
$markerPath = [IO.Path]::Combine($localDataRoot, 'HermesWindowsBridge', 'remote-input.disabled')
$serviceProgramRoot = [IO.Path]::Combine([Environment]::GetFolderPath('ProgramFiles'), 'HermesWindowsBridge')
$gatewayServiceName = 'HermesWindowsBridgeGateway'
$privilegedServiceName = 'HermesWindowsBridgePrivileged'
$workerTaskName = 'HermesWindowsBridgeWorker'
$workerPipeName = '\\.\pipe\HermesWindowsBridgeWorker'
$privilegedPipeName = '\\.\pipe\HermesWindowsBridgePrivileged'
# 이후 helper import가 호출자 변수를 덮어쓰지 못하도록 transport Host를 doctor 전용 변수에 고정합니다.
$doctorTransportServeHost = [string]$ServeHost

$hasContextPath = -not [string]::IsNullOrWhiteSpace($InstallationContextPath)
$hasContextSha256 = -not [string]::IsNullOrWhiteSpace($InstallationContextSha256)
if ($hasContextPath -xor $hasContextSha256) {
    throw [ArgumentException]::new('BridgeInstallationContextPairRequired')
}
if ($hasContextPath) {
    $candidateRootArguments = @(
        'ServiceReleaseRoot', 'GatewayServiceHostRoot', 'PrivilegedServiceHostRoot' |
            Where-Object { $PSBoundParameters.ContainsKey($_) }
    )
    if ($candidateRootArguments.Count -ne 0 -and $candidateRootArguments.Count -ne 3) {
        # pointer commit 전에는 release와 두 host anchor를 하나의 검증 tuple로만 받습니다.
        throw [ArgumentException]::new('BridgeInstallationContextCandidateRootsIncomplete')
    }
    $candidateRoots = @($ServiceReleaseRoot, $GatewayServiceHostRoot, $PrivilegedServiceHostRoot)
    if ($candidateRootArguments.Count -eq 3 -and
        (@($candidateRoots | Where-Object { [string]::IsNullOrWhiteSpace([string]$_) }).Count -ne 0)) {
        throw [ArgumentException]::new('BridgeInstallationContextCandidateRootsIncomplete')
    }
    $contextHelperPath = [IO.Path]::Combine($PSScriptRoot, 'installation-context.ps1')
    $contextHelperItem = Get-Item -LiteralPath $contextHelperPath -Force -ErrorAction Stop
    if ($contextHelperItem.PSIsContainer -or
        ($contextHelperItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not $contextHelperItem.FullName.Equals($contextHelperPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw [IO.IOException]::new('BridgeInstallationContextHelperUnsafe')
    }
    . $contextHelperItem.FullName -LibraryMode
    $installationContext = Get-BridgeInstallationContext -Path $InstallationContextPath -Sha256 $InstallationContextSha256
    if ($PSBoundParameters.ContainsKey('GatewayPort') -and $GatewayPort -ne [int]$installationContext.port) {
        throw [ArgumentException]::new('BridgeInstallationContextConflictsWithGatewayPort')
    }
    if ($PSBoundParameters.ContainsKey('ServeHost') -and
        $ServeHost -cne [string]$installationContext.serveHost) {
        throw [ArgumentException]::new('BridgeInstallationContextConflictsWithServeHost')
    }
    $installationContextMode = $true
    $gatewayPort = [int]$installationContext.port
    $programDataRoot = [string]$installationContext.programDataRoot
    $localDataRoot = [string]$installationContext.localDataRoot
    $tokenPath = [string]$installationContext.tokenPath
    $markerPath = [IO.Path]::Combine([string]$installationContext.userRoot, 'remote-input.disabled')
    $serviceProgramRoot = [string]$installationContext.programRoot
    $gatewayServiceName = [string]$installationContext.gatewayServiceName
    $privilegedServiceName = [string]$installationContext.privilegedServiceName
    $workerTaskName = [string]$installationContext.workerTaskName
    $workerPipeName = [string]$installationContext.workerPipe
    $privilegedPipeName = [string]$installationContext.privilegedPipe
    # DNS를 조회하지 않고 loopback request의 Host/Origin에 context가 고정한 host만 사용합니다.
    $doctorTransportServeHost = [string]$installationContext.serveHost
}

function New-CheckResult {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][ValidateSet('pass', 'warn', 'fail')][string]$Status,
        [Parameter(Mandatory)][bool]$Critical,
        [Parameter(Mandatory)][string]$Detail
    )
    return [ordered]@{ id = $Id; status = $Status; critical = $Critical; detail = $Detail }
}

function Invoke-BoundedCommand {
    param([Parameter(Mandatory)][string]$FilePath, [Parameter(Mandatory)][string[]]$ArgumentList)
    $job = Start-Job -ScriptBlock {
        param([string]$CommandPath, [string[]]$CommandArguments)
        $output = & $CommandPath @CommandArguments 2>$null
        [pscustomobject]@{ exitCode = $LASTEXITCODE; output = ($output -join [Environment]::NewLine) }
    } -ArgumentList $FilePath, $ArgumentList
    try {
        if ($null -eq (Wait-Job -Job $job -Timeout $externalCommandTimeoutSeconds)) {
            Stop-Job -Job $job
            return [ordered]@{ completed = $false; exitCode = $null; output = '' }
        }
        $value = Receive-Job -Job $job
        return [ordered]@{ completed = $true; exitCode = [int]$value.exitCode; output = [string]$value.output }
    } finally {
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
}

function Get-ServiceCheck {
    param([string]$Id, [string]$Name, [string]$ExpectedAccount)
    $serviceCommand = Get-Command -Name 'sc.exe' -ErrorAction SilentlyContinue
    if ($null -eq $serviceCommand) {
        return New-CheckResult -Id $Id -Status 'warn' -Critical $true -Detail 'Service Control CLI is unavailable; service state was not assumed'
    }
    $query = Invoke-BoundedCommand -FilePath $serviceCommand.Source -ArgumentList @('query', $Name)
    $config = Invoke-BoundedCommand -FilePath $serviceCommand.Source -ArgumentList @('qc', $Name)
    $recovery = Invoke-BoundedCommand -FilePath $serviceCommand.Source -ArgumentList @('qfailure', $Name)
    if (-not $query.completed -or -not $config.completed -or -not $recovery.completed) {
        return New-CheckResult -Id $Id -Status 'fail' -Critical $true -Detail 'service status query timed out'
    }
    $serviceQueryExitCodes = @($query.exitCode, $config.exitCode, $recovery.exitCode)
    # 조회 권한 거부는 설치 부재의 증거가 아니므로 Win32 오류 코드를 구분합니다.
    if ($serviceQueryExitCodes -contains 1060) {
        return New-CheckResult -Id $Id -Status 'fail' -Critical $true -Detail 'service is not installed'
    }
    if ($serviceQueryExitCodes -contains 5) {
        return New-CheckResult -Id $Id -Status 'warn' -Critical $true -Detail 'service query access denied; service state is unverified'
    }
    if ($query.exitCode -ne 0 -or $config.exitCode -ne 0 -or $recovery.exitCode -ne 0) {
        return New-CheckResult -Id $Id -Status 'warn' -Critical $true -Detail 'service query failed; service state is unverified'
    }
    if ($query.output -notmatch '(?m)^\s*(?:STATE|\uC0C1\uD0DC)\s*:\s*4\s+RUNNING\b' -or $config.output -notmatch ('(?m)^\s*SERVICE_START_NAME\s*:\s*' + [regex]::Escape($ExpectedAccount) + '\s*$')) {
        return New-CheckResult -Id $Id -Status 'fail' -Critical $true -Detail 'service is stopped or its account is unexpected'
    }
    # Windows PowerShell 자식 작업은 OS 표시 언어로 sc.exe 결과를 반환합니다.
    $restartPattern = '(?:RESTART\s+--\s+Delay|\uB2E4\uC2DC\s+\uC2DC\uC791\s+--\s+\uC9C0\uC5F0)\s*=\s*'
    $expectedRecovery = $recovery.output -match 'RESET_PERIOD\s*\(in seconds\)\s*:\s*86400(?!\d)' -and $recovery.output -match ($restartPattern + '5000(?!\d)') -and $recovery.output -match ($restartPattern + '15000(?!\d)') -and $recovery.output -match ($restartPattern + '60000(?!\d)')
    if (-not $expectedRecovery) {
        return New-CheckResult -Id $Id -Status 'fail' -Critical $true -Detail 'service recovery restart policy does not match the approved bounded delays'
    }
    return New-CheckResult -Id $Id -Status 'pass' -Critical $true -Detail 'service is running with the expected account'
}

function Get-ProtectedServiceRuntimeCheck {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$ProgramRoot,
        [string]$ServiceReleaseRoot = '',
        [string]$GatewayServiceHostRoot = '',
        [string]$PrivilegedServiceHostRoot = '',
        [string]$GatewayServiceName = 'HermesWindowsBridgeGateway',
        [string]$PrivilegedServiceName = 'HermesWindowsBridgePrivileged',
        $InstallationContext = $null
    )
    if ($null -eq (Get-Command Resolve-BridgeServiceReleaseSelection -ErrorAction SilentlyContinue) -or
        $null -eq (Get-Command Get-BridgeServicePairInspection -ErrorAction SilentlyContinue)) {
        return New-CheckResult -Id $Id -Status 'warn' -Critical $true -Detail 'protected service runtime is unverified'
    }
    try {
        # SCM PathName은 후보 경로가 아니라 검증된 release와의 exact readback 비교에만 사용됩니다.
        $selectionArguments = @{
            ProgramRoot = $ProgramRoot
            ServiceReleaseRoot = $ServiceReleaseRoot
        }
        if ($null -ne $InstallationContext) { $selectionArguments.InstallationContext = $InstallationContext }
        if (-not [string]::IsNullOrWhiteSpace($GatewayServiceHostRoot) -or
            -not [string]::IsNullOrWhiteSpace($PrivilegedServiceHostRoot)) {
            $selectionArguments.GatewayServiceHostRoot = $GatewayServiceHostRoot
            $selectionArguments.PrivilegedServiceHostRoot = $PrivilegedServiceHostRoot
        }
        $release = Resolve-BridgeServiceReleaseSelection @selectionArguments
        $inspectionArguments = @{ ScriptRoot = $PSScriptRoot; Release = $release }
        if ($null -ne $InstallationContext) { $inspectionArguments.InstallationContext = $InstallationContext }
        $inspection = Get-BridgeServicePairInspection @inspectionArguments
        if ($inspection.previousState -ceq 'safe-pair') {
            if ($null -ne $release.PSObject.Properties['gatewayServiceHostRoot'] -or
                $null -ne $release.PSObject.Properties['privilegedServiceHostRoot']) {
                $hostChild = Get-ProtectedServiceHostChildCheck -Id $Id -Release $release `
                    -GatewayServiceName $GatewayServiceName -PrivilegedServiceName $PrivilegedServiceName `
                    -InstallationContext $InstallationContext
                if ($null -ne $hostChild) { return $hostChild }
            }
            return New-CheckResult -Id $Id -Status 'pass' -Critical $true `
                -Detail 'protected release and service pair are verified'
        }
        return New-CheckResult -Id $Id -Status 'fail' -Critical $true `
            -Detail 'protected release does not match the required service pair'
    } catch [UnauthorizedAccessException] {
        return New-CheckResult -Id $Id -Status 'warn' -Critical $true `
            -Detail 'protected service runtime is unverified'
    } catch [Security.SecurityException], [IO.InvalidDataException] {
        return New-CheckResult -Id $Id -Status 'fail' -Critical $true `
            -Detail 'protected release verification failed'
    } catch [IO.IOException], [Management.Automation.RuntimeException] {
        return New-CheckResult -Id $Id -Status 'warn' -Critical $true `
            -Detail 'protected service runtime is unverified'
    }
}

function Get-ProtectedServiceHostChildCheck {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)]$Release,
        [string]$GatewayServiceName = 'HermesWindowsBridgeGateway',
        [string]$PrivilegedServiceName = 'HermesWindowsBridgePrivileged',
        $InstallationContext = $null
    )
    $gatewayRootProperty = $Release.PSObject.Properties['gatewayServiceHostRoot']
    $privilegedRootProperty = $Release.PSObject.Properties['privilegedServiceHostRoot']
    if ($null -eq $gatewayRootProperty -and $null -eq $privilegedRootProperty) { return $null }
    if ($null -eq $gatewayRootProperty -or $null -eq $privilegedRootProperty) {
        return New-CheckResult -Id $Id -Status 'fail' -Critical $true `
            -Detail 'protected host selection is incomplete'
    }
    $hostHelperPath = Join-Path $PSScriptRoot 'service-host.ps1'
    if (-not (Test-Path -LiteralPath $hostHelperPath -PathType Leaf)) {
        return New-CheckResult -Id $Id -Status 'fail' -Critical $true `
            -Detail 'protected host contract is unavailable'
    }
    $contextPath = ''
    $contextSha256 = ''
    if ($null -ne $InstallationContext) {
        # LibraryMode import가 호출자 scope의 context 값을 선택하지 않도록 값을 먼저 고정합니다.
        $contextPath = [string]$InstallationContext.contextPath
        $contextSha256 = [string]$InstallationContext.contextSha256
        if ([string]::IsNullOrWhiteSpace($contextPath) -or [string]::IsNullOrWhiteSpace($contextSha256)) {
            return New-CheckResult -Id $Id -Status 'fail' -Critical $true `
                -Detail 'protected host installation context is incomplete'
        }
    }
    try {
        $definitions = @(
            [ordered]@{ name = $GatewayServiceName; profile = 'gateway'; hostRoot = [string]$gatewayRootProperty.Value },
            [ordered]@{ name = $PrivilegedServiceName; profile = 'privileged'; hostRoot = [string]$privilegedRootProperty.Value }
        )
        foreach ($definition in $definitions) {
            $contract = & {
                param($HelperPath, $SelectedHostRoot, $SelectedProfile, $SelectedReleaseRoot, $ContextPath, $ContextSha256)
                . $HelperPath -LibraryMode
                if ([string]::IsNullOrWhiteSpace($ContextPath)) {
                    Get-BridgeServiceHostContract -HostRoot $SelectedHostRoot -Profile $SelectedProfile -ReleaseRoot $SelectedReleaseRoot
                } else {
                    Get-BridgeServiceHostContract -HostRoot $SelectedHostRoot -Profile $SelectedProfile -ReleaseRoot $SelectedReleaseRoot `
                        -InstallationContextPath $ContextPath -InstallationContextSha256 $ContextSha256
                }
            } $hostHelperPath $definition.hostRoot $definition.profile ([string]$Release.releaseRoot) $contextPath $contextSha256
            if (-not $contract.verified -or [string]$contract.state -cne 'verified' -or
                [string]::IsNullOrWhiteSpace([string]$contract.releaseExecutable)) {
                return New-CheckResult -Id $Id -Status 'fail' -Critical $true `
                    -Detail 'protected host contract verification failed'
            }
            $usesRuntimeBinding = ([int]$contract.schemaVersion -eq 2)
            if (($null -ne $InstallationContext -and -not $usesRuntimeBinding) -or
                ($usesRuntimeBinding -and
                    ([string]::IsNullOrWhiteSpace([string]$contract.runtimeBindingPath) -or
                     [string]$contract.runtimeBindingSha256 -cnotmatch '^[a-f0-9]{64}$'))) {
                return New-CheckResult -Id $Id -Status 'fail' -Critical $true `
                    -Detail 'protected host runtime binding verification failed'
            }
            $service = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $definition.name) -ErrorAction Stop
            $hostProcessId = [int]$service.ProcessId
            if ([string]$service.State -cne 'Running' -or $hostProcessId -le 0) {
                return New-CheckResult -Id $Id -Status 'fail' -Critical $true `
                    -Detail 'protected host child process is missing'
            }
            $hostProcess = Get-CimInstance -ClassName Win32_Process -Filter ("ProcessId={0}" -f $hostProcessId) -ErrorAction Stop
            if ([string]::IsNullOrWhiteSpace([string]$hostProcess.ExecutablePath) -or
                [string]::IsNullOrWhiteSpace([string]$hostProcess.CommandLine)) {
                return New-CheckResult -Id $Id -Status 'warn' -Critical $true `
                    -Detail 'protected host child process is unverified'
            }
            if (-not ([string]$hostProcess.ExecutablePath).Equals([string]$contract.hostExecutable, [StringComparison]::OrdinalIgnoreCase) -or
                [string]$hostProcess.CommandLine -cne ('"{0}" --profile {1}' -f [string]$contract.hostExecutable, [string]$definition.profile)) {
                return New-CheckResult -Id $Id -Status 'fail' -Critical $true `
                    -Detail 'protected host process identity does not match the verified host'
            }
            $children = @(Get-CimInstance -ClassName Win32_Process `
                -Filter ("ParentProcessId={0}" -f $hostProcessId) -ErrorAction Stop)
            $expectedCommandLine = '"{0}" -I -B -m hermes_windows_bridge.service_child --profile {1}' -f `
                [string]$contract.releaseExecutable, [string]$definition.profile
            if ($usesRuntimeBinding) {
                $expectedCommandLine += ' --runtime-binding "{0}" --runtime-binding-sha256 {1}' -f `
                    [string]$contract.runtimeBindingPath, [string]$contract.runtimeBindingSha256
            }
            if (@($children | Where-Object {
                    [string]::IsNullOrWhiteSpace([string]$_.ExecutablePath) -or
                    [string]::IsNullOrWhiteSpace([string]$_.CommandLine)
                }).Count -gt 0) {
                return New-CheckResult -Id $Id -Status 'warn' -Critical $true `
                    -Detail 'protected host child process is unverified'
            }
            $matchingChildren = @($children | Where-Object {
                ([string]$_.ExecutablePath).Equals([string]$contract.releaseExecutable, [StringComparison]::OrdinalIgnoreCase) -and
                [string]$_.CommandLine -ceq $expectedCommandLine
            })
            if ($children.Count -ne 1 -or $matchingChildren.Count -ne 1) {
                return New-CheckResult -Id $Id -Status 'fail' -Critical $true `
                    -Detail 'protected host child process identity does not match the verified release'
            }
        }
        return New-CheckResult -Id $Id -Status 'pass' -Critical $true `
            -Detail 'protected host child process identity is verified'
    } catch [UnauthorizedAccessException], [System.Management.Automation.RuntimeException] {
        return New-CheckResult -Id $Id -Status 'warn' -Critical $true `
            -Detail 'protected host child process is unverified'
    }
}

function Initialize-BridgeDoctorServiceSecurityApi {
    if ($null -ne ('HermesBridge.DoctorServiceSecurityApi' -as [type])) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace HermesBridge {
    public static class DoctorServiceSecurityApi {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr OpenSCManager(string machineName, string databaseName, uint desiredAccess);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr OpenService(IntPtr serviceManager, string serviceName, uint desiredAccess);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool QueryServiceObjectSecurity(IntPtr service, uint securityInformation,
            byte[] securityDescriptor, uint bufferSize, out uint bytesNeeded);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CloseServiceHandle(IntPtr serviceHandle);
    }
}
'@
}

function Get-BridgeServiceSecurityDescriptor {
    param([Parameter(Mandatory)][string]$Name)
    try {
        Initialize-BridgeDoctorServiceSecurityApi
        # Windows PowerShell 5.1은 P/Invoke $null을 빈 문자열로 바꿀 수 있어 CLR null string을 명시합니다.
        $nativeNull = [System.Management.Automation.Language.NullString]::Value
        $scManager = [HermesBridge.DoctorServiceSecurityApi]::OpenSCManager($nativeNull, $nativeNull, [uint32]0x0001)
        if ($scManager -eq [IntPtr]::Zero) { return [pscustomobject]@{ result = 'unverified'; descriptor = $null } }
        try {
            # READ_CONTROL만 요청해야 DACL 확인이 설정 변경 권한을 요구하지 않습니다.
            $service = [HermesBridge.DoctorServiceSecurityApi]::OpenService($scManager, $Name, [uint32]0x00020000)
            if ($service -eq [IntPtr]::Zero) { return [pscustomobject]@{ result = 'unverified'; descriptor = $null } }
            try {
                [uint32]$required = 0
                $ownerAndDacl = [uint32]0x00000005
                [void][HermesBridge.DoctorServiceSecurityApi]::QueryServiceObjectSecurity(
                    $service, $ownerAndDacl, $null, 0, [ref]$required)
                # 비정상 크기의 descriptor는 메모리 할당 대신 검증 불가로 처리합니다.
                if ($required -eq 0 -or $required -gt 1048576) {
                    return [pscustomobject]@{ result = 'unverified'; descriptor = $null }
                }
                $buffer = [byte[]]::new($required)
                if (-not [HermesBridge.DoctorServiceSecurityApi]::QueryServiceObjectSecurity(
                    $service, $ownerAndDacl, $buffer, $required, [ref]$required)) {
                    return [pscustomobject]@{ result = 'unverified'; descriptor = $null }
                }
                return [pscustomobject]@{
                    result = 'verified'
                    descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($buffer, 0)
                }
            } finally {
                [void][HermesBridge.DoctorServiceSecurityApi]::CloseServiceHandle($service)
            }
        } finally {
            [void][HermesBridge.DoctorServiceSecurityApi]::CloseServiceHandle($scManager)
        }
    } catch {
        return [pscustomobject]@{ result = 'unverified'; descriptor = $null }
    }
}

function Get-BridgeServiceRegistrySecurityDescriptor {
    param([Parameter(Mandatory)][string]$Name)
    try {
        # Registry provider는 -LiteralPath로 기존 key를 찾지 못할 수 있으므로 wildcard를 명시적으로 escape한 -Path를 사용합니다.
        $registryPath = [Management.Automation.WildcardPattern]::Escape(("HKLM:\SYSTEM\CurrentControlSet\Services\{0}" -f $Name))
        $acl = Get-Acl -Path $registryPath -ErrorAction Stop
        return [pscustomobject]@{
            result = 'verified'
            descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
        }
    } catch {
        return [pscustomobject]@{ result = 'unverified'; descriptor = $null }
    }
}

function Test-BridgeDangerousServiceAccessMask {
    param([Parameter(Mandatory)][uint32]$Mask)
    [uint32]$dangerous = 0x00000172 # change-config/start/stop/pause/user-defined-control
    $dangerous = $dangerous -bor [uint32]0x00010000 -bor [uint32]0x00040000 -bor [uint32]0x00080000
    # Service GENERIC_EXECUTE에는 start/stop/pause가 매핑되므로 별도 위험 권한입니다.
    $dangerous = $dangerous -bor [uint32]0x20000000 -bor [uint32]0x40000000 -bor [uint32]0x10000000
    return ($Mask -band $dangerous) -ne 0
}

function Test-BridgeDangerousRegistryAccessMask {
    param([Parameter(Mandatory)][uint32]$Mask)
    [uint32]$dangerous = 0x00000026 # set-value/create-subkey/create-link
    $dangerous = $dangerous -bor [uint32]0x00010000 -bor [uint32]0x00040000 -bor [uint32]0x00080000
    $dangerous = $dangerous -bor [uint32]0x40000000 -bor [uint32]0x10000000
    return ($Mask -band $dangerous) -ne 0
}

function Get-BridgeAclDescriptorAssessment {
    param(
        [Parameter(Mandatory)]$Descriptor,
        [Parameter(Mandatory)][ValidateSet('service', 'registry')][string]$Kind
    )
    if ($Descriptor -isnot [Security.AccessControl.RawSecurityDescriptor]) {
        return [pscustomobject]@{ state = 'fail'; reason = 'descriptor-invalid' }
    }
    if ($null -eq $Descriptor.Owner -or $Descriptor.Owner.Value -notin @('S-1-5-18', 'S-1-5-32-544')) {
        return [pscustomobject]@{ state = 'fail'; reason = 'owner-untrusted' }
    }
    if ($null -eq $Descriptor.DiscretionaryAcl) {
        return [pscustomobject]@{ state = 'fail'; reason = 'dacl-missing' }
    }
    foreach ($ace in $Descriptor.DiscretionaryAcl) {
        if (([int]$ace.AceFlags -band [int][Security.AccessControl.AceFlags]::InheritOnly) -ne 0) { continue }
        if ($ace -isnot [Security.AccessControl.QualifiedAce]) {
            return [pscustomobject]@{ state = 'unverified'; reason = 'ace-unverified' }
        }
        if ($ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed) { continue }
        if ($null -eq $ace.SecurityIdentifier) {
            return [pscustomobject]@{ state = 'unverified'; reason = 'ace-unverified' }
        }
        if ($ace.SecurityIdentifier.Value -in @('S-1-5-18', 'S-1-5-32-544')) { continue }
        [uint32]$mask = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$ace.AccessMask), 0)
        $dangerous = if ($Kind -eq 'service') {
            Test-BridgeDangerousServiceAccessMask -Mask $mask
        } else {
            Test-BridgeDangerousRegistryAccessMask -Mask $mask
        }
        if ($dangerous) { return [pscustomobject]@{ state = 'fail'; reason = 'untrusted-write-allow' } }
    }
    return [pscustomobject]@{ state = 'pass'; reason = 'verified' }
}

function Get-BridgeServiceObjectAclCheck {
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][string]$Name)
    $read = Get-BridgeServiceSecurityDescriptor -Name $Name
    if ($read.result -ne 'verified' -or $null -eq $read.descriptor) {
        return New-CheckResult -Id $Id -Status 'warn' -Critical $true -Detail 'service object ACL is unverified'
    }
    $assessment = Get-BridgeAclDescriptorAssessment -Descriptor $read.descriptor -Kind 'service'
    if ($assessment.state -eq 'pass') {
        return New-CheckResult -Id $Id -Status 'pass' -Critical $true -Detail 'service object ACL excludes untrusted change rights'
    }
    if ($assessment.state -eq 'fail') {
        return New-CheckResult -Id $Id -Status 'fail' -Critical $true -Detail 'service object ACL fails protected ownership or write policy'
    }
    return New-CheckResult -Id $Id -Status 'warn' -Critical $true -Detail 'service object ACL is unverified'
}

function Get-BridgeServiceRegistryAclCheck {
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][string]$Name)
    $read = Get-BridgeServiceRegistrySecurityDescriptor -Name $Name
    if ($read.result -ne 'verified' -or $null -eq $read.descriptor) {
        return New-CheckResult -Id $Id -Status 'warn' -Critical $true -Detail 'service registry ACL is unverified'
    }
    $assessment = Get-BridgeAclDescriptorAssessment -Descriptor $read.descriptor -Kind 'registry'
    if ($assessment.state -eq 'pass') {
        return New-CheckResult -Id $Id -Status 'pass' -Critical $true -Detail 'service registry ACL excludes untrusted change rights'
    }
    if ($assessment.state -eq 'fail') {
        return New-CheckResult -Id $Id -Status 'fail' -Critical $true -Detail 'service registry ACL fails protected ownership or write policy'
    }
    return New-CheckResult -Id $Id -Status 'warn' -Critical $true -Detail 'service registry ACL is unverified'
}

function Get-UnauthorizedStatus {
    param([hashtable]$Headers, [ValidateRange(1, 65535)][int]$Port)
    try {
        $null = Invoke-WebRequest -Uri ("http://127.0.0.1:{0}/mcp" -f $Port) -Headers $Headers -UseBasicParsing -TimeoutSec $externalCommandTimeoutSeconds
        return 200
    } catch {
        if ($null -ne $_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
        return 0
    }
}

function Get-BearerAuthCheck {
    param([int]$Port, [string]$ServeHost, [string]$Capability = 'hermes.local/windows-control')
    $headers = @{}
    if (-not [string]::IsNullOrWhiteSpace($ServeHost)) {
        # 로컬 bearer 검증만 분리하며 실제 tailnet grant의 증거로 사용하지 않습니다.
        $headers['Host'] = $ServeHost
        $headers['Tailscale-App-Capabilities'] = (@{ $Capability = @(@{ src = @('local-doctor-probe') }) } | ConvertTo-Json -Compress -Depth 5)
    }
    $missingStatus = Get-UnauthorizedStatus -Headers $headers -Port $Port
    $headers['Authorization'] = 'Bearer invalid-doctor-probe'
    $invalidStatus = Get-UnauthorizedStatus -Headers $headers -Port $Port
    if ($missingStatus -eq 401 -and $invalidStatus -eq 401) {
        return New-CheckResult -Id 'bearer_auth' -Status 'pass' -Critical $true -Detail 'local probe rejects missing and invalid bearer tokens; tailnet grants are not verified'
    }
    return New-CheckResult -Id 'bearer_auth' -Status 'fail' -Critical $true -Detail ("local bearer probe expected 401; missing={0}, invalid={1}" -f $missingStatus, $invalidStatus)
}

function Get-TransportPolicyProbeStatus {
    param(
        [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$Port,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$HostHeader,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Origin,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Capability,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Token
    )
    $handler = $null
    $client = $null
    $request = $null
    $response = $null
    try {
        Add-Type -AssemblyName System.Net.Http -ErrorAction Stop
        $handler = [Net.Http.HttpClientHandler]::new()
        $handler.UseProxy = $false
        $handler.AllowAutoRedirect = $false
        $client = [Net.Http.HttpClient]::new($handler)
        $client.Timeout = [TimeSpan]::FromSeconds(5)
        $request = [Net.Http.HttpRequestMessage]::new(
            [Net.Http.HttpMethod]::Get, ("http://127.0.0.1:{0}/mcp" -f $Port))
        $request.Headers.Host = $HostHeader
        [void]$request.Headers.TryAddWithoutValidation('Origin', $Origin)
        $request.Headers.Accept.Add([Net.Http.Headers.MediaTypeWithQualityHeaderValue]::new('application/json'))
        $capabilities = @{ $Capability = @(@{ src = @('local-doctor-probe') }) } | ConvertTo-Json -Compress -Depth 5
        [void]$request.Headers.TryAddWithoutValidation('Tailscale-App-Capabilities', $capabilities)
        $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $Token)
        $response = $client.SendAsync($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        return [pscustomobject]@{ state = 'observed'; status = [int]$response.StatusCode }
    } catch {
        # 연결·권한·시간 초과의 원문은 hostname이나 인증 정보를 포함할 수 있어 상태만 반환합니다.
        return [pscustomobject]@{ state = 'unavailable'; status = 0 }
    } finally {
        if ($null -ne $response) { $response.Dispose() }
        if ($null -ne $request) { $request.Dispose() }
        if ($null -ne $client) { $client.Dispose() }
        if ($null -ne $handler) { $handler.Dispose() }
    }
}

function Get-TransportPolicyCheck {
    param(
        [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$Port,
        [string]$ServeHost,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Capability,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$TokenPath
    )
    if ([string]::IsNullOrWhiteSpace($ServeHost)) {
        return New-CheckResult -Id 'transport_policy' -Status 'warn' -Critical $true `
            -Detail 'live transport policy is unverified because ServeHost was not provided'
    }
    try {
        $token = [IO.File]::ReadAllText($TokenPath).Trim()
    } catch {
        return New-CheckResult -Id 'transport_policy' -Status 'warn' -Critical $true `
            -Detail 'live transport policy is unverified because the protected token is unavailable'
    }
    if ([string]::IsNullOrWhiteSpace($token)) {
        return New-CheckResult -Id 'transport_policy' -Status 'warn' -Critical $true `
            -Detail 'live transport policy is unverified because the protected token is unavailable'
    }
    $canonicalOrigin = "https://$ServeHost"
    $canonical = Get-TransportPolicyProbeStatus -Port $Port -HostHeader $ServeHost -Origin $canonicalOrigin `
        -Capability $Capability -Token $token
    $wrongOrigin = Get-TransportPolicyProbeStatus -Port $Port -HostHeader $ServeHost `
        -Origin 'https://invalid-doctor-origin.invalid' -Capability $Capability -Token $token
    $wrongHost = Get-TransportPolicyProbeStatus -Port $Port -HostHeader 'invalid-doctor-host.invalid' `
        -Origin $canonicalOrigin -Capability $Capability -Token $token
    if ($canonical.state -ne 'observed' -or $wrongOrigin.state -ne 'observed' -or $wrongHost.state -ne 'observed') {
        return New-CheckResult -Id 'transport_policy' -Status 'warn' -Critical $true `
            -Detail 'live transport policy is unverified because the loopback gateway is unavailable'
    }
    if ($canonical.status -eq 406 -and $wrongOrigin.status -eq 403 -and $wrongHost.status -eq 403) {
        return New-CheckResult -Id 'transport_policy' -Status 'pass' -Critical $true `
            -Detail 'live status-only boundary observed: canonical authenticated Host/Origin/capability=406; wrong Origin=403; wrong Host=403; this does not prove a complete allowlist or tailnet grants'
    }
    return New-CheckResult -Id 'transport_policy' -Status 'fail' -Critical $true `
        -Detail ("live status-only boundary expected canonical=406, wrong Origin=403, wrong Host=403; observed canonical={0}, wrong Origin={1}, wrong Host={2}" -f $canonical.status, $wrongOrigin.status, $wrongHost.status)
}

function Initialize-BridgeDoctorJsonInspector {
    if ($null -ne ('HermesBridge.DoctorJsonInspector' -as [type])) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Text;
namespace HermesBridge {
    public static class DoctorJsonInspector {
        public static bool HasUniqueObjectProperties(string text) {
            if (text == null) return false;
            int index = 0;
            if (!ParseValue(text, ref index)) return false;
            SkipWhitespace(text, ref index);
            return index == text.Length;
        }
        private static void SkipWhitespace(string text, ref int index) {
            while (index < text.Length && char.IsWhiteSpace(text[index])) index++;
        }
        private static bool ParseValue(string text, ref int index) {
            SkipWhitespace(text, ref index);
            if (index >= text.Length) return false;
            if (text[index] == '{') return ParseObject(text, ref index);
            if (text[index] == '[') return ParseArray(text, ref index);
            if (text[index] == '"') { string ignored; return ParseString(text, ref index, out ignored); }
            int start = index;
            while (index < text.Length && ",]} \t\r\n".IndexOf(text[index]) < 0) index++;
            return index > start;
        }
        private static bool ParseObject(string text, ref int index) {
            index++;
            SkipWhitespace(text, ref index);
            var names = new HashSet<string>(StringComparer.Ordinal);
            if (index < text.Length && text[index] == '}') { index++; return true; }
            while (true) {
                string name;
                if (!ParseString(text, ref index, out name) || !names.Add(name)) return false;
                SkipWhitespace(text, ref index);
                if (index >= text.Length || text[index++] != ':') return false;
                if (!ParseValue(text, ref index)) return false;
                SkipWhitespace(text, ref index);
                if (index >= text.Length) return false;
                if (text[index] == '}') { index++; return true; }
                if (text[index++] != ',') return false;
                SkipWhitespace(text, ref index);
            }
        }
        private static bool ParseArray(string text, ref int index) {
            index++;
            SkipWhitespace(text, ref index);
            if (index < text.Length && text[index] == ']') { index++; return true; }
            while (true) {
                if (!ParseValue(text, ref index)) return false;
                SkipWhitespace(text, ref index);
                if (index >= text.Length) return false;
                if (text[index] == ']') { index++; return true; }
                if (text[index++] != ',') return false;
            }
        }
        private static bool ParseString(string text, ref int index, out string value) {
            value = null;
            if (index >= text.Length || text[index++] != '"') return false;
            var builder = new StringBuilder();
            while (index < text.Length) {
                char current = text[index++];
                if (current == '"') { value = builder.ToString(); return true; }
                if (current < 0x20) return false;
                if (current != '\\') { builder.Append(current); continue; }
                if (index >= text.Length) return false;
                char escaped = text[index++];
                if (escaped == '"' || escaped == '\\' || escaped == '/') { builder.Append(escaped); continue; }
                if (escaped == 'b') { builder.Append('\b'); continue; }
                if (escaped == 'f') { builder.Append('\f'); continue; }
                if (escaped == 'n') { builder.Append('\n'); continue; }
                if (escaped == 'r') { builder.Append('\r'); continue; }
                if (escaped == 't') { builder.Append('\t'); continue; }
                if (escaped != 'u' || index + 4 > text.Length) return false;
                int code = 0;
                for (int offset = 0; offset < 4; offset++) {
                    int digit = Hex(text[index++]);
                    if (digit < 0) return false;
                    code = (code << 4) | digit;
                }
                builder.Append((char)code);
            }
            return false;
        }
        private static int Hex(char value) {
            if (value >= '0' && value <= '9') return value - '0';
            if (value >= 'a' && value <= 'f') return value - 'a' + 10;
            if (value >= 'A' && value <= 'F') return value - 'A' + 10;
            return -1;
        }
    }
}
'@
}

function Test-BridgeDoctorJsonNoDuplicateProperties {
    param([Parameter(Mandatory)][string]$Json)
    try {
        Initialize-BridgeDoctorJsonInspector
        return [HermesBridge.DoctorJsonInspector]::HasUniqueObjectProperties($Json)
    } catch { return $false }
}

function Read-BridgeDoctorBoundedHttpContent {
    param(
        [Parameter(Mandatory)][Net.Http.HttpContent]$Content,
        [Parameter(Mandatory)][Threading.CancellationToken]$CancellationToken
    )
    $maximumBytes = 65536
    $stream = $null
    $memory = [IO.MemoryStream]::new()
    try {
        if ($Content.Headers.ContentLength -ne $null -and $Content.Headers.ContentLength -gt $maximumBytes) { return $null }
        # ResponseHeadersRead 뒤 Content stream 획득도 cancellation deadline 밖으로 빠지지 않게 합니다.
        $openStreamTask = $Content.ReadAsStreamAsync()
        $deadlineTask = [Threading.Tasks.Task]::Delay([Threading.Timeout]::Infinite, $CancellationToken)
        if ([Threading.Tasks.Task]::WaitAny([Threading.Tasks.Task[]]@($openStreamTask, $deadlineTask)) -ne 0) {
            return $null
        }
        $stream = $openStreamTask.GetAwaiter().GetResult()
        $buffer = [byte[]]::new(4096)
        while ($true) {
            $remaining = ($maximumBytes + 1) - [int]$memory.Length
            if ($remaining -le 0) { return $null }
            $read = $stream.ReadAsync($buffer, 0, [Math]::Min($buffer.Length, $remaining), $CancellationToken).GetAwaiter().GetResult()
            if ($read -eq 0) { break }
            $memory.Write($buffer, 0, $read)
        }
        if ($memory.Length -gt $maximumBytes) { return $null }
        return ([Text.UTF8Encoding]::new($false, $true)).GetString($memory.ToArray())
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        $memory.Dispose()
    }
}

function Get-BridgeDoctorSseJsonMessage {
    param([Parameter(Mandatory)][string]$Body)
    $messages = [Collections.Generic.List[string]]::new()
    $dataLines = [Collections.Generic.List[string]]::new()
    $eventName = ''
    foreach ($line in [regex]::Split($Body, "`r?`n")) {
        if ($line.Length -eq 0) {
            if ($dataLines.Count -gt 0) {
                if ($eventName.Length -gt 0 -and $eventName -cne 'message') { return $null }
                $messages.Add(($dataLines -join "`n"))
            }
            $dataLines.Clear(); $eventName = ''
        } elseif ($line.StartsWith(':', [StringComparison]::Ordinal)) {
            continue
        } elseif ($line.StartsWith('event:', [StringComparison]::Ordinal)) {
            if ($eventName.Length -gt 0) { return $null }
            $eventName = $line.Substring(6).TrimStart(' ')
        } elseif ($line.StartsWith('data:', [StringComparison]::Ordinal)) {
            $dataLines.Add($line.Substring(5).TrimStart(' '))
        } else { return $null }
    }
    if ($dataLines.Count -ne 0 -or $messages.Count -ne 1) { return $null }
    return $messages[0]
}

function Get-AuthenticatedPipeAclStatus {
    param(
        [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$Port,
        [string]$ServeHost,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Capability,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$TokenPath
    )
    $unavailable = [pscustomobject]@{ state = 'unavailable'; worker = ''; privileged = '' }
    if ([string]::IsNullOrWhiteSpace($ServeHost)) { return $unavailable }
    $timeoutSeconds = 5
    $deadline = $null
    try {
        $token = [IO.File]::ReadAllText($TokenPath).Trim()
        if ([string]::IsNullOrWhiteSpace($token)) { return $unavailable }
        Add-Type -AssemblyName System.Net.Http -ErrorAction Stop
        $handler = [Net.Http.HttpClientHandler]::new()
        $client = [Net.Http.HttpClient]::new($handler)
        $deadline = [Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($timeoutSeconds))
        $request = $null
        $response = $null
        try {
            # 같은 인증된 MCP endpoint의 status tool만 읽으며 proxy/redirect와 새 IPC 연결을 만들지 않습니다.
            $handler.UseProxy = $false
            $handler.AllowAutoRedirect = $false
            $client.Timeout = [Threading.Timeout]::InfiniteTimeSpan
            $request = [Net.Http.HttpRequestMessage]::new(
                [Net.Http.HttpMethod]::Post, ("http://127.0.0.1:{0}/mcp" -f $Port))
            $request.Headers.Host = $ServeHost
            [void]$request.Headers.TryAddWithoutValidation('Origin', ("https://{0}" -f $ServeHost))
            $request.Headers.Accept.Add([Net.Http.Headers.MediaTypeWithQualityHeaderValue]::new('application/json'))
            $request.Headers.Accept.Add([Net.Http.Headers.MediaTypeWithQualityHeaderValue]::new('text/event-stream'))
            $capabilities = @{ $Capability = @(@{ src = @('local-doctor-probe') }) } | ConvertTo-Json -Compress -Depth 5
            [void]$request.Headers.TryAddWithoutValidation('Tailscale-App-Capabilities', $capabilities)
            [void]$request.Headers.TryAddWithoutValidation('MCP-Protocol-Version', '2026-07-28')
            [void]$request.Headers.TryAddWithoutValidation('Mcp-Method', 'tools/call')
            [void]$request.Headers.TryAddWithoutValidation('Mcp-Name', 'status')
            $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $token)
            $requestBody = '{"jsonrpc":"2.0","id":"doctor-pipe-acl-status","method":"tools/call","params":{"name":"status","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"local-doctor","version":"1"}}}}'
            $request.Content = [Net.Http.StringContent]::new($requestBody, [Text.Encoding]::UTF8, 'application/json')
            $response = $client.SendAsync(
                $request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $deadline.Token).GetAwaiter().GetResult()
            if ([int]$response.StatusCode -ne 200 -or $null -eq $response.Content) { return $unavailable }
            $body = Read-BridgeDoctorBoundedHttpContent -Content $response.Content -CancellationToken $deadline.Token
            if ([string]::IsNullOrWhiteSpace($body)) {
                return [pscustomobject]@{ state = 'malformed'; worker = ''; privileged = '' }
            }
            $contentType = if ($null -eq $response.Content.Headers.ContentType) { '' } else { [string]$response.Content.Headers.ContentType.MediaType }
            if ($contentType -ceq 'text/event-stream') { $body = Get-BridgeDoctorSseJsonMessage -Body $body }
            if ([string]::IsNullOrWhiteSpace($body) -or -not (Test-BridgeDoctorJsonNoDuplicateProperties -Json $body)) {
                return [pscustomobject]@{ state = 'malformed'; worker = ''; privileged = '' }
            }
            if ($contentType -cne 'application/json' -and $contentType -cne 'text/event-stream') {
                return [pscustomobject]@{ state = 'malformed'; worker = ''; privileged = '' }
            }
            try { $document = $body | ConvertFrom-Json -ErrorAction Stop }
            catch { return [pscustomobject]@{ state = 'malformed'; worker = ''; privileged = '' } }
            $topFields = @($document.PSObject.Properties | ForEach-Object { [string]$_.Name })
            if ($document.jsonrpc -cne '2.0' -or $document.id -cne 'doctor-pipe-acl-status' -or
                $topFields -notcontains 'result' -or $topFields -contains 'error' -or $null -eq $document.result) {
                return [pscustomobject]@{ state = 'malformed'; worker = ''; privileged = '' }
            }
            $resultFields = @($document.result.PSObject.Properties | ForEach-Object { [string]$_.Name })
            if ($resultFields -notcontains 'structuredContent' -or $null -eq $document.result.structuredContent -or
                ($resultFields -contains 'isError' -and ($document.result.isError -isnot [bool] -or $document.result.isError))) {
                return [pscustomobject]@{ state = 'malformed'; worker = ''; privileged = '' }
            }
            $structured = $document.result.structuredContent
            $structuredFields = @($structured.PSObject.Properties | ForEach-Object { [string]$_.Name })
            if ($structuredFields -notcontains 'pipe_acl' -or $null -eq $structured.pipe_acl) {
                return [pscustomobject]@{ state = 'malformed'; worker = ''; privileged = '' }
            }
            $pipeAcl = $structured.pipe_acl
            $pipeFields = @($pipeAcl.PSObject.Properties | ForEach-Object { [string]$_.Name } | Sort-Object)
            if (($pipeFields | ConvertTo-Json -Compress) -cne ('privileged','worker' | Sort-Object | ConvertTo-Json -Compress)) {
                return [pscustomobject]@{ state = 'malformed'; worker = ''; privileged = '' }
            }
            $states = @('verified', 'mismatch', 'unverified', 'offline')
            $worker = [string]$pipeAcl.worker
            $privileged = [string]$pipeAcl.privileged
            if ($worker -notin $states -or $privileged -notin $states) {
                return [pscustomobject]@{ state = 'malformed'; worker = ''; privileged = '' }
            }
            return [pscustomobject]@{ state = 'observed'; worker = $worker; privileged = $privileged }
        } finally {
            if ($null -ne $response) { $response.Dispose() }
            if ($null -ne $request) { $request.Dispose() }
            if ($null -ne $client) { $client.Dispose() }
            if ($null -ne $handler) { $handler.Dispose() }
            if ($null -ne $deadline) { $deadline.Dispose() }
        }
    } catch {
        # token, network, parser, auth failure의 원문은 output으로 내보내지 않습니다.
        return $unavailable
    }
}

function Get-PipeAclStatusChecks {
    param(
        [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$Port,
        [string]$ServeHost,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Capability,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$TokenPath
    )
    $observation = Get-AuthenticatedPipeAclStatus -Port $Port -ServeHost $ServeHost `
        -Capability $Capability -TokenPath $TokenPath
    $checks = [Collections.Generic.List[object]]::new()
    foreach ($definition in @(
            [ordered]@{ id = 'worker_pipe_acl'; role = 'worker' },
            [ordered]@{ id = 'privileged_pipe_acl'; role = 'privileged' }
        )) {
        $state = if ($observation.state -eq 'observed') { [string]$observation.($definition.role) } else { '' }
        if ($state -eq 'verified') {
            $checks.Add((New-CheckResult -Id $definition.id -Status 'pass' -Critical $true `
                -Detail 'authenticated current gateway pipe ACL observation is verified'))
        } elseif ($state -eq 'mismatch') {
            $checks.Add((New-CheckResult -Id $definition.id -Status 'fail' -Critical $true `
                -Detail 'authenticated current gateway pipe ACL observation reports an exact template mismatch'))
        } else {
            # 구버전/부재/끊긴 연결/확인 불가 모두 online 상태로 승격하지 않습니다.
            $checks.Add((New-CheckResult -Id $definition.id -Status 'warn' -Critical $true `
                -Detail 'authenticated current gateway pipe ACL observation is unavailable or unverified'))
        }
    }
    return $checks
}

function Get-InstallationContextCheck {
    param([Parameter(Mandatory)]$Context)
    try {
        $expectedPrefix = 'HermesWindowsBridgeEval-{0}' -f [string]$Context.nonce
        $expectedProgramRoot = [IO.Path]::Combine([Environment]::GetFolderPath('ProgramFiles'), $expectedPrefix)
        $expectedProgramDataRoot = [IO.Path]::Combine([Environment]::GetFolderPath('CommonApplicationData'), $expectedPrefix)
        $expectedLocalDataRoot = [IO.Path]::Combine([Environment]::GetFolderPath('LocalApplicationData'), $expectedPrefix)
        $valid = [int]$Context.schemaVersion -eq 1 -and
            [string]$Context.prefix -ceq $expectedPrefix -and
            [string]$Context.programRoot -ceq $expectedProgramRoot -and
            [string]$Context.programDataRoot -ceq $expectedProgramDataRoot -and
            [string]$Context.localDataRoot -ceq $expectedLocalDataRoot -and
            [string]$Context.gatewayServiceName -ceq ($expectedPrefix + '-Gateway') -and
            [string]$Context.privilegedServiceName -ceq ($expectedPrefix + '-Privileged') -and
            [string]$Context.workerTaskName -ceq ($expectedPrefix + '-Worker') -and
            [string]$Context.workerPipe -ceq ('\\.\pipe\' + $expectedPrefix + '-Worker') -and
            [string]$Context.privilegedPipe -ceq ('\\.\pipe\' + $expectedPrefix + '-Privileged') -and
            [string]$Context.serveHost -ceq ('eval-{0}.ts.net' -f [string]$Context.nonce) -and
            [string]$Context.tokenPath -ceq ([IO.Path]::Combine($expectedProgramDataRoot, 'HermesWindowsBridge', 'secrets', 'token')) -and
            [int]$Context.port -ge 49152 -and [int]$Context.port -le 65535
        if ($valid) {
            return New-CheckResult -Id 'installation_context' -Status 'pass' -Critical $true `
                -Detail 'validated nonce-scoped installation context selects exact local roots, service/task names, and port'
        }
        return New-CheckResult -Id 'installation_context' -Status 'fail' -Critical $true `
            -Detail 'installation context does not derive the required nonce-scoped local resources'
    } catch {
        return New-CheckResult -Id 'installation_context' -Status 'fail' -Critical $true `
            -Detail 'installation context could not be validated'
    }
}

$checks = [Collections.Generic.List[object]]::new()
if ($installationContextMode) {
    $checks.Add((Get-InstallationContextCheck -Context $installationContext))
}
$tailscaleCommand = Get-Command -Name 'tailscale.exe' -ErrorAction SilentlyContinue
if ($null -eq $tailscaleCommand) {
    $checks.Add((New-CheckResult -Id 'tailscale' -Status 'fail' -Critical $true -Detail 'Tailscale CLI is not installed'))
} else {
    # 읽기 전용 공식 CLI 표면: status --json; serve status --json
    $tailscaleStatus = Invoke-BoundedCommand -FilePath $tailscaleCommand.Source -ArgumentList @('status', '--json')
    $serveStatus = Invoke-BoundedCommand -FilePath $tailscaleCommand.Source -ArgumentList @('serve', 'status', '--json')
    $policyIntent = Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Policies\Tailscale' -Name 'UnattendedMode' -ErrorAction SilentlyContinue
    $connected = $tailscaleStatus.completed -and $tailscaleStatus.exitCode -eq 0 -and $tailscaleStatus.output -match '"BackendState"\s*:\s*"Running"'
    $serveConfigured = $serveStatus.completed -and $serveStatus.exitCode -eq 0 -and $serveStatus.output -notmatch '^\s*\{\s*\}\s*$'
    $appCapsConfigured = $serveConfigured -and $serveStatus.output -match 'hermes\.local/windows-control|accept-app-caps|AppCaps'
    $intentKnown = $policyIntent -in @('always', 'never')
    if (-not $intentKnown) {
        # 사용자 CLI 설정은 조직 정책 레지스트리에 기록되지 않습니다.
        $unattendedPreference = Invoke-BoundedCommand -FilePath $tailscaleCommand.Source -ArgumentList @('get', 'unattended')
        $intentKnown = $unattendedPreference.completed -and $unattendedPreference.exitCode -eq 0 -and
            ([string]$unattendedPreference.output).Trim() -cin @('true', 'false')
    }
    if (-not $tailscaleStatus.completed -or -not $serveStatus.completed) {
        $checks.Add((New-CheckResult -Id 'tailscale' -Status 'fail' -Critical $true -Detail 'Tailscale status query timed out'))
    } elseif (-not $connected) {
        $checks.Add((New-CheckResult -Id 'tailscale' -Status 'fail' -Critical $true -Detail 'Tailscale is installed but not connected'))
    } elseif ($serveConfigured -and $appCapsConfigured -and $intentKnown) {
        $checks.Add((New-CheckResult -Id 'tailscale' -Status 'pass' -Critical $true -Detail 'connected; unattended intent, Serve, and App Capability forwarding are observable'))
    } else {
        $checks.Add((New-CheckResult -Id 'tailscale' -Status 'warn' -Critical $true -Detail 'connected; unattended intent, Serve, or App Capability forwarding is not fully observable'))
    }
}

$checks.Add((Get-ServiceCheck -Id 'gateway_service' -Name $gatewayServiceName -ExpectedAccount 'NT AUTHORITY\LocalService'))
$checks.Add((Get-ServiceCheck -Id 'privileged_helper_service' -Name $privilegedServiceName -ExpectedAccount 'LocalSystem'))

$listeners = @(Get-NetTCPConnection -State Listen -LocalPort $gatewayPort -ErrorAction SilentlyContinue)
$publicListeners = @($listeners | Where-Object { $_.LocalAddress -notin @('127.0.0.1', '::1') })
if ($publicListeners.Count -gt 0) {
    $checks.Add((New-CheckResult -Id 'backend_listener' -Status 'fail' -Critical $true -Detail ("port {0} is listening on a public interface" -f $gatewayPort)))
} elseif ($listeners.Count -eq 0) {
    $checks.Add((New-CheckResult -Id 'backend_listener' -Status 'fail' -Critical $true -Detail ("loopback backend is not listening on port {0}" -f $gatewayPort)))
} else {
    $checks.Add((New-CheckResult -Id 'backend_listener' -Status 'pass' -Critical $true -Detail ("port {0} listens on loopback only; no public listener exists" -f $gatewayPort)))
}

if ($listeners.Count -eq 0) {
    $checks.Add((New-CheckResult -Id 'bearer_auth' -Status 'fail' -Critical $true -Detail 'missing and invalid bearer rejection cannot be tested without the backend'))
} else {
$checks.Add((Get-BearerAuthCheck -Port $gatewayPort -ServeHost $doctorTransportServeHost -Capability $Capability))
}

$workerTask = Get-ScheduledTask -TaskName $workerTaskName -ErrorAction SilentlyContinue
$capabilityFiles = @('worker\desktop_capture.py', 'worker\uia.py', 'worker\shell.py', 'worker\browser.py')
$missingCapabilities = @($capabilityFiles | Where-Object { -not (Test-Path -LiteralPath ([IO.Path]::Combine($PSScriptRoot, '..', 'src', 'hermes_windows_bridge', $_))) })
if ($null -eq $workerTask) {
    $checks.Add((New-CheckResult -Id 'interactive_worker' -Status 'fail' -Critical $true -Detail 'interactive Worker task is not registered; runtime capabilities are unavailable'))
} elseif ($workerTask.Principal.RunLevel -ne 'Limited') {
    $checks.Add((New-CheckResult -Id 'interactive_worker' -Status 'fail' -Critical $true -Detail 'interactive Worker task is elevated'))
} elseif ($workerTask.State -eq 'Running' -and $missingCapabilities.Count -eq 0) {
    $checks.Add((New-CheckResult -Id 'interactive_worker' -Status 'pass' -Critical $true -Detail 'non-elevated Worker is online; screenshot, UIA, shell, and browser adapters are present'))
} else {
    $checks.Add((New-CheckResult -Id 'interactive_worker' -Status 'warn' -Critical $true -Detail 'Worker is Limited but no online capability signal is available; runtime success was not assumed'))
}

$playwrightCommand = Get-Command -Name 'playwright.exe' -ErrorAction SilentlyContinue
$playwrightModule = Test-Path -LiteralPath ([IO.Path]::Combine($PSScriptRoot, '..', '.venv', 'Lib', 'site-packages', 'playwright'))
$checks.Add((New-CheckResult -Id 'playwright' -Status $(if ($null -ne $playwrightCommand -or $playwrightModule) { 'pass' } else { 'warn' }) -Critical $false -Detail $(if ($null -ne $playwrightCommand -or $playwrightModule) { 'Playwright is installed; launch requires an online Worker probe' } else { 'Playwright is not installed' })))
$codexCommand = Get-Command -Name 'codex.exe' -ErrorAction SilentlyContinue
$checks.Add((New-CheckResult -Id 'codex' -Status $(if ($null -ne $codexCommand) { 'pass' } else { 'warn' }) -Critical $false -Detail $(if ($null -ne $codexCommand) { 'Codex CLI is available' } else { 'Codex CLI was not found' })))

try {
if (-not (Test-Path -LiteralPath $tokenPath -PathType Leaf)) {
    $checks.Add((New-CheckResult -Id 'token_acl' -Status 'fail' -Critical $true -Detail 'bridge token file does not exist'))
} else {
    $tokenAcl = Get-Acl -LiteralPath $tokenPath
    $allowedSids = @('S-1-5-18', 'S-1-5-19', 'S-1-5-32-544')
    $unexpected = @($tokenAcl.Access | Where-Object {
        try { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $allowedSids } catch { $true }
    })
    $status = if ($tokenAcl.AreAccessRulesProtected -and $unexpected.Count -eq 0) { 'pass' } else { 'fail' }
    $checks.Add((New-CheckResult -Id 'token_acl' -Status $status -Critical $true -Detail $(if ($status -eq 'pass') { 'token ACL is protected and restricted to expected service/admin identities' } else { 'token ACL is inherited or grants an unexpected identity' })))
}

} catch [System.UnauthorizedAccessException] {
    $checks.Add((New-CheckResult -Id 'token_acl' -Status 'fail' -Critical $true -Detail 'token ACL cannot be inspected by this process; run doctor as administrator'))
}

if ($securityMode -or $installationContextMode -or -not [string]::IsNullOrWhiteSpace($selectedServiceReleaseRoot)) {
    $commonHelperPath = Join-Path $PSScriptRoot 'lifecycle-common.ps1'
    $runtimeHelperPath = Join-Path $PSScriptRoot 'service-runtime.ps1'
    $transactionHelperPath = Join-Path $PSScriptRoot 'service-runtime-transaction.ps1'
    try {
        # transaction의 Inspect child는 공통 read-only process boundary를 쓰므로 현재 checkout helper만 함께 load합니다.
        . $commonHelperPath
        . $runtimeHelperPath -LibraryMode
        . $transactionHelperPath
    } catch {
        # helper load failure는 아래 runtime check가 explicit unverified로 정규화합니다.
    }
    $checks.Add((Get-ProtectedServiceRuntimeCheck -Id 'protected_service_runtime' `
        -ProgramRoot $serviceProgramRoot -ServiceReleaseRoot $selectedServiceReleaseRoot `
        -GatewayServiceHostRoot $selectedGatewayServiceHostRoot `
        -PrivilegedServiceHostRoot $selectedPrivilegedServiceHostRoot `
        -GatewayServiceName $gatewayServiceName -PrivilegedServiceName $privilegedServiceName `
        -InstallationContext $installationContext))
}

if ($securityMode) {
    $checks.Add((Get-BridgeServiceObjectAclCheck -Id 'gateway_service_object_acl' -Name $gatewayServiceName))
    $checks.Add((Get-BridgeServiceRegistryAclCheck -Id 'gateway_service_registry_acl' -Name $gatewayServiceName))
    $checks.Add((Get-BridgeServiceObjectAclCheck -Id 'privileged_service_object_acl' -Name $privilegedServiceName))
    $checks.Add((Get-BridgeServiceRegistryAclCheck -Id 'privileged_service_registry_acl' -Name $privilegedServiceName))
    $checks.Add((Get-TransportPolicyCheck -Port $gatewayPort -ServeHost $doctorTransportServeHost `
        -Capability $Capability -TokenPath $tokenPath))
    foreach ($pipeCheck in @(Get-PipeAclStatusChecks -Port $gatewayPort -ServeHost $doctorTransportServeHost `
            -Capability $Capability -TokenPath $tokenPath)) {
        $checks.Add($pipeCheck)
    }
    $markerState = if (Test-Path -LiteralPath $markerPath -PathType Leaf) { 'disabled marker is present' } else { 'disabled marker is absent; remote input is enabled' }
    $checks.Add((New-CheckResult -Id 'remote_input_state' -Status 'pass' -Critical $false -Detail $markerState))
    $operationSource = Get-Content -LiteralPath ([IO.Path]::Combine($PSScriptRoot, '..', 'src', 'hermes_windows_bridge', 'privileged', 'operations.py')) -Raw
    $closedSurface = $operationSource -match 'frozenset\(\{"reboot", "shutdown"\}\)' -and $operationSource -notmatch '(?im)^\s*["'']?(?:shell|exec|command)'
    $checks.Add((New-CheckResult -Id 'privileged_tool_surface' -Status $(if ($closedSurface) { 'pass' } else { 'fail' }) -Critical $true -Detail $(if ($closedSurface) { 'privileged registry exposes only typed reboot/shutdown operations' } else { 'privileged registry is unavailable or not a closed typed surface' })))
}

$criticalFailures = @($checks | Where-Object { $_.critical -and $_.status -eq 'fail' })
$report = [ordered]@{
    schemaVersion = 1
    kind = 'hermes-windows-bridge-doctor'
    readOnly = $true
    securityMode = $securityMode
    installationContext = $installationContextMode
    gatewayPort = $gatewayPort
    maxExternalCommandSeconds = $externalCommandTimeoutSeconds
    healthy = ($criticalFailures.Count -eq 0)
    checks = $checks
}
if ($jsonOutput) {
    $report | ConvertTo-Json -Depth 6
} else {
    Write-Output 'Hermes Windows Bridge doctor (read-only)'
    foreach ($check in $checks) { Write-Output ("[{0}] {1} - {2}" -f $check.status.ToUpperInvariant(), $check.id, $check.detail) }
    Write-Output ("Healthy: {0}" -f $report.healthy)
}
if ($report.healthy) { exit 0 }
exit 1
