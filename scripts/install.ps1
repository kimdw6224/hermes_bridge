[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Apply,
    [switch]$Json,
    [switch]$ConfigureTailscale,
    [switch]$InstallPlaywright,
    [switch]$AcknowledgeLegacyFailedRollback,
    [ValidateSet('Production', 'Simulate')][string]$AdapterMode = 'Production',
    [ValidateSet(
        'None', 'dependencies', 'runtime_directories', 'token', 'token_acl', 'hermes_config',
        'gateway_service', 'privileged_helper_service', 'interactive_worker_task',
        'runtime_access', 'privileged_service_start', 'gateway_service_start', 'worker_task_start',
        'playwright_chromium', 'tailscale_serve', 'doctor', 'backup_resume'
    )][string]$SimulationFailureStep = 'None',
    [ValidateSet('Desired', 'EmptyApply', 'ApplyReadbackMismatch', 'ConcurrentConflict')]
    [string]$SimulationScenario = 'Desired',
    [string]$ServeHost = '',
    [string]$Capability = 'hermes.local/windows-control',
    [ValidateRange(1, 65535)][int]$Port = 8765,
    [string]$ProgramDataRoot = $env:ProgramData,
    [string]$LocalDataRoot = $env:LOCALAPPDATA,
    [string]$ExistingConfigPath = '',
    [string]$ServiceReleaseRoot = '',
    [string]$GatewayServiceHostRoot = '',
    [string]$PrivilegedServiceHostRoot = '',
    [string]$InstallationContextPath = '',
    [string]$InstallationContextSha256 = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$callerSpecifiedProgramDataRoot = $PSBoundParameters.ContainsKey('ProgramDataRoot')
$callerSpecifiedLocalDataRoot = $PSBoundParameters.ContainsKey('LocalDataRoot')
$callerSpecifiedPort = $PSBoundParameters.ContainsKey('Port')
$canonicalScriptRoot = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\', '/')
$scriptRootItem = Get-Item -LiteralPath $canonicalScriptRoot -Force -ErrorAction Stop
if (-not $scriptRootItem.PSIsContainer -or
    ($scriptRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    -not $scriptRootItem.FullName.TrimEnd('\', '/').Equals($canonicalScriptRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw [IO.IOException]::new('BridgeScriptRootUnsafe: script root is non-canonical or a reparse point.')
}
$commonScriptPath = [IO.Path]::GetFullPath([IO.Path]::Combine($canonicalScriptRoot, 'lifecycle-common.ps1'))
$commonScriptItem = Get-Item -LiteralPath $commonScriptPath -Force -ErrorAction Stop
if ($commonScriptItem.PSIsContainer -or
    ($commonScriptItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    -not $commonScriptItem.FullName.Equals($commonScriptPath, [StringComparison]::OrdinalIgnoreCase) -or
    -not (Split-Path -Parent $commonScriptItem.FullName).Equals($canonicalScriptRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw [IO.IOException]::new('BridgeCommonScriptUnsafe: common script is non-canonical, relocated, or a reparse point.')
}
. ($commonScriptItem.FullName)
$contextScriptPath = [IO.Path]::GetFullPath([IO.Path]::Combine($canonicalScriptRoot, 'installation-context.ps1'))
$contextScriptItem = Get-Item -LiteralPath $contextScriptPath -Force -ErrorAction Stop
if ($contextScriptItem.PSIsContainer -or
    ($contextScriptItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    -not $contextScriptItem.FullName.Equals($contextScriptPath, [StringComparison]::OrdinalIgnoreCase)) {
    throw [IO.IOException]::new('BridgeInstallationContextScriptUnsafe')
}
. $contextScriptItem.FullName
$runtimeContractPath = [IO.Path]::Combine($canonicalScriptRoot, 'service-runtime.ps1')
$callerApply = $Apply
$callerJson = $Json
$callerInstallationContextPath = $InstallationContextPath
$callerInstallationContextSha256 = $InstallationContextSha256
. $runtimeContractPath -LibraryMode
# dot-source 대상의 동일 이름 매개변수가 호출자의 실행 의도나 nonce context 쌍을 덮지 못하게 보존합니다.
$Apply = $callerApply
$Json = $callerJson
$InstallationContextPath = $callerInstallationContextPath
$InstallationContextSha256 = $callerInstallationContextSha256
$transactionScriptPath = [IO.Path]::Combine($canonicalScriptRoot, 'service-runtime-transaction.ps1')
if (-not (Test-Path -LiteralPath $transactionScriptPath -PathType Leaf)) {
    throw [IO.FileNotFoundException]::new('BridgeServiceRuntimeTransactionMissing')
}
. $transactionScriptPath

$serviceHostsSpecified = -not [string]::IsNullOrWhiteSpace($GatewayServiceHostRoot) -or
    -not [string]::IsNullOrWhiteSpace($PrivilegedServiceHostRoot)
if ($serviceHostsSpecified -and
    ([string]::IsNullOrWhiteSpace($GatewayServiceHostRoot) -or [string]::IsNullOrWhiteSpace($PrivilegedServiceHostRoot))) {
    throw [ArgumentException]::new('BridgeServiceHostRootsIncomplete: GatewayServiceHostRoot and PrivilegedServiceHostRoot must be specified together.')
}

if ([string]::IsNullOrWhiteSpace($ProgramDataRoot)) { $ProgramDataRoot = [Environment]::GetFolderPath('CommonApplicationData') }
if ([string]::IsNullOrWhiteSpace($LocalDataRoot)) { $LocalDataRoot = [Environment]::GetFolderPath('LocalApplicationData') }
$installationContext = $null
if (-not [string]::IsNullOrWhiteSpace($InstallationContextPath) -or -not [string]::IsNullOrWhiteSpace($InstallationContextSha256)) {
    Assert-BridgeInstallationContextPair -Path $InstallationContextPath -Sha256 $InstallationContextSha256
    if ($callerSpecifiedProgramDataRoot -or $callerSpecifiedLocalDataRoot -or $callerSpecifiedPort -or $ConfigureTailscale -or $InstallPlaywright -or
        -not [string]::IsNullOrWhiteSpace($ExistingConfigPath) -or $AdapterMode -cne 'Production') {
        throw [ArgumentException]::new('BridgeInstallationContextConflictingSwitch')
    }
    $installationContext = Get-BridgeInstallationContext -Path $InstallationContextPath -Sha256 $InstallationContextSha256
    $ProgramDataRoot = [string]$installationContext.programDataRoot
    $LocalDataRoot = [string]$installationContext.localDataRoot
    $Port = [int]$installationContext.port
}
$ProgramDataRoot = Resolve-BridgeLocalRoot -Path $ProgramDataRoot
$LocalDataRoot = Resolve-BridgeLocalRoot -Path $LocalDataRoot
if ($ExistingConfigPath) {
    if (-not [IO.Path]::IsPathRooted($ExistingConfigPath) -or $ExistingConfigPath.StartsWith('\\')) {
        throw [ArgumentException]::new('BridgeConfigPathInvalid: config path must be local and absolute.')
    }
    $ExistingConfigPath = [IO.Path]::GetFullPath($ExistingConfigPath)
    if (-not (Test-Path -LiteralPath $ExistingConfigPath -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new('BridgeConfigPathMissing: config source does not exist.', $ExistingConfigPath)
    }
    $existingConfigItem = Get-Item -LiteralPath $ExistingConfigPath -Force -ErrorAction Stop
    if (($existingConfigItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not $existingConfigItem.FullName.Equals($ExistingConfigPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw [IO.IOException]::new('BridgeConfigPathUnsafe: config source is non-canonical or a reparse point.')
    }
}
if ($ServeHost -and $ServeHost -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$') {
    throw [ArgumentException]::new('BridgeServeHostInvalid: ServeHost format is invalid.')
}
if ($Capability -notmatch '^[A-Za-z0-9.-]+/[A-Za-z0-9._/-]+$') {
    throw [ArgumentException]::new('BridgeCapabilityInvalid: Capability format is invalid.')
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$serviceProgramRoot = if ($null -eq $installationContext) {
    [IO.Path]::Combine([Environment]::GetFolderPath('ProgramFiles'), 'HermesWindowsBridge')
} else { [string]$installationContext.programRoot }
$serviceTransactionLock = $null
$serviceRelease = $null
$runtimeRoot = [IO.Path]::Combine($ProgramDataRoot, 'HermesWindowsBridge')
$userRoot = [IO.Path]::Combine($LocalDataRoot, 'HermesWindowsBridge')
$runtimeDirectories = @(
    $runtimeRoot, [IO.Path]::Combine($runtimeRoot, 'logs'), [IO.Path]::Combine($runtimeRoot, 'jobs'),
    [IO.Path]::Combine($runtimeRoot, 'secrets'), $userRoot,
    [IO.Path]::Combine($userRoot, 'browser-profile'), [IO.Path]::Combine($userRoot, 'logs')
)

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdministrator = Test-BridgeAdministrator
$pythonCommand = Get-Command -Name 'python.exe' -ErrorAction SilentlyContinue
$uvCommand = Get-Command -Name 'uv.exe' -ErrorAction SilentlyContinue
$tailscaleCommand = Get-Command -Name 'tailscale.exe' -ErrorAction SilentlyContinue
$playwrightCommand = Get-Command -Name 'playwright.exe' -ErrorAction SilentlyContinue
$codexCommand = Get-Command -Name 'codex.exe' -ErrorAction SilentlyContinue
$pythonPath = [IO.Path]::Combine($projectRoot, '.venv', 'Scripts', 'python.exe')
$workerPythonPath = [IO.Path]::Combine($projectRoot, '.venv', 'Scripts', 'pythonw.exe')
$runtimePythonVerified = Test-Path -LiteralPath $pythonPath -PathType Leaf
$dependenciesPresent = (Test-Path -LiteralPath ([IO.Path]::Combine($projectRoot, 'pyproject.toml'))) -and (Test-Path -LiteralPath ([IO.Path]::Combine($projectRoot, 'uv.lock')))
$runtimeEntrypoints = @(
    [ordered]@{ role = 'gateway'; module = 'hermes_windows_bridge.gateway.windows_service'; verified = (Test-BridgePythonEntrypoint -ProjectRoot $projectRoot -Module 'hermes_windows_bridge.gateway.windows_service') },
    [ordered]@{ role = 'privileged_helper'; module = 'hermes_windows_bridge.privileged.main'; verified = (Test-BridgePythonEntrypoint -ProjectRoot $projectRoot -Module 'hermes_windows_bridge.privileged.main') },
    [ordered]@{ role = 'interactive_worker'; module = 'hermes_windows_bridge.worker.main'; verified = (Test-BridgePythonEntrypoint -ProjectRoot $projectRoot -Module 'hermes_windows_bridge.worker.main') }
)
$runtimeEntrypointsVerified = @($runtimeEntrypoints | Where-Object { -not $_.verified }).Count -eq 0
$runtimeContract = if ($runtimePythonVerified) {
    Get-BridgeRuntimeContract -ProjectRoot $projectRoot -PythonPath $pythonPath
} else {
    [pscustomobject]@{ verified = $false; failureReason = 'runtime-python-unverified'; contract = $null }
}
$registrationAdapterNames = @(
    'register-gateway-service.ps1',
    'register-privileged-service.ps1',
    'register-worker-task.ps1'
)
$registrationAdaptersReady = @($registrationAdapterNames | Where-Object {
    -not (Test-BridgeRegistrationAdapterContract -ScriptRoot $PSScriptRoot -ScriptName $_)
}).Count -eq 0
$prerequisites = @(
    [ordered]@{ id = 'python'; present = ($null -ne $pythonCommand); required = $true; status = if ($null -ne $pythonCommand) { 'pass' } else { 'fail' } },
    [ordered]@{ id = 'uv'; present = ($null -ne $uvCommand); required = $true; status = if ($null -ne $uvCommand) { 'pass' } else { 'fail' } },
    [ordered]@{ id = 'dependencies'; present = $dependenciesPresent; required = $true; status = if ($dependenciesPresent) { 'pass' } else { 'fail' } },
    [ordered]@{ id = 'tailscale'; present = ($null -ne $tailscaleCommand); required = $true; status = if ($null -ne $tailscaleCommand) { 'pass' } else { 'fail' } },
    [ordered]@{ id = 'playwright'; present = ($null -ne $playwrightCommand); required = $false; status = if ($null -ne $playwrightCommand) { 'pass' } else { 'warn' } },
    [ordered]@{ id = 'codex'; present = ($null -ne $codexCommand); required = $false; status = if ($null -ne $codexCommand) { 'pass' } else { 'warn' } }
)
$registrationPlans = @(
    [ordered]@{ kind = 'windows-service'; name = $(if ($null -eq $installationContext) { 'HermesWindowsBridgeGateway' } else { $installationContext.gatewayServiceName }); script = [IO.Path]::Combine($PSScriptRoot, 'register-gateway-service.ps1'); argv = @('-RuntimeManifestPath', $(if ($null -eq $serviceRelease) { '<protected-release-required>' } else { $serviceRelease.manifestPath }), '-RuntimeReleaseRoot', $(if ($null -eq $serviceRelease) { '<protected-release-required>' } else { $serviceRelease.releaseRoot })); serviceArgv = @($(if ($null -eq $serviceRelease) { '<protected-release-required>' } else { $serviceRelease.serviceExecutable }), '-I', '-B', '-m', 'hermes_windows_bridge.gateway.windows_service'); account = 'NT AUTHORITY\LocalService'; recovery = 'restart-on-failure' },
    [ordered]@{ kind = 'windows-service'; name = $(if ($null -eq $installationContext) { 'HermesWindowsBridgePrivileged' } else { $installationContext.privilegedServiceName }); script = [IO.Path]::Combine($PSScriptRoot, 'register-privileged-service.ps1'); argv = @('-RuntimeManifestPath', $(if ($null -eq $serviceRelease) { '<protected-release-required>' } else { $serviceRelease.manifestPath }), '-RuntimeReleaseRoot', $(if ($null -eq $serviceRelease) { '<protected-release-required>' } else { $serviceRelease.releaseRoot })); serviceArgv = @($(if ($null -eq $serviceRelease) { '<protected-release-required>' } else { $serviceRelease.serviceExecutable }), '-I', '-B', '-m', 'hermes_windows_bridge.privileged.main'); account = 'LocalSystem'; recovery = 'restart-on-failure' },
    [ordered]@{ kind = 'scheduled-task'; name = $(if ($null -eq $installationContext) { 'HermesWindowsBridgeWorker' } else { $installationContext.workerTaskName }); script = [IO.Path]::Combine($PSScriptRoot, 'register-worker-task.ps1'); argv = @('-UserId', $identity.Name, '-ExecutablePath', $pythonPath); serviceArgv = @($workerPythonPath, '-m', 'hermes_windows_bridge.worker.main'); account = $identity.Name; runLevel = 'Limited' }
)

$computerName = if ([string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) { 'windows-bridge' } else { $env:COMPUTERNAME.ToLowerInvariant() }
$effectiveServeHost = if ($ServeHost) { $ServeHost.ToLowerInvariant() } else { "$computerName.ts.net" }
if ($null -ne $installationContext) { $effectiveServeHost = [string]$installationContext.serveHost }
$finalMcpUrl = "https://$effectiveServeHost/mcp"
$tailscaleServeArgv = @('serve', '--bg', '--accept-app-caps', $Capability, [string]$Port)
$recommendedGrant = [ordered]@{
    grants = @(
        [ordered]@{ src = @('tag:hermes'); dst = @('tag:windows-bridge'); ip = @('tcp:443') },
        [ordered]@{ src = @('tag:hermes'); dst = @('tag:windows-bridge'); app = [ordered]@{ $Capability = @([ordered]@{ src = @('main', 'self') }) } }
    )
} | ConvertTo-Json -Depth 8 -Compress
$hermesConfigSnippet = @"
mcp_servers:
  windows_pc:
    url: "$finalMcpUrl"
    headers:
      Authorization: "Bearer `${HERMES_WINDOWS_BRIDGE_TOKEN}"
    timeout: 120
    connect_timeout: 20
    supports_parallel_tool_calls: false
    trust: untrusted
    elicitation:
      enabled: true
      timeout: 300
"@.Trim()

function Test-BridgeWorkerTaskAbsent {
    [CmdletBinding()]
    param([string]$TaskName = 'HermesWindowsBridgeWorker')
    try {
        return $null -eq (Get-ScheduledTask -TaskPath '\' -TaskName $TaskName -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -eq 'CmdletizationQuery_NotFound,Get-ScheduledTask') { return $true }
        throw
    }
}

function Get-BridgeLegacyRollbackReadBack {
    param(
        [Parameter(Mandatory)][string]$InstallRuntimeRoot,
        [Parameter(Mandatory)][int]$InstallPort,
        [Parameter(Mandatory)][string]$TailscalePath
    )

    $servicesAbsent = @('HermesWindowsBridgeGateway', 'HermesWindowsBridgePrivileged' | ForEach-Object {
        $null -eq (Get-Service -Name $_ -ErrorAction SilentlyContinue)
    }) -notcontains $false
    $workerTaskAbsent = $null -eq (Get-ScheduledTask -TaskName 'HermesWindowsBridgeWorker' -ErrorAction SilentlyContinue)
    $runtimeFilesAbsent = @(
        [IO.Path]::Combine($InstallRuntimeRoot, 'secrets', 'token'),
        [IO.Path]::Combine($InstallRuntimeRoot, 'config.yaml'),
        [IO.Path]::Combine($InstallRuntimeRoot, 'policy.yaml'),
        (Get-BridgeRuntimeAccessMarkerPath -RuntimeRoot $InstallRuntimeRoot)
    ) | ForEach-Object { -not (Test-Path -LiteralPath $_ -PathType Leaf) }
    $listenerAbsent = $false
    $tailscaleServeEmpty = $false
    try {
        $listenerAbsent = @(Get-NetTCPConnection -State Listen -LocalPort $InstallPort -ErrorAction Stop).Count -eq 0
    } catch {
        if ($_.FullyQualifiedErrorId -eq 'CmdletizationQuery_NotFound,Get-NetTCPConnection') { $listenerAbsent = $true }
    }
    try {
        $serveResult = Invoke-BridgeChildProcess -FilePath $TailscalePath -ArgumentList @('serve', 'status', '--json') `
            -WorkingDirectory $PSScriptRoot -TimeoutSeconds 30
        if ($serveResult.exitCode -ne 0) { throw [InvalidOperationException]::new('serve status unreadable') }
        $serveConfiguration = $serveResult.stdout | ConvertFrom-Json -ErrorAction Stop
        $tailscaleServeEmpty = @($serveConfiguration.PSObject.Properties).Count -eq 0
    } catch { }
    $clean = $servicesAbsent -and $workerTaskAbsent -and ($runtimeFilesAbsent -notcontains $false) -and $listenerAbsent -and $tailscaleServeEmpty
    return [ordered]@{
        servicesAbsent = $servicesAbsent; workerTaskAbsent = $workerTaskAbsent; runtimeFilesAbsent = $runtimeFilesAbsent
        listenerAbsent = $listenerAbsent; tailscaleServeEmpty = $tailscaleServeEmpty; verified = $clean
    }
}

$backups = @()
$unresolvedBackupState = $false
foreach ($backupRoot in @([IO.Path]::Combine($ProgramDataRoot, 'backups'), [IO.Path]::Combine($runtimeRoot, 'backups'))) {
    if (Test-Path -LiteralPath $backupRoot -PathType Container) {
        try {
            $backups += @(Get-ChildItem -LiteralPath $backupRoot -File -Recurse -ErrorAction Stop |
                Where-Object { $_.Name -in @('receipt.json', 'state.json') } | ForEach-Object { $_.FullName })
        } catch {
            # 제한 ACL을 읽을 수 없는 비관리자 계획은 변경 없이 운영자 검토 필요 상태로 표시합니다.
            $unresolvedBackupState = $true
        }
    }
}
$legacyFailedBackupStates = @()
foreach ($backupStatePath in @($backups | Where-Object { [IO.Path]::GetFileName($_) -eq 'state.json' })) {
    try {
        $backupState = Get-Content -LiteralPath $backupStatePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $status = [string]$backupState.status
        $interruptedProperty = $backupState.PSObject.Properties['interrupted']
        $rollbackVerifiedProperty = $backupState.PSObject.Properties['rollbackVerified']
        if ($null -ne $interruptedProperty -and $interruptedProperty.Value -eq $true) {
            $unresolvedBackupState = $true
        } elseif ($status -eq 'failed') {
            $legacyFailedBackupStates += [pscustomobject]@{ path = $backupStatePath; state = $backupState }
        } elseif ($status -eq 'recovered') {
            $recoveryScriptPath = Join-Path $canonicalScriptRoot 'recover-service-switch.ps1'
            $recoveryVerified = & {
                param($RecoveryScriptPath, $JournalPath)
                . $RecoveryScriptPath -LibraryMode
                Test-BridgeRecoveredJournal -StatePath $JournalPath
            } $recoveryScriptPath $backupStatePath
            if ($recoveryVerified -isnot [bool] -or -not $recoveryVerified) { $unresolvedBackupState = $true }
        } elseif ($status -eq 'completed' -or ($status -eq 'rolled-back' -and $null -ne $rollbackVerifiedProperty -and $rollbackVerifiedProperty.Value -eq $true)) {
            continue
        } else {
            $unresolvedBackupState = $true
        }
    } catch {
        $unresolvedBackupState = $true
    }
}
$interruptedBackupState = $unresolvedBackupState -or $legacyFailedBackupStates.Count -gt 0

$tokenPath = [IO.Path]::Combine($runtimeRoot, 'secrets', 'token')
$tokenExists = Test-Path -LiteralPath $tokenPath -PathType Leaf
$actions = @(
    [ordered]@{ id = 'dependencies'; planned = $true },
    [ordered]@{ id = 'token'; planned = (-not $tokenExists); state = if ($tokenExists) { 'unchanged' } else { 'create' } },
    [ordered]@{ id = 'token_acl'; planned = $true }, [ordered]@{ id = 'runtime_access'; planned = $true },
    [ordered]@{ id = 'gateway_service'; planned = $true },
    [ordered]@{ id = 'privileged_helper_service'; planned = $true }, [ordered]@{ id = 'interactive_worker_task'; planned = $true }
)
if ($InstallPlaywright) { $actions += [ordered]@{ id = 'playwright_chromium'; planned = $true } }
if ($ConfigureTailscale) {
    $actions += [ordered]@{ id = 'tailscale_serve'; planned = $true }
    $actions += [ordered]@{ id = 'tailscale_grant'; planned = $true }
}
$actions += [ordered]@{ id = 'hermes_config'; planned = $true }
$actions += [ordered]@{ id = 'doctor'; planned = $true }
$actions += [ordered]@{ id = 'backup_resume'; planned = $true }

$plan = [ordered]@{
    schemaVersion = 1; kind = 'hermes-windows-bridge-install-plan'; mode = if ($WhatIfPreference) { 'what-if' } elseif ($Apply) { 'apply' } else { 'read-only' }
    applied = $false; atomic = $true; resumeSafe = $true; administratorRequiredForInstall = $true; currentProcessElevated = $isAdministrator
    runtimeDirectories = $runtimeDirectories
    existingConfigAction = if ($ExistingConfigPath -and (Test-Path -LiteralPath $ExistingConfigPath -PathType Leaf)) { 'preserve-existing' } else { 'create-during-approved-install' }
    prerequisites = $prerequisites; registrations = $registrationPlans; actions = $actions; backups = @($backups)
    dependencyArgv = @('uv', 'sync', '--frozen')
    playwrightArgv = if ($InstallPlaywright) { @('uv', 'run', 'python', '-m', 'playwright', 'install', 'chromium') } else { @() }
    tailscaleServeArgv = if ($ConfigureTailscale) { $tailscaleServeArgv } else { @() }
    tailscaleAdapterArgv = if ($ConfigureTailscale) { @('-File', [IO.Path]::Combine($PSScriptRoot, 'configure-tailscale.ps1'), '-ServeHost', $effectiveServeHost, '-Capability', $Capability, '-Port', [string]$Port, '-Apply') } else { @() }
    recommendedGrant = $recommendedGrant; finalMcpUrl = $finalMcpUrl; hermesConfigSnippet = $hermesConfigSnippet
    gatewayConfiguration = [ordered]@{ bindHost = '127.0.0.1'; port = $Port; allowedHosts = @($effectiveServeHost); allowedOrigins = @("https://$effectiveServeHost") }
    tokenPolicy = [ordered]@{ bytes = 32; output = 'never'; existing = 'preserve'; environmentVariable = 'HERMES_WINDOWS_BRIDGE_TOKEN' }
    runtimePython = [ordered]@{ path = $pythonPath; verified = $runtimePythonVerified }
    runtimeEntrypoints = $runtimeEntrypoints; runtimeEntrypointsVerified = $runtimeEntrypointsVerified
    runtimeContract = $runtimeContract
    registrationAdaptersReady = $registrationAdaptersReady; state = 'planned'; failureReason = $null
    registrationResults = @()
    serviceTransaction = $null
    adapterMode = $AdapterMode
    receipts = @()
    rollback = @()
    preservedChanges = @()
    failedStep = $null
    externalCalls = if ($AdapterMode -eq 'Simulate') { 0 } else { $null }
    tailscaleTransaction = $null
    legacyRollbackAcknowledgement = [ordered]@{
        requested = [bool]$AcknowledgeLegacyFailedRollback; candidates = @($legacyFailedBackupStates | ForEach-Object { $_.path })
        cleanReadBack = $null; acknowledged = $false
    }
    nextStep = 'Review the plan. Apply requires verified prerequisites, runtime imports, registration adapters, and explicit approval.'
}

if ($AdapterMode -eq 'Simulate' -and -not $Apply) {
    throw [ArgumentException]::new('BridgeAdapterSimulationRequiresApply: Simulate is valid only with -Apply.')
}
if ($SimulationFailureStep -ne 'None' -and ($AdapterMode -ne 'Simulate' -or -not $Apply)) {
    throw [ArgumentException]::new('BridgeSimulationFailureRequiresSimulation: failure injection is valid only with -Apply -AdapterMode Simulate.')
}
if ($SimulationScenario -ne 'Desired' -and ($AdapterMode -ne 'Simulate' -or -not $Apply -or -not $ConfigureTailscale)) {
    throw [ArgumentException]::new('BridgeSimulationScenarioInvalid: non-default scenarios require -Apply -AdapterMode Simulate -ConfigureTailscale.')
}
if ($AcknowledgeLegacyFailedRollback -and ($AdapterMode -ne 'Production' -or -not $Apply -or $WhatIfPreference)) {
    throw [ArgumentException]::new('BridgeLegacyRollbackAcknowledgementRequiresElevatedProductionApply: acknowledgement requires Production -Apply without WhatIf.')
}

if ($Apply -and -not $WhatIfPreference) {
    $requiredPrerequisitesVerified = @($prerequisites | Where-Object { $_.required -and $_.status -ne 'pass' }).Count -eq 0
    $tailscalePreflightFailure = $null
    $tailscalePreflightState = $null
    if ($AdapterMode -eq 'Production' -and $ConfigureTailscale -and $isAdministrator -and $requiredPrerequisitesVerified) {
        try {
            $tailscalePreflightResult = Invoke-BridgeChildProcess -FilePath ([IO.Path]::Combine($PSHOME, 'powershell.exe')) `
                -ArgumentList @(
                    '-NoProfile', '-NonInteractive', '-File',
                    [IO.Path]::Combine($PSScriptRoot, 'configure-tailscale.ps1'), '-ServeHost', $effectiveServeHost,
                    '-Capability', $Capability, '-Port', [string]$Port, '-Json'
                ) -WorkingDirectory $PSScriptRoot -TimeoutSeconds 120
            if ($tailscalePreflightResult.exitCode -ne 0) { throw [InvalidOperationException]::new('read-only preflight failed') }
            $tailscalePreflight = $tailscalePreflightResult.stdout | ConvertFrom-Json -ErrorAction Stop
            $tailscalePreflightState = if ($tailscalePreflight.idempotent) { 'desired' } else { [string]$tailscalePreflight.state }
            if ($tailscalePreflightState -notin @('desired', 'empty')) {
                $tailscalePreflightFailure = 'tailscale-state-conflict'
            }
        } catch {
            $tailscalePreflightFailure = 'tailscale-preflight-unverified'
        }
    }
    $legacyAcknowledgementFailure = $null
    if ($AcknowledgeLegacyFailedRollback -and $legacyFailedBackupStates.Count -eq 0) {
        $legacyAcknowledgementFailure = 'legacy-failed-backup-state-not-found'
    } elseif ($AcknowledgeLegacyFailedRollback -and $unresolvedBackupState) {
        $legacyAcknowledgementFailure = 'interrupted-backup-state-requires-operator-review'
    } elseif ($AcknowledgeLegacyFailedRollback -and $isAdministrator -and $requiredPrerequisitesVerified) {
        if (-not $PSCmdlet.ShouldProcess('HermesWindowsBridge legacy failed transaction journal', 'Acknowledge only after clean installed-resource readback')) {
            $legacyAcknowledgementFailure = 'legacy-failed-backup-state-acknowledgement-declined'
        } else {
            $cleanReadBack = Get-BridgeLegacyRollbackReadBack -InstallRuntimeRoot $runtimeRoot -InstallPort $Port -TailscalePath $tailscaleCommand.Source
            $plan.legacyRollbackAcknowledgement.cleanReadBack = $cleanReadBack
            if (-not $cleanReadBack.verified) {
                $legacyAcknowledgementFailure = 'legacy-failed-backup-state-readback-unverified'
            } else {
                try {
                    foreach ($legacyBackupState in $legacyFailedBackupStates) {
                        [IO.File]::WriteAllText(
                            $legacyBackupState.path,
                            ([ordered]@{
                                schemaVersion = 1; status = 'rolled-back'; rollbackVerified = $true
                                legacyFailureAcknowledgedUtc = [DateTime]::UtcNow.ToString('O')
                            } | ConvertTo-Json -Compress),
                            [Text.UTF8Encoding]::new($false)
                        )
                    }
                    $interruptedBackupState = $false
                    $plan.legacyRollbackAcknowledgement.acknowledged = $true
                } catch {
                    $legacyAcknowledgementFailure = 'legacy-failed-backup-state-acknowledgement-write-failed'
                }
            }
        }
    }
    $plan.failureReason = if ($AdapterMode -eq 'Production' -and -not $isAdministrator) {
        'administrator-required'
    } elseif (-not $requiredPrerequisitesVerified) {
        'prerequisite-unverified'
    } elseif (-not $runtimePythonVerified) {
        'runtime-python-unverified'
    } elseif (-not $runtimeEntrypointsVerified) {
        'runtime-entrypoint-unverified'
    } elseif (-not $runtimeContract.verified) {
        $runtimeContract.failureReason
    } elseif (-not $registrationAdaptersReady) {
        'registration-adapter-contract-unverified'
    } elseif ($null -ne $legacyAcknowledgementFailure) {
        $legacyAcknowledgementFailure
    } elseif ($interruptedBackupState) {
        'interrupted-backup-state-requires-operator-review'
    } elseif ($null -ne $tailscalePreflightFailure) {
        $tailscalePreflightFailure
    } else {
        $null
    }
    if ($null -ne $plan.failureReason) {
        $plan.state = 'blocked'
        if ($Json) { $plan | ConvertTo-Json -Depth 10 }
        else { Write-Error -ErrorId 'BridgeLifecycleApplyBlocked' -Category InvalidOperation -Message ("BridgeLifecycleApplyBlocked: {0}. No changes were made." -f $plan.failureReason) }
        exit 2
    }

    if ($AdapterMode -eq 'Simulate') {
        # Simulate도 production과 같은 orchestration 함수를 지나야 fault 순서가 갈라지지 않습니다.
        $simulatedServiceCalls = [Collections.Generic.List[string]]::new()
        $simulatedServiceAdapter = {
            param($step)
            [void]$simulatedServiceCalls.Add($step)
            if ($step -like '*_start') { return $true }
        }
        $plan.serviceTransaction = Invoke-BridgeServiceSwitchTransaction `
            -PreviousState 'absent-pair' -InvokeStep $simulatedServiceAdapter
        if ($plan.serviceTransaction.state -cne 'switched' -or
            $plan.serviceTransaction.workerCalls -ne 0) {
            throw [InvalidOperationException]::new('BridgeSimulatedServiceTransactionInvalid')
        }
        $simulationSteps = @(
            'dependencies', 'runtime_directories', 'runtime_access', 'token', 'token_acl', 'hermes_config',
            'gateway_service', 'privileged_helper_service', 'interactive_worker_task',
            'privileged_service_start', 'gateway_service_start', 'worker_task_start'
        )
        if ($InstallPlaywright) { $simulationSteps += 'playwright_chromium' }
        if ($ConfigureTailscale) { $simulationSteps += 'tailscale_serve' }
        $simulationSteps += @('doctor', 'backup_resume')
        foreach ($step in $simulationSteps) {
            if ($SimulationFailureStep -eq $step) {
                $plan.receipts += [ordered]@{ step = $step; state = 'failed-simulated'; externalCalls = 0 }
                $plan.failedStep = $step
                for ($index = $plan.receipts.Count - 2; $index -ge 0; $index--) {
                    $rollbackStep = $plan.receipts[$index].step
                    if ($rollbackStep -eq 'tailscale_serve' -and $SimulationScenario -eq 'EmptyApply') {
                        $plan.rollback += [ordered]@{ step = $rollbackStep; state = 'rolled-back-to-empty'; externalCalls = 0 }
                        $plan.tailscaleTransaction.rollback.inspected = $true
                        $plan.tailscaleTransaction.rollback.eligible = $true
                        $plan.tailscaleTransaction.rollback.attempted = $true
                        $plan.tailscaleTransaction.rollback.succeeded = $true
                        $plan.tailscaleTransaction.rollback.state = 'empty'
                    } else {
                        $plan.rollback += [ordered]@{ step = $rollbackStep; state = 'rollback-simulated'; externalCalls = 0 }
                    }
                }
                $plan.state = 'failed'
                $plan.applied = $false
                if ($Json) { $plan | ConvertTo-Json -Depth 10 }
                else { Write-Output ("Install simulation failed at fixed step: {0}; no changes were made." -f $step) }
                exit 2
            }
            if ($step -eq 'gateway_service') {
                $plan.registrationResults += Invoke-BridgeRegistrationAdapter -ScriptRoot $PSScriptRoot `
                    -ScriptName 'register-gateway-service.ps1' -ArgumentList @('-ExecutablePath', $pythonPath) `
                    -AdapterMode Simulate -Operation Register -ExpectedName 'HermesWindowsBridgeGateway' `
                    -ExpectedAccount 'NT AUTHORITY\LocalService' -ExpectedArgv @($pythonPath, '-I', '-B', '-m', 'hermes_windows_bridge.gateway.windows_service')
            } elseif ($step -eq 'privileged_helper_service') {
                $plan.registrationResults += Invoke-BridgeRegistrationAdapter -ScriptRoot $PSScriptRoot `
                    -ScriptName 'register-privileged-service.ps1' -ArgumentList @('-ExecutablePath', $pythonPath) `
                    -AdapterMode Simulate -Operation Register -ExpectedName 'HermesWindowsBridgePrivileged' `
                    -ExpectedAccount 'LocalSystem' -ExpectedArgv @($pythonPath, '-I', '-B', '-m', 'hermes_windows_bridge.privileged.main')
            } elseif ($step -eq 'interactive_worker_task') {
                $plan.registrationResults += Invoke-BridgeRegistrationAdapter -ScriptRoot $PSScriptRoot `
                    -ScriptName 'register-worker-task.ps1' -ArgumentList @('-UserId', $identity.Name, '-ExecutablePath', $pythonPath) `
                    -AdapterMode Simulate -Operation Register -ExpectedName 'HermesWindowsBridgeWorker' `
                    -ExpectedAccount $identity.Name -ExpectedArgv @($workerPythonPath, '-m', 'hermes_windows_bridge.worker.main')
            } elseif ($step -eq 'tailscale_serve') {
                $simulatedTailscaleResult = Invoke-BridgeChildProcess -FilePath ([IO.Path]::Combine($PSHOME, 'powershell.exe')) `
                    -ArgumentList @(
                        '-NoProfile', '-NonInteractive', '-File',
                        [IO.Path]::Combine($PSScriptRoot, 'configure-tailscale.ps1'), '-ServeHost', $effectiveServeHost,
                        '-Capability', $Capability, '-Port', [string]$Port, '-Apply', '-AdapterMode', 'Simulate',
                        '-SimulationScenario', $SimulationScenario, '-Json'
                    ) -WorkingDirectory $PSScriptRoot -TimeoutSeconds 30
                if ([string]::IsNullOrWhiteSpace($simulatedTailscaleResult.stdout)) {
                    throw [InvalidDataException]::new('BridgeTailscaleSimulationOutputInvalid: simulator returned no JSON.')
                }
                $simulatedTailscale = $simulatedTailscaleResult.stdout | ConvertFrom-Json -ErrorAction Stop
                $plan.tailscaleTransaction = $simulatedTailscale
                if ($simulatedTailscale.externalCalls -ne 0 -or $simulatedTailscale.adapterMode -cne 'Simulate') {
                    throw [InvalidDataException]::new('BridgeTailscaleSimulationBoundaryInvalid: simulator reported a real external call.')
                }
                if ($simulatedTailscaleResult.exitCode -ne 0) {
                    $plan.receipts += [ordered]@{ step = $step; state = [string]$simulatedTailscale.state; externalCalls = 0 }
                    $plan.failedStep = $step
                    if ($simulatedTailscale.rollback.succeeded -eq $true) {
                        $plan.rollback += [ordered]@{ step = $step; state = 'rolled-back-to-empty'; externalCalls = 0 }
                    } else {
                        $plan.atomic = $false
                        $plan.rollback += [ordered]@{ step = $step; state = 'concurrent_state_conflict'; action = 'manual-scoped-cleanup-required'; externalCalls = 0 }
                    }
                    for ($index = $plan.receipts.Count - 2; $index -ge 0; $index--) {
                        $plan.rollback += [ordered]@{ step = $plan.receipts[$index].step; state = 'rollback-simulated'; externalCalls = 0 }
                    }
                    $plan.state = 'failed'
                    $plan.applied = $false
                    if ($Json) { $plan | ConvertTo-Json -Depth 10 }
                    else { Write-Output 'Tailscale simulation read-back mismatch; no real calls were made.' }
                    exit 2
                }
            }
            $plan.receipts += [ordered]@{ step = $step; state = 'simulated'; externalCalls = 0 }
        }
        $plan.state = 'simulated'
        $plan.applied = $false
        if ($Json) { $plan | ConvertTo-Json -Depth 10 }
        else { Write-Output 'Hermes Windows Bridge full install simulation completed; no changes were made.' }
        exit 0
    }

    if (-not $PSCmdlet.ShouldProcess(
        'HermesWindowsBridgeGateway, HermesWindowsBridgePrivileged',
        'Switch the verified protected service release; preserve the Worker registration'
    )) {
        $plan.mode = 'what-if'
        if ($Json) { $plan | ConvertTo-Json -Depth 10 }
        exit 0
    }

    try {
        $contextBindings = @()
        if ($null -ne $installationContext) {
            $contextBindings = @(
                Get-BridgeInstallationContextBinding -Context $installationContext -Profile 'gateway'
                Get-BridgeInstallationContextBinding -Context $installationContext -Profile 'privileged'
                Get-BridgeInstallationContextBinding -Context $installationContext -Profile 'worker'
            )
        }
        $serviceTransactionLock = Enter-BridgeServiceReleaseTransaction -ProgramRoot $serviceProgramRoot
        $serviceRelease = Resolve-BridgeServiceReleaseSelection -ProgramRoot $serviceProgramRoot `
            -ServiceReleaseRoot $ServiceReleaseRoot -GatewayServiceHostRoot $GatewayServiceHostRoot `
            -PrivilegedServiceHostRoot $PrivilegedServiceHostRoot -InstallationContext $installationContext
        $activePointerPath = Join-Path $serviceProgramRoot 'active-release.json'
        $previousPointerExisted = Test-Path -LiteralPath $activePointerPath -PathType Leaf
        $previousPointerBody = if ($previousPointerExisted) {
            Get-Content -LiteralPath $activePointerPath -Raw -ErrorAction Stop
        } else { $null }
        $previousRelease = if ($previousPointerExisted) {
            Resolve-BridgeServiceReleaseSelection -ProgramRoot $serviceProgramRoot -InstallationContext $installationContext
        } else {
            $serviceRelease
        }
        $previousInspection = Get-BridgeServicePairInspection -ScriptRoot $PSScriptRoot -Release $previousRelease -InstallationContext $installationContext
        $workerTaskAbsent = Test-BridgeWorkerTaskAbsent -TaskName $registrationPlans[2].name
        if (-not (Test-Path -LiteralPath $activePointerPath -PathType Leaf) -and
            $previousInspection.previousState -cne 'absent-pair') {
            $previousInspection.previousState = 'unsafe'
        }
    $registrationResults = @()
    $registrationRequests = @(
        Get-BridgeServiceRegistrationRequest -Release $serviceRelease -Profile 'gateway' -InstallationContext $installationContext
        Get-BridgeServiceRegistrationRequest -Release $serviceRelease -Profile 'privileged' -InstallationContext $installationContext
    )
    $createdDirectories = @()
    $createdFiles = @()
    $savedDirectoryAcls = @()
    $savedTokenAcl = $null
    $runtimeAccessApplied = $false
    $startedComponents = @()
    $playwrightApplied = $false
    $tailscaleApplied = $false
    $transactionStatePath = $null
    $workerRegistrationApplied = $false
    $serviceSwitch = $null
    $currentStep = 'dependencies'
    try {
        $plan.receipts += [ordered]@{ step = 'dependencies'; state = 'verified'; externalCalls = 0 }

        $currentStep = 'runtime_directories'
        foreach ($directory in $runtimeDirectories) {
            if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
                [void](New-Item -ItemType Directory -Path $directory -Force)
                $createdDirectories += $directory
            } else {
                $savedDirectoryAcls += [ordered]@{ path = $directory; acl = (Get-Acl -LiteralPath $directory) }
            }
        }
        if ($null -eq $installationContext) {
            Set-BridgeRuntimeDirectoryAcl -Path $runtimeRoot -UserSid $identity.User.Value
        } else {
            Set-BridgeInstallationReadonlyDirectoryAcl -Path $runtimeRoot -WorkerSid $identity.User.Value
        }
        Set-BridgeAuditDirectoryAcl -Path ([IO.Path]::Combine($runtimeRoot, 'logs'))
        Set-BridgeAuditDirectoryAcl -Path ([IO.Path]::Combine($runtimeRoot, 'jobs'))
        Set-BridgeSecretsDirectoryAcl -Path ([IO.Path]::Combine($runtimeRoot, 'secrets'))
        Set-BridgeBrowserDirectoryAcl -Path $userRoot -UserSid $identity.User.Value
        Set-BridgeBrowserDirectoryAcl -Path ([IO.Path]::Combine($userRoot, 'browser-profile')) -UserSid $identity.User.Value
        Set-BridgeBrowserDirectoryAcl -Path ([IO.Path]::Combine($userRoot, 'logs')) -UserSid $identity.User.Value
        if (@($runtimeDirectories | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Container) }).Count -ne 0) {
            throw [IO.IOException]::new('BridgeRuntimeDirectoryVerificationFailed: a required directory is missing after creation.')
        }
        $directoryAclChecks = @(
            $(if ($null -eq $installationContext) {
                Test-BridgeDirectoryAclExact -Path $runtimeRoot -Profile Runtime -UserSid $identity.User.Value
            } else {
                Test-BridgeInstallationReadonlyDirectoryAcl -Path $runtimeRoot -WorkerSid $identity.User.Value
            }),
            (Test-BridgeDirectoryAclExact -Path ([IO.Path]::Combine($runtimeRoot, 'logs')) -Profile Audit),
            (Test-BridgeDirectoryAclExact -Path ([IO.Path]::Combine($runtimeRoot, 'jobs')) -Profile Audit),
            (Test-BridgeDirectoryAclExact -Path ([IO.Path]::Combine($runtimeRoot, 'secrets')) -Profile Secrets),
            (Test-BridgeDirectoryAclExact -Path $userRoot -Profile Browser -UserSid $identity.User.Value),
            (Test-BridgeDirectoryAclExact -Path ([IO.Path]::Combine($userRoot, 'browser-profile')) -Profile Browser -UserSid $identity.User.Value),
            (Test-BridgeDirectoryAclExact -Path ([IO.Path]::Combine($userRoot, 'logs')) -Profile Browser -UserSid $identity.User.Value)
        )
        if (@($directoryAclChecks | Where-Object { -not $_ }).Count -ne 0) {
            throw [UnauthorizedAccessException]::new('BridgeRuntimeDirectoryAclVerificationFailed: an exact restrictive ACL was not observed.')
        }
        $plan.receipts += [ordered]@{ step = 'runtime_directories'; state = 'verified'; externalCalls = 0 }
        $transactionDirectory = [IO.Path]::Combine($runtimeRoot, 'backups', ('install-' + [guid]::NewGuid().ToString('N')))
        [void](New-Item -ItemType Directory -Path $transactionDirectory -Force)
        Set-BridgeSecretsDirectoryAcl -Path $transactionDirectory
        $transactionStatePath = [IO.Path]::Combine($transactionDirectory, 'state.json')
        $serviceBackupPath = [IO.Path]::Combine($transactionDirectory, 'service-definitions.json')
        [IO.File]::WriteAllText(
            $transactionStatePath,
            ([ordered]@{ schemaVersion = 1; status = 'running'; startedUtc = [DateTime]::UtcNow.ToString('O') } | ConvertTo-Json -Compress),
            [Text.UTF8Encoding]::new($false)
        )
        $plan.backups += $transactionStatePath
        $serviceBackup = [ordered]@{
            schemaVersion = 1
            releaseId = [string]$previousRelease.releaseId
            manifestSha256 = [string]$previousRelease.manifestSha256
            pairState = [string]$previousInspection.previousState
            definitions = @($previousInspection.definitions | ForEach-Object {
                [ordered]@{
                    name = [string]$_.name
                    pathName = [string]$_.observedDefinition.pathName
                    account = [string]$_.observedDefinition.account
                    startMode = [string]$_.observedDefinition.startMode
                    running = [bool]$_.observedDefinition.running
                    recoveryExact = [bool]$_.observedDefinition.recoveryExact
                }
            })
        }
        $serviceBackupBody = $serviceBackup | ConvertTo-Json -Depth 6 -Compress
        [IO.File]::WriteAllText($serviceBackupPath, $serviceBackupBody, [Text.UTF8Encoding]::new($false))
        $serviceBackupReadBackBody = [IO.File]::ReadAllText($serviceBackupPath, [Text.UTF8Encoding]::new($false))
        $serviceBackupReadBack = $serviceBackupReadBackBody | ConvertFrom-Json -ErrorAction Stop
        if ($serviceBackupReadBackBody -cne $serviceBackupBody -or
            $serviceBackupReadBack.releaseId -cne $serviceBackup.releaseId -or
            @($serviceBackupReadBack.definitions).Count -ne 2 -or
            $null -ne (Test-BridgeTreeAcl -Path $serviceBackupPath -RequireTrustedOwner $true) -or
            (Get-BridgeFileLinkCount -Path $serviceBackupPath) -ne 1) {
            throw [IO.IOException]::new('BridgePreviousServiceBackupVerificationFailed')
        }
        $plan.backups += $serviceBackupPath

        $currentStep = 'runtime_access'
        # 보호 release는 개인 Python ACL을 변경하지 않고 자체 검증된 runtime만 사용합니다.
        $plan.receipts += [ordered]@{ step = 'runtime_access'; state = 'protected-release-self-contained'; externalCalls = 0 }

        $currentStep = 'token'
        if ($tokenExists) {
            $savedTokenAcl = Get-Acl -LiteralPath $tokenPath
            Set-BridgeSecretAcl -TokenPath $tokenPath
            $tokenReceiptState = 'preserved'
        } else {
            $tokenResult = Write-BridgeTokenAtomic -Root $ProgramDataRoot -TokenPath $tokenPath -Token (New-BridgeToken)
            $createdFiles += $tokenPath
            $tokenReceiptState = 'created'
        }
        if (-not (Test-BridgeSecretAclExact -TokenPath $tokenPath)) {
            throw [UnauthorizedAccessException]::new('BridgeTokenVerificationFailed: exact restrictive token ACL was not observed.')
        }
        $plan.receipts += [ordered]@{ step = 'token'; state = $tokenReceiptState; externalCalls = 0 }
        $plan.receipts += [ordered]@{ step = 'token_acl'; state = 'verified'; externalCalls = 0 }

        $currentStep = 'hermes_config'
        $configPath = [IO.Path]::Combine($runtimeRoot, 'config.yaml')
        $policyPath = [IO.Path]::Combine($runtimeRoot, 'policy.yaml')
        if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
            $configSource = if ($ExistingConfigPath) { $ExistingConfigPath } else { [IO.Path]::Combine($projectRoot, 'config', 'config.example.yaml') }
            $configText = [IO.File]::ReadAllText($configSource)
            if (-not $ExistingConfigPath) {
                $configText = $configText.Replace('main-pc.<tailnet>.ts.net', $effectiveServeHost)
                $configText = $configText.Replace('port: 8765', ("port: {0}" -f $Port))
            }
            [IO.File]::WriteAllText($configPath, $configText, [Text.UTF8Encoding]::new($false))
            $createdFiles += $configPath
            if ([IO.File]::ReadAllText($configPath) -cne $configText) {
                throw [IO.IOException]::new('BridgeConfigurationReadBackFailed: config content differs after write.')
            }
        }
        if (-not (Test-Path -LiteralPath $policyPath -PathType Leaf)) {
            $policySource = [IO.Path]::Combine($projectRoot, 'config', 'policy.example.yaml')
            [IO.File]::WriteAllText($policyPath, [IO.File]::ReadAllText($policySource), [Text.UTF8Encoding]::new($false))
            $createdFiles += $policyPath
            if ([IO.File]::ReadAllText($policyPath) -cne [IO.File]::ReadAllText($policySource)) {
                throw [IO.IOException]::new('BridgePolicyReadBackFailed: policy content differs after write.')
            }
        }
        if (-not (Test-Path -LiteralPath $configPath -PathType Leaf) -or -not (Test-Path -LiteralPath $policyPath -PathType Leaf)) {
            throw [IO.IOException]::new('BridgeConfigurationVerificationFailed: installed config or policy is missing.')
        }
        $plan.receipts += [ordered]@{ step = 'hermes_config'; state = 'verified'; externalCalls = 0 }

        if ($previousInspection.previousState -ceq 'absent-pair' -and $workerTaskAbsent) {
            $currentStep = 'interactive_worker_task'
            $workerRequest = $registrationPlans[2]
            $workerArguments = @('-UserId', $identity.Name, '-ExecutablePath', $pythonPath)
            $workerExpectedArgv = @($workerRequest.serviceArgv)
            if ($null -ne $installationContext) {
                $workerBinding = @($contextBindings | Where-Object { $_.profile -ceq 'worker' })[0]
                $workerArguments += @('-InstallationContextPath', $installationContext.contextPath, '-InstallationContextSha256', $installationContext.contextSha256)
                $workerExpectedArgv += @('--runtime-binding', $workerBinding.path, '--runtime-binding-sha256', $workerBinding.sha256)
            }
            $workerResult = Invoke-BridgeRegistrationAdapter -ScriptRoot $PSScriptRoot `
                -ScriptName 'register-worker-task.ps1' `
                -ArgumentList $workerArguments `
                -AdapterMode Production -Operation Register -ExpectedName $workerRequest.name `
                -ExpectedAccount $identity.Name -ExpectedArgv $workerExpectedArgv
            $workerRegistrationApplied = [bool]$workerResult.applied
            $registrationResults += $workerResult
            $currentStep = 'worker_task_start'
            Start-ScheduledTask -TaskName $workerRequest.name -ErrorAction Stop
            $startedComponents += [ordered]@{ kind = 'task'; name = $workerRequest.name }
            $plan.receipts += [ordered]@{ step = 'interactive_worker_task'; state = 'registered-first-install'; externalCalls = $null }
        }

        if ($null -eq $installationContext) {
            $currentStep = 'worker_identity'
            $workerTask = Get-ScheduledTask -TaskName 'HermesWindowsBridgeWorker' -TaskPath '\' -ErrorAction Stop
            if ($workerTask.Principal.RunLevel -ne 'Limited' -or $workerTask.Principal.LogonType -ne 'Interactive') {
                throw [Security.SecurityException]::new('BridgeWorkerIdentityTaskRejected')
            }
            $workerAccount = [string]$workerTask.Principal.UserId
            $workerSid = if ($workerAccount -match '^S-1-') {
                [Security.Principal.SecurityIdentifier]::new($workerAccount).Value
            } else {
                ([Security.Principal.NTAccount]::new($workerAccount)).Translate([Security.Principal.SecurityIdentifier]).Value
            }
            if ($workerSid -in @('S-1-5-18', 'S-1-5-19', 'S-1-5-20')) {
                throw [Security.SecurityException]::new('BridgeWorkerIdentityServiceAccountRejected')
            }
            $workerIdentityPath = Join-Path $serviceProgramRoot 'worker-identity.json'
            $workerIdentityBody = [ordered]@{ schemaVersion = 1; workerSid = $workerSid } | ConvertTo-Json -Compress
            if (-not (Test-Path -LiteralPath $workerIdentityPath)) {
                $identityStream = [IO.File]::Open($workerIdentityPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                $createdFiles += $workerIdentityPath
                try {
                    $identityBytes = ([Text.UTF8Encoding]::new($false)).GetBytes($workerIdentityBody)
                    $identityStream.Write($identityBytes, 0, $identityBytes.Length)
                } finally { $identityStream.Dispose() }
                Set-BridgeInstallationBindingAcl -Path $workerIdentityPath -Profile gateway -WorkerSid $workerSid
            }
            $null = Assert-BridgeInstallationContextProtectedFile -Path $workerIdentityPath -Root $serviceProgramRoot -FailureReason 'BridgeWorkerIdentityUnsafe'
            if ([IO.File]::ReadAllText($workerIdentityPath) -cne $workerIdentityBody) {
                throw [Security.SecurityException]::new('BridgeWorkerIdentityMismatch')
            }
            $plan.receipts += [ordered]@{ step = 'worker_identity'; state = 'verified'; externalCalls = 0 }
        }

        $currentStep = 'service_release_transaction'
        $adapterReceipts = [Collections.Generic.List[object]]::new()
        $switchContext = [pscustomobject]@{
            rollingBack = $false
            playwrightApplied = $false
            tailscaleApplied = $false
        }
        $serviceSwitchIdempotent = $previousInspection.previousState -ceq 'safe-pair' -and
            (Test-BridgeServiceReleaseIdentity -Left $previousRelease -Right $serviceRelease)
        $invokeServiceStep = {
            param($step)
            $isGateway = $step -like 'gateway_*'
            $request = if ($isGateway) { $registrationRequests[0] } else { $registrationRequests[1] }
            $serviceName = [string]$request.name
            if ($step -like '*_stop') {
                if ($serviceSwitchIdempotent) { return }
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($null -ne $service -and $service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
                    Stop-Service -Name $serviceName -Force -ErrorAction Stop
                    $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(20))
                }
            } elseif ($step -like '*_register') {
                if ($serviceSwitchIdempotent) { return }
                if ($previousInspection.previousState -ceq 'safe-pair' -and
                    -not (Test-BridgeServiceReleaseIdentity -Left $previousRelease -Right $serviceRelease)) {
                    $previousProfile = if ($isGateway) { 'gateway' } else { 'privileged' }
                    $previousRequest = Get-BridgeServiceRegistrationRequest -Release $previousRelease -Profile $previousProfile -InstallationContext $installationContext
                    [void]$adapterReceipts.Add((Invoke-BridgeRegistrationAdapter -ScriptRoot $PSScriptRoot `
                        -ScriptName $previousRequest.script -ArgumentList $previousRequest.arguments -AdapterMode Production -Operation Remove `
                        -ExpectedName $previousRequest.name -ExpectedAccount $previousRequest.account `
                        -ExpectedArgv $previousRequest.argv))
                }
                [void]$adapterReceipts.Add((Invoke-BridgeRegistrationAdapter -ScriptRoot $PSScriptRoot `
                    -ScriptName $request.script -ArgumentList $request.arguments -AdapterMode Production -Operation Register `
                    -ExpectedName $request.name -ExpectedAccount $request.account -ExpectedArgv $request.argv))
            } elseif ($step -like '*_start') {
                if ($serviceSwitchIdempotent) { return $false }
                $definitionIndex = if ($isGateway) { 0 } else { 1 }
                if ($switchContext.rollingBack -and
                    -not [bool]$previousInspection.definitions[$definitionIndex].observedDefinition.running) {
                    return $false
                }
                Start-Service -Name $serviceName -ErrorAction Stop
                (Get-Service -Name $serviceName -ErrorAction Stop).WaitForStatus(
                    [System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(20))
                return $true
            } elseif ($step -ceq 'final_readback') {
                $readBack = Get-BridgeServicePairInspection -ScriptRoot $PSScriptRoot -Release $serviceRelease -InstallationContext $installationContext
                if ($readBack.previousState -cne 'safe-pair' -or
                    @($readBack.definitions | Where-Object { -not $_.observedDefinition.running }).Count -ne 0) {
                    throw [InvalidOperationException]::new('BridgeServiceReleaseReadBackMismatch')
                }
            } elseif ($step -ceq 'doctor') {
                if ($InstallPlaywright -and -not $switchContext.playwrightApplied) {
                    $playwrightResult = Invoke-BridgeChildProcess -FilePath $pythonPath `
                        -ArgumentList @('-m', 'playwright', 'install', 'chromium') `
                        -WorkingDirectory $projectRoot -TimeoutSeconds 300
                    if ($playwrightResult.exitCode -ne 0) {
                        throw [InvalidOperationException]::new('BridgePlaywrightInstallFailed: Chromium installation failed.')
                    }
                    $switchContext.playwrightApplied = $true
                    $plan.receipts += [ordered]@{ step = 'playwright_chromium'; state = 'applied'; externalCalls = 1 }
                }
                if ($ConfigureTailscale -and -not $switchContext.tailscaleApplied) {
                    $tailscaleArguments = @(
                        '-NoProfile', '-NonInteractive', '-File',
                        [IO.Path]::Combine($PSScriptRoot, 'configure-tailscale.ps1'), '-ServeHost', $effectiveServeHost,
                        '-Capability', $Capability, '-Port', [string]$Port, '-Apply', '-Json'
                    )
                    $tailscaleResult = Invoke-BridgeChildProcess -FilePath ([IO.Path]::Combine($PSHOME, 'powershell.exe')) `
                        -ArgumentList $tailscaleArguments -WorkingDirectory $PSScriptRoot -TimeoutSeconds 120
                    if ([string]::IsNullOrWhiteSpace($tailscaleResult.stdout)) {
                        throw [InvalidDataException]::new('BridgeTailscaleApplyOutputInvalid: adapter returned no JSON.')
                    }
                    $tailscalePlan = $tailscaleResult.stdout | ConvertFrom-Json -ErrorAction Stop
                    $plan.tailscaleTransaction = $tailscalePlan
                    if ($tailscaleResult.exitCode -ne 0 -or
                        ((-not $tailscalePlan.applied -and -not $tailscalePlan.idempotent) -or
                        -not $tailscalePlan.readBack.performed -or -not $tailscalePlan.readBack.exact -or
                        -not $tailscalePlan.readBack.bridgeOnly)) {
                        throw [InvalidOperationException]::new('BridgeTailscaleVerificationFailed: exact bridge-only state was not verified.')
                    }
                    $switchContext.tailscaleApplied = [bool]$tailscalePlan.applied
                    $plan.receipts += [ordered]@{ step = 'tailscale_serve'; state = if ($switchContext.tailscaleApplied) { 'applied-exact-bridge-only' } else { 'unchanged-exact-desired' }; externalCalls = 1 }
                }
                $doctorPath = Assert-BridgePathUnderRoot -Root $PSScriptRoot -Path ([IO.Path]::Combine($PSScriptRoot, 'doctor.ps1'))
                $savedProgramData = $env:ProgramData
                $savedLocalAppData = $env:LOCALAPPDATA
                try {
                    if ($null -eq $installationContext) {
                        $env:ProgramData = $ProgramDataRoot
                        $env:LOCALAPPDATA = $LocalDataRoot
                    }
                    $doctorArguments = @(
                        '-NoProfile', '-NonInteractive', '-File',
                        $doctorPath, '-Json', '-GatewayPort', [string]$Port,
                        '-Capability', $Capability, '-ServiceReleaseRoot', $serviceRelease.releaseRoot
                    )
                    if ($null -ne $installationContext) {
                        $doctorArguments += @('-InstallationContextPath', $installationContext.contextPath,
                            '-InstallationContextSha256', $installationContext.contextSha256)
                    }
                    if ($null -ne $serviceRelease.PSObject.Properties['gatewayServiceHostRoot']) {
                        $doctorArguments += @(
                            '-GatewayServiceHostRoot', $serviceRelease.gatewayServiceHostRoot,
                            '-PrivilegedServiceHostRoot', $serviceRelease.privilegedServiceHostRoot
                        )
                    }
                    if (-not [string]::IsNullOrWhiteSpace($ServeHost)) {
                        # 빈 선택 인자를 자식 프로세스 경계에 넘기지 않고 doctor의 기본 동작을 유지합니다.
                        $doctorArguments += @('-ServeHost', $ServeHost)
                    }
                    # 두 service Inspect(각 60초), 기존 bounded checks(50초), startup 여유를 하나의 child 예산으로 맞춥니다.
                    $doctorTimeoutSeconds = 180
                    $doctorResult = Invoke-BridgeChildProcess -FilePath ([IO.Path]::Combine($PSHOME, 'powershell.exe')) `
                        -ArgumentList $doctorArguments `
                        -WorkingDirectory $PSScriptRoot -TimeoutSeconds $doctorTimeoutSeconds
                } finally {
                    if ($null -eq $installationContext) {
                        $env:ProgramData = $savedProgramData
                        $env:LOCALAPPDATA = $savedLocalAppData
                    }
                }
                if ($doctorResult.exitCode -ne 0) {
                    $doctorReport = $doctorResult.stdout | ConvertFrom-Json -ErrorAction Stop
                    $failedChecks = @($doctorReport.checks | Where-Object { $_.critical -and $_.status -eq 'fail' })
                    $failedCheckIds = @($failedChecks | ForEach-Object { if ($_.id -match '^[a-z_]+$') { $_.id } })
                    throw [InvalidOperationException]::new(('BridgeDoctorFailed[{0}]: installed state did not pass critical checks.' -f ($failedCheckIds -join ',')))
                }
            } elseif ($step -ceq 'pointer_commit') {
                if (-not $serviceSwitchIdempotent) {
                    Publish-BridgeActiveReleasePointer -ProgramRoot $serviceProgramRoot -Release $serviceRelease
                }
            } elseif ($step -ceq 'post_commit_readback') {
                if ((Get-Content -LiteralPath $activePointerPath -Raw -ErrorAction Stop) -cne
                    (Get-BridgeActiveReleasePointerBody -Release $serviceRelease)) {
                    throw [InvalidOperationException]::new('BridgeActiveReleaseCommitUnverified')
                }
                [IO.File]::WriteAllText(
                    $transactionStatePath,
                    ([ordered]@{ schemaVersion = 1; status = 'completed'; completedUtc = [DateTime]::UtcNow.ToString('O') } | ConvertTo-Json -Compress),
                    [Text.UTF8Encoding]::new($false)
                )
                $completedTransactionState = Get-Content -LiteralPath $transactionStatePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                if ($completedTransactionState.status -cne 'completed') {
                    throw [IO.IOException]::new('BridgeInstallReceiptVerificationFailed: completed journal was not read back.')
                }
            } elseif ($step -ceq 'pointer_restore') {
                if ($previousPointerExisted) {
                    Restore-BridgeActiveReleasePointerBody -ProgramRoot $serviceProgramRoot -Body $previousPointerBody
                } elseif (Test-Path -LiteralPath $activePointerPath -PathType Leaf) {
                    [IO.File]::Delete($activePointerPath)
                }
            } elseif ($step -like '*_restore') {
                $switchContext.rollingBack = $true
                $previousProfile = if ($isGateway) { 'gateway' } else { 'privileged' }
                $previousRequest = Get-BridgeServiceRegistrationRequest -Release $previousRelease -Profile $previousProfile -InstallationContext $installationContext
                $previousDefinition = Get-BridgeServiceDefinitionInspection -ScriptRoot $PSScriptRoot -Definition $previousRequest
                # 후보 등록 전 실패한 경우에는 후보 검증에 기대지 않고 확인된 이전 상태를 복원합니다.
                if ($previousDefinition.state -ceq 'desired') { return }
                if ($previousDefinition.state -ceq 'conflict') {
                    [void]$adapterReceipts.Add((Invoke-BridgeRegistrationAdapter -ScriptRoot $PSScriptRoot `
                        -ScriptName $request.script -ArgumentList $request.arguments -AdapterMode Production -Operation Remove `
                        -ExpectedName $request.name -ExpectedAccount $request.account -ExpectedArgv $request.argv))
                }
                [void]$adapterReceipts.Add((Invoke-BridgeRegistrationAdapter -ScriptRoot $PSScriptRoot `
                    -ScriptName $previousRequest.script -ArgumentList $previousRequest.arguments `
                    -AdapterMode Production -Operation Register -ExpectedName $previousRequest.name -ExpectedAccount $previousRequest.account `
                    -ExpectedArgv $previousRequest.argv))
            } elseif ($step -like '*_remove') {
                [void]$adapterReceipts.Add((Invoke-BridgeRegistrationAdapter -ScriptRoot $PSScriptRoot `
                    -ScriptName $request.script -ArgumentList $request.arguments -AdapterMode Production -Operation Remove `
                    -ExpectedName $request.name -ExpectedAccount $request.account -ExpectedArgv $request.argv))
            } elseif ($step -ceq 'restore_readback') {
                $readBack = Get-BridgeServicePairInspection -ScriptRoot $PSScriptRoot -Release $previousRelease -InstallationContext $installationContext
                if ($readBack.previousState -cne 'safe-pair') { throw [InvalidOperationException]::new('BridgePreviousServiceReadBackMismatch') }
            } elseif ($step -ceq 'remove_readback') {
                $readBack = Get-BridgeServicePairInspection -ScriptRoot $PSScriptRoot -Release $serviceRelease -InstallationContext $installationContext
                if ($readBack.previousState -cne 'absent-pair') {
                    throw [InvalidOperationException]::new('BridgeRemovedServicePairReadBackMismatch')
                }
            } elseif ($step -ceq 'restore_running_readback') {
                $readBack = Get-BridgeServicePairInspection -ScriptRoot $PSScriptRoot -Release $previousRelease -InstallationContext $installationContext
                $expectedRunning = @($previousInspection.definitions | ForEach-Object { [bool]$_.observedDefinition.running })
                $actualRunning = @($readBack.definitions | ForEach-Object { [bool]$_.observedDefinition.running })
                if ($readBack.previousState -cne 'safe-pair' -or
                    ($expectedRunning -join ',') -cne ($actualRunning -join ',')) {
                    throw [InvalidOperationException]::new('BridgePreviousServiceRunningStateMismatch')
                }
            }
        }
        $serviceSwitch = Invoke-BridgeServiceSwitchTransaction `
            -PreviousState $previousInspection.previousState -InvokeStep $invokeServiceStep
        $plan.serviceTransaction = $serviceSwitch
        $playwrightApplied = [bool]$switchContext.playwrightApplied
        $tailscaleApplied = [bool]$switchContext.tailscaleApplied
        if ($serviceSwitch.state -cne 'switched') {
            if ($serviceSwitch.state -ceq 'manual-recovery-required' -or
                @($serviceSwitch.rollbackFailures).Count -ne 0 -or
                ($serviceSwitch.pointerCommitted -and -not $serviceSwitch.pointerCompensated)) {
                $plan.atomic = $false
            }
            throw [InvalidOperationException]::new(('BridgeServiceReleaseSwitchFailed:{0}' -f $serviceSwitch.state))
        }
        $plan.registrationResults = @($adapterReceipts)
        $plan.receipts += [ordered]@{ step = 'service_release_transaction'; state = 'switched'; externalCalls = $null }

        $currentStep = 'active_release_commit'
        $plan.receipts += [ordered]@{ step = 'doctor'; state = 'verified'; externalCalls = 1 }
        $plan.receipts += [ordered]@{ step = 'backup_resume'; state = 'verified'; externalCalls = 0 }
        $currentStep = 'backup_resume'
    } catch {
        $applyError = $_
        $plan.failedStep = $currentStep
        $plan.state = 'failed'
        $plan.applied = $false
        $manualServiceRecovery = $false
        if ($null -ne $serviceSwitch) {
            $plan.serviceTransaction = $serviceSwitch
            $serviceFailureLabels = @{
                'gateway_stop' = 'gateway_service_start'
                'privileged_stop' = 'privileged_service_start'
                'gateway_register' = 'gateway_service'
                'privileged_register' = 'privileged_helper_service'
                'privileged_start' = 'privileged_service_start'
                'gateway_start' = 'gateway_service_start'
                'final_readback' = 'service_release_transaction'
                'doctor' = 'doctor'
                'pointer_commit' = 'active_release_commit'
                'post_commit_readback' = 'active_release_commit'
            }
            if ($null -ne $serviceSwitch.failedStep -and
                $serviceFailureLabels.ContainsKey([string]$serviceSwitch.failedStep)) {
                $plan.failedStep = [string]$serviceFailureLabels[[string]$serviceSwitch.failedStep]
            }
            if ($serviceSwitch.state -ceq 'manual-recovery-required' -or
                @($serviceSwitch.rollbackFailures).Count -ne 0 -or
                ($serviceSwitch.pointerCommitted -and -not $serviceSwitch.pointerCompensated)) {
                $plan.atomic = $false
                $manualServiceRecovery = $true
                $plan.preservedChanges += [ordered]@{
                    step = 'service_release_transaction'
                    state = 'preserved-for-manual-recovery'
                    reason = [string]$serviceSwitch.state
                }
            }
        }
        if ($manualServiceRecovery) {
            # 서비스 상태가 불확실하면 의존 데이터까지 제거해 실행 상태를 더 깨뜨리지 않습니다.
            $tailscaleApplied = $false
            $playwrightApplied = $false
            $startedComponents = @()
            $workerRegistrationApplied = $false
            $registrationResults = @()
            $runtimeAccessApplied = $false
            $createdFiles = @()
            $savedTokenAcl = $null
            $savedDirectoryAcls = @()
            $createdDirectories = @()
        }
        if ($tailscaleApplied) {
            try {
                $rollbackStatusResult = Invoke-BridgeChildProcess -FilePath ([IO.Path]::Combine($PSHOME, 'powershell.exe')) `
                    -ArgumentList @(
                        '-NoProfile', '-NonInteractive', '-File',
                        [IO.Path]::Combine($PSScriptRoot, 'configure-tailscale.ps1'), '-ServeHost', $effectiveServeHost,
                        '-Capability', $Capability, '-Port', [string]$Port, '-Json'
                    ) -WorkingDirectory $PSScriptRoot -TimeoutSeconds 120
                if ($rollbackStatusResult.exitCode -ne 0) { throw [InvalidOperationException]::new('rollback status unreadable') }
                $rollbackStatus = $rollbackStatusResult.stdout | ConvertFrom-Json -ErrorAction Stop
                if (-not $rollbackStatus.idempotent -or -not $rollbackStatus.serveStatus.bridgeOnly) {
                    $plan.atomic = $false
                    $plan.tailscaleTransaction.rollback.inspected = $true
                    $plan.tailscaleTransaction.rollback.eligible = $false
                    $plan.tailscaleTransaction.rollback.attempted = $false
                    $plan.tailscaleTransaction.rollback.state = 'conflict'
                    $plan.tailscaleTransaction.manualActionRequired = $true
                    $plan.rollback += [ordered]@{ step = 'tailscale_serve'; state = 'concurrent_state_conflict'; action = 'manual-scoped-cleanup-required'; externalCalls = 1 }
                } else {
                    $plan.tailscaleTransaction.rollback.inspected = $true
                    $plan.tailscaleTransaction.rollback.eligible = $true
                    $plan.tailscaleTransaction.rollback.attempted = $true
                    $tailscaleReset = Invoke-BridgeChildProcess -FilePath $tailscaleCommand.Source `
                        -ArgumentList @('serve', 'reset') -WorkingDirectory $PSScriptRoot -TimeoutSeconds 30
                    if ($tailscaleReset.exitCode -ne 0) { throw [InvalidOperationException]::new('scoped reset failed') }
                    $resetReadBackResult = Invoke-BridgeChildProcess -FilePath ([IO.Path]::Combine($PSHOME, 'powershell.exe')) `
                        -ArgumentList @(
                            '-NoProfile', '-NonInteractive', '-File',
                            [IO.Path]::Combine($PSScriptRoot, 'configure-tailscale.ps1'), '-ServeHost', $effectiveServeHost,
                            '-Capability', $Capability, '-Port', [string]$Port, '-Json'
                        ) -WorkingDirectory $PSScriptRoot -TimeoutSeconds 120
                    if ($resetReadBackResult.exitCode -ne 0) { throw [InvalidOperationException]::new('reset read-back failed') }
                    $resetReadBack = $resetReadBackResult.stdout | ConvertFrom-Json -ErrorAction Stop
                    if ($resetReadBack.state -cne 'empty' -or $resetReadBack.idempotent) { throw [InvalidOperationException]::new('reset read-back was not empty') }
                    $plan.tailscaleTransaction.rollback.inspected = $true
                    $plan.tailscaleTransaction.rollback.eligible = $true
                    $plan.tailscaleTransaction.rollback.attempted = $true
                    $plan.tailscaleTransaction.rollback.succeeded = $true
                    $plan.tailscaleTransaction.rollback.state = 'empty'
                    $plan.rollback += [ordered]@{ step = 'tailscale_serve'; state = 'rolled-back-to-empty'; externalCalls = 3 }
                }
            } catch {
                $plan.atomic = $false
                if ($null -ne $plan.tailscaleTransaction) {
                    $plan.tailscaleTransaction.rollback.inspected = $true
                    $plan.tailscaleTransaction.rollback.succeeded = $false
                    $plan.tailscaleTransaction.rollback.state = 'verification-failed'
                    $plan.tailscaleTransaction.manualActionRequired = $true
                }
                $plan.rollback += [ordered]@{ step = 'tailscale_serve'; state = 'rollback-unverified'; action = 'manual-scoped-cleanup-required'; externalCalls = $null }
            }
        }
        if ($playwrightApplied) {
            $plan.preservedChanges += [ordered]@{ step = 'playwright_chromium'; state = 'preserved-shared-dependency'; reason = 'shared-browser-cache-is-not-owned-install-state' }
        }
        for ($startedIndex = $startedComponents.Count - 1; $startedIndex -ge 0; $startedIndex--) {
            $started = $startedComponents[$startedIndex]
            try {
                if ($started.kind -eq 'task') { Stop-ScheduledTask -TaskName $started.name -ErrorAction Stop }
                else { Stop-Service -Name $started.name -Force -ErrorAction Stop }
                $plan.rollback += [ordered]@{ step = ("stop:{0}" -f $started.name); state = 'rolled-back'; externalCalls = $null }
            } catch { $plan.rollback += [ordered]@{ step = ("stop:{0}" -f $started.name); state = 'rollback-failed'; externalCalls = $null } }
        }
        if ($workerRegistrationApplied) {
            # Worker 결과를 service request 인덱스로 오인하는 generic rollback에서 분리합니다.
            $registrationResults = @()
            try {
                [void](Invoke-BridgeRegistrationAdapter -ScriptRoot $PSScriptRoot `
                    -ScriptName 'register-worker-task.ps1' `
                    -ArgumentList $workerArguments `
                    -AdapterMode Production -Operation Remove -ExpectedName $registrationPlans[2].name `
                    -ExpectedAccount $identity.Name -ExpectedArgv $workerExpectedArgv)
                $plan.rollback += [ordered]@{ step = $registrationPlans[2].name; state = 'rolled-back'; externalCalls = $null }
                $workerRegistrationApplied = $false
            } catch {
                $plan.rollback += [ordered]@{ step = $registrationPlans[2].name; state = 'rollback-failed'; externalCalls = $null }
            }
        }
        for ($index = $registrationResults.Count - 1; $index -ge 0; $index--) {
            if ($registrationResults[$index].applied -ne $true) { continue }
            $request = $registrationRequests[$index]
            try {
                [void](Invoke-BridgeRegistrationAdapter -ScriptRoot $PSScriptRoot `
                    -ScriptName $request.script -ArgumentList $request.arguments -AdapterMode Production `
                    -Operation Remove -ExpectedName $request.name -ExpectedAccount $request.account -ExpectedArgv $request.argv)
                $plan.rollback += [ordered]@{ step = $request.name; state = 'rolled-back'; externalCalls = $null }
            } catch {
                $plan.rollback += [ordered]@{ step = $request.name; state = 'rollback-failed'; externalCalls = $null }
            }
        }
        if ($runtimeAccessApplied) {
            try {
                $runtimeAccessRollback = Restore-BridgeBaseRuntimeAccess -RuntimeRoot $runtimeRoot
                $plan.rollback += [ordered]@{ step = 'runtime_access'; state = $runtimeAccessRollback.state; externalCalls = 0 }
            } catch {
                $plan.rollback += [ordered]@{ step = 'runtime_access'; state = 'rollback-failed'; externalCalls = 0 }
            }
        }
        for ($fileIndex = $createdFiles.Count - 1; $fileIndex -ge 0; $fileIndex--) {
            $file = $createdFiles[$fileIndex]
            try {
                if (Test-Path -LiteralPath $file -PathType Leaf) { Remove-Item -LiteralPath $file -Force }
                $plan.rollback += [ordered]@{ step = $file; state = 'rolled-back'; externalCalls = 0 }
            } catch { $plan.rollback += [ordered]@{ step = $file; state = 'rollback-failed'; externalCalls = 0 } }
        }
        if ($null -ne $savedTokenAcl -and (Test-Path -LiteralPath $tokenPath -PathType Leaf)) {
            try { Set-Acl -LiteralPath $tokenPath -AclObject $savedTokenAcl; $plan.rollback += [ordered]@{ step = 'token_acl'; state = 'restored'; externalCalls = 0 } }
            catch { $plan.rollback += [ordered]@{ step = 'token_acl'; state = 'rollback-failed'; externalCalls = 0 } }
        }
        for ($aclIndex = $savedDirectoryAcls.Count - 1; $aclIndex -ge 0; $aclIndex--) {
            $entry = $savedDirectoryAcls[$aclIndex]
            try { Set-Acl -LiteralPath $entry.path -AclObject $entry.acl; $plan.rollback += [ordered]@{ step = $entry.path; state = 'restored'; externalCalls = 0 } }
            catch { $plan.rollback += [ordered]@{ step = $entry.path; state = 'rollback-failed'; externalCalls = 0 } }
        }
        for ($directoryIndex = $createdDirectories.Count - 1; $directoryIndex -ge 0; $directoryIndex--) {
            $directory = $createdDirectories[$directoryIndex]
            try {
                if ((Test-Path -LiteralPath $directory -PathType Container) -and @(Get-ChildItem -LiteralPath $directory -Force).Count -eq 0) { [IO.Directory]::Delete($directory, $false) }
                $plan.rollback += [ordered]@{ step = $directory; state = 'rolled-back-if-empty'; externalCalls = 0 }
            } catch { $plan.rollback += [ordered]@{ step = $directory; state = 'rollback-failed'; externalCalls = 0 } }
        }
        if (@($plan.rollback | Where-Object { $_.state -eq 'rollback-failed' }).Count -gt 0) { $plan.atomic = $false }
        if ($plan.atomic -and $null -ne $transactionStatePath -and (Test-Path -LiteralPath $transactionStatePath -PathType Leaf)) {
            try {
                # rollback 영수증이 모두 성공한 뒤에만 재시도를 허용하는 terminal state를 기록합니다.
                [IO.File]::WriteAllText(
                    $transactionStatePath,
                    ([ordered]@{
                        schemaVersion = 1; status = 'rolled-back'; rollbackVerified = $true
                        failedStep = $currentStep; rollbackCompletedUtc = [DateTime]::UtcNow.ToString('O')
                    } | ConvertTo-Json -Compress),
                    [Text.UTF8Encoding]::new($false)
                )
            } catch { $plan.atomic = $false }
        }
        $plan.failureReason = $applyError.Exception.Message.Split(':')[0]
        $plan.registrationResults = @($registrationResults)
        if ($Json) { $plan | ConvertTo-Json -Depth 10 }
        else { Write-Output ("Install failed at {0}; rollback results were recorded." -f $currentStep) }
        exit 2
    }
    $plan.registrationResults = @($registrationResults)
    $plan.state = 'applied'
    $plan.applied = $true
    if ($Json) { $plan | ConvertTo-Json -Depth 10 }
    else { Write-Output ("Hermes Windows Bridge registration orchestration state: {0}" -f $plan.state) }
    exit 0
    } finally {
        # 선택부터 검증·commit 또는 rollback까지 동일한 배타 잠금을 반드시 해제합니다.
        if ($null -ne $serviceTransactionLock) {
            $serviceTransactionLock.Dispose()
            $serviceTransactionLock = $null
        }
    }
}

if ($Json) { $plan | ConvertTo-Json -Depth 10 }
else {
    Write-Output 'Hermes Windows Bridge installation plan (read-only).'
    foreach ($action in $actions) { Write-Output ("Action {0}: planned={1}" -f $action.id, $action.planned) }
    Write-Output ("Dependency argv: {0}" -f ($plan.dependencyArgv -join ' '))
    if ($InstallPlaywright) { Write-Output ("Playwright argv: {0}" -f ($plan.playwrightArgv -join ' ')) }
    if ($ConfigureTailscale) { Write-Output ("Tailscale Serve argv: {0}" -f ($tailscaleServeArgv -join ' ')) }
    Write-Output 'Recommended tailnet grant fragment (manual merge only):'; Write-Output $recommendedGrant
    Write-Output ("Final MCP URL: {0}" -f $finalMcpUrl)
    Write-Output 'Hermes config snippet (manual merge only):'; Write-Output $hermesConfigSnippet
    Write-Output 'No directories, services, tasks, tokens, ACLs, Tailscale settings, or Hermes configuration were changed.'
}
exit 0
