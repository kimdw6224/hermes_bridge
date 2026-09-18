[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Apply,
    [switch]$Json,
    [switch]$RemoveUserData,
    [ValidateSet('Production', 'Simulate')][string]$AdapterMode = 'Production',
    [ValidateSet(
        'None', 'backup_state', 'interactive_worker_task', 'gateway_service',
        'privileged_helper_service', 'remove_user_data', 'runtime_access_restore'
    )][string]$SimulationFailureStep = 'None',
    [string]$ProgramDataRoot = $env:ProgramData,
    [string]$LocalDataRoot = $env:LOCALAPPDATA,
    [string]$InstallationContextPath = '',
    [string]$InstallationContextSha256 = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$installationContextPathProvided = $PSBoundParameters.ContainsKey('InstallationContextPath')
$installationContextHashProvided = $PSBoundParameters.ContainsKey('InstallationContextSha256')
$programDataRootProvided = $PSBoundParameters.ContainsKey('ProgramDataRoot')
$localDataRootProvided = $PSBoundParameters.ContainsKey('LocalDataRoot')
$installationContext = $null

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
$runtimeContractPath = Join-Path $canonicalScriptRoot 'service-runtime.ps1'
# LibraryMode의 동명 switch 기본값이 호출자의 실행 의도를 덮지 않도록 보존합니다.
$uninstallApply = $Apply
$uninstallJson = $Json
$uninstallInstallationContextPath = $InstallationContextPath
$uninstallInstallationContextSha256 = $InstallationContextSha256
. $runtimeContractPath -LibraryMode
$Apply = $uninstallApply
$Json = $uninstallJson
$InstallationContextPath = $uninstallInstallationContextPath
$InstallationContextSha256 = $uninstallInstallationContextSha256
. (Join-Path $canonicalScriptRoot 'service-runtime-transaction.ps1')

if ($installationContextPathProvided -or $installationContextHashProvided) {
    if ($installationContextPathProvided -xor $installationContextHashProvided) {
        throw [ArgumentException]::new('BridgeInstallationContextPairRequired')
    }
    $installationContextScriptPath = Join-Path $canonicalScriptRoot 'installation-context.ps1'
    if (-not (Test-Path -LiteralPath $installationContextScriptPath -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new('BridgeInstallationContextContractMissing')
    }
    . $installationContextScriptPath -LibraryMode
}

function Resolve-UninstallInstallationContext {
    if (-not $installationContextPathProvided) { return $null }
    if ($programDataRootProvided -or $localDataRootProvided) {
        throw [ArgumentException]::new('BridgeContextRootOverrideForbidden')
    }
    $requestedContextPath = $InstallationContextPath
    $requestedContextSha256 = $InstallationContextSha256
    return Get-BridgeInstallationContext -Path $requestedContextPath -Sha256 $requestedContextSha256
}

$installationContext = Resolve-UninstallInstallationContext
if ($null -ne $installationContext -and $AdapterMode -eq 'Simulate') {
    throw [ArgumentException]::new('BridgeContextSimulationForbidden')
}

if ($null -ne $installationContext) {
    $ProgramDataRoot = [string]$installationContext.programDataRoot
    $LocalDataRoot = [string]$installationContext.localDataRoot
} elseif ([string]::IsNullOrWhiteSpace($ProgramDataRoot)) {
    $ProgramDataRoot = [Environment]::GetFolderPath('CommonApplicationData')
}
if ([string]::IsNullOrWhiteSpace($LocalDataRoot)) {
    $LocalDataRoot = [Environment]::GetFolderPath('LocalApplicationData')
}
$ProgramDataRoot = Resolve-BridgeLocalRoot -Path $ProgramDataRoot
$LocalDataRoot = Resolve-BridgeLocalRoot -Path $LocalDataRoot
$runtimeRoot = [IO.Path]::Combine($ProgramDataRoot, 'HermesWindowsBridge')
$userRoot = [IO.Path]::Combine($LocalDataRoot, 'HermesWindowsBridge')
[void](Assert-BridgePathUnderRoot -Root $ProgramDataRoot -Path $runtimeRoot)
[void](Assert-BridgePathUnderRoot -Root $LocalDataRoot -Path $userRoot)
$runtimeAccessMarkerPath = Get-BridgeRuntimeAccessMarkerPath -RuntimeRoot $runtimeRoot
$runtimeAccessMarkerPresent = Test-Path -LiteralPath $runtimeAccessMarkerPath -PathType Leaf
$runtimeAccessMarkerVerified = $true
if ($runtimeAccessMarkerPresent) {
    try { [void](Read-BridgeRuntimeAccessMarker -RuntimeRoot $runtimeRoot) }
    catch { $runtimeAccessMarkerVerified = $false }
}

$gatewayServiceName = if ($null -ne $installationContext) { [string]$installationContext.gatewayServiceName } else { 'HermesWindowsBridgeGateway' }
$privilegedServiceName = if ($null -ne $installationContext) { [string]$installationContext.privilegedServiceName } else { 'HermesWindowsBridgePrivileged' }
$workerTaskName = if ($null -ne $installationContext) { [string]$installationContext.workerTaskName } else { 'HermesWindowsBridgeWorker' }
$gatewayService = Get-Service -Name $gatewayServiceName -ErrorAction SilentlyContinue
$privilegedService = Get-Service -Name $privilegedServiceName -ErrorAction SilentlyContinue
$workerTask = $null
$scheduledTaskCommand = Get-Command -Name 'Get-ScheduledTask' -ErrorAction SilentlyContinue
if ($null -ne $scheduledTaskCommand) {
    $workerTask = Get-ScheduledTask -TaskName $workerTaskName -ErrorAction SilentlyContinue
}
$projectRoot = Split-Path -Parent $PSScriptRoot
$pythonPath = [IO.Path]::Combine($projectRoot, '.venv', 'Scripts', 'python.exe')
$workerPythonPath = [IO.Path]::Combine($projectRoot, '.venv', 'Scripts', 'pythonw.exe')
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$registrationAdapterNames = @(
    'register-gateway-service.ps1',
    'register-privileged-service.ps1',
    'register-worker-task.ps1'
)
$registrationAdaptersReady = @($registrationAdapterNames | Where-Object {
    -not (Test-BridgeRegistrationAdapterContract -ScriptRoot $PSScriptRoot -ScriptName $_)
}).Count -eq 0

$backupSources = @()
foreach ($candidate in @(
    [IO.Path]::Combine($runtimeRoot, 'config.yaml'),
    [IO.Path]::Combine($runtimeRoot, 'config.yml'),
    [IO.Path]::Combine($runtimeRoot, 'config.json'),
    [IO.Path]::Combine($runtimeRoot, 'policy.yaml'),
    [IO.Path]::Combine($runtimeRoot, 'secrets', 'token')
)) {
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        $backupSources += $candidate
    }
}

$actions = @(
    [ordered]@{ id = 'backup_state'; planned = ($backupSources.Count -gt 0); state = if ($backupSources.Count -gt 0) { 'planned' } else { 'unchanged' } },
    [ordered]@{ id = 'gateway_service'; planned = ($null -ne $gatewayService); state = if ($null -ne $gatewayService) { 'remove-through-registration-adapter' } else { 'unchanged' } },
    [ordered]@{ id = 'privileged_helper_service'; planned = ($null -ne $privilegedService); state = if ($null -ne $privilegedService) { 'remove-through-registration-adapter' } else { 'unchanged' } },
    [ordered]@{ id = 'interactive_worker_task'; planned = ($null -ne $workerTask); state = if ($null -ne $workerTask) { 'remove-through-registration-adapter' } else { 'unchanged' } },
    [ordered]@{ id = 'runtime_access_restore'; planned = $runtimeAccessMarkerPresent; state = if ($runtimeAccessMarkerPresent) { 'remove-owned-exact-ace' } else { 'unchanged' } },
    [ordered]@{ id = 'preserve_token'; planned = $true; state = 'preserved' },
    [ordered]@{ id = 'preserve_config'; planned = $true; state = 'preserved' },
    [ordered]@{ id = 'preserve_user_data'; planned = (-not $RemoveUserData); state = if ($RemoveUserData) { 'explicit-removal-requested' } else { 'preserved' } },
    [ordered]@{ id = 'tailscale_scoped_cleanup'; planned = $false; state = 'manual-action-required' }
)
if ($RemoveUserData) {
    $userDataExists = Test-Path -LiteralPath $userRoot -PathType Container
    $actions += [ordered]@{ id = 'remove_user_data'; planned = $userDataExists; state = if ($userDataExists) { 'planned' } else { 'unchanged' } }
}

$plan = [ordered]@{
    schemaVersion = 1
    kind = 'hermes-windows-bridge-uninstall-plan'
    mode = if ($WhatIfPreference) { 'what-if' } elseif ($Apply) { 'apply' } else { 'read-only' }
    applied = $false
    atomic = $true
    resumeSafe = $true
    removeUserData = [bool]$RemoveUserData
    administratorRequiredForApply = $true
    currentProcessElevated = (Test-BridgeAdministrator)
    actions = $actions
    backups = @($backupSources)
    preserved = if ($RemoveUserData) { @('configuration', 'token') } else { @('user-data', 'browser-profile', 'configuration', 'token') }
    registrationAdaptersReady = $registrationAdaptersReady
    runtimeAccessMarkerVerified = $runtimeAccessMarkerVerified
    registrationResults = @()
    adapterMode = $AdapterMode
    receipts = @()
    rollback = @()
    failedStep = $null
    externalCalls = if ($AdapterMode -eq 'Simulate') { 0 } else { $null }
    state = 'planned'
    failureReason = $null
    tailscaleCleanup = 'Manually remove only the Hermes Windows Bridge Serve handler after reviewing current state. Never reset all Serve configuration or tailnet policy.'
    nextStep = if ($null -ne $installationContext) { 'Review this plan. Apply removes only the three exact context registrations and preserves configuration/token data by default.' } else { 'Review this plan. Apply removes only the three fixed registrations and preserves configuration/token data by default.' }
}

if ($AdapterMode -eq 'Simulate' -and -not $Apply) {
    throw [ArgumentException]::new('BridgeAdapterSimulationRequiresApply: Simulate is valid only with -Apply.')
}
if ($SimulationFailureStep -ne 'None' -and ($AdapterMode -ne 'Simulate' -or -not $Apply)) {
    throw [ArgumentException]::new('BridgeSimulationFailureRequiresSimulation: failure injection is valid only with -Apply -AdapterMode Simulate.')
}

if ($Apply -and -not $WhatIfPreference) {
    $plan.failureReason = if ($AdapterMode -eq 'Production' -and -not $plan.currentProcessElevated) {
        'administrator-required'
    } elseif (-not $registrationAdaptersReady) {
        'registration-adapter-remove-contract-unverified'
    } elseif (-not $runtimeAccessMarkerVerified) {
        'runtime-access-marker-unverified'
    } else {
        $null
    }
    if ($null -ne $plan.failureReason) {
        $plan.state = 'blocked'
        if ($Json) { $plan | ConvertTo-Json -Depth 8 }
        else { Write-Output ("Uninstall Apply blocked: {0}; no changes were made." -f $plan.failureReason) }
        exit 2
    }

    if ($AdapterMode -eq 'Simulate') {
        $simulationSteps = @('backup_state', 'interactive_worker_task', 'gateway_service', 'privileged_helper_service')
        if ($RemoveUserData) { $simulationSteps += 'remove_user_data' }
        $simulationSteps += 'runtime_access_restore'
        foreach ($step in $simulationSteps) {
            if ($SimulationFailureStep -eq $step) {
                $plan.receipts += [ordered]@{ step = $step; state = 'failed-simulated'; externalCalls = 0 }
                $plan.failedStep = $step
                for ($index = $plan.receipts.Count - 2; $index -ge 0; $index--) {
                    $plan.rollback += [ordered]@{ step = $plan.receipts[$index].step; state = 'rollback-simulated'; externalCalls = 0 }
                }
                $plan.state = 'failed'
                $plan.applied = $false
                if ($Json) { $plan | ConvertTo-Json -Depth 8 }
                else { Write-Output ("Uninstall simulation failed at fixed step: {0}; no changes were made." -f $step) }
                exit 2
            }
            if ($step -eq 'interactive_worker_task') {
                $plan.registrationResults += Invoke-BridgeRegistrationAdapter -ScriptRoot $PSScriptRoot `
                    -ScriptName 'register-worker-task.ps1' -ArgumentList @('-UserId', $identity.Name, '-ExecutablePath', $pythonPath) `
                    -AdapterMode Simulate -Operation Remove -ExpectedName 'HermesWindowsBridgeWorker' `
                    -ExpectedAccount $identity.Name -ExpectedArgv @($workerPythonPath, '-m', 'hermes_windows_bridge.worker.main')
            } elseif ($step -eq 'gateway_service') {
                $plan.registrationResults += Invoke-BridgeRegistrationAdapter -ScriptRoot $PSScriptRoot `
                    -ScriptName 'register-gateway-service.ps1' -ArgumentList @('-ExecutablePath', $pythonPath) `
                    -AdapterMode Simulate -Operation Remove -ExpectedName 'HermesWindowsBridgeGateway' `
                    -ExpectedAccount 'NT AUTHORITY\LocalService' -ExpectedArgv @($pythonPath, '-I', '-B', '-m', 'hermes_windows_bridge.gateway.windows_service')
            } elseif ($step -eq 'privileged_helper_service') {
                $plan.registrationResults += Invoke-BridgeRegistrationAdapter -ScriptRoot $PSScriptRoot `
                    -ScriptName 'register-privileged-service.ps1' -ArgumentList @('-ExecutablePath', $pythonPath) `
                    -AdapterMode Simulate -Operation Remove -ExpectedName 'HermesWindowsBridgePrivileged' `
                    -ExpectedAccount 'LocalSystem' -ExpectedArgv @($pythonPath, '-I', '-B', '-m', 'hermes_windows_bridge.privileged.main')
            }
            $plan.receipts += [ordered]@{ step = $step; state = 'simulated'; externalCalls = 0 }
        }
        $plan.state = 'simulated'
        $plan.applied = $false
        if ($Json) { $plan | ConvertTo-Json -Depth 8 }
        else { Write-Output 'Hermes Windows Bridge full uninstall simulation completed; no changes were made.' }
        exit 0
    }

    if (-not $PSCmdlet.ShouldProcess(
        ($workerTaskName + ', ' + $gatewayServiceName + ', ' + $privilegedServiceName),
        $(if ($null -ne $installationContext) { 'Remove only the verified exact context scheduled-task and service registrations' } else { 'Remove only the verified fixed scheduled-task and service registrations' })
    )) {
        $plan.mode = 'what-if'
        if ($Json) { $plan | ConvertTo-Json -Depth 8 }
        exit 0
    }

    $serviceTransactionLock = $null
    try {
    try {
        $serviceProgramRoot = if ($null -ne $installationContext) { [string]$installationContext.programRoot } else { Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'HermesWindowsBridge' }
        $serviceTransactionLock = Enter-BridgeServiceReleaseTransaction -ProgramRoot $serviceProgramRoot
        $serviceRelease = Resolve-BridgeServiceReleaseSelection -ProgramRoot $serviceProgramRoot -InstallationContext $installationContext
        $serviceInspection = Get-BridgeServicePairInspection -ScriptRoot $PSScriptRoot -Release $serviceRelease -InstallationContext $installationContext
        if ($serviceInspection.previousState -notin @('safe-pair', 'absent-pair')) {
            throw [Security.SecurityException]::new('BridgeUninstallServicePairUnverified')
        }
    } catch {
        $plan.state = 'blocked'
        $plan.failureReason = 'protected-service-removal-unverified'
        if ($Json) { $plan | ConvertTo-Json -Depth 8 }
        else { Write-Output 'Uninstall blocked: protected service identity could not be verified.' }
        exit 2
    }
    $servicesInstalled = $serviceInspection.previousState -ceq 'safe-pair'
    $gatewayRequest = Get-BridgeServiceRegistrationRequest -Release $serviceRelease -Profile 'gateway' -InstallationContext $installationContext
    $privilegedRequest = Get-BridgeServiceRegistrationRequest -Release $serviceRelease -Profile 'privileged' -InstallationContext $installationContext
    $workerArguments = @('-UserId', $identity.Name, '-ExecutablePath', $pythonPath)
    $workerExpectedArgv = @($workerPythonPath, '-m', 'hermes_windows_bridge.worker.main')
    if ($null -ne $installationContext) {
        $workerArguments += @('-InstallationContextPath', [string]$installationContext.contextPath, '-InstallationContextSha256', [string]$installationContext.contextSha256)
        $workerBinding = Get-BridgeInstallationContextBinding -Context $installationContext -Profile 'worker'
        if ([string]$workerBinding.path -cne (Join-Path $installationContext.bindingsDirectory 'worker.json') -or
            [string]$workerBinding.sha256 -cnotmatch '^[a-f0-9]{64}$') {
            throw [Security.SecurityException]::new('BridgeContextWorkerBindingUnverified')
        }
        $workerExpectedArgv += @('--runtime-binding', [string]$workerBinding.path, '--runtime-binding-sha256', [string]$workerBinding.sha256)
    }
    $plan.preserved += @('protected-service-release', 'active-release-pointer')
    $registrationResults = @()
    $removalRequests = @(
        [ordered]@{ installed = ($null -ne $workerTask); script = 'register-worker-task.ps1'; arguments = $workerArguments; name = $workerTaskName; account = $identity.Name; argv = $workerExpectedArgv },
        [ordered]@{ installed = $servicesInstalled; script = $gatewayRequest.script; arguments = $gatewayRequest.arguments; name = $gatewayRequest.name; account = $gatewayRequest.account; argv = $gatewayRequest.argv },
        [ordered]@{ installed = $servicesInstalled; script = $privilegedRequest.script; arguments = $privilegedRequest.arguments; name = $privilegedRequest.name; account = $privilegedRequest.account; argv = $privilegedRequest.argv }
    )
    $executedRequests = @()
    $backupDirectory = $null
    $userDataBackupPath = $null
    $userDataRemovalStarted = $false
    $currentStep = 'backup_state'
    try {
        if ($backupSources.Count -gt 0 -or ($RemoveUserData -and (Test-Path -LiteralPath $userRoot -PathType Container))) {
            $backupsRoot = [IO.Path]::Combine($runtimeRoot, 'backups')
            if (-not (Test-Path -LiteralPath $backupsRoot -PathType Container)) { [void](New-Item -ItemType Directory -Path $backupsRoot -Force) }
            $backupDirectory = [IO.Path]::Combine($backupsRoot, ('uninstall-' + [guid]::NewGuid().ToString('N')))
            [void](New-Item -ItemType Directory -Path $backupDirectory)
            Set-BridgeSecretsDirectoryAcl -Path $backupDirectory
            foreach ($source in $backupSources) {
                $destination = [IO.Path]::Combine($backupDirectory, [IO.Path]::GetFileName($source))
                Copy-Item -LiteralPath $source -Destination $destination -Force
                if (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
                    (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -cne (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash) {
                    throw [IO.IOException]::new('BridgeUninstallBackupVerificationFailed: copied file hash differs from source.')
                }
                $plan.backups += $destination
            }
            if ($RemoveUserData -and (Test-Path -LiteralPath $userRoot -PathType Container)) {
                $userDataBackupPath = [IO.Path]::Combine($backupDirectory, 'user-data')
                Copy-Item -LiteralPath $userRoot -Destination $userDataBackupPath -Recurse
                $sourceFiles = @(Get-ChildItem -LiteralPath $userRoot -Recurse -Force -File | ForEach-Object {
                    $_.FullName.Substring($userRoot.Length) + ':' + (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
                } | Sort-Object)
                $backupFiles = @(Get-ChildItem -LiteralPath $userDataBackupPath -Recurse -Force -File | ForEach-Object {
                    $_.FullName.Substring($userDataBackupPath.Length) + ':' + (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
                } | Sort-Object)
                if (($sourceFiles | ConvertTo-Json -Compress) -cne ($backupFiles | ConvertTo-Json -Compress)) {
                    throw [IO.IOException]::new('BridgeUninstallUserDataBackupVerificationFailed: backup differs from source.')
                }
                $plan.backups += $userDataBackupPath
            }
        }
        $plan.receipts += [ordered]@{ step = 'backup_state'; state = if ($null -ne $backupDirectory) { 'created-and-verified' } else { 'unchanged' }; externalCalls = 0 }

        foreach ($request in $removalRequests) {
            if (-not $request.installed) { continue }
            $currentStep = switch ($request.name) {
                $workerTaskName { 'interactive_worker_task' }
                $gatewayServiceName { 'gateway_service' }
                $privilegedServiceName { 'privileged_helper_service' }
                default { throw [Security.SecurityException]::new('BridgeUninstallContextRegistrationNameUnverified') }
            }
            $registrationResults += Invoke-BridgeRegistrationAdapter -ScriptRoot $PSScriptRoot `
                -ScriptName $request.script -ArgumentList $request.arguments -AdapterMode $AdapterMode `
                -Operation Remove -ExpectedName $request.name -ExpectedAccount $request.account -ExpectedArgv $request.argv
            $executedRequests += $request
            $plan.receipts += [ordered]@{ step = $currentStep; state = if ($registrationResults[-1].applied) { 'removed' } else { 'unchanged' }; externalCalls = $null }
        }

        $currentStep = 'service_removal_readback'
        $removedPair = Get-BridgeServicePairInspection -ScriptRoot $PSScriptRoot -Release $serviceRelease -InstallationContext $installationContext
        if ($removedPair.previousState -cne 'absent-pair') {
            throw [Security.SecurityException]::new('BridgeUninstallServiceRemovalUnverified')
        }
        $plan.receipts += [ordered]@{ step = $currentStep; state = 'verified-absent'; externalCalls = $null }

        if ($RemoveUserData -and (Test-Path -LiteralPath $userRoot -PathType Container)) {
            $currentStep = 'remove_user_data'
            $safeUserRoot = Assert-BridgePathUnderRoot -Root $LocalDataRoot -Path $userRoot
            $userDataRemovalStarted = $true
            Remove-Item -LiteralPath $safeUserRoot -Recurse -Force
            if (Test-Path -LiteralPath $safeUserRoot) {
                throw [IO.IOException]::new('BridgeUserDataRemovalVerificationFailed: user data still exists.')
            }
            $plan.receipts += [ordered]@{ step = 'remove_user_data'; state = 'removed'; externalCalls = 0 }
        }
        if ($runtimeAccessMarkerPresent) {
            $currentStep = 'runtime_access_restore'
            $runtimeAccessRestore = Restore-BridgeBaseRuntimeAccess -RuntimeRoot $runtimeRoot
            $plan.receipts += [ordered]@{ step = 'runtime_access_restore'; state = $runtimeAccessRestore.state; externalCalls = 0 }
        }
    } catch {
        $removalError = $_
        $plan.state = 'failed'
        $plan.applied = $false
        $plan.failedStep = $currentStep
        if ($userDataRemovalStarted -and $null -ne $userDataBackupPath -and (Test-Path -LiteralPath $userDataBackupPath -PathType Container)) {
            try {
                if (Test-Path -LiteralPath $userRoot) { Remove-Item -LiteralPath $userRoot -Recurse -Force }
                Copy-Item -LiteralPath $userDataBackupPath -Destination $userRoot -Recurse
                $plan.rollback += [ordered]@{ step = 'remove_user_data'; state = 'restored-from-backup'; externalCalls = 0 }
            } catch { $plan.rollback += [ordered]@{ step = 'remove_user_data'; state = 'rollback-failed'; externalCalls = 0 } }
        }
        for ($index = $registrationResults.Count - 1; $index -ge 0; $index--) {
            if ($registrationResults[$index].applied -ne $true) { continue }
            $request = $executedRequests[$index]
            try {
                $restoreResult = Invoke-BridgeRegistrationAdapter -ScriptRoot $PSScriptRoot `
                    -ScriptName $request.script -ArgumentList $request.arguments -AdapterMode Production `
                    -Operation Register -ExpectedName $request.name -ExpectedAccount $request.account -ExpectedArgv $request.argv
                $plan.rollback += [ordered]@{ step = $request.name; state = if ($restoreResult.readBack.exact) { 'restored' } else { 'rollback-failed' }; externalCalls = $null }
            } catch {
                $plan.rollback += [ordered]@{ step = $request.name; state = 'rollback-failed'; externalCalls = $null }
            }
        }
        if (@($plan.rollback | Where-Object { $_.state -eq 'rollback-failed' }).Count -gt 0) { $plan.atomic = $false }
        $plan.failureReason = $removalError.Exception.Message.Split(':')[0]
        $plan.registrationResults = @($registrationResults)
        if ($Json) { $plan | ConvertTo-Json -Depth 8 }
        else { Write-Output ("Uninstall failed at {0}; rollback and backup results were recorded." -f $currentStep) }
        exit 2
    }
    $plan.registrationResults = @($registrationResults)
    $plan.state = 'applied'
    $plan.applied = $true
    if ($Json) { $plan | ConvertTo-Json -Depth 8 }
    else { Write-Output ("Hermes Windows Bridge uninstall registration state: {0}" -f $plan.state) }
    exit 0
    } finally {
        if ($null -ne $serviceTransactionLock) { $serviceTransactionLock.Dispose() }
    }
}

if ($Json) {
    $plan | ConvertTo-Json -Depth 8
} else {
    Write-Output 'Hermes Windows Bridge uninstall plan.'
    foreach ($action in $actions) {
        Write-Output ("Action {0}: planned={1}; state={2}" -f $action.id, $action.planned, $action.state)
    }
    Write-Output $plan.tailscaleCleanup
    Write-Output 'No services, tasks, Tailscale settings, tailnet policy, files, tokens, configuration, or user data were changed.'
}

exit 0
