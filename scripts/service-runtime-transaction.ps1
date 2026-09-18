Set-StrictMode -Version Latest

$script:BridgeServiceNames = @('HermesWindowsBridgeGateway', 'HermesWindowsBridgePrivileged')

function Resolve-BridgeServiceReleaseSelection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProgramRoot,
        [string]$ServiceReleaseRoot = '',
        [string]$GatewayServiceHostRoot = '',
        [string]$PrivilegedServiceHostRoot = '',
        $InstallationContext = $null
    )
    $requestedHostsSpecified = -not [string]::IsNullOrWhiteSpace($GatewayServiceHostRoot) -or
        -not [string]::IsNullOrWhiteSpace($PrivilegedServiceHostRoot)
    if ($requestedHostsSpecified -and
        ([string]::IsNullOrWhiteSpace($GatewayServiceHostRoot) -or [string]::IsNullOrWhiteSpace($PrivilegedServiceHostRoot))) {
        throw [Security.SecurityException]::new('BridgeServiceHostRootsIncomplete')
    }
    $program = [IO.Path]::GetFullPath($ProgramRoot).TrimEnd('\')
    $releases = Join-Path $program 'releases'
    if ([string]::IsNullOrWhiteSpace($ServiceReleaseRoot)) {
        $pointerPath = Join-Path $program 'active-release.json'
        if (-not (Test-Path -LiteralPath $pointerPath -PathType Leaf)) {
            throw [Security.SecurityException]::new('BridgeActiveReleasePointerMissing')
        }
        $pointerItem = Get-Item -LiteralPath $pointerPath -Force
        if (($pointerItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            (Get-BridgeFileLinkCount -Path $pointerPath) -ne 1 -or
            $null -ne (Test-BridgeTreeAcl -Path $pointerPath -RequireTrustedOwner $true)) {
            throw [Security.SecurityException]::new('BridgeActiveReleasePointerUnprotected')
        }
        $pointer = Get-Content -LiteralPath $pointerPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $fields = @($pointer.PSObject.Properties.Name)
        $schemaOneFields = 'manifestSha256,releaseRoot,schemaVersion'
        $schemaTwoFields = 'gatewayHostRoot,manifestSha256,privilegedHostRoot,releaseRoot,schemaVersion'
        $sortedFields = ($fields | Sort-Object) -join ','
        if ((($pointer.schemaVersion -eq 1 -and $sortedFields -ceq $schemaOneFields) -or
                ($pointer.schemaVersion -eq 2 -and $sortedFields -ceq $schemaTwoFields)) -eq $false -or
            [string]$pointer.manifestSha256 -cnotmatch '^[a-f0-9]{64}$') {
            throw [Security.SecurityException]::new('BridgeActiveReleasePointerInvalid')
        }
        if ($pointer.schemaVersion -eq 2) {
            if ($requestedHostsSpecified -and
                (-not [IO.Path]::GetFullPath($GatewayServiceHostRoot).TrimEnd('\').Equals(
                    [IO.Path]::GetFullPath([string]$pointer.gatewayHostRoot).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase) -or
                 -not [IO.Path]::GetFullPath($PrivilegedServiceHostRoot).TrimEnd('\').Equals(
                    [IO.Path]::GetFullPath([string]$pointer.privilegedHostRoot).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase))) {
                throw [Security.SecurityException]::new('BridgeActiveReleasePointerHostMismatch')
            }
            $GatewayServiceHostRoot = [string]$pointer.gatewayHostRoot
            $PrivilegedServiceHostRoot = [string]$pointer.privilegedHostRoot
        }
        $ServiceReleaseRoot = [string]$pointer.releaseRoot
    } else { $pointer = $null }
    $release = [IO.Path]::GetFullPath($ServiceReleaseRoot).TrimEnd('\')
    $releaseId = [IO.Path]::GetFileName($release)
    if ($releaseId -cnotmatch '^[a-f0-9]{64}$' -or
        -not (Split-Path -Parent $release).Equals($releases, [StringComparison]::OrdinalIgnoreCase)) {
        throw [Security.SecurityException]::new('BridgeServiceReleaseRootInvalid')
    }
    $manifestPath = Join-Path $release 'release-manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw [Security.SecurityException]::new('BridgeServiceReleaseManifestMissing')
    }
    if ($null -ne $pointer -and
        (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$pointer.manifestSha256) {
        throw [Security.SecurityException]::new('BridgeActiveReleaseManifestMismatch')
    }
    $runtimePath = Join-Path $PSScriptRoot 'service-runtime.ps1'
    $launch = & {
        param($RuntimeScriptPath, $SelectedManifestPath, $SelectedReleaseRoot)
        . $RuntimeScriptPath -LibraryMode
        Get-BridgeServiceLaunchContract -ManifestPath $SelectedManifestPath -ReleaseRoot $SelectedReleaseRoot
    } $runtimePath $manifestPath $release
    if (-not $launch.verified) { throw [Security.SecurityException]::new('BridgeServiceReleaseUnverified') }
    $selection = [pscustomobject][ordered]@{
        releaseRoot = $release; releaseId = $releaseId; manifestPath = $manifestPath
        manifestSha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
        serviceExecutable = [string]$launch.serviceExecutable
    }
    $hostsSpecified = -not [string]::IsNullOrWhiteSpace($GatewayServiceHostRoot) -or
        -not [string]::IsNullOrWhiteSpace($PrivilegedServiceHostRoot)
    if ($hostsSpecified -and
        ([string]::IsNullOrWhiteSpace($GatewayServiceHostRoot) -or [string]::IsNullOrWhiteSpace($PrivilegedServiceHostRoot))) {
        throw [Security.SecurityException]::new('BridgeServiceHostRootsIncomplete')
    }
    if ($hostsSpecified) {
        Add-Member -InputObject $selection -MemberType NoteProperty -Name gatewayServiceHostRoot `
            -Value ([IO.Path]::GetFullPath($GatewayServiceHostRoot).TrimEnd('\'))
        Add-Member -InputObject $selection -MemberType NoteProperty -Name privilegedServiceHostRoot `
            -Value ([IO.Path]::GetFullPath($PrivilegedServiceHostRoot).TrimEnd('\'))
        # schema 2는 포인터에 기록된 각 host anchor를 이 선택 시점에 검증해야 legacy Python 실행으로 내려가지 않습니다.
        $null = Get-BridgeServiceRegistrationRequest -Release $selection -Profile 'gateway' -InstallationContext $InstallationContext
        $null = Get-BridgeServiceRegistrationRequest -Release $selection -Profile 'privileged' -InstallationContext $InstallationContext
    }
    return $selection
}

function Enter-BridgeServiceReleaseTransaction {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProgramRoot)
    $program = [IO.Path]::GetFullPath($ProgramRoot).TrimEnd('\')
    $programItem = Get-Item -LiteralPath $program -Force -ErrorAction Stop
    if (-not $programItem.PSIsContainer -or
        ($programItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $null -ne (Test-BridgeTreeAcl -Path $program -RequireTrustedOwner $true)) {
        throw [Security.SecurityException]::new('BridgeServiceProgramRootUnprotected')
    }
    $lockPath = Join-Path $program 'service-release.lock'
    try { $lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
    catch [IO.IOException] { throw [IO.IOException]::new('BridgeServiceReleaseTransactionBusy', $_.Exception) }
    try {
        if ($null -ne (Test-BridgeTreeAcl -Path $lockPath -RequireTrustedOwner $true) -or
            (Get-BridgeFileLinkCount -Path $lockPath) -ne 1) {
            throw [Security.SecurityException]::new('BridgeServiceReleaseLockUnprotected')
        }
        return $lock
    } catch {
        $lock.Dispose()
        throw
    }
}

function Publish-BridgeActiveReleasePointer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProgramRoot,
        [Parameter(Mandatory)]$Release
    )
    $program = [IO.Path]::GetFullPath($ProgramRoot).TrimEnd('\')
    $pointerPath = Join-Path $program 'active-release.json'
    $temporaryPath = Join-Path $program ('active-release.{0}.tmp' -f [guid]::NewGuid().ToString('N'))
    $body = Get-BridgeActiveReleasePointerBody -Release $Release
    try {
        [IO.File]::WriteAllText($temporaryPath, $body, [Text.UTF8Encoding]::new($false))
        if ($null -ne (Test-BridgeTreeAcl -Path $temporaryPath -RequireTrustedOwner $true) -or
            (Get-BridgeFileLinkCount -Path $temporaryPath) -ne 1) {
            throw [Security.SecurityException]::new('BridgeActiveReleaseTemporaryUnprotected')
        }
        if (Test-Path -LiteralPath $pointerPath -PathType Leaf) {
            # Windows PowerShell 5.1은 $null을 빈 경로로 변환하므로 CLR null 문자열을 명시합니다.
            [IO.File]::Replace(
                $temporaryPath,
                $pointerPath,
                [System.Management.Automation.Language.NullString]::Value,
                $true
            )
        } else {
            [IO.File]::Move($temporaryPath, $pointerPath)
        }
    } finally {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            [IO.File]::Delete($temporaryPath)
        }
    }
}

function Get-BridgeReleaseStringProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Release,
        [Parameter(Mandatory)][string]$Name
    )
    $property = $Release.PSObject.Properties[$Name]
    if ($null -eq $property) { return '' }
    return [string]$property.Value
}

function Get-BridgeActiveReleasePointerBody {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Release)
    $gatewayHostRoot = Get-BridgeReleaseStringProperty -Release $Release -Name 'gatewayServiceHostRoot'
    $privilegedHostRoot = Get-BridgeReleaseStringProperty -Release $Release -Name 'privilegedServiceHostRoot'
    $hostsSpecified = -not [string]::IsNullOrWhiteSpace($gatewayHostRoot) -or
        -not [string]::IsNullOrWhiteSpace($privilegedHostRoot)
    if ($hostsSpecified -and
        ([string]::IsNullOrWhiteSpace($gatewayHostRoot) -or [string]::IsNullOrWhiteSpace($privilegedHostRoot))) {
        throw [Security.SecurityException]::new('BridgeServiceHostRootsIncomplete')
    }
    $body = [ordered]@{
        schemaVersion = if ($hostsSpecified) { 2 } else { 1 }
        releaseRoot = [string]$Release.releaseRoot
        manifestSha256 = [string]$Release.manifestSha256
    }
    if ($hostsSpecified) {
        $body.gatewayHostRoot = $gatewayHostRoot
        $body.privilegedHostRoot = $privilegedHostRoot
    }
    return ($body | ConvertTo-Json -Compress)
}

function Get-BridgeServiceRegistrationRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Release,
        [Parameter(Mandatory)][ValidateSet('gateway', 'privileged')][string]$Profile,
        $InstallationContext = $null
    )
    $isGateway = $Profile -ceq 'gateway'
    $hostProperty = if ($isGateway) { 'gatewayServiceHostRoot' } else { 'privilegedServiceHostRoot' }
    $hostRoot = Get-BridgeReleaseStringProperty -Release $Release -Name $hostProperty
    $module = if ($isGateway) { 'hermes_windows_bridge.gateway.windows_service' } else { 'hermes_windows_bridge.privileged.main' }
    $script = if ($isGateway) { 'register-gateway-service.ps1' } else { 'register-privileged-service.ps1' }
    $name = if ($null -eq $InstallationContext) {
        if ($isGateway) { 'HermesWindowsBridgeGateway' } else { 'HermesWindowsBridgePrivileged' }
    } elseif ($isGateway) { [string]$InstallationContext.gatewayServiceName } else { [string]$InstallationContext.privilegedServiceName }
    $account = if ($isGateway) { 'NT AUTHORITY\LocalService' } else { 'LocalSystem' }
    $arguments = @('-RuntimeManifestPath', [string]$Release.manifestPath, '-RuntimeReleaseRoot', [string]$Release.releaseRoot)
    if ($null -ne $InstallationContext) {
        $arguments += @('-InstallationContextPath', [string]$InstallationContext.contextPath, '-InstallationContextSha256', [string]$InstallationContext.contextSha256)
    }
    $argv = @([string]$Release.serviceExecutable, '-I', '-B', '-m', $module)
    if (-not [string]::IsNullOrWhiteSpace($hostRoot)) {
        $canonicalHostRoot = [IO.Path]::GetFullPath($hostRoot).TrimEnd('\')
        $canonicalReleaseRoot = [IO.Path]::GetFullPath([string]$Release.releaseRoot).TrimEnd('\')
        $hostHelperPath = Join-Path $PSScriptRoot 'service-host.ps1'
        if (-not (Test-Path -LiteralPath $hostHelperPath -PathType Leaf)) {
            throw [Security.SecurityException]::new('BridgeServiceHostContractMissing')
        }
        $contract = & {
            param($HelperPath, $RequestedHostRoot, $RequestedProfile, $RequestedReleaseRoot, $Context)
            . $HelperPath -LibraryMode
            if ($null -eq $Context) {
                Get-BridgeServiceHostContract -HostRoot $RequestedHostRoot -Profile $RequestedProfile -ReleaseRoot $RequestedReleaseRoot
            } else {
                Get-BridgeServiceHostContract -HostRoot $RequestedHostRoot -Profile $RequestedProfile -ReleaseRoot $RequestedReleaseRoot `
                    -InstallationContextPath ([string]$Context.contextPath) -InstallationContextSha256 ([string]$Context.contextSha256)
            }
        } $hostHelperPath $canonicalHostRoot $Profile $canonicalReleaseRoot $InstallationContext
        $binding = if ($null -eq $InstallationContext) { $null } else {
            Get-BridgeInstallationContextBinding -Context $InstallationContext -Profile $Profile
        }
        if (-not $contract.verified -or [string]$contract.state -cne 'verified' -or [string]$contract.profile -cne $Profile -or
            -not [IO.Path]::GetFullPath([string]$contract.releaseRoot).TrimEnd('\').Equals($canonicalReleaseRoot, [StringComparison]::OrdinalIgnoreCase) -or
            -not [IO.Path]::GetFullPath([string]$contract.hostRoot).TrimEnd('\').Equals($canonicalHostRoot, [StringComparison]::OrdinalIgnoreCase) -or
            [string]$contract.hostDigest -cnotmatch '^[a-f0-9]{64}$' -or
            [string]$contract.manifestSha256 -cne [string]$Release.manifestSha256 -or
            [string]::IsNullOrWhiteSpace([string]$contract.releaseExecutable) -or
            -not [IO.Path]::GetFullPath([string]$contract.releaseExecutable).Equals(
                [IO.Path]::GetFullPath([string]$Release.serviceExecutable), [StringComparison]::OrdinalIgnoreCase) -or
            @($contract.argv).Count -ne 3 -or
            [string]$contract.argv[0] -cne [string]$contract.hostExecutable -or
            [string]$contract.argv[1] -cne '--profile' -or [string]$contract.argv[2] -cne $Profile -or
            ($null -ne $InstallationContext -and (
                [string]$contract.contextNonce -cne [string]$InstallationContext.nonce -or
                [string]$contract.runtimeBindingPath -cne [string]$binding.path -or
                [string]$contract.runtimeBindingSha256 -cne [string]$binding.sha256 -or
                [string]$contract.serviceName -cne $name))) {
            throw [Security.SecurityException]::new('BridgeServiceHostContractUnverified')
        }
        $arguments += @('-ServiceHostRoot', $canonicalHostRoot)
        $argv = @($contract.argv | ForEach-Object { [string]$_ })
    }
    return [pscustomobject][ordered]@{
        script = $script; arguments = $arguments; name = $name; account = $account
        argv = $argv; profile = $Profile; serviceHostRoot = $hostRoot
    }
}

function Test-BridgeServiceReleaseIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Left,
        [Parameter(Mandatory)]$Right
    )
    if ([string]$Left.releaseId -cne [string]$Right.releaseId) { return $false }
    $leftGateway = Get-BridgeReleaseStringProperty -Release $Left -Name 'gatewayServiceHostRoot'
    $rightGateway = Get-BridgeReleaseStringProperty -Release $Right -Name 'gatewayServiceHostRoot'
    $leftPrivileged = Get-BridgeReleaseStringProperty -Release $Left -Name 'privilegedServiceHostRoot'
    $rightPrivileged = Get-BridgeReleaseStringProperty -Release $Right -Name 'privilegedServiceHostRoot'
    return $leftGateway.Equals($rightGateway, [StringComparison]::OrdinalIgnoreCase) -and
        $leftPrivileged.Equals($rightPrivileged, [StringComparison]::OrdinalIgnoreCase)
}

function Restore-BridgeActiveReleasePointerBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProgramRoot,
        [Parameter(Mandatory)][string]$Body
    )
    $program = [IO.Path]::GetFullPath($ProgramRoot).TrimEnd('\')
    $pointerPath = Join-Path $program 'active-release.json'
    $temporaryPath = Join-Path $program ('active-release.{0}.restore.tmp' -f [guid]::NewGuid().ToString('N'))
    try {
        [IO.File]::WriteAllText($temporaryPath, $Body, [Text.UTF8Encoding]::new($false))
        if ($null -ne (Test-BridgeTreeAcl -Path $temporaryPath -RequireTrustedOwner $true) -or
            (Get-BridgeFileLinkCount -Path $temporaryPath) -ne 1) {
            throw [Security.SecurityException]::new('BridgeActiveReleaseTemporaryUnprotected')
        }
        [IO.File]::Replace(
            $temporaryPath,
            $pointerPath,
            [System.Management.Automation.Language.NullString]::Value,
            $true
        )
    } finally {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) { [IO.File]::Delete($temporaryPath) }
    }
}

function Get-BridgeServiceDefinitionInspection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ScriptRoot,
        [Parameter(Mandatory)]$Definition
    )
    $result = Invoke-BridgeChildProcess -FilePath ([IO.Path]::Combine($PSHOME, 'powershell.exe')) `
        -ArgumentList (@(
            '-NoProfile', '-NonInteractive', '-File',
            (Join-Path $ScriptRoot $Definition.script), '-Operation', 'Inspect'
        ) + @($Definition.arguments) + @('-Json')) `
        -WorkingDirectory $ScriptRoot -TimeoutSeconds 60
    if ([string]::IsNullOrWhiteSpace($result.stdout)) {
        throw [IO.InvalidDataException]::new('BridgeServiceInspectionOutputMissing')
    }
    $record = $result.stdout | ConvertFrom-Json -ErrorAction Stop
    if ($record.mode -cne 'inspect' -or $record.name -cne $Definition.name -or
        $record.account -cne $Definition.account -or $record.inspect.writes -ne 0 -or
        $record.readBack.performed -ne $true -or $record.state -notin @('desired', 'absent', 'conflict') -or
        $record.readBack.state -cne $record.state -or $record.readBack.exact -isnot [bool] -or
        $record.readBack.exact -ne ($record.state -in @('desired', 'absent')) -or
        ($result.exitCode -eq 0) -ne ($record.state -in @('desired', 'absent'))) {
        throw [IO.InvalidDataException]::new('BridgeServiceInspectionContractInvalid')
    }
    return $record
}

function Get-BridgeServicePairInspection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ScriptRoot,
        [Parameter(Mandatory)]$Release,
        $InstallationContext = $null
    )
    $definitions = @(
        Get-BridgeServiceRegistrationRequest -Release $Release -Profile 'gateway' -InstallationContext $InstallationContext
        Get-BridgeServiceRegistrationRequest -Release $Release -Profile 'privileged' -InstallationContext $InstallationContext
    )
    $observed = @($definitions | ForEach-Object {
        Get-BridgeServiceDefinitionInspection -ScriptRoot $ScriptRoot -Definition $_
    })
    $states = @($observed | ForEach-Object { [string]$_.state })
    $pairState = if (@($states | Where-Object { $_ -ceq 'desired' }).Count -eq 2) {
        'safe-pair'
    } elseif (@($states | Where-Object { $_ -ceq 'absent' }).Count -eq 2) {
        'absent-pair'
    } elseif ($states -contains 'conflict') {
        'unsafe'
    } else {
        'mixed'
    }
    return [pscustomobject][ordered]@{ previousState = $pairState; definitions = $observed }
}

function Invoke-BridgeServiceSwitchTransaction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('safe-pair', 'absent-pair', 'unsafe', 'mixed')][string]$PreviousState,
        [Parameter(Mandatory)][scriptblock]$InvokeStep
    )
    # 포인터는 서비스와 doctor의 최종 검증이 모두 끝난 뒤에만 publish합니다.
    $steps = @(
        'gateway_stop', 'privileged_stop', 'gateway_register', 'privileged_register',
        'privileged_start', 'gateway_start', 'final_readback', 'doctor',
        'pointer_commit', 'post_commit_readback'
    )
    if ($PreviousState -in @('unsafe', 'mixed')) {
        return [pscustomobject][ordered]@{
            state = 'manual-recovery-required'; steps = @(); rollback = @(); starts = 0
            workerCalls = 0; pointerCommitted = $false; failedStep = $null
            pointerCompensated = $false
            failureReason = 'previous-service-state-unverified'; rollbackFailures = @()
        }
    }
    $completed = [Collections.Generic.List[string]]::new()
    $startCount = 0
    $pointerCommitted = $false
    foreach ($step in $steps) {
        try {
            $stepResult = & $InvokeStep $step
            if ($step -like '*_start' -and $stepResult -eq $true) { $startCount++ }
            if ($step -ceq 'pointer_commit') { $pointerCommitted = $true }
        }
        catch {
            $failureReason = $_.Exception.Message
            if ($step -like '*_stop') {
                # 정지 실패 뒤에는 정의 변경을 시도하지 않아 불확실한 실행 상태를 보존합니다.
                return [pscustomobject][ordered]@{
                    state = 'manual-recovery-required'; steps = @($completed); rollback = @(); starts = $startCount
                    workerCalls = 0; pointerCommitted = $pointerCommitted; pointerCompensated = $false
                    failedStep = $step; failureReason = $failureReason
                    rollbackFailures = @(('{0}:{1}' -f $step, $failureReason))
                }
            }
            $rollback = if ($PreviousState -ceq 'safe-pair') {
                @('gateway_stop', 'privileged_stop', 'gateway_restore', 'privileged_restore', 'restore_readback')
            } else {
                @('gateway_stop', 'privileged_stop', 'gateway_remove', 'privileged_remove', 'remove_readback')
            }
            if ($pointerCommitted) { $rollback += 'pointer_restore' }
            if ($PreviousState -ceq 'safe-pair') {
                $rollback += @('privileged_start', 'gateway_start', 'restore_running_readback')
            }
            $rolledBack = [Collections.Generic.List[string]]::new()
            $rollbackFailures = [Collections.Generic.List[string]]::new()
            $mutationFenced = $false
            foreach ($rollbackStep in $rollback) {
                if ($mutationFenced) { break }
                if (($rollbackStep -like '*_start' -or $rollbackStep -ceq 'restore_running_readback') -and
                    $rollbackFailures.Count -gt 0) { continue }
                try {
                    $rollbackResult = & $InvokeStep $rollbackStep
                    $rolledBack.Add($rollbackStep)
                    if ($rollbackStep -like '*_start' -and $rollbackResult -eq $true) { $startCount++ }
                }
                catch {
                    $rollbackFailures.Add(('{0}:{1}' -f $rollbackStep, $_.Exception.Message))
                    if ($rollbackStep -like '*_stop') { $mutationFenced = $true }
                }
            }
            $pointerCompensated = $pointerCommitted -and $rolledBack.Contains('pointer_restore') -and
                @($rollbackFailures | Where-Object { $_ -like 'pointer_restore:*' }).Count -eq 0
            return [pscustomobject][ordered]@{
                state = if ($rollbackFailures.Count -eq 0) { 'rolled-back' } else { 'manual-recovery-required' }
                steps = @($completed); rollback = @($rolledBack)
                starts = $startCount
                workerCalls = 0
                pointerCommitted = $pointerCommitted -and -not $pointerCompensated
                pointerCompensated = $pointerCompensated
                failedStep = $step
                failureReason = $failureReason; rollbackFailures = @($rollbackFailures)
            }
        }
        $completed.Add($step)
    }
    return [pscustomobject][ordered]@{
        state = 'switched'; steps = @($completed); rollback = @(); starts = $startCount
        workerCalls = 0; pointerCommitted = $true; pointerCompensated = $false; failedStep = $null
        failureReason = $null; rollbackFailures = @()
    }
}
