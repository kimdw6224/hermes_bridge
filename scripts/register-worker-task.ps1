[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9_.@-]+(\\[A-Za-z0-9_.@-]+)?$')]
    [string]$UserId,

    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[^\r\n]+$')]
    [string]$ExecutablePath = 'python.exe',

    [string]$ExistingManifestPath = '',

    [string]$InstallationContextPath = '',

    [string]$InstallationContextSha256 = '',

    [switch]$Apply,

    [ValidateSet('Register', 'Remove')]
    [string]$Operation = 'Register',

    [ValidateSet('Production', 'Simulate')]
    [string]$AdapterMode = 'Production',

    [switch]$Json
)

$ErrorActionPreference = 'Stop'
$runtimeModule = 'hermes_windows_bridge.worker.main'
$installationContextPathProvided = $PSBoundParameters.ContainsKey('InstallationContextPath')
$installationContextHashProvided = $PSBoundParameters.ContainsKey('InstallationContextSha256')
$installationContext = $null
$installationContextBinding = $null

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

if ($AdapterMode -eq 'Simulate' -and (-not $Apply -or $WhatIfPreference)) {
    throw 'AdapterMode Simulate requires -Apply and cannot be combined with -WhatIf.'
}

function Resolve-RuntimeExecutable {
    param([Parameter(Mandatory)][string]$Path)
    if ([IO.Path]::GetFileName($Path) -ine 'python.exe') { throw 'ExecutablePath must identify python.exe.' }
    if ([IO.Path]::IsPathRooted($Path)) {
        if ($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path -match '^(\\\\|//|\\\\[?.]\\)') { throw 'ExecutablePath must be a rooted local file path.' }
        $candidate = $Path
    } else {
        if ($Path -notmatch '^[A-Za-z0-9_.-]+\.exe$') { throw 'ExecutablePath must be an executable name or rooted local path.' }
        $candidate = @(Get-Command -Name $Path -CommandType Application -All -ErrorAction Stop)[0].Source
    }
    $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'ExecutablePath must name a regular local file.' }
    return $item.FullName
}

function Resolve-WindowlessRuntimeExecutable {
    param([Parameter(Mandatory)][string]$ConsolePythonPath)
    $candidate = [IO.Path]::Combine((Split-Path -Parent $ConsolePythonPath), 'pythonw.exe')
    $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Windowless runtime must name a regular local file.' }
    return $item.FullName
}

function Resolve-WorkerInstallationContext {
    if (-not $installationContextPathProvided) { return $null }
    $requestedContextPath = $InstallationContextPath
    $requestedContextSha256 = $InstallationContextSha256
    return Get-BridgeInstallationContext -Path $requestedContextPath -Sha256 $requestedContextSha256
}

function Get-WorkerRuntimeArgv {
    param([Parameter(Mandatory)][string]$PythonwPath)
    $argv = @($PythonwPath, '-m', $runtimeModule)
    if ($null -ne $installationContextBinding) {
        $bindingPath = [string]$installationContextBinding.path
        $bindingSha256 = [string]$installationContextBinding.sha256
        if ([string]::IsNullOrWhiteSpace($bindingPath) -or $bindingSha256 -cnotmatch '^[a-f0-9]{64}$') {
            throw [Security.SecurityException]::new('BridgeContextWorkerBindingUnverified')
        }
        $argv += @('--runtime-binding', $bindingPath, '--runtime-binding-sha256', $bindingSha256)
    }
    return $argv
}

function ConvertTo-WorkerTaskArgumentText {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $encoded = foreach ($argument in $Arguments) {
        if ($argument.Length -gt 0 -and $argument -notmatch '[\s"]') {
            $argument
            continue
        }
        $builder = [Text.StringBuilder]::new()
        [void]$builder.Append('"')
        $backslashes = 0
        foreach ($character in $argument.ToCharArray()) {
            if ($character -eq [char]'\') {
                $backslashes++
            } elseif ($character -eq [char]'"') {
                [void]$builder.Append('\', ($backslashes * 2) + 1)
                [void]$builder.Append('"')
                $backslashes = 0
            } else {
                if ($backslashes -gt 0) { [void]$builder.Append('\', $backslashes) }
                [void]$builder.Append($character)
                $backslashes = 0
            }
        }
        if ($backslashes -gt 0) { [void]$builder.Append('\', $backslashes * 2) }
        [void]$builder.Append('"')
        $builder.ToString()
    }
    return $encoded -join ' '
}

function Test-RuntimeModuleImport {
    param([Parameter(Mandatory)][string]$PythonPath)
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $PythonPath
    $startInfo.Arguments = '-c "import importlib,sys; importlib.import_module(''hermes_windows_bridge.worker.main''); print(sys.executable)"'
    $startInfo.UseShellExecute = $false; $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true; $startInfo.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new(); $process.StartInfo = $startInfo
    try {
        if (-not $process.Start() -or -not $process.WaitForExit(10000)) { if (-not $process.HasExited) { $process.Kill() }; return $false }
        $reportedExecutable = $process.StandardOutput.ReadToEnd().Trim(); $null = $process.StandardError.ReadToEnd()
        return $process.ExitCode -eq 0 -and $reportedExecutable.Equals($PythonPath, [StringComparison]::OrdinalIgnoreCase)
    } finally { $process.Dispose() }
}

function Test-SameWorkerAccount {
    param(
        [AllowEmptyString()][string]$ExpectedAccount,
        [AllowEmptyString()][string]$ActualAccount
    )
    if ([string]::IsNullOrWhiteSpace($ExpectedAccount) -or [string]::IsNullOrWhiteSpace($ActualAccount)) {
        return $false
    }
    try {
        $sidType = [Security.Principal.SecurityIdentifier]
        $expectedSid = ([Security.Principal.NTAccount]::new($ExpectedAccount)).Translate($sidType).Value
        $actualSid = ([Security.Principal.NTAccount]::new($ActualAccount)).Translate($sidType).Value
        return $expectedSid -ceq $actualSid
    }
    catch {
        return $false
    }
}

function Resolve-WorkerAccountSid {
    param([Parameter(Mandatory)][string]$Account)
    try {
        return ([Security.Principal.NTAccount]::new($Account)).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        throw [Security.SecurityException]::new('BridgeContextWorkerIdentityUnverified')
    }
}

function Get-WorkerTaskStopState {
    param([Parameter(Mandatory)][string]$TaskName)
    $service = $null; $folder = $null; $task = $null; $instances = $null
    try {
        $service = New-Object -ComObject 'Schedule.Service'
        $service.Connect()
        $folder = $service.GetFolder('\')
        $task = $folder.GetTask($TaskName)
        $instances = $task.GetInstances(0)
        return [pscustomobject]@{
            runningInstanceCount = [int]$instances.Count
            state = [int]$task.State
        }
    } finally {
        foreach ($comObject in @($instances, $task, $folder, $service)) {
            if ($null -ne $comObject -and [Runtime.InteropServices.Marshal]::IsComObject($comObject)) {
                [Runtime.InteropServices.Marshal]::FinalReleaseComObject($comObject) | Out-Null
            }
        }
    }
}

function Remove-WorkerTaskAndVerifyAbsent {
    param([string]$TaskName = 'HermesWindowsBridgeWorker')
    $result = [ordered]@{ removed = $false; failureReason = $null }
    try {
        # 등록을 먼저 지우면 기존 Worker 인스턴스의 소유 경계가 사라집니다.
        Stop-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction Stop | Out-Null
    } catch {
        $result.failureReason = 'task-stop-failed'
        return [pscustomobject]$result
    }
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $stopped = $false
    do {
        try { $stopState = Get-WorkerTaskStopState -TaskName $TaskName }
        catch {
            $result.failureReason = 'task-instance-unverified'
            return [pscustomobject]$result
        }
        if ($stopState.runningInstanceCount -eq 0 -and $stopState.state -in @(1, 3)) {
            $stopped = $true
            break
        }
        Start-Sleep -Milliseconds 100
    } while ($stopwatch.Elapsed -lt [TimeSpan]::FromSeconds(30))
    if (-not $stopped) {
        $result.failureReason = 'task-stop-unverified'
        return [pscustomobject]$result
    }
    try {
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath '\' -Confirm:$false -ErrorAction Stop
    } catch {
        $result.failureReason = 'task-remove-failed'
        return [pscustomobject]$result
    }
    $result.removed = $null -eq (Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction SilentlyContinue)
    if (-not $result.removed) { $result.failureReason = 'post-remove-verification-failed' }
    return [pscustomobject]$result
}

function Get-WorkerTaskDefinitionState {
    param(
        [string]$PythonPath,
        [string]$ExpectedUserId = $UserId,
        [string]$LegacyPythonPath = '',
        [string]$TaskName = 'HermesWindowsBridgeWorker',
        [string[]]$ExpectedArguments = @()
    )
    $task = Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction SilentlyContinue
    if ($null -eq $task) { return 'absent' }
    $actions = @($task.Actions); $triggers = @($task.Triggers)
    if ($ExpectedArguments.Count -eq 0) { $ExpectedArguments = @('-m', $runtimeModule) }
    $expectedArgumentsText = ConvertTo-WorkerTaskArgumentText -Arguments $ExpectedArguments
    $logonType = [string]$task.Principal.LogonType
    $restartInterval = [string]$task.Settings.RestartInterval
    $triggerAccountMatches = $triggers.Count -eq 1 -and (Test-SameWorkerAccount -ExpectedAccount $ExpectedUserId -ActualAccount ([string]$triggers[0].UserId))
    $principalAccountMatches = Test-SameWorkerAccount -ExpectedAccount $ExpectedUserId -ActualAccount ([string]$task.Principal.UserId)
    $executableMatches = $actions.Count -eq 1 -and (
        $actions[0].Execute -ieq $PythonPath -or
        ($LegacyPythonPath -and $actions[0].Execute -ieq $LegacyPythonPath)
    )
    if ($actions.Count -eq 1 -and $executableMatches -and $actions[0].Arguments -ceq $expectedArgumentsText -and
        $triggerAccountMatches -and $triggers[0].CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' -and $principalAccountMatches -and
        $logonType -in @('Interactive', 'InteractiveToken') -and [string]$task.Principal.RunLevel -eq 'Limited' -and
        $task.Settings.Hidden -and $task.Settings.RestartCount -eq 3 -and $restartInterval -in @('PT1M', '00:01:00')) { return 'desired' }
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
        'schemaVersion', 'kind', 'name', 'account', 'trigger', 'logonType', 'runLevel',
        'restartOnFailure', 'hidden', 'argv', 'typedApis'
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

$installationContext = Resolve-WorkerInstallationContext
if ($null -ne $installationContext) {
    if ($AdapterMode -eq 'Simulate') {
        throw [ArgumentException]::new('BridgeContextSimulationForbidden')
    }
    $installationContextBinding = Get-BridgeInstallationContextBinding -Context $installationContext -Profile 'worker'
    if ([string]$installationContextBinding.path -cne (Join-Path $installationContext.bindingsDirectory 'worker.json') -or
        [string]$installationContextBinding.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$installationContextBinding.profile -cne 'worker' -or
        [string]$installationContextBinding.contextNonce -cne [string]$installationContext.nonce -or
        [string]$installationContextBinding.workerSid -cne (Resolve-WorkerAccountSid -Account $UserId)) {
        throw [Security.SecurityException]::new('BridgeContextWorkerBindingUnverified')
    }
}

$manifest = [ordered]@{
    schemaVersion = 1
    kind = 'scheduled-task-registration-plan'
    mode = 'dry-run'
    installed = $false
    applied = $false
    state = 'planned'
    atomic = $true
    applyRequiresAdministrator = $true
    name = if ($null -ne $installationContext) { [string]$installationContext.workerTaskName } else { 'HermesWindowsBridgeWorker' }
    account = $UserId
    trigger = 'AtLogOn'
    logonType = 'InteractiveToken'
    runLevel = 'Limited'
    restartOnFailure = $true
    hidden = $true
    operation = $Operation
    argv = Get-WorkerRuntimeArgv -PythonwPath $(if ([IO.Path]::IsPathRooted($ExecutablePath)) { [IO.Path]::Combine((Split-Path -Parent $ExecutablePath), 'pythonw.exe') } else { 'pythonw.exe' })
    typedApis = @(
        'New-ScheduledTaskAction',
        'New-ScheduledTaskTrigger',
        'New-ScheduledTaskPrincipal',
        'Register-ScheduledTask'
    )
    recovery = [ordered]@{
        atomic = $true
        resumeSafe = $true
        definitionComparison = 'exact-security-definition'
        mutation = 'fixed-scheduledtasks-api'
        restartCount = 3
        restartInterval = 'PT1M'
    }
    receipt = [ordered]@{ operation = $Operation; target = if ($null -ne $installationContext) { [string]$installationContext.workerTaskName } else { 'HermesWindowsBridgeWorker' }; changed = $false; before = 'not-read'; after = 'not-read' }
    readBack = [ordered]@{ performed = $false; state = 'not-read'; exact = $false }
    rollback = [ordered]@{ supported = $true; inverseOperation = if ($Operation -eq 'Register') { 'Remove' } else { 'Register' }; attempted = $false; succeeded = $null }
}

if ($WhatIfPreference) {
    $manifest.mode = 'what-if'
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

if ($Apply -and -not $WhatIfPreference) {
    $manifest.mode = 'apply'
    $manifest.dispatch = [ordered]@{ adapterMode = $AdapterMode; operation = $Operation; typedApis = $manifest.typedApis; argv = $manifest.argv; externalCalls = 0 }
    if ($AdapterMode -eq 'Simulate') {
        if ([IO.Path]::GetFileName($ExecutablePath) -ine 'python.exe') { $manifest.state='conflict'; $manifest.failureReason='runtime-entrypoint-unverified'; $manifest | ConvertTo-Json -Depth 8; exit 3 }
        $manifest.state = 'simulated'
        $manifest | ConvertTo-Json -Depth 8
        exit 0
    }
    if (-not (Test-Administrator)) {
        $manifest.state = 'conflict'
        $manifest.failureReason = 'administrator-required'
        $manifest | ConvertTo-Json -Depth 8
        exit 3
    }

    $task = Get-ScheduledTask -TaskName $manifest.name -TaskPath '\' -ErrorAction SilentlyContinue
    if ($Operation -eq 'Remove') {
        try { $resolvedExecutable = Resolve-RuntimeExecutable -Path $ExecutablePath }
        catch { $manifest.state='conflict'; $manifest.failureReason='runtime-entrypoint-unverified'; $manifest | ConvertTo-Json -Depth 8; exit 3 }
        try { $windowlessExecutable = Resolve-WindowlessRuntimeExecutable -ConsolePythonPath $resolvedExecutable }
        catch { $manifest.state='conflict'; $manifest.failureReason='runtime-entrypoint-unverified'; $manifest | ConvertTo-Json -Depth 8; exit 3 }
        $manifest.argv = Get-WorkerRuntimeArgv -PythonwPath $windowlessExecutable
        $existingState = Get-WorkerTaskDefinitionState -PythonPath $windowlessExecutable -ExpectedUserId $UserId -LegacyPythonPath $resolvedExecutable -TaskName $manifest.name -ExpectedArguments $manifest.argv[1..($manifest.argv.Count - 1)]
        $manifest.receipt.before = $existingState
        if ($existingState -eq 'absent') { $manifest.state='unchanged'; $manifest.receipt.after='absent'; $manifest.readBack.performed=$true; $manifest.readBack.state='absent'; $manifest.readBack.exact=$true }
        elseif ($existingState -eq 'conflict') { $manifest.state='conflict'; $manifest.failureReason='installed-definition-mismatch'; $manifest.receipt.after='conflict'; $manifest | ConvertTo-Json -Depth 8; exit 2 }
        else {
            $removal = Remove-WorkerTaskAndVerifyAbsent -TaskName $manifest.name
            $removed = [bool]$removal.removed
            $manifest.readBack.performed=$true; $manifest.readBack.state=if($removed){'absent'}else{'present'}; $manifest.readBack.exact=$removed
            if (-not $removed) { $manifest.state='conflict'; $manifest.failureReason=if($null -eq $removal.failureReason){'post-remove-verification-failed'}else{$removal.failureReason}; $manifest.receipt.after='present'; $manifest | ConvertTo-Json -Depth 8; exit 3 }
            $manifest.state='removed'; $manifest.applied=$true; $manifest.receipt.changed=$true; $manifest.receipt.after='absent'
        }
    } else {
        try { $resolvedExecutable = Resolve-RuntimeExecutable -Path $ExecutablePath }
        catch { $manifest.state='conflict'; $manifest.failureReason='runtime-entrypoint-unverified'; $manifest | ConvertTo-Json -Depth 8; exit 3 }
        if (-not (Test-RuntimeModuleImport -PythonPath $resolvedExecutable)) { $manifest.state='conflict'; $manifest.failureReason='runtime-entrypoint-unverified'; $manifest | ConvertTo-Json -Depth 8; exit 3 }
        try { $windowlessExecutable = Resolve-WindowlessRuntimeExecutable -ConsolePythonPath $resolvedExecutable }
        catch { $manifest.state='conflict'; $manifest.failureReason='runtime-entrypoint-unverified'; $manifest | ConvertTo-Json -Depth 8; exit 3 }
        $manifest.argv = Get-WorkerRuntimeArgv -PythonwPath $windowlessExecutable
        $state = Get-WorkerTaskDefinitionState -PythonPath $windowlessExecutable -ExpectedUserId $UserId -TaskName $manifest.name -ExpectedArguments $manifest.argv[1..($manifest.argv.Count - 1)]
        $manifest.receipt.before = $state
        if ($state -eq 'conflict') { $manifest.state='conflict'; $manifest.failureReason='installed-definition-mismatch'; $manifest | ConvertTo-Json -Depth 8; exit 2 }
        if ($state -eq 'absent') {
            $action = New-ScheduledTaskAction -Execute $windowlessExecutable -Argument (ConvertTo-WorkerTaskArgumentText -Arguments $manifest.argv[1..($manifest.argv.Count - 1)])
            $trigger = New-ScheduledTaskTrigger -AtLogOn -User $UserId
            $principal = New-ScheduledTaskPrincipal -UserId $UserId -LogonType Interactive -RunLevel Limited
            $settings = New-ScheduledTaskSettingsSet -Hidden -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
            $null = Register-ScheduledTask -TaskName $manifest.name -TaskPath '\' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Hermes Windows Bridge interactive worker' -ErrorAction Stop
            $manifest.applied = $true
        }
        $verificationFailed = $false
        try { $verifiedState = Get-WorkerTaskDefinitionState -PythonPath $windowlessExecutable -ExpectedUserId $UserId -TaskName $manifest.name -ExpectedArguments $manifest.argv[1..($manifest.argv.Count - 1)] }
        catch { $verificationFailed = $true; $verifiedState = 'unverified' }
        $manifest.readBack.performed=$true; $manifest.readBack.state=$verifiedState; $manifest.readBack.exact=$verifiedState -eq 'desired'; $manifest.receipt.after=$verifiedState; $manifest.receipt.changed=$manifest.applied
        if ($verifiedState -ne 'desired') {
            $manifest.state='conflict'
            $manifest.failureReason = if ($verificationFailed) { 'post-apply-verification-unavailable' } else { 'post-apply-verification-failed' }
            if ($manifest.applied) {
                $manifest.rollback.attempted = $true
                try {
                    $rollbackRemoval = Remove-WorkerTaskAndVerifyAbsent -TaskName $manifest.name
                    $removed = [bool]$rollbackRemoval.removed
                    $manifest.rollback.succeeded = $removed
                    $manifest.readBack.state = if ($removed) { 'absent' } else { 'present' }
                    $manifest.readBack.exact = $removed
                    $manifest.receipt.after = if ($removed) { 'absent' } else { 'present' }
                    $manifest.receipt.changed = -not $removed
                    if (-not $removed) { $manifest.failureReason = 'post-apply-verification-failed-rollback-failed' }
                }
                catch {
                    $manifest.rollback.succeeded = $false
                    $manifest.readBack.state = 'unverified'
                    $manifest.readBack.exact = $false
                    $manifest.receipt.after = 'unverified'
                    $manifest.failureReason = 'post-apply-verification-failed-rollback-failed'
                }
            }
            $manifest.applied=$false
            $manifest | ConvertTo-Json -Depth 8
            exit 3
        }
        $manifest.installed = $true; $manifest.state = if ($manifest.applied) { 'applied' } else { 'unchanged' }
    }
}

$manifest | ConvertTo-Json -Depth 8
