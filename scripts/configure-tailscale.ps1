[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$ServeHost,
    [ValidatePattern('^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?/[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*$')]
    [string]$Capability = 'hermes.local/windows-control',
    [ValidateRange(1, 65535)]
    [int]$Port = 8765,
    [ValidatePattern('^(?:tag:|group:|user:|autogroup:)?[A-Za-z0-9@._-]+$')]
    [string]$HermesSource = 'tag:hermes',
    [ValidatePattern('^(?:tag:|group:|user:|autogroup:)?[A-Za-z0-9@._-]+$')]
    [string]$WindowsDestination = 'tag:windows-bridge',
    [switch]$Apply,
    [ValidateSet('Production', 'Simulate')]
    [string]$AdapterMode = 'Production',
    [ValidateSet('Desired', 'EmptyApply', 'ApplyReadbackMismatch', 'ConcurrentConflict')]
    [string]$SimulationScenario = 'EmptyApply',
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
$externalCommandTimeoutSeconds = 5
$script:externalCalls = 0
$script:simulationStatusReads = 0
$script:adapterCalls = [Collections.Generic.List[object]]::new()
$serveHostPattern = '^(?=.{3,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$'

if ($ServeHost -notmatch $serveHostPattern) {
    $validationFailure = [ordered]@{
        schemaVersion = 1
        kind = 'hermes-windows-bridge-tailscale-validation-error'
        error = [ordered]@{
            code = 'invalid-serve-host'
            field = 'ServeHost'
        }
        externalCalls = $script:externalCalls
        adapterCalls = @()
    }
    if ($Json) {
        $validationFailure | ConvertTo-Json -Depth 4 -Compress
    } else {
        [Console]::Error.WriteLine('invalid-serve-host: ServeHost must be a valid fully-qualified hostname.')
    }
    exit 2
}

if ($AdapterMode -eq 'Simulate' -and (-not $Apply -or $WhatIfPreference)) {
    throw 'AdapterMode Simulate requires -Apply and cannot be combined with -WhatIf.'
}

function New-SimulatedServeJson {
    param([ValidateSet('empty', 'desired', 'bridge-only-mismatch', 'concurrent-conflict')][string]$State)
    if ($State -eq 'empty') { return '{}' }
    $handler = [ordered]@{ Proxy = "http://127.0.0.1:$Port"; AcceptAppCaps = @($Capability) }
    if ($State -eq 'bridge-only-mismatch') { $handler.AcceptAppCaps = @('hermes.local/wrong-capability') }
    $handlers = [ordered]@{ '/' = $handler }
    if ($State -eq 'concurrent-conflict') {
        $handlers['/other'] = [ordered]@{ Proxy = 'http://127.0.0.1:9999' }
    }
    return ([ordered]@{
        TCP = [ordered]@{ '443' = [ordered]@{ HTTPS = $true } }
        Web = [ordered]@{ "$($ServeHost.ToLowerInvariant()):443" = [ordered]@{ Handlers = $handlers } }
    } | ConvertTo-Json -Depth 8 -Compress)
}

function Invoke-SimulatedTailscaleQuery {
    param([Parameter(Mandatory)][string[]]$ArgumentList)
    $script:adapterCalls.Add([ordered]@{ argv = @($ArgumentList); simulated = $true })
    $key = $ArgumentList -join [char]0
    if ($key -eq 'version') { return [ordered]@{ completed = $true; exitCode = 0; output = '1.92.0' } }
    if ($key -eq (@('serve', '--help') -join [char]0)) { return [ordered]@{ completed = $true; exitCode = 0; output = '--bg --accept-app-caps=<capabilities>' } }
    if ($key -eq (@('serve', 'status', '--json') -join [char]0)) {
        $script:simulationStatusReads++
        $state = switch ($SimulationScenario) {
            'Desired' { 'desired' }
            'EmptyApply' { if ($script:simulationStatusReads -le 2) { 'empty' } else { 'desired' } }
            'ApplyReadbackMismatch' { if ($script:simulationStatusReads -le 2) { 'empty' } else { 'bridge-only-mismatch' } }
            'ConcurrentConflict' { if ($script:simulationStatusReads -le 2) { 'empty' } else { 'concurrent-conflict' } }
        }
        return [ordered]@{ completed = $true; exitCode = 0; output = (New-SimulatedServeJson -State $state) }
    }
    $desired = @('serve', '--bg', "--accept-app-caps=$Capability", [string]$Port)
    if (($ArgumentList | ConvertTo-Json -Compress) -ceq ($desired | ConvertTo-Json -Compress)) {
        return [ordered]@{ completed = $true; exitCode = 0; output = 'simulated bridge-only apply' }
    }
    if ($key -eq (@('serve', 'reset') -join [char]0)) {
        return [ordered]@{ completed = $true; exitCode = 0; output = 'simulated bridge-only reset' }
    }
    throw 'Simulation accepts only fixed Tailscale version, help, status, bridge Apply, and reset argv.'
}

function Invoke-BoundedTailscaleQuery {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList
    )
    if ($AdapterMode -eq 'Simulate') {
        return Invoke-SimulatedTailscaleQuery -ArgumentList $ArgumentList
    }
    $script:externalCalls++
    $script:adapterCalls.Add([ordered]@{ argv = @($ArgumentList); simulated = $false })
    # PowerShell 7에서는 셸 파싱 없이 argv를 ProcessStartInfo로 직접 전달합니다.
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    if ($null -ne $startInfo.ArgumentList) {
        $startInfo.FileName = $FilePath
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        foreach ($argument in $ArgumentList) {
            $null = $startInfo.ArgumentList.Add($argument)
        }
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        try {
            $null = $process.Start()
            $standardOutput = $process.StandardOutput.ReadToEndAsync()
            $standardError = $process.StandardError.ReadToEndAsync()
            $completed = $process.WaitForExit($externalCommandTimeoutSeconds * 1000)
            if (-not $completed) {
                $process.Kill()
                return [ordered]@{ completed = $false; exitCode = $null; output = '' }
            }
            [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($standardOutput, $standardError))
            return [ordered]@{
                completed = $true
                exitCode = $process.ExitCode
                output = $standardOutput.Result
            }
        } finally {
            $process.Dispose()
        }
    }

    # Windows PowerShell 5.1에는 ArgumentList가 없으므로, 검증된 argv를 데이터로
    # 전달하는 bounded job으로 네이티브 호출을 제한합니다.
    $argumentsJson = ConvertTo-Json -InputObject @($ArgumentList) -Compress
    $savedWhatIfPreference = $WhatIfPreference
    $savedGlobalWhatIfPreference = $global:WhatIfPreference
    $WhatIfPreference = $false
    $global:WhatIfPreference = $false
    $job = Start-Job -ScriptBlock {
        param([string]$Executable, [string]$ArgumentsJson)

        [string[]]$Arguments = ConvertFrom-Json -InputObject $ArgumentsJson -ErrorAction Stop
        switch ($Arguments.Count) {
            1 { $output = @(& $Executable $Arguments[0] 2>&1) }
            2 { $output = @(& $Executable $Arguments[0] $Arguments[1] 2>&1) }
            3 { $output = @(& $Executable $Arguments[0] $Arguments[1] $Arguments[2] 2>&1) }
            4 { $output = @(& $Executable $Arguments[0] $Arguments[1] $Arguments[2] $Arguments[3] 2>&1) }
            default { throw 'Unexpected Tailscale argument count.' }
        }
        [pscustomobject]@{
            marker = 'hermes-windows-bridge-tailscale-result'
            exitCode = $LASTEXITCODE
            output = (($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine)
        }
    } -ArgumentList $FilePath, $argumentsJson
    try {
        $completedJob = Wait-Job -Job $job -Timeout $externalCommandTimeoutSeconds
        if ($null -eq $completedJob) {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            return [ordered]@{ completed = $false; exitCode = $null; output = '' }
        }

        $records = @(
            Receive-Job -Job $job -ErrorAction SilentlyContinue |
                Where-Object { $_.marker -eq 'hermes-windows-bridge-tailscale-result' }
        )
        if ($records.Count -ne 1 -or $null -eq $records[0].exitCode) {
            return [ordered]@{ completed = $false; exitCode = $null; output = '' }
        }

        return [ordered]@{
            completed = $true
            exitCode = [int]$records[0].exitCode
            output = [string]$records[0].output
        }
    } finally {
        if ($job.State -eq 'Running') {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
        }
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        $WhatIfPreference = $savedWhatIfPreference
        $global:WhatIfPreference = $savedGlobalWhatIfPreference
    }
}

function Get-ServeStatus {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string]$CapabilityName,
        [Parameter(Mandatory)][int]$TargetPort,
        [Parameter(Mandatory)][string]$ServeHostName
    )

    $query = @('serve', 'status', '--json')
    $result = Invoke-BoundedTailscaleQuery -FilePath $FilePath -ArgumentList $query
    $status = [ordered]@{
        query = $query
        readable = $result.completed -and ($result.exitCode -eq 0)
        exitCode = $result.exitCode
        state = 'unreadable'
        matchesDesired = $false
        bridgeOnly = $false
    }
    if (-not $status.readable) {
        return $status
    }

    try {
        $configuration = $result.output | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return $status
    }

    $topLevel = @($configuration.PSObject.Properties)
    if ($topLevel.Count -eq 0) {
        $status.state = 'empty'
        return $status
    }

    # desired 구성은 443의 background HTTPS root handler 하나만 허용합니다.
    # 그 밖의 handler, service, foreground, public 설정은 모두 conflict입니다.
    $topLevelNames = @($topLevel.Name | Sort-Object)
    if (($topLevelNames -join ',') -ne 'TCP,Web') {
        $status.state = 'conflict'
        return $status
    }
    $tcpPorts = @($configuration.TCP.PSObject.Properties)
    $webHosts = @($configuration.Web.PSObject.Properties)
    if ($tcpPorts.Count -ne 1 -or $webHosts.Count -ne 1 -or
        $tcpPorts[0].Name -ne '443' -or
        @($tcpPorts[0].Value.PSObject.Properties).Count -ne 1 -or
        $tcpPorts[0].Value.HTTPS -ne $true) {
        $status.state = 'conflict'
        return $status
    }
    if ($webHosts[0].Name -ne "$($ServeHostName.ToLowerInvariant()):443") {
        $status.state = 'conflict'
        return $status
    }
    $webProperties = @($webHosts[0].Value.PSObject.Properties)
    if ($webProperties.Count -ne 1 -or $webProperties[0].Name -ne 'Handlers') {
        $status.state = 'conflict'
        return $status
    }
    $handlers = @($webProperties[0].Value.PSObject.Properties)
    if ($handlers.Count -ne 1 -or $handlers[0].Name -ne '/') {
        $status.state = 'conflict'
        return $status
    }
    $handler = $handlers[0].Value
    $handlerNames = @($handler.PSObject.Properties.Name | Sort-Object)
    $expectedProxy = "http://127.0.0.1:$TargetPort"
    $expectedNames = 'AcceptAppCaps,Proxy'
    $status.bridgeOnly = $handler.Proxy -eq $expectedProxy -and
        ($handlerNames -join ',') -in @('Proxy', $expectedNames)
    if (($handlerNames -join ',') -ne $expectedNames -or
        $handler.Proxy -ne $expectedProxy -or
        @($handler.AcceptAppCaps).Count -ne 1 -or
        $handler.AcceptAppCaps[0] -ne $CapabilityName) {
        $status.state = 'conflict'
        return $status
    }

    $status.state = 'desired'
    $status.matchesDesired = $true
    return $status
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$tailscale = if ($AdapterMode -eq 'Simulate') {
    [pscustomobject]@{ Source = 'tailscale.exe' }
} else {
    Get-Command -Name 'tailscale.exe' -CommandType Application -ErrorAction SilentlyContinue
}
$serveQuery = @('serve', 'status', '--json')
$serveStatus = [ordered]@{
    query = $serveQuery
    available = ($null -ne $tailscale)
    readable = $false
    exitCode = $null
    state = 'unavailable'
    matchesDesired = $false
    bridgeOnly = $false
    version = $null
    appCapabilitiesSupported = $false
}

if ($null -ne $tailscale) {
    $versionResult = Invoke-BoundedTailscaleQuery -FilePath $tailscale.Source -ArgumentList @('version')
    $serveHelpResult = Invoke-BoundedTailscaleQuery -FilePath $tailscale.Source -ArgumentList @('serve', '--help')
    $versionOutput = $versionResult.output
    if ($versionOutput -match '(?m)^(\d+\.\d+\.\d+)') {
        $serveStatus.version = $Matches[1]
    }
    $serveStatus.appCapabilitiesSupported = $serveHelpResult.completed -and
        $serveHelpResult.exitCode -eq 0 -and $serveHelpResult.output -match '(?m)--accept-app-caps(?:[=\s]|$)'
    $queriedServeStatus = Get-ServeStatus -FilePath $tailscale.Source -CapabilityName $Capability -TargetPort $Port -ServeHostName $ServeHost
    $serveStatus.exitCode = $queriedServeStatus.exitCode
    $serveStatus.readable = $queriedServeStatus.readable
    $serveStatus.state = $queriedServeStatus.state
    $serveStatus.matchesDesired = $queriedServeStatus.matchesDesired
    $serveStatus.bridgeOnly = $queriedServeStatus.bridgeOnly
}

$desiredServeArgv = @(
    'serve',
    '--bg',
    "--accept-app-caps=$Capability",
    [string]$Port
)
$grant = [ordered]@{
    grants = @(
        [ordered]@{
            src = @($HermesSource)
            dst = @($WindowsDestination)
            ip = @('tcp:443')
        },
        [ordered]@{
            src = @($HermesSource)
            dst = @($WindowsDestination)
            app = [ordered]@{
                $Capability = @([ordered]@{ src = @('main', 'self') })
            }
        }
    )
}
$grantFragment = $grant | ConvertTo-Json -Depth 8 -Compress
$hermesConfigSnippet = @"
mcp_servers:
  windows_pc:
    url: "https://$ServeHost/mcp"
    headers:
      Authorization: "Bearer `${HERMES_WINDOWS_BRIDGE_TOKEN}"
    timeout: 120
    connect_timeout: 20
    supports_parallel_tool_calls: false
    trust: untrusted
    elicitation:
      enabled: true
      timeout: 300
    tools:
      resources: false
      prompts: false
"@
$ociEnvironmentInstruction = @"
On Oracle Cloud (SSH alias: server), set the Hermes process environment without writing the token to config.yaml:
export HERMES_WINDOWS_BRIDGE_TOKEN='<BRIDGE_TOKEN_FROM_APPROVED_INSTALL_OR_ROTATION>'
Restart or reload Hermes using the operator-approved service command, then run /reload-mcp.
This script does not SSH to Oracle Cloud and does not modify OCI or Hermes configuration.
"@.Trim()

$plan = [ordered]@{
    schemaVersion = 1
    kind = 'hermes-windows-bridge-tailscale-plan'
    readOnly = (-not $Apply -or $WhatIfPreference -or $AdapterMode -eq 'Simulate')
    applied = $false
    idempotent = $serveStatus.matchesDesired
    mode = if ($WhatIfPreference) { 'what-if' } elseif ($Apply) { 'apply' } else { 'read-only' }
    state = $serveStatus.state
    maxExternalCommandSeconds = $externalCommandTimeoutSeconds
    funnelEnabled = $false
    serveHost = $ServeHost.ToLowerInvariant()
    desiredServeArgv = $desiredServeArgv
    unattendedArgv = @('up', '--unattended=true')
    serveStatus = $serveStatus
    recommendedGrantFragment = $grantFragment
    hermesConfigSnippet = $hermesConfigSnippet.Trim()
    ociEnvironmentInstruction = $ociEnvironmentInstruction
    nextStep = 'Manually merge the grant and Hermes snippets; actual Serve configuration requires an elevated -Apply invocation.'
    adapterMode = $AdapterMode
    simulationScenario = if ($AdapterMode -eq 'Simulate') { $SimulationScenario } else { $null }
    externalCalls = 0
    transaction = [ordered]@{ initialState = $serveStatus.state; preApplyState = 'not-read'; applyAttempted = $false; wouldApply = $false }
    readBack = [ordered]@{ performed = $false; state = 'not-read'; exact = $false; bridgeOnly = $false }
    rollback = [ordered]@{ supported = $true; inspected = $false; eligible = $false; attempted = $false; succeeded = $null; state = 'not-needed' }
    bridgeOnly = $serveStatus.bridgeOnly
    manualAction = $false
    manualActionRequired = $false
    adapterCalls = @()
}

if ($Apply -and -not $WhatIfPreference) {
    if ($AdapterMode -eq 'Production' -and -not (Test-Administrator)) {
        $plan.state = 'administrator-required'
        $plan.idempotent = $false
        if ($Json) { $plan | ConvertTo-Json -Depth 8 }
        [Console]::Error.WriteLine('Administrator privileges are required for Tailscale Serve configuration; made no changes.')
        exit 2
    }
    if (-not $serveStatus.appCapabilitiesSupported) {
        $plan.state = 'app-capabilities-unsupported'
        $plan.idempotent = $false
        if ($Json) { $plan | ConvertTo-Json -Depth 8 }
        [Console]::Error.WriteLine('Installed Tailscale does not support the requested App Capability forwarding.')
        exit 2
    }

    # elevated 호출이 Serve를 변경해도 되는지 결정하기 직전에 다시 읽습니다.
    $freshServeStatus = Get-ServeStatus -FilePath $tailscale.Source -CapabilityName $Capability -TargetPort $Port -ServeHostName $ServeHost
    $plan.serveStatus.exitCode = $freshServeStatus.exitCode
    $plan.serveStatus.readable = $freshServeStatus.readable
    $plan.serveStatus.state = $freshServeStatus.state
    $plan.serveStatus.matchesDesired = $freshServeStatus.matchesDesired
    $plan.serveStatus.bridgeOnly = $freshServeStatus.bridgeOnly
    $plan.state = $freshServeStatus.state
    $plan.bridgeOnly = $freshServeStatus.bridgeOnly
    $plan.transaction.preApplyState = $freshServeStatus.state
    if (-not $freshServeStatus.readable) {
        $plan.state = 'unreadable'
        $plan.idempotent = $false
        if ($Json) { $plan | ConvertTo-Json -Depth 8 }
        [Console]::Error.WriteLine('Unable to read current Tailscale Serve status; refusing to apply.')
        exit 2
    }
    if ($freshServeStatus.matchesDesired) {
        $plan.state = 'desired'
        $plan.idempotent = $true
        $plan.readBack.performed = $true
        $plan.readBack.state = 'desired'
        $plan.readBack.exact = $true
        $plan.readBack.bridgeOnly = $true
        $plan.externalCalls = $script:externalCalls
        $plan.adapterCalls = @($script:adapterCalls)
        if ($Json) { $plan | ConvertTo-Json -Depth 8 } else { Write-Output 'Desired Tailscale Serve configuration already exists; no changes were made.' }
        exit 0
    }
    if ($freshServeStatus.state -ne 'empty') {
        $plan.state = 'conflict'
        $plan.idempotent = $false
        if ($Json) { $plan | ConvertTo-Json -Depth 8 }
        [Console]::Error.WriteLine('Existing Tailscale Serve configuration conflicts with the requested bridge configuration; refusing to overwrite it.')
        exit 2
    }

    $plan.transaction.applyAttempted = $true
    $plan.transaction.wouldApply = $true
    $applyResult = Invoke-BoundedTailscaleQuery -FilePath $tailscale.Source -ArgumentList $desiredServeArgv
    if (-not $applyResult.completed -or $applyResult.exitCode -ne 0) {
        $plan.state = 'apply-failed'
        $plan.idempotent = $false
        if ($Json) { $plan | ConvertTo-Json -Depth 8 }
        [Console]::Error.WriteLine('Tailscale Serve command did not complete successfully; configuration result is unknown.')
        exit 2
    }

    # 종료 코드만으로는 정확한 private handler 저장을 증명할 수 없습니다.
    # daemon 구성을 다시 읽어 오도하는 출력이 성공으로 보고되지 않게 합니다.
    $postApplyServeStatus = Get-ServeStatus -FilePath $tailscale.Source -CapabilityName $Capability -TargetPort $Port -ServeHostName $ServeHost
    $plan.serveStatus.exitCode = $postApplyServeStatus.exitCode
    $plan.serveStatus.readable = $postApplyServeStatus.readable
    $plan.serveStatus.state = $postApplyServeStatus.state
    $plan.serveStatus.matchesDesired = $postApplyServeStatus.matchesDesired
    $plan.serveStatus.bridgeOnly = $postApplyServeStatus.bridgeOnly
    $plan.readBack.performed = $true
    $plan.readBack.state = $postApplyServeStatus.state
    $plan.readBack.exact = $postApplyServeStatus.matchesDesired
    $plan.readBack.bridgeOnly = $postApplyServeStatus.bridgeOnly
    $plan.bridgeOnly = $postApplyServeStatus.bridgeOnly
    if (-not $postApplyServeStatus.readable -or -not $postApplyServeStatus.matchesDesired) {
        $plan.applied = $false
        $plan.idempotent = $false
        $plan.state = 'apply-verification-conflict'
        $plan.rollback.state = if ($SimulationScenario -eq 'ConcurrentConflict') { 'conflict' } else { 'unverified' }
        $plan.manualAction = $true
        $plan.manualActionRequired = $true
        $plan.externalCalls = $script:externalCalls
        $plan.adapterCalls = @($script:adapterCalls)
        if ($Json) { $plan | ConvertTo-Json -Depth 8 }
        [Console]::Error.WriteLine('Tailscale Serve apply read-back was not exact; refusing reset because ownership is unverified. Manual scoped cleanup is required.')
        exit 2
    }
    $plan.applied = $AdapterMode -eq 'Production'
    $plan.state = if ($AdapterMode -eq 'Simulate') { 'simulated' } else { 'applied' }
    $plan.idempotent = $AdapterMode -eq 'Simulate'
}

$plan.externalCalls = $script:externalCalls
$plan.adapterCalls = @($script:adapterCalls)

if ($Json) {
    $plan | ConvertTo-Json -Depth 8
} else {
    Write-Output 'Hermes Windows Bridge Tailscale plan.'
    Write-Output ("Serve status readable: {0}" -f $serveStatus.readable)
    Write-Output ("Desired argv: tailscale {0}" -f ($desiredServeArgv -join ' '))
    Write-Output 'Recommended tailnet grant fragment (merge manually):'
    Write-Output $grantFragment
    Write-Output 'Hermes config snippet (merge under the existing config):'
    Write-Output $hermesConfigSnippet.Trim()
    Write-Output 'OCI Hermes environment instruction:'
    Write-Output $ociEnvironmentInstruction
    if ($plan.applied) {
        Write-Output 'Private Tailscale Serve configuration was applied; no Funnel, unattended-mode, ACL, or Hermes configuration changes were made.'
    } else {
        Write-Output 'No Funnel, Serve, unattended-mode, ACL, or Hermes configuration changes were made.'
    }
}

exit 0
