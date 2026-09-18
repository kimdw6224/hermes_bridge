[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Apply,
    [switch]$Json,
    [ValidateSet('Production', 'Simulate')][string]$AdapterMode = 'Production',
    [ValidateSet('None', 'generate_token', 'backup_token', 'atomic_replace', 'token_acl', 'doctor')]
    [string]$SimulationFailureStep = 'None',
    [string]$ProgramDataRoot = $env:ProgramData
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

if ([string]::IsNullOrWhiteSpace($ProgramDataRoot)) {
    $ProgramDataRoot = [Environment]::GetFolderPath('CommonApplicationData')
}
$ProgramDataRoot = Resolve-BridgeLocalRoot -Path $ProgramDataRoot
$runtimeRoot = [IO.Path]::Combine($ProgramDataRoot, 'HermesWindowsBridge')
$secretsRoot = [IO.Path]::Combine($runtimeRoot, 'secrets')
$tokenPath = [IO.Path]::Combine($secretsRoot, 'token')
[void](Assert-BridgePathUnderRoot -Root $ProgramDataRoot -Path $runtimeRoot)
[void](Assert-BridgePathUnderRoot -Root $ProgramDataRoot -Path $secretsRoot)
[void](Assert-BridgePathUnderRoot -Root $ProgramDataRoot -Path $tokenPath)

$tokenExists = Test-Path -LiteralPath $tokenPath -PathType Leaf
$backupPath = $tokenPath + '.backup'
$backups = if ($tokenExists) { @($backupPath) } else { @() }
$ociEnvironmentInstruction = @"
On Oracle Cloud, set the Hermes process environment without putting the token in config.yaml:
export HERMES_WINDOWS_BRIDGE_TOKEN='<NEW_TOKEN_SHOWN_ONCE_AFTER_APPLY>'
Restart or reload the Hermes service using its operator-approved service command, then run /reload-mcp.
This script does not SSH to Oracle Cloud and does not write any OCI or Hermes configuration.
"@.Trim()
$actions = @(
    [ordered]@{ id = 'generate_token'; planned = $true; state = 'deferred-until-approved-apply' },
    [ordered]@{ id = 'backup_token'; planned = $tokenExists; state = if ($tokenExists) { 'planned' } else { 'unchanged' } },
    [ordered]@{ id = 'atomic_replace'; planned = $tokenExists; state = if ($tokenExists) { 'planned' } else { 'blocked-token-missing' } },
    [ordered]@{ id = 'token_acl'; planned = $tokenExists; state = if ($tokenExists) { 'restrictive' } else { 'unchanged' } },
    [ordered]@{ id = 'doctor'; planned = $tokenExists; state = if ($tokenExists) { 'planned' } else { 'blocked-token-missing' } },
    [ordered]@{ id = 'oci_environment'; planned = $true; state = 'operator-action-required' },
    [ordered]@{ id = 'hermes_reload'; planned = $true; state = 'operator-action-required' }
)
$plan = [ordered]@{
    schemaVersion = 1
    kind = 'hermes-windows-bridge-token-rotation-plan'
    mode = if ($WhatIfPreference) { 'what-if' } elseif ($Apply) { 'apply' } else { 'read-only' }
    applied = $false
    atomic = $true
    resumeSafe = $true
    administratorRequiredForApply = $true
    currentProcessElevated = (Test-BridgeAdministrator)
    actions = $actions
    backups = @($backups)
    tokenState = if ($tokenExists) { 'present' } else { 'missing' }
    tokenOutput = 'placeholder-only-until-approved-apply'
    ociEnvironmentInstruction = $ociEnvironmentInstruction
    remoteMutation = $false
    state = if ($tokenExists) { 'planned' } else { 'blocked' }
    failureReason = if ($tokenExists) { $null } else { 'token-missing' }
    adapterMode = $AdapterMode
    receipts = @()
    rollback = @()
    failedStep = $null
    externalCalls = if ($AdapterMode -eq 'Simulate') { 0 } else { $null }
}

if ($AdapterMode -eq 'Simulate' -and -not $Apply) {
    throw [ArgumentException]::new('BridgeAdapterSimulationRequiresApply: Simulate is valid only with -Apply.')
}
if ($SimulationFailureStep -ne 'None' -and ($AdapterMode -ne 'Simulate' -or -not $Apply)) {
    throw [ArgumentException]::new('BridgeSimulationFailureRequiresSimulation: failure injection is valid only with -Apply -AdapterMode Simulate.')
}

if ($Apply -and -not $WhatIfPreference) {
    if ($AdapterMode -eq 'Simulate') {
        $simulationSteps = @('generate_token', 'backup_token', 'atomic_replace', 'token_acl', 'doctor')
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
                else { Write-Output ("Token rotation simulation failed at fixed step: {0}; no token was read or changed." -f $step) }
                exit 2
            }
            $plan.receipts += [ordered]@{ step = $step; state = 'simulated'; externalCalls = 0 }
        }
        $plan.state = 'simulated'
        $plan.failureReason = $null
        $plan.applied = $false
        if ($Json) { $plan | ConvertTo-Json -Depth 8 }
        else { Write-Output 'Hermes Windows Bridge token rotation simulation completed; no token was read, generated, or changed.' }
        exit 0
    }
    if (-not (Test-BridgeAdministrator)) {
        $plan.state = 'blocked'
        $plan.failureReason = 'administrator-required'
        if ($Json) { $plan | ConvertTo-Json -Depth 8 }
        else { Write-Output 'Administrator privileges are required; no token change was made.' }
        exit 2
    }
    if (-not $tokenExists) {
        $plan.state = 'blocked'
        $plan.failureReason = 'token-missing'
        if ($Json) { $plan | ConvertTo-Json -Depth 8 }
        else { Write-Output 'The installed token is missing; rotation cannot create a new installation.' }
        exit 2
    }
    if (-not $PSCmdlet.ShouldProcess($tokenPath, 'Atomically rotate the Hermes Windows Bridge bearer token')) {
        $plan.mode = 'what-if'
        if ($Json) { $plan | ConvertTo-Json -Depth 8 }
        exit 0
    }

    $doctorPath = [IO.Path]::Combine($canonicalScriptRoot, 'doctor.ps1')
    $doctorItem = Get-Item -LiteralPath $doctorPath -Force -ErrorAction Stop
    if ($doctorItem.PSIsContainer -or
        ($doctorItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not (Split-Path -Parent $doctorItem.FullName).Equals($canonicalScriptRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw [IO.IOException]::new('BridgeDoctorScriptUnsafe: doctor script is relocated or a reparse point.')
    }

    # 승인 뒤에만 token을 생성하며 helper가 교체, backup ACL, 1차 rollback을 담당합니다.
    $newToken = New-BridgeToken
    $plan.receipts += [ordered]@{ step = 'generate_token'; state = 'generated-not-logged'; externalCalls = 0 }
    $writeResult = Write-BridgeTokenAtomic -Root $ProgramDataRoot -TokenPath $tokenPath -Token $newToken
    $plan.receipts += [ordered]@{ step = 'backup_token'; state = if ($writeResult.replaced) { 'created-and-protected' } else { 'unchanged' }; externalCalls = 0 }
    $plan.receipts += [ordered]@{ step = 'atomic_replace'; state = 'applied'; externalCalls = 0 }
    if (-not (Test-BridgeSecretAclExact -TokenPath $tokenPath)) {
        try {
            Remove-Item -LiteralPath $tokenPath -Force
            [IO.File]::Move($writeResult.backupPath, $tokenPath)
            Set-BridgeSecretAcl -TokenPath $tokenPath
            $plan.rollback += [ordered]@{ step = 'atomic_replace'; state = 'restored-previous-token'; externalCalls = 0 }
        } catch {
            $plan.rollback += [ordered]@{ step = 'atomic_replace'; state = 'rollback-failed'; externalCalls = 0 }
            $plan.atomic = $false
        }
        $plan.state = 'failed'
        $plan.applied = $false
        $plan.failedStep = 'token_acl'
        $plan.failureReason = 'BridgeTokenAclVerificationFailed'
        $newToken = $null
        if ($Json) { $plan | ConvertTo-Json -Depth 8 }
        else { Write-Output 'Token rotation failed ACL verification; rollback results were recorded.' }
        exit 2
    }
    $plan.receipts += [ordered]@{ step = 'token_acl'; state = 'verified'; externalCalls = 0 }
    $savedProgramData = $env:ProgramData
    try {
        $freshDoctorItem = Get-Item -LiteralPath $doctorPath -Force -ErrorAction Stop
        if ($freshDoctorItem.PSIsContainer -or
            ($freshDoctorItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not $freshDoctorItem.FullName.Equals($doctorItem.FullName, [StringComparison]::OrdinalIgnoreCase)) {
            throw [IO.IOException]::new('BridgeDoctorScriptPathSwap: doctor script changed before validation.')
        }
        $env:ProgramData = $ProgramDataRoot
        $doctorResult = Invoke-BridgeChildProcess -FilePath 'powershell.exe' -ArgumentList @(
            '-NoProfile', '-NonInteractive', '-File', $doctorItem.FullName, '-Json'
        ) -TimeoutSeconds 30
        if ($doctorResult.exitCode -ne 0) {
            throw [InvalidOperationException]::new('BridgeTokenDoctorFailed: doctor rejected the rotated local token state.')
        }
    } catch {
        $doctorError = $_
        try {
            if (-not $writeResult.replaced -or -not (Test-Path -LiteralPath $writeResult.backupPath -PathType Leaf)) {
                throw [IO.IOException]::new('BridgeTokenRollbackSourceMissing: the protected previous token backup is unavailable.')
            }
            Remove-Item -LiteralPath $tokenPath -Force
            [IO.File]::Move($writeResult.backupPath, $tokenPath)
            Set-BridgeSecretAcl -TokenPath $tokenPath
            $plan.rollback += [ordered]@{ step = 'atomic_replace'; state = 'restored-previous-token'; externalCalls = 0 }
        } catch {
            $plan.rollback += [ordered]@{ step = 'atomic_replace'; state = 'rollback-failed'; externalCalls = 0 }
            $plan.state = 'failed'
            $plan.applied = $false
            $plan.failedStep = 'doctor'
            $plan.failureReason = 'BridgeTokenRollbackFailed'
            $newToken = $null
            if ($Json) { $plan | ConvertTo-Json -Depth 8 }
            else { Write-Output 'Token rotation failed and rollback could not be verified.' }
            exit 2
        }
        $plan.state = 'failed'
        $plan.applied = $false
        $plan.failedStep = 'doctor'
        $plan.failureReason = $doctorError.Exception.Message.Split(':')[0]
        $newToken = $null
        if ($Json) { $plan | ConvertTo-Json -Depth 8 }
        else { Write-Output 'Token rotation failed; the previous token was restored.' }
        exit 2
    } finally {
        $env:ProgramData = $savedProgramData
    }
    $plan.receipts += [ordered]@{ step = 'doctor'; state = 'verified'; externalCalls = 1 }

    $plan.applied = $true
    $plan.state = 'applied'
    $plan.tokenOutput = 'shown-once'
    if ($Json) {
        $plan['newToken'] = $newToken
        $plan | ConvertTo-Json -Depth 8
    } else {
        Write-Output ("NEW TOKEN (shown once): {0}" -f $newToken)
        Write-Output $ociEnvironmentInstruction
    }
    exit 0
}

if ($Json) {
    $plan | ConvertTo-Json -Depth 8
} else {
    Write-Output 'Hermes Windows Bridge token rotation plan.'
    foreach ($action in $actions) {
        Write-Output ("Action {0}: planned={1}; state={2}" -f $action.id, $action.planned, $action.state)
    }
    Write-Output $ociEnvironmentInstruction
    Write-Output 'No token was read, generated, displayed, or changed.'
}

exit 0
