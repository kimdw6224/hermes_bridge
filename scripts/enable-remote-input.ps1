[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Apply,
    [switch]$Json,
    [string]$LocalDataRoot = $env:LOCALAPPDATA
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

if ([string]::IsNullOrWhiteSpace($LocalDataRoot)) {
    $LocalDataRoot = [Environment]::GetFolderPath('LocalApplicationData')
}
$LocalDataRoot = Resolve-BridgeLocalRoot -Path $LocalDataRoot
$stateDirectory = Assert-BridgePathUnderRoot -Root $LocalDataRoot -Path ([IO.Path]::Combine($LocalDataRoot, 'HermesWindowsBridge'))
$statePath = Assert-BridgePathUnderRoot -Root $LocalDataRoot -Path ([IO.Path]::Combine($stateDirectory, 'remote-input.disabled'))
$markerExists = Test-Path -LiteralPath $statePath -PathType Leaf
$applied = $false
$state = if ($markerExists) { 'planned' } else { 'unchanged' }
$failureReason = $null
$receipts = @()
$rollback = @()
$failedStep = $null

if ($Apply -and -not $WhatIfPreference -and -not (Test-BridgeAdministrator)) {
    $state = 'blocked'
    $failureReason = 'administrator-required'
} elseif ($Apply -and $markerExists -and $PSCmdlet.ShouldProcess($statePath, 'Remove local remote-input emergency-stop marker')) {
    $safeStatePath = Assert-BridgePathUnderRoot -Root $LocalDataRoot -Path $statePath
    $restorePath = $safeStatePath + '.restore'
    if (Test-Path -LiteralPath $restorePath) {
        throw [IO.IOException]::new('BridgeRemoteInputRestoreConflict: a prior restore file requires operator review.')
    }
    try {
        [IO.File]::Move($safeStatePath, $restorePath)
        Remove-Item -LiteralPath $restorePath -Force
        if ((Test-Path -LiteralPath $safeStatePath) -or (Test-Path -LiteralPath $restorePath)) {
            throw [IO.IOException]::new('BridgeRemoteInputVerificationFailed: marker removal was not verified.')
        }
        $applied = $true
        $state = 'enabled'
        $receipts += [ordered]@{ step = 'enable_remote_input'; state = 'applied-and-verified'; externalCalls = 0 }
    } catch {
        $operationError = $_
        if ((Test-Path -LiteralPath $restorePath -PathType Leaf) -and -not (Test-Path -LiteralPath $safeStatePath)) {
            [IO.File]::Move($restorePath, $safeStatePath)
            $rollback += [ordered]@{ step = 'enable_remote_input'; state = 'marker-restored'; externalCalls = 0 }
        } elseif (-not (Test-Path -LiteralPath $safeStatePath) -and -not (Test-Path -LiteralPath $restorePath)) {
            $state = 'unchanged'
            $operationError = $null
        }
        if ($null -ne $operationError) {
            $state = 'failed'
            $failureReason = $operationError.Exception.Message.Split(':')[0]
            $failedStep = 'enable_remote_input'
            $receipts += [ordered]@{ step = 'enable_remote_input'; state = 'failed'; externalCalls = 0 }
        }
    }
}

$report = [ordered]@{
    schemaVersion = 1
    kind = 'hermes-windows-bridge-remote-input-plan'
    mode = if ($Apply -and -not $WhatIfPreference) { 'apply' } else { 'what-if' }
    applied = $applied
    atomic = $true
    resumeSafe = $true
    state = $state
    failureReason = $failureReason
    administratorRequiredForApply = $true
    remoteInputEnabled = -not (Test-Path -LiteralPath $statePath -PathType Leaf)
    actions = @([ordered]@{ id = 'enable_remote_input'; planned = $markerExists; target = $statePath })
    backups = @()
    receipts = $receipts
    rollback = $rollback
    failedStep = $failedStep
    externalCalls = 0
}

if ($Json) {
    $report | ConvertTo-Json -Depth 5
} else {
    Write-Output 'Hermes Windows Bridge remote input (local operator only)'
    Write-Output ("Mode: {0}; State: {1}; Applied: {2}" -f $report.mode, $report.state, $report.applied)
}
if ($failureReason) { exit 2 }
