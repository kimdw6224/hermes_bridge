[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ReleaseRoot,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ManifestSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-BridgeHostVerificationResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][bool]$Verified,
        [Parameter(Mandatory)][string]$ReleaseRoot,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$FailureReasons,
        [Parameter()][AllowNull()][string]$ServiceExecutable
    )
    $result = [ordered]@{ schemaVersion = 1; verified = $Verified; releaseRoot = $ReleaseRoot; serviceExecutable = $ServiceExecutable }
    if (-not $Verified) { $result.failureReasons = @($FailureReasons | Sort-Object -Unique) }
    $result | ConvertTo-Json -Depth 4 -Compress
}

function Exit-BridgeHostVerificationFailure {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ReleaseRoot, [Parameter(Mandatory)][string]$Reason)
    Write-BridgeHostVerificationResult -Verified $false -ReleaseRoot $ReleaseRoot `
        -FailureReasons @($Reason) -ServiceExecutable $null
    exit 2
}

function Test-BridgeHostConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter(Mandatory)][string]$ExpectedReleaseRoot,
        [Parameter(Mandatory)][string]$ExpectedManifestSha256
    )
    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { return $false }
    try {
        $raw = [IO.File]::ReadAllText($ConfigPath, [Text.UTF8Encoding]::new($false, $true))
        $config = $raw | ConvertFrom-Json -ErrorAction Stop
        $keys = @($config.PSObject.Properties.Name | Sort-Object)
        $schemaVersion = $config.schemaVersion
        $expectedKeys = if ($schemaVersion -eq 1) {
            @('manifestSha256', 'profile', 'releaseRoot', 'schemaVersion')
        } elseif ($schemaVersion -eq 2) {
            @('manifestSha256', 'profile', 'releaseRoot', 'runtimeBindingPath', 'runtimeBindingSha256', 'schemaVersion')
        } else { return $false }
        if ($keys.Count -ne $expectedKeys.Count -or (Compare-Object $keys $expectedKeys)) { return $false }
        if ($config.schemaVersion -isnot [int] -and $config.schemaVersion -isnot [long] -or
            $config.schemaVersion -notin @(1, 2)) { return $false }
        if ([string]$config.profile -cnotin @('gateway', 'privileged')) { return $false }
        if (-not [IO.Path]::GetFullPath([string]$config.releaseRoot).Equals(
                [IO.Path]::GetFullPath($ExpectedReleaseRoot), [StringComparison]::OrdinalIgnoreCase)) { return $false }
        if ($config.schemaVersion -eq 2 -and
            (-not ([string]$config.runtimeBindingPath -match '^[A-Za-z]:\\') -or
             [string]$config.runtimeBindingSha256 -cnotmatch '^[a-f0-9]{64}$')) { return $false }
        return ([string]$config.manifestSha256 -ceq $ExpectedManifestSha256)
    } catch [IO.IOException], [Text.DecoderFallbackException], [Management.Automation.RuntimeException] {
        return $false
    }
}

function Get-BridgeVerifierFileSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose(); $stream.Dispose() }
}

$safeReleaseRoot = try { [IO.Path]::GetFullPath($ReleaseRoot) } catch { $ReleaseRoot }
$configPath = Join-Path $PSScriptRoot 'host-config.json'
if (-not (Test-BridgeHostConfig -ConfigPath $configPath -ExpectedReleaseRoot $safeReleaseRoot `
            -ExpectedManifestSha256 $ManifestSha256)) {
    Exit-BridgeHostVerificationFailure -ReleaseRoot $safeReleaseRoot -Reason 'host-config-invalid'
}

$manifestPath = Join-Path $safeReleaseRoot 'release-manifest.json'
try {
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
        -not ((Get-BridgeVerifierFileSha256 -Path $manifestPath).Equals(
                $ManifestSha256, [StringComparison]::Ordinal))) {
        Exit-BridgeHostVerificationFailure -ReleaseRoot $safeReleaseRoot -Reason 'manifest-digest-mismatch'
    }
} catch [IO.IOException], [UnauthorizedAccessException], [Security.SecurityException] {
    Exit-BridgeHostVerificationFailure -ReleaseRoot $safeReleaseRoot -Reason 'manifest-digest-mismatch'
}

try {
    # 후보 release가 아니라 host anchor에 snapshot한 검증기만 로드합니다.
    $runtimeValidator = Join-Path $PSScriptRoot 'service-runtime.ps1'
    $closureValidator = Join-Path $PSScriptRoot 'service-runtime-closure.ps1'
    if (-not (Test-Path -LiteralPath $runtimeValidator -PathType Leaf) -or
        -not (Test-Path -LiteralPath $closureValidator -PathType Leaf)) {
        Exit-BridgeHostVerificationFailure -ReleaseRoot $safeReleaseRoot -Reason 'host-validator-missing'
    }
    . $runtimeValidator -LibraryMode -ManifestPath $manifestPath -ReleaseRoot $safeReleaseRoot
    $contract = Get-BridgeServiceLaunchContract -ManifestPath $manifestPath -ReleaseRoot $safeReleaseRoot
    if (-not $contract.verified -or [string]::IsNullOrWhiteSpace([string]$contract.serviceExecutable)) {
        Exit-BridgeHostVerificationFailure -ReleaseRoot $safeReleaseRoot -Reason 'runtime-entrypoint-unverified'
    }
    Write-BridgeHostVerificationResult -Verified $true -ReleaseRoot $safeReleaseRoot `
        -FailureReasons @() -ServiceExecutable ([string]$contract.serviceExecutable)
    exit 0
} catch [IO.IOException], [UnauthorizedAccessException], [Security.SecurityException],
         [Management.Automation.RuntimeException] {
    Exit-BridgeHostVerificationFailure -ReleaseRoot $safeReleaseRoot -Reason 'runtime-entrypoint-unverified'
}
