[CmdletBinding()]
param(
    [Parameter()][string]$HostRoot,
    [Parameter()][ValidateSet('gateway', 'privileged')][string]$Profile,
    [Parameter()][string]$ReleaseRoot,
    [switch]$BuildHost,
    [switch]$Apply,
    [Parameter()][string]$SourceRoot,
    [Parameter()][string]$ProgramRoot,
    [Parameter()][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedManifestSha256,
    [Parameter()][string]$InstallationContextPath,
    [Parameter()][AllowEmptyString()][ValidatePattern('^(?:[a-f0-9]{64})?$')][string]$InstallationContextSha256,
    [switch]$Json,
    [switch]$LibraryMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:BridgeHostProfiles = @('gateway', 'privileged')
$script:BridgeHostRequiredFiles = @(
    'HermesBridge.ServiceHost.exe', 'host-config.json', 'verify-release.ps1',
    'service-runtime.ps1', 'service-runtime-closure.ps1', 'host-manifest.json'
)
$script:BridgeHostTrustedSids = @('S-1-5-18', 'S-1-5-32-544')
$script:BridgeHostWriteMask = [int64]0x500D0156

function Get-BridgeHostFileSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose(); $stream.Dispose() }
}

function Test-BridgeHostAbsoluteLocalPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    return $Path -match '^[A-Za-z]:\\' -and -not $Path.StartsWith('\\')
}

function Get-BridgeHostSidValue {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Identity)
    try {
        return $Identity.Translate([Security.Principal.SecurityIdentifier]).Value
    } catch [Security.Principal.IdentityNotMappedException] {
        return [string]$Identity.Value
    }
}

function Test-BridgeHostAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $script:BridgeHostTrustedSids) {
            return $false
        }
        $sddl = $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
        if ($sddl -match 'NO_ACCESS_CONTROL') { return $false }
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
            $sid = Get-BridgeHostSidValue -Identity $rule.IdentityReference
            if ($sid -notin $script:BridgeHostTrustedSids -and
                (([int64]$rule.FileSystemRights -band $script:BridgeHostWriteMask) -ne 0)) {
                return $false
            }
        }
        return $true
    } catch [UnauthorizedAccessException], [Security.SecurityException], [IO.IOException] {
        return $false
    }
}

function Get-BridgeHostSourceInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectPath)
    $projectDirectory = Split-Path -Parent ([IO.Path]::GetFullPath($ProjectPath))
    $serviceHostRoot = Split-Path -Parent $projectDirectory
    $files = [Collections.Generic.List[object]]::new()
    foreach ($name in @('global.json', 'Directory.Build.props', 'Directory.Build.targets', 'NuGet.config')) {
        $parentFile = Join-Path $serviceHostRoot $name
        if (Test-Path -LiteralPath $parentFile -PathType Leaf) {
            $item = Get-Item -LiteralPath $parentFile -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw [Security.SecurityException]::new('BridgeServiceHostSourceReparseDisallowed')
            }
            $files.Add([pscustomobject]@{ sourcePath = $item.FullName; relativePath = $name; sha256 = (Get-BridgeHostFileSha256 -Path $item.FullName); size = [int64]$item.Length })
        }
    }
    foreach ($item in Get-ChildItem -LiteralPath $projectDirectory -File -Recurse -Force) {
        $relative = $item.FullName.Substring($serviceHostRoot.Length).TrimStart('\').Replace('\', '/')
        if ($relative -match '(^|/)(obj|bin)/' -or $relative -notmatch '\.(cs|csproj)$') { continue }
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw [Security.SecurityException]::new('BridgeServiceHostSourceReparseDisallowed')
        }
        $files.Add([pscustomobject]@{ sourcePath = $item.FullName; relativePath = $relative; sha256 = (Get-BridgeHostFileSha256 -Path $item.FullName); size = [int64]$item.Length })
    }
    if ($files.Count -eq 0) { throw [IO.InvalidDataException]::new('BridgeServiceHostSourceMissing') }
    return @($files | Sort-Object relativePath)
}

function Copy-BridgeHostSourceSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProjectPath,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Inventory
    )
    Set-BridgeHostProtectedDirectory -Path $Destination
    foreach ($entry in $Inventory) {
        $target = Join-Path $Destination ([string]$entry.relativePath).Replace('/', '\')
        $targetParent = Split-Path -Parent $target
        if (-not (Test-Path -LiteralPath $targetParent -PathType Container)) { Set-BridgeHostProtectedDirectory -Path $targetParent }
        [IO.File]::WriteAllBytes($target, [IO.File]::ReadAllBytes([string]$entry.sourcePath))
        if ((Get-BridgeHostFileSha256 -Path $target) -cne [string]$entry.sha256 -or
            (Get-Item -LiteralPath $target -Force).Length -ne [int64]$entry.size -or -not (Test-BridgeHostAcl -Path $target)) {
            throw [Security.SecurityException]::new('BridgeServiceHostSourceCopyUnverified')
        }
    }
}

function Get-BridgeHostSourceDigest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Inventory)
    $material = @($Inventory | ForEach-Object { "$($_.relativePath)|$($_.sha256)|$($_.size)" } | Sort-Object) -join "`n"
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.UTF8Encoding]::new($false).GetBytes($material)))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Test-BridgeHostReparseFree {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    try {
        $current = [IO.Path]::GetFullPath($Path)
        while ($true) {
            if (((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                return $false
            }
            $parent = Split-Path -Parent $current
            if ([string]::IsNullOrWhiteSpace($parent) -or
                $parent.Equals($current, [StringComparison]::OrdinalIgnoreCase)) { return $true }
            $current = $parent
        }
    } catch [UnauthorizedAccessException], [IO.IOException] {
        return $false
    }
}

function Get-BridgeHostConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ConfigPath)
    try {
        $config = [IO.File]::ReadAllText($ConfigPath, [Text.UTF8Encoding]::new($false, $true)) |
            ConvertFrom-Json -ErrorAction Stop
        $keys = @($config.PSObject.Properties.Name | Sort-Object)
        $schemaVersion = $config.schemaVersion
        $expected = if ($schemaVersion -eq 1) {
            @('manifestSha256', 'profile', 'releaseRoot', 'schemaVersion')
        } elseif ($schemaVersion -eq 2) {
            @('manifestSha256', 'profile', 'releaseRoot', 'runtimeBindingPath', 'runtimeBindingSha256', 'schemaVersion')
        } else { return $null }
        if ($keys.Count -ne $expected.Count -or (Compare-Object $keys $expected)) { return $null }
        if (($config.schemaVersion -isnot [int] -and $config.schemaVersion -isnot [long]) -or
            [string]$config.profile -cnotin $script:BridgeHostProfiles -or
            [string]$config.manifestSha256 -cnotmatch '^[a-f0-9]{64}$') { return $null }
        [void][IO.Path]::GetFullPath([string]$config.releaseRoot)
        if ($config.schemaVersion -eq 2 -and
            ([string]::IsNullOrWhiteSpace([string]$config.runtimeBindingPath) -or
             -not (Test-BridgeHostAbsoluteLocalPath -Path ([string]$config.runtimeBindingPath)) -or
             [string]$config.runtimeBindingSha256 -cnotmatch '^[a-f0-9]{64}$')) { return $null }
        return $config
    } catch [IO.IOException], [Text.DecoderFallbackException], [Management.Automation.RuntimeException] {
        return $null
    }
}

function Get-BridgeServiceHostInstallationContext {
    [CmdletBinding()]
    param(
        [Parameter()][string]$InstallationContextPath,
        [Parameter()][string]$InstallationContextSha256
    )
    $hasPath = -not [string]::IsNullOrWhiteSpace($InstallationContextPath)
    $hasSha = -not [string]::IsNullOrWhiteSpace($InstallationContextSha256)
    if ($hasPath -ne $hasSha) {
        throw [ArgumentException]::new('BridgeServiceHostInstallationContextPairRequired')
    }
    if (-not $hasPath) { return $null }

    # dot-source한 컨텍스트 모듈의 CLI param 기본값이 이 함수의 입력을 바꾸지 않도록 보관합니다.
    $requestedPath = $InstallationContextPath
    $requestedSha256 = $InstallationContextSha256
    $contextScript = Join-Path $PSScriptRoot 'installation-context.ps1'
    if (-not (Test-Path -LiteralPath $contextScript -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new('BridgeServiceHostInstallationContextModuleMissing')
    }
    . $contextScript -LibraryMode
    $context = Get-BridgeInstallationContext -Path $requestedPath -Sha256 $requestedSha256
    if ($null -eq $context -or [string]$context.nonce -cnotmatch '^[a-f0-9]{32}$' -or
        [string]::IsNullOrWhiteSpace([string]$context.programRoot) -or
        [string]::IsNullOrWhiteSpace([string]$context.gatewayServiceName) -or
        [string]::IsNullOrWhiteSpace([string]$context.privilegedServiceName)) {
        throw [Security.SecurityException]::new('BridgeServiceHostInstallationContextInvalid')
    }
    return $context
}

function Get-BridgeServiceHostInstallationBinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InstallationContextPath,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$InstallationContextSha256,
        [Parameter(Mandatory)][ValidateSet('gateway', 'privileged')][string]$Profile
    )
    # 컨텍스트와 profile binding은 같은 모듈 범위에서 해석해 독립 호출도 dot-source 순서에 의존하지 않습니다.
    $requestedPath = $InstallationContextPath
    $requestedSha256 = $InstallationContextSha256
    $contextScript = Join-Path $PSScriptRoot 'installation-context.ps1'
    if (-not (Test-Path -LiteralPath $contextScript -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new('BridgeServiceHostInstallationContextModuleMissing')
    }
    . $contextScript -LibraryMode
    $context = Get-BridgeInstallationContext -Path $requestedPath -Sha256 $requestedSha256
    $binding = Get-BridgeInstallationContextBinding -Context $context -Profile $Profile
    return [pscustomobject][ordered]@{ context = $context; binding = $binding }
}

function Get-BridgeHostDigest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$HostRoot)
    $lines = [Collections.Generic.List[string]]::new()
    foreach ($item in Get-ChildItem -LiteralPath $HostRoot -File -Recurse -Force) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not (Test-BridgeHostReparseFree -Path $item.FullName)) {
            throw [Security.SecurityException]::new('BridgeServiceHostPackageReparseDisallowed')
        }
        $relative = $item.FullName.Substring(([IO.Path]::GetFullPath($HostRoot)).Length).TrimStart('\').Replace('\', '/')
        if ($relative -ceq 'host-manifest.json') { continue }
        if ($relative.Contains('..') -or $relative.StartsWith('/')) { throw [IO.InvalidDataException]::new('BridgeServiceHostInventoryPathInvalid') }
        $lines.Add("$relative|$(Get-BridgeHostFileSha256 -Path $item.FullName)|$($item.Length)")
    }
    if ($lines.Count -eq 0) { throw [IO.InvalidDataException]::new('BridgeServiceHostInventoryEmpty') }
    $sortedLines = [string[]]@($lines)
    [Array]::Sort($sortedLines, [StringComparer]::Ordinal)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($sortedLines -join "`n") + "`n")
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Write-BridgeHostManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$HostRoot, [Parameter(Mandatory)][ValidateSet('gateway', 'privileged')][string]$Profile)
    $files = [Collections.Generic.List[object]]::new()
    $itemByRelativePath = @{}
    foreach ($item in Get-ChildItem -LiteralPath $HostRoot -File -Recurse -Force) {
        if (-not (Test-BridgeHostReparseFree -Path $item.FullName)) {
            throw [Security.SecurityException]::new('BridgeServiceHostPackageReparseDisallowed')
        }
        $relative = $item.FullName.Substring(([IO.Path]::GetFullPath($HostRoot)).Length).TrimStart('\').Replace('\', '/')
        $itemByRelativePath[$relative] = $item
    }
    $relativePaths = [string[]]@($itemByRelativePath.Keys)
    [Array]::Sort($relativePaths, [StringComparer]::Ordinal)
    foreach ($relative in $relativePaths) {
        $entry = [pscustomobject]@{ item = $itemByRelativePath[$relative]; relativePath = $relative }
        $item = $entry.item
        if ($relative -ceq 'host-manifest.json') { continue }
        $files.Add([pscustomobject][ordered]@{ relativePath = $relative; sha256 = (Get-BridgeHostFileSha256 -Path $item.FullName); size = [int64]$item.Length })
    }
    $manifest = [ordered]@{ schemaVersion = 1; hostDigest = (Get-BridgeHostDigest -HostRoot $HostRoot); profile = $Profile; files = @($files) }
    [IO.File]::WriteAllText((Join-Path $HostRoot 'host-manifest.json'), ($manifest | ConvertTo-Json -Depth 6 -Compress), [Text.UTF8Encoding]::new($false))
}

function Test-BridgeHostManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$HostRoot, [Parameter(Mandatory)][ValidateSet('gateway', 'privileged')][string]$Profile)
    $path = Join-Path $HostRoot 'host-manifest.json'
    try {
        $manifest = [IO.File]::ReadAllText($path, [Text.UTF8Encoding]::new($false, $true)) | ConvertFrom-Json -ErrorAction Stop
        $keys = @($manifest.PSObject.Properties.Name | Sort-Object)
        $expectedKeys = @('files', 'hostDigest', 'profile', 'schemaVersion')
        if ($keys.Count -ne $expectedKeys.Count -or (Compare-Object $keys $expectedKeys) -or
            ($manifest.schemaVersion -isnot [int] -and $manifest.schemaVersion -isnot [long]) -or
            $manifest.schemaVersion -ne 1 -or [string]$manifest.profile -cne $Profile -or
            [string]$manifest.hostDigest -cnotmatch '^[a-f0-9]{64}$') { return $false }
        $actual = Get-BridgeHostDigest -HostRoot $HostRoot
        if ($actual -cne [string]$manifest.hostDigest) { return $false }
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $actualFiles = [Collections.Generic.List[string]]::new()
        foreach ($item in Get-ChildItem -LiteralPath $HostRoot -File -Recurse -Force) {
            if (-not (Test-BridgeHostReparseFree -Path $item.FullName) -or
                -not (Test-BridgeHostAcl -Path $item.FullName)) { return $false }
            $relative = $item.FullName.Substring(([IO.Path]::GetFullPath($HostRoot)).Length).TrimStart('\').Replace('\', '/')
            if ($relative -ceq 'host-manifest.json') { continue }
            $actualFiles.Add("$relative|$(Get-BridgeHostFileSha256 -Path $item.FullName)|$($item.Length)")
        }
        $declaredFiles = [Collections.Generic.List[string]]::new()
        foreach ($file in @($manifest.files)) {
            $relative = [string]$file.relativePath
            if ([IO.Path]::IsPathRooted($relative) -or $relative.Contains('..') -or -not $seen.Add($relative) -or
                [string]$file.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
                ($file.size -isnot [int] -and $file.size -isnot [long]) -or [int64]$file.size -lt 0) { return $false }
            $declaredFiles.Add("$relative|$([string]$file.sha256)|$([int64]$file.size)")
        }
        $actualSorted = [string[]]@($actualFiles); $declaredSorted = [string[]]@($declaredFiles)
        [Array]::Sort($actualSorted, [StringComparer]::Ordinal); [Array]::Sort($declaredSorted, [StringComparer]::Ordinal)
        return ($actualSorted.Count -eq $declaredSorted.Count -and -not (Compare-Object $actualSorted $declaredSorted -CaseSensitive))
    } catch [IO.IOException], [Text.DecoderFallbackException], [Management.Automation.RuntimeException] {
        return $false
    }
}

function Get-BridgeServiceHostContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$HostRoot,
        [Parameter(Mandatory)][ValidateSet('gateway', 'privileged')][string]$Profile,
        [Parameter(Mandatory)][string]$ReleaseRoot,
        [Parameter()][string]$InstallationContextPath,
        [Parameter()][AllowEmptyString()][ValidatePattern('^(?:[a-f0-9]{64})?$')][string]$InstallationContextSha256
    )
    $context = try {
        Get-BridgeServiceHostInstallationContext -InstallationContextPath $InstallationContextPath `
            -InstallationContextSha256 $InstallationContextSha256
    } catch [ArgumentException], [IO.IOException], [UnauthorizedAccessException], [Security.SecurityException], [Management.Automation.RuntimeException] {
        $null
    }
    $contextRequested = -not [string]::IsNullOrWhiteSpace($InstallationContextPath) -or
        -not [string]::IsNullOrWhiteSpace($InstallationContextSha256)
    $safeHostRoot = try { [IO.Path]::GetFullPath($HostRoot) } catch { $HostRoot }
    $safeReleaseRoot = try { [IO.Path]::GetFullPath($ReleaseRoot) } catch { $ReleaseRoot }
    $reasons = [Collections.Generic.List[string]]::new()
    $result = [ordered]@{
        schemaVersion = if ($contextRequested) { 2 } else { 1 }; state = 'blocked'; verified = $false; failureReasons = $reasons
        profile = $Profile; hostRoot = $safeHostRoot; hostDigest = $null
        hostExecutable = $null; argv = @(); configPath = (Join-Path $safeHostRoot 'host-config.json')
        verifierPath = (Join-Path $safeHostRoot 'verify-release.ps1'); releaseRoot = $safeReleaseRoot
        manifestSha256 = $null; releaseExecutable = $null; contextNonce = $null
        runtimeBindingPath = $null; runtimeBindingSha256 = $null; serviceName = $null
    }
    if ($contextRequested -and $null -eq $context) {
        $reasons.Add('installation-context-invalid'); return [pscustomobject]$result
    }
    if (-not (Test-Path -LiteralPath $safeHostRoot -PathType Container) -or
        -not (Split-Path -Leaf $safeHostRoot).Equals($Profile, [StringComparison]::Ordinal)) {
        $reasons.Add('host-anchor-invalid'); return [pscustomobject]$result
    }
    if (-not (Test-BridgeHostReparseFree -Path $safeHostRoot) -or -not (Test-BridgeHostAcl -Path $safeHostRoot)) {
        $reasons.Add('host-anchor-untrusted'); return [pscustomobject]$result
    }
    $config = Get-BridgeHostConfig -ConfigPath $result.configPath
    if ($null -eq $config -or -not [IO.Path]::GetFullPath([string]$config.releaseRoot).Equals(
            $safeReleaseRoot, [StringComparison]::OrdinalIgnoreCase) -or [string]$config.profile -cne $Profile) {
        $reasons.Add('host-config-invalid'); return [pscustomobject]$result
    }
    if ($null -ne $context) {
        try {
            $resolvedBinding = Get-BridgeServiceHostInstallationBinding -InstallationContextPath $InstallationContextPath `
                -InstallationContextSha256 $InstallationContextSha256 -Profile $Profile
            $context = $resolvedBinding.context
            $expectedProgramRoot = [IO.Path]::GetFullPath([string]$context.programRoot)
            $expectedBinding = $resolvedBinding.binding
            $expectedServiceName = if ($Profile -ceq 'gateway') { [string]$context.gatewayServiceName } else { [string]$context.privilegedServiceName }
        } catch [IO.IOException], [UnauthorizedAccessException], [Security.SecurityException], [Management.Automation.RuntimeException] {
            $reasons.Add('runtime-binding-invalid'); return [pscustomobject]$result
        }
        if (-not $safeHostRoot.StartsWith(([IO.Path]::Combine($expectedProgramRoot, 'hosts') + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase) -or
            $config.schemaVersion -ne 2 -or [string]$config.runtimeBindingPath -cne [string]$expectedBinding.path -or
            [string]$config.runtimeBindingSha256 -cne [string]$expectedBinding.sha256 -or
            [string]$expectedBinding.contextNonce -cne [string]$context.nonce -or
            [string]::IsNullOrWhiteSpace($expectedServiceName)) {
            $reasons.Add('runtime-binding-invalid'); return [pscustomobject]$result
        }
        $result.contextNonce = [string]$context.nonce
        $result.runtimeBindingPath = [string]$expectedBinding.path
        $result.runtimeBindingSha256 = [string]$expectedBinding.sha256
        $result.serviceName = $expectedServiceName
    } elseif ($config.schemaVersion -ne 1) {
        $reasons.Add('runtime-binding-context-required'); return [pscustomobject]$result
    }
    foreach ($file in $script:BridgeHostRequiredFiles) {
        $path = Join-Path $safeHostRoot $file
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or -not (Test-BridgeHostReparseFree -Path $path) -or
            -not (Test-BridgeHostAcl -Path $path)) {
            $reasons.Add('host-package-untrusted'); return [pscustomobject]$result
        }
    }
    if (-not (Test-BridgeHostManifest -HostRoot $safeHostRoot -Profile $Profile)) {
        $reasons.Add('host-manifest-invalid'); return [pscustomobject]$result
    }
    try { $digest = Get-BridgeHostDigest -HostRoot $safeHostRoot }
    catch [IO.IOException], [UnauthorizedAccessException], [Security.SecurityException] {
        $reasons.Add('host-package-untrusted'); return [pscustomobject]$result
    }
    $digestParent = Split-Path -Parent $safeHostRoot
    if (-not (Split-Path -Leaf $digestParent).Equals($digest, [StringComparison]::Ordinal)) {
        $reasons.Add('host-digest-mismatch'); return [pscustomobject]$result
    }
    $manifestPath = Join-Path $safeReleaseRoot 'release-manifest.json'
    try {
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
            (Get-BridgeHostFileSha256 -Path $manifestPath) -cne [string]$config.manifestSha256) {
            $reasons.Add('manifest-digest-mismatch'); return [pscustomobject]$result
        }
        . (Join-Path $safeHostRoot 'service-runtime.ps1') -LibraryMode `
            -ManifestPath $manifestPath -ReleaseRoot $safeReleaseRoot
        $runtime = Get-BridgeServiceLaunchContract -ManifestPath $manifestPath -ReleaseRoot $safeReleaseRoot
        if (-not $runtime.verified) {
            $reasons.Add('runtime-entrypoint-unverified'); return [pscustomobject]$result
        }
        $hostExecutable = Join-Path $safeHostRoot 'HermesBridge.ServiceHost.exe'
        $result.hostDigest = $digest; $result.hostExecutable = $hostExecutable
        $result.argv = @($hostExecutable, '--profile', $Profile); $result.manifestSha256 = [string]$config.manifestSha256
        $result.releaseExecutable = [string]$runtime.serviceExecutable; $result.state = 'verified'; $result.verified = $true
        if ($null -eq $context) {
            $result.serviceName = if ($Profile -ceq 'gateway') { 'HermesWindowsBridgeGateway' } else { 'HermesWindowsBridgePrivileged' }
        }
    } catch [IO.IOException], [UnauthorizedAccessException], [Security.SecurityException], [Management.Automation.RuntimeException] {
        $reasons.Add('runtime-entrypoint-unverified')
    }
    return [pscustomobject]$result
}

function Get-BridgeServiceHostBuildPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$ProgramRoot,
        [Parameter(Mandatory)][string]$ReleaseRoot,
        [Parameter()][string]$ExpectedManifestSha256,
        [Parameter()][string]$InstallationContextPath,
        [Parameter()][AllowEmptyString()][ValidatePattern('^(?:[a-f0-9]{64})?$')][string]$InstallationContextSha256
    )
    $context = Get-BridgeServiceHostInstallationContext -InstallationContextPath $InstallationContextPath `
        -InstallationContextSha256 $InstallationContextSha256
    $project = Join-Path ([IO.Path]::GetFullPath($SourceRoot)) 'service-host\HermesBridge.ServiceHost\HermesBridge.ServiceHost.csproj'
    $manifest = Join-Path ([IO.Path]::GetFullPath($ReleaseRoot)) 'release-manifest.json'
    $manifestHash = if ([string]::IsNullOrWhiteSpace($ExpectedManifestSha256)) { $null } else { $ExpectedManifestSha256 }
    $commands = [Collections.Generic.List[string[]]]::new()
    $commands.Add([string[]]@('dotnet', 'restore', $project, '-r', 'win-x64'))
    $commands.Add([string[]]@('dotnet', 'publish', $project, '-c', 'Release', '-r', 'win-x64', '--self-contained', 'true', '--no-restore'))
    return [pscustomobject][ordered]@{
        schemaVersion = if ($null -eq $context) { 1 } else { 2 }; state = 'planned'; applied = $false; projectPath = $project
        releaseRoot = [IO.Path]::GetFullPath($ReleaseRoot); manifestPath = $manifest; manifestSha256 = $manifestHash
        contextNonce = if ($null -eq $context) { $null } else { [string]$context.nonce }
        commands = $commands
    }
}

function Set-BridgeHostProtectedDirectory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $acl = New-BridgeHostDirectorySecurity
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetFullPath($Path), $acl)
    if (-not (Test-BridgeHostAcl -Path $Path) -or -not (Test-BridgeHostLocalServiceReadExecute -Path $Path)) {
        throw [Security.SecurityException]::new('BridgeServiceHostAclUnverified')
    }
}

function New-BridgeHostDirectorySecurity {
    [CmdletBinding()]
    param()
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sidValue in $script:BridgeHostTrustedSids) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($sidValue),
                [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow))
    }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-19'),
            [Security.AccessControl.FileSystemRights]::ReadAndExecute,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    return $acl
}

function Test-BridgeHostLocalServiceReadExecute {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $localService = [Security.Principal.SecurityIdentifier]::new('S-1-5-19')
        $rights = [int64]0
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                $rule.IdentityReference.Value -ceq $localService.Value) {
                $rights = $rights -bor [int64]$rule.FileSystemRights
            }
        }
        return (($rights -band [int64][Security.AccessControl.FileSystemRights]::ReadAndExecute) -eq
            [int64][Security.AccessControl.FileSystemRights]::ReadAndExecute)
    } catch [UnauthorizedAccessException], [Security.SecurityException], [IO.IOException] {
        return $false
    }
}

function Invoke-BridgeServiceHostBuild {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$ProgramRoot,
        [Parameter(Mandatory)][string]$ReleaseRoot,
        [Parameter()][string]$ExpectedManifestSha256,
        [Parameter()][string]$InstallationContextPath,
        [Parameter()][AllowEmptyString()][ValidatePattern('^(?:[a-f0-9]{64})?$')][string]$InstallationContextSha256
    )
    $requestedInstallationContextPath = $InstallationContextPath
    $requestedInstallationContextSha256 = $InstallationContextSha256
    $plan = Get-BridgeServiceHostBuildPlan -SourceRoot $SourceRoot -ProgramRoot $ProgramRoot `
        -ReleaseRoot $ReleaseRoot -ExpectedManifestSha256 $ExpectedManifestSha256 `
        -InstallationContextPath $requestedInstallationContextPath -InstallationContextSha256 $requestedInstallationContextSha256
    $context = Get-BridgeServiceHostInstallationContext -InstallationContextPath $requestedInstallationContextPath `
        -InstallationContextSha256 $requestedInstallationContextSha256
    $manifestPath = [string]$plan.manifestPath
    $expectedProgramRoot = if ($null -eq $context) {
        Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'HermesWindowsBridge'
    } else { [string]$context.programRoot }
    if (-not ([IO.Path]::GetFullPath($ProgramRoot)).Equals($expectedProgramRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw [Security.SecurityException]::new('BridgeServiceHostProgramRootInvalid')
    }
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new('BridgeServiceHostManifestMissing')
    }
    $manifestHash = Get-BridgeHostFileSha256 -Path $manifestPath
    if (-not [string]::IsNullOrWhiteSpace($ExpectedManifestSha256) -and $manifestHash -cne $ExpectedManifestSha256) {
        throw [Security.SecurityException]::new('BridgeServiceHostManifestDigestMismatch')
    }
    $runtimeValidator = Join-Path $PSScriptRoot 'service-runtime.ps1'
    $closureValidator = Join-Path $PSScriptRoot 'service-runtime-closure.ps1'
    if (-not (Test-Path -LiteralPath $plan.projectPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $runtimeValidator -PathType Leaf) -or
        -not (Test-Path -LiteralPath $closureValidator -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new('BridgeServiceHostBuildInputMissing')
    }
    # dot-source의 param 초기화가 빌드 입력을 덮어쓰지 않도록 현재 값을 전달합니다.
    . $runtimeValidator -LibraryMode -ManifestPath $manifestPath -ReleaseRoot $plan.releaseRoot `
        -SourceRoot $SourceRoot -ProgramRoot $ProgramRoot `
        -InstallationContextPath $requestedInstallationContextPath -InstallationContextSha256 $requestedInstallationContextSha256
    $runtime = Get-BridgeServiceLaunchContract -ManifestPath $manifestPath -ReleaseRoot $plan.releaseRoot
    if (-not $runtime.verified) { throw [Security.SecurityException]::new('BridgeServiceHostRuntimeUnverified') }
    $validatorSnapshots = @{
        'verify-release.ps1' = Get-BridgeHostFileSha256 -Path (Join-Path $PSScriptRoot 'verify-release.ps1')
        'service-runtime.ps1' = Get-BridgeHostFileSha256 -Path $runtimeValidator
        'service-runtime-closure.ps1' = Get-BridgeHostFileSha256 -Path $closureValidator
    }
    $sourceInventory = @(Get-BridgeHostSourceInventory -ProjectPath $plan.projectPath)
    $dotnetPath = (Get-Command dotnet.exe -CommandType Application -ErrorAction Stop).Source
    $expectedDotnet = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'dotnet\dotnet.exe'
    if (-not ([IO.Path]::GetFullPath($dotnetPath)).Equals($expectedDotnet, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-BridgeHostReparseFree -Path $dotnetPath) -or -not (Test-BridgeHostAcl -Path $dotnetPath)) {
        throw [Security.SecurityException]::new('BridgeServiceHostDotnetUnverified')
    }
    $sdkVersion = (& $dotnetPath --version 2>$null).Trim()
    if ($LASTEXITCODE -ne 0 -or $sdkVersion -cne '10.0.400') {
        throw [Security.SecurityException]::new('BridgeServiceHostSdkUnverified')
    }
    $hostsRoot = Join-Path ([IO.Path]::GetFullPath($ProgramRoot)) 'hosts'
    Set-BridgeHostProtectedDirectory -Path $hostsRoot
    $stageRoot = Join-Path $hostsRoot ('.staging-' + [guid]::NewGuid().ToString('N'))
    Set-BridgeHostProtectedDirectory -Path $stageRoot
    $stageSource = Join-Path $stageRoot 'source'
    Copy-BridgeHostSourceSnapshot -ProjectPath $plan.projectPath -Destination $stageSource -Inventory $sourceInventory
    $stagedProject = Join-Path $stageSource ((Split-Path -Leaf (Split-Path -Parent $plan.projectPath)) + '\\' + (Split-Path -Leaf $plan.projectPath))
    Push-Location -LiteralPath $stageSource
    try {
        $restoreOutput = & $dotnetPath restore $stagedProject -r win-x64
        $restoreOutput | ForEach-Object { Write-Verbose $_ }
        if ($LASTEXITCODE -ne 0) { throw [ComponentModel.Win32Exception]::new('BridgeServiceHostRestoreFailed') }
        foreach ($currentProfile in $script:BridgeHostProfiles) {
            $stageProfile = Join-Path $stageRoot $currentProfile
            Set-BridgeHostProtectedDirectory -Path $stageProfile
            $publishOutput = & $dotnetPath publish $stagedProject -c Release -r win-x64 --self-contained true --no-restore --output $stageProfile
            $publishOutput | ForEach-Object { Write-Verbose $_ }
            if ($LASTEXITCODE -ne 0) { throw [ComponentModel.Win32Exception]::new('BridgeServiceHostPublishFailed') }
            foreach ($scriptName in @('verify-release.ps1', 'service-runtime.ps1', 'service-runtime-closure.ps1')) {
                if ((Get-BridgeHostFileSha256 -Path (Join-Path $PSScriptRoot $scriptName)) -cne $validatorSnapshots[$scriptName]) {
                    throw [Security.SecurityException]::new('BridgeServiceHostValidatorSourceChanged')
                }
                Copy-Item -LiteralPath (Join-Path $PSScriptRoot $scriptName) -Destination (Join-Path $stageProfile $scriptName) -Force
            }
            $binding = if ($null -eq $context) { $null } else {
                (Get-BridgeServiceHostInstallationBinding -InstallationContextPath $requestedInstallationContextPath `
                    -InstallationContextSha256 $requestedInstallationContextSha256 -Profile $currentProfile).binding
            }
            $config = if ($null -eq $binding) {
                [ordered]@{ schemaVersion = 1; profile = $currentProfile; releaseRoot = $plan.releaseRoot; manifestSha256 = $manifestHash }
            } else {
                [ordered]@{ schemaVersion = 2; profile = $currentProfile; releaseRoot = $plan.releaseRoot; manifestSha256 = $manifestHash; runtimeBindingPath = [string]$binding.path; runtimeBindingSha256 = [string]$binding.sha256 }
            }
            [IO.File]::WriteAllText((Join-Path $stageProfile 'host-config.json'),
                ($config | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
            Write-BridgeHostManifest -HostRoot $stageProfile -Profile $currentProfile
            foreach ($file in Get-ChildItem -LiteralPath $stageProfile -File -Recurse) {
                if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                    -not (Test-BridgeHostAcl -Path $file.FullName)) {
                    throw [Security.SecurityException]::new('BridgeServiceHostPackageAclUnverified')
                }
            }
        }
    } finally { Pop-Location }
    if ((Get-BridgeHostSourceDigest -Inventory @(Get-BridgeHostSourceInventory -ProjectPath $plan.projectPath)) -cne
        (Get-BridgeHostSourceDigest -Inventory $sourceInventory)) {
        throw [Security.SecurityException]::new('BridgeServiceHostSourceChanged')
    }
    $firstDigest = Get-BridgeHostDigest -HostRoot (Join-Path $stageRoot 'gateway')
    $secondDigest = Get-BridgeHostDigest -HostRoot (Join-Path $stageRoot 'privileged')
    if ($firstDigest -ceq $secondDigest) { throw [Security.SecurityException]::new('BridgeServiceHostProfilesNotBound') }
    $contracts = [Collections.Generic.List[object]]::new()
    foreach ($currentProfile in $script:BridgeHostProfiles) {
        $stageProfile = [IO.Path]::GetFullPath((Join-Path $stageRoot $currentProfile))
        $digest = Get-BridgeHostDigest -HostRoot $stageProfile
        $digestRoot = [IO.Path]::GetFullPath((Join-Path $hostsRoot $digest))
        if (-not $stageProfile.Equals((Join-Path $stageRoot $currentProfile), [StringComparison]::OrdinalIgnoreCase) -or
            -not (Split-Path -Parent $stageProfile).Equals($stageRoot, [StringComparison]::OrdinalIgnoreCase) -or
            -not (Split-Path -Leaf $stageProfile).Equals($currentProfile, [StringComparison]::Ordinal) -or
            -not ((Split-Path -Leaf $stageRoot) -match '^\.staging-[a-f0-9]{32}$') -or
            -not (Test-BridgeHostReparseFree -Path $stageRoot) -or
            -not (Test-BridgeHostReparseFree -Path $hostsRoot) -or
            -not (Split-Path -Parent $digestRoot).Equals($hostsRoot, [StringComparison]::OrdinalIgnoreCase) -or
            -not (Split-Path -Leaf $digestRoot).Equals($digest, [StringComparison]::Ordinal)) {
            throw [Security.SecurityException]::new('BridgeServiceHostMoveBoundaryInvalid')
        }
        if (Test-Path -LiteralPath $digestRoot) { throw [IO.IOException]::new('BridgeServiceHostDigestAlreadyExists') }
        Set-BridgeHostProtectedDirectory -Path $digestRoot
        Move-Item -LiteralPath $stageProfile -Destination $digestRoot -ErrorAction Stop
        $contract = Get-BridgeServiceHostContract -HostRoot (Join-Path $digestRoot $currentProfile) `
            -Profile $currentProfile -ReleaseRoot $plan.releaseRoot `
            -InstallationContextPath $requestedInstallationContextPath -InstallationContextSha256 $requestedInstallationContextSha256
        if (-not $contract.verified) { throw [Security.SecurityException]::new('BridgeServiceHostPostBuildUnverified') }
        $contracts.Add($contract)
    }
    return [pscustomobject][ordered]@{
        schemaVersion = 1; state = 'built'; applied = $true; stagingRoot = $stageRoot; hosts = @($contracts)
    }
}

if (-not $LibraryMode) {
    if (-not $BuildHost) { throw [ArgumentException]::new('BridgeServiceHostBuildRequired') }
    $requestedInstallationContextPath = $InstallationContextPath
    $requestedInstallationContextSha256 = $InstallationContextSha256
    $plan = Get-BridgeServiceHostBuildPlan -SourceRoot $SourceRoot -ProgramRoot $ProgramRoot `
        -ReleaseRoot $ReleaseRoot -ExpectedManifestSha256 $ExpectedManifestSha256 `
        -InstallationContextPath $requestedInstallationContextPath -InstallationContextSha256 $requestedInstallationContextSha256
    $result = if ($Apply) {
        Invoke-BridgeServiceHostBuild -SourceRoot $SourceRoot -ProgramRoot $ProgramRoot -ReleaseRoot $ReleaseRoot `
            -ExpectedManifestSha256 $ExpectedManifestSha256 -InstallationContextPath $requestedInstallationContextPath `
            -InstallationContextSha256 $requestedInstallationContextSha256
    } else { $plan }
    if ($Json) { $result | ConvertTo-Json -Depth 12 -Compress } else { $result }
}
