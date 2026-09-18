[CmdletBinding()]
param(
    [Parameter()][string]$ManifestPath,
    [Parameter()][string]$ReleaseRoot,
    [switch]$BuildRelease,
    [switch]$Apply,
    [Parameter()][string]$SourceRoot,
    [Parameter()][string]$ProgramRoot,
    [Parameter()][string]$ExpectedSourceDigest,
    [Parameter()][string]$ExpectedLockDigest,
    [Parameter()][string]$TrustedUvPath,
    [Parameter()][string]$ExpectedUvSha256,
    [Parameter()][string]$InstallationContextPath,
    [Parameter()][AllowEmptyString()][ValidatePattern('^(?:[a-f0-9]{64})?$')][string]$InstallationContextSha256,
    [ValidateRange(30, 3600)][int]$TimeoutSeconds = 900,
    [switch]$Json,
    [switch]$LibraryMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ManifestV1Fields = @(
    'schemaVersion', 'releaseId', 'sourceDigest', 'lockDigest', 'pythonVersion',
    'architecture', 'uvVersion', 'fileInventory', 'baseExecutable', 'serviceExecutable'
)
$script:ManifestV2Fields = @($script:ManifestV1Fields + @('closureReceipt', 'closureReceiptSha256'))
$script:AllowedInventoryFields = @('relativePath', 'sha256', 'size')
$script:TrustedWriterSids = @('S-1-5-18', 'S-1-5-32-544')
$script:TrustedOwnerSids = @('S-1-5-18', 'S-1-5-32-544')
$script:TrustedInstallerSid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$script:WriteMask = [int64]0x500D0156 # DELETE/WRITE_DAC/WRITE_OWNER/GENERIC_WRITE/GENERIC_ALL/file writes

function Get-BridgeSidValue {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Identity)
    $reference = if ($Identity -is [Security.Principal.IdentityReference]) {
        $Identity
    } else {
        [Security.Principal.NTAccount]::new([string]$Identity)
    }
    try { return $reference.Translate([Security.Principal.SecurityIdentifier]).Value }
    catch [Security.Principal.IdentityNotMappedException] { return [string]$Identity.Value }
}

function Test-BridgeProtectedAclDescriptor {
    [CmdletBinding()]
    param([Parameter(Mandatory)][Security.AccessControl.FileSystemSecurity]$Acl)
    $ownerSid = $Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($ownerSid -notin $script:TrustedOwnerSids) { return $false }
    return Test-BridgeAclHasNoUntrustedWrite -Acl $Acl
}

function Get-BridgeCanonicalTrustedInstallerPaths {
    [CmdletBinding()]
    param()
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    $programFilesX86 = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
    $windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    $paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($path in @(
        $programFiles, $programFilesX86, $windows,
        (Join-Path $windows 'System32'), (Join-Path $windows 'WinSxS'),
        [IO.Path]::GetPathRoot($programFiles), [IO.Path]::GetPathRoot($programFilesX86),
        [IO.Path]::GetPathRoot($windows)
    )) {
        if (-not [string]::IsNullOrWhiteSpace($path)) {
            [void]$paths.Add([IO.Path]::GetFullPath($path).TrimEnd('\'))
        }
    }
    return $paths
}

function Test-BridgeAclHasNoUntrustedWrite {
    [CmdletBinding()]
    param([Parameter(Mandatory)][Security.AccessControl.FileSystemSecurity]$Acl)
    $accessSddl = $Acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
    if ($accessSddl -match 'NO_ACCESS_CONTROL') { return $false }
    foreach ($rule in $Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        $sid = Get-BridgeSidValue -Identity $rule.IdentityReference
        $rights = [int64]$rule.FileSystemRights
        if ($sid -notin $script:TrustedWriterSids -and ($rights -band $script:WriteMask) -ne 0) { return $false }
    }
    return $true
}

function Test-BridgeAncestorAclHasNoUntrustedReplacement {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Security.AccessControl.FileSystemSecurity]$Acl,
        [Parameter(Mandatory)][string]$Path
    )
    $canonicalPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if (-not (Get-BridgeCanonicalTrustedInstallerPaths).Contains($canonicalPath)) {
        return Test-BridgeAclHasNoUntrustedWrite -Acl $Acl
    }
    $accessSddl = $Acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
    if ($accessSddl -match 'NO_ACCESS_CONTROL') { return $false }
    $canonicalRoots = @(
        [IO.Path]::GetPathRoot([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)),
        [IO.Path]::GetPathRoot([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows))
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object {
        [IO.Path]::GetFullPath($_)
    } | Select-Object -Unique
    $isCanonicalVolumeRoot = $canonicalRoots -contains ([IO.Path]::GetFullPath($Path))
    # 볼륨 루트 자체의 DELETE는 보호된 하위 release 교체 권한이 아니므로 루트에서만 제외합니다.
    $replacementMask = if ($isCanonicalVolumeRoot) {
        [int64]0x500C0040 # GENERIC_ALL/GENERIC_WRITE/WRITE_DAC/WRITE_OWNER/FILE_DELETE_CHILD
    } else {
        [int64]0x500D0040 # + DELETE outside a volume root
    }
    foreach ($rule in $Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        if (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) {
            continue
        }
        $sid = Get-BridgeSidValue -Identity $rule.IdentityReference
        $rights = [int64]$rule.FileSystemRights
        $trustedWriter = $sid -in $script:TrustedWriterSids -or $sid -ceq $script:TrustedInstallerSid
        if (-not $trustedWriter -and ($rights -band $replacementMask) -ne 0) { return $false }
    }
    return $true
}

function Test-BridgeOwnerTrustedForPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$OwnerSid)
    if ($OwnerSid -in $script:TrustedOwnerSids) { return $true }
    if ($OwnerSid -cne $script:TrustedInstallerSid) { return $false }
    $candidate = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    return (Get-BridgeCanonicalTrustedInstallerPaths).Contains($candidate)
}

function Test-BridgePathUnderRoot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Path)
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $candidate = [IO.Path]::GetFullPath($Path)
    return $candidate.StartsWith($rootPath, [StringComparison]::OrdinalIgnoreCase)
}

function Test-BridgePathReparseFree {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Path)
    if (-not (Test-BridgePathUnderRoot -Root $Root -Path $Path) -and
        -not ([IO.Path]::GetFullPath($Root)).Equals([IO.Path]::GetFullPath($Path), [StringComparison]::OrdinalIgnoreCase)) {
        return $false
    }
    $rootPath = [IO.Path]::GetFullPath($Root)
    $current = $rootPath
    try {
        if (([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            return $false
        }
    } catch [IO.IOException], [UnauthorizedAccessException], [Security.SecurityException] {
        return $false
    }
    $relative = [IO.Path]::GetFullPath($Path).Substring($rootPath.TrimEnd('\').Length).TrimStart('\')
    # 수천 파일의 각 경로를 캐시 없이 재검사하되 PowerShell provider의 반복 비용을 피합니다.
    foreach ($segment in $relative.Split([IO.Path]::DirectorySeparatorChar)) {
        if ([string]::IsNullOrEmpty($segment)) { continue }
        $current = [IO.Path]::Combine($current, $segment)
        try {
            if (([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                return $false
            }
        } catch [IO.FileNotFoundException], [IO.DirectoryNotFoundException] {
            # 존재 여부는 호출자의 inventory 검사에서 별도로 판정합니다.
            continue
        } catch [IO.IOException], [UnauthorizedAccessException], [Security.SecurityException] {
            return $false
        }
    }
    return $true
}

function Add-BridgeReason {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[string]]$Reasons,
        [Parameter(Mandatory)][string]$Reason
    )
    if (-not $Reasons.Contains($Reason)) { $Reasons.Add($Reason) }
}

function Get-BridgeFileSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $algorithm.Dispose(); $stream.Dispose() }
}

function Get-BridgePathAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $sections = [Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner
    if (([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::Directory) -ne 0) {
        return ([IO.DirectoryInfo]::new($Path)).GetAccessControl($sections)
    }
    return ([IO.FileInfo]::new($Path)).GetAccessControl($sections)
}

function Get-BridgeFileLinkCount {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if ($null -eq ('HermesBridge.FileIdentity' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace HermesBridge {
  public static class FileIdentity {
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation {
      public uint FileAttributes; public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
      public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
      public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
      public uint VolumeSerialNumber; public uint FileSizeHigh; public uint FileSizeLow;
      public uint NumberOfLinks; public uint FileIndexHigh; public uint FileIndexLow;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security,
      uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation info);
    public static uint GetLinkCount(string path) {
      using (SafeFileHandle handle = CreateFile(path, 0, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero)) {
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        FileInformation info;
        if (!GetFileInformationByHandle(handle, out info)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return info.NumberOfLinks;
      }
    }
  }
}
'@
    }
    return [HermesBridge.FileIdentity]::GetLinkCount($Path)
}

function Get-BridgeReleaseInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ReleaseRoot)
    $root = [IO.Path]::GetFullPath($ReleaseRoot)
    $inventory = [Collections.Generic.List[object]]::new()
    $releaseFiles = [Collections.Generic.List[object]]::new()
    foreach ($file in Get-ChildItem -LiteralPath $root -File -Recurse -Force) {
        $releaseFiles.Add($file)
    }
    # closure receipt의 digest도 실행 PowerShell에 관계없이 동일해야 합니다.
    $releaseFiles.Sort([Comparison[object]]{
        param($left, $right)
        return [StringComparer]::Ordinal.Compare(
            [string]$left.FullName,
            [string]$right.FullName
        )
    })
    foreach ($file in $releaseFiles) {
        # manifest와 closure receipt는 서로의 무결성을 별도 해시로 결속하여 자기참조를 피합니다.
        if ($file.Name -in @('release-manifest.json', 'closure-receipt.json')) { continue }
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            (Get-BridgeFileLinkCount -Path $file.FullName) -ne 1) {
            throw [Security.SecurityException]::new('BridgeRuntimeReleaseLinkDisallowed')
        }
        $inventory.Add([pscustomobject][ordered]@{
            relativePath = $file.FullName.Substring($root.TrimEnd('\').Length + 1).Replace('\', '/')
            sha256 = Get-BridgeFileSha256 -Path $file.FullName
            size = [int64]$file.Length
        })
    }
    return @($inventory)
}

function Get-BridgeInventoryDigest {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Inventory)
    $json = @($Inventory) | ConvertTo-Json -Depth 5 -Compress
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($algorithm.ComputeHash([Text.UTF8Encoding]::new($false).GetBytes($json)))).Replace('-', '').ToLowerInvariant()
    } finally { $algorithm.Dispose() }
}

function Test-BridgeManifestShape {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Manifest, [Parameter(Mandatory)][string]$RawJson)
    if ($RawJson.Length -gt 4194304 -or $Manifest.schemaVersion -isnot [int]) { return $false }
    $allowedFields = switch ($Manifest.schemaVersion) {
        1 { $script:ManifestV1Fields }
        2 { $script:ManifestV2Fields }
        default { return $false }
    }
    $properties = @($Manifest.PSObject.Properties.Name)
    if (@($properties | Where-Object { $_ -notin $allowedFields }).Count -ne 0 -or
        @($allowedFields | Where-Object { $_ -notin $properties }).Count -ne 0) { return $false }
    if (
        [string]$Manifest.releaseId -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$Manifest.sourceDigest -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$Manifest.lockDigest -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$Manifest.pythonVersion -cnotmatch '^3\.14\.3$' -or
        [string]$Manifest.architecture -cne 'x64' -or
        [string]$Manifest.uvVersion -cnotmatch '^\d+\.\d+\.\d+$') { return $false }
    if ($Manifest.schemaVersion -eq 2 -and
        ([string]$Manifest.closureReceipt -cne 'closure-receipt.json' -or
            [string]$Manifest.closureReceiptSha256 -cnotmatch '^[a-f0-9]{64}$')) { return $false }
    if ($Manifest.fileInventory -isnot [Array]) { return $false }
    $inventory = @($Manifest.fileInventory)
    if ($inventory.Count -lt 1 -or $inventory.Count -gt 20000) { return $false }
    foreach ($entry in $inventory) {
        $entryProperties = @($entry.PSObject.Properties.Name)
        if (@($entryProperties | Where-Object { $_ -notin $script:AllowedInventoryFields }).Count -ne 0 -or
            @($script:AllowedInventoryFields | Where-Object { $_ -notin $entryProperties }).Count -ne 0 -or
            [string]$entry.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
            ($entry.size -isnot [int] -and $entry.size -isnot [long]) -or [int64]$entry.size -lt 0) { return $false }
    }
    return $true
}

function Test-BridgeJsonStructure {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RawJson)
    $depth = 0; $inString = $false; $escaped = $false; $expectingKey = $false
    $keyBuilder = [Text.StringBuilder]::new()
    $keySets = [Collections.Generic.Stack[Collections.Generic.HashSet[string]]]::new()
    for ($index = 0; $index -lt $RawJson.Length; $index++) {
        $character = $RawJson[$index]
        if ($inString) {
            if ($escaped) {
                if ($character -eq 'u') {
                    if ($index + 4 -ge $RawJson.Length) { return $false }
                    $hex = $RawJson.Substring($index + 1, 4)
                    if ($hex -cnotmatch '^[a-fA-F0-9]{4}$') { return $false }
                    [void]$keyBuilder.Append([char][Convert]::ToInt32($hex, 16)); $index += 4
                } elseif ($character -in @('"', '\', '/', 'b', 'f', 'n', 'r', 't')) {
                    [void]$keyBuilder.Append($character)
                } else { return $false }
                $escaped = $false; continue
            }
            if ($character -eq '\') { $escaped = $true; continue }
            if ($character -eq '"') {
                $inString = $false
                if ($expectingKey) {
                    $lookahead = $index + 1
                    while ($lookahead -lt $RawJson.Length -and [char]::IsWhiteSpace($RawJson[$lookahead])) { $lookahead++ }
                    if ($lookahead -ge $RawJson.Length -or $RawJson[$lookahead] -ne ':') { return $false }
                    if (-not $keySets.Peek().Add($keyBuilder.ToString())) { return $false }
                    $expectingKey = $false
                }
                continue
            }
            if ($expectingKey) { [void]$keyBuilder.Append($character) }
            continue
        }
        if ($character -eq '"') {
            $inString = $true; $keyBuilder.Clear() | Out-Null
            continue
        }
        if ($character -eq '{') {
            $depth++; if ($depth -gt 32) { return $false }
            $keySets.Push([Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase))
            $expectingKey = $true; continue
        }
        if ($character -eq '[') { $depth++; if ($depth -gt 32) { return $false }; continue }
        if ($character -eq '}') { if ($keySets.Count -eq 0) { return $false }; $keySets.Pop() | Out-Null; $depth--; continue }
        if ($character -eq ']') { $depth--; continue }
        if ($character -eq ',' -and $keySets.Count -gt 0) { $expectingKey = $true }
        if ($depth -lt 0) { return $false }
    }
    return -not $inString -and -not $escaped -and $depth -eq 0 -and $keySets.Count -eq 0
}

function Test-BridgeTreeAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][bool]$RequireTrustedOwner)
    $acl = Get-BridgePathAcl -Path $Path
    if ($RequireTrustedOwner -and $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $script:TrustedOwnerSids) {
        return 'acl-owner-untrusted'
    }
    if (-not (Test-BridgeProtectedAclDescriptor -Acl $acl)) { return 'acl-write-untrusted' }
    return $null
}

function Get-BridgeServiceRuntimeContract {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ManifestPath, [Parameter(Mandatory)][string]$ReleaseRoot)
    $reasons = [Collections.Generic.List[string]]::new()
    $safeRoot = [IO.Path]::GetFullPath($ReleaseRoot)
    $safeManifest = [IO.Path]::GetFullPath($ManifestPath)
    $result = [ordered]@{
        schemaVersion = 1; state = 'blocked'; verified = $false; failureReasons = $reasons
        manifestPath = $safeManifest; releaseRoot = $safeRoot; readOnly = $true
        authorizationReusable = $false
        serviceExecutable = $null
        warning = 'Read-only snapshot only; revalidate under the future Apply lock immediately before activation.'
    }
    if (-not (Test-BridgePathUnderRoot -Root $safeRoot -Path $safeManifest) -or
        -not (Test-Path -LiteralPath $safeRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $safeManifest -PathType Leaf) -or
        -not (Split-Path -Parent $safeManifest).Equals($safeRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Split-Path -Leaf $safeManifest).Equals('release-manifest.json', [StringComparison]::Ordinal)) {
        Add-BridgeReason -Reasons $reasons -Reason 'manifest-path-invalid'
        return [pscustomobject]$result
    }
    if (-not (Test-BridgePathReparseFree -Root $safeRoot -Path $safeManifest)) {
        Add-BridgeReason -Reasons $reasons -Reason 'reparse-point-disallowed'
        return [pscustomobject]$result
    }
    $ancestor = $safeRoot
    while ($true) {
        if (((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Add-BridgeReason -Reasons $reasons -Reason 'reparse-point-disallowed'
            return [pscustomobject]$result
        }
        $ancestorParent = Split-Path -Parent $ancestor
        if ([string]::IsNullOrEmpty($ancestorParent) -or
            $ancestorParent.Equals($ancestor, [StringComparison]::OrdinalIgnoreCase)) { break }
        $ancestor = $ancestorParent
    }
    try {
        $manifestInfo = [IO.FileInfo]::new($safeManifest)
        if ($manifestInfo.Length -gt 4194304) {
            Add-BridgeReason -Reasons $reasons -Reason 'manifest-schema-invalid'
            return [pscustomobject]$result
        }
        $bytes = [IO.File]::ReadAllBytes($safeManifest)
        $raw = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        if (-not (Test-BridgeJsonStructure -RawJson $raw)) {
            Add-BridgeReason -Reasons $reasons -Reason 'manifest-schema-invalid'
            return [pscustomobject]$result
        }
        $manifest = $raw | ConvertFrom-Json -ErrorAction Stop
        if (-not (Test-BridgeManifestShape -Manifest $manifest -RawJson $raw)) {
            Add-BridgeReason -Reasons $reasons -Reason 'manifest-schema-invalid'
        }
    } catch [Management.Automation.RuntimeException], [IO.IOException], [Text.DecoderFallbackException] {
        Add-BridgeReason -Reasons $reasons -Reason 'manifest-schema-invalid'
        return [pscustomobject]$result
    }
    if ($reasons.Contains('manifest-schema-invalid')) { return [pscustomobject]$result }
    $result.schemaVersion = $manifest.schemaVersion
    if (-not (Split-Path -Leaf $safeRoot).Equals([string]$manifest.releaseId, [StringComparison]::Ordinal)) {
        Add-BridgeReason -Reasons $reasons -Reason 'release-id-path-mismatch'
    }
    $expectedBase = Join-Path $safeRoot 'python\python.exe'
    $expectedService = Join-Path $safeRoot 'venv\Scripts\python.exe'
    foreach ($property in @('baseExecutable', 'serviceExecutable')) {
        $candidate = [string]$manifest.$property
        if (-not (Test-BridgePathUnderRoot -Root $safeRoot -Path $candidate)) {
            Add-BridgeReason -Reasons $reasons -Reason 'path-outside-release'
        }
    }
    if (-not ([IO.Path]::GetFullPath([string]$manifest.baseExecutable)).Equals($expectedBase, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([IO.Path]::GetFullPath([string]$manifest.serviceExecutable)).Equals($expectedService, [StringComparison]::OrdinalIgnoreCase)) {
        Add-BridgeReason -Reasons $reasons -Reason 'runtime-entrypoint-invalid'
    }
    $seenInventoryPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in @($manifest.fileInventory)) {
        $relative = [string]$entry.relativePath
        if ([IO.Path]::IsPathRooted($relative) -or $relative.Contains(':') -or
            $relative -match '(^|[\\/])\.\.([\\/]|$)' -or $relative.Contains('\')) {
            Add-BridgeReason -Reasons $reasons -Reason 'inventory-path-invalid'
            continue
        }
        $candidate = [IO.Path]::GetFullPath([IO.Path]::Combine($safeRoot, $relative.Replace('/', '\')))
        if (-not (Test-BridgePathUnderRoot -Root $safeRoot -Path $candidate) -or -not $seenInventoryPaths.Add($relative)) {
            Add-BridgeReason -Reasons $reasons -Reason 'inventory-path-invalid'
            continue
        }
        if (-not (Test-BridgePathReparseFree -Root $safeRoot -Path $candidate)) {
            Add-BridgeReason -Reasons $reasons -Reason 'reparse-point-disallowed'
            continue
        }
        $item = [IO.FileInfo]::new($candidate)
        if (-not $item.Exists) {
            Add-BridgeReason -Reasons $reasons -Reason 'inventory-file-missing'
            continue
        }
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Add-BridgeReason -Reasons $reasons -Reason 'reparse-point-disallowed'
        }
        try {
            if ((Get-BridgeFileLinkCount -Path $candidate) -ne 1) {
                Add-BridgeReason -Reasons $reasons -Reason 'hardlink-disallowed'
            }
        } catch [ComponentModel.Win32Exception], [Management.Automation.MethodInvocationException] {
            Add-BridgeReason -Reasons $reasons -Reason 'hardlink-unverified'
        }
        if ($item.Length -ne [int64]$entry.size -or
            (Get-BridgeFileSha256 -Path $candidate) -cne [string]$entry.sha256) {
            Add-BridgeReason -Reasons $reasons -Reason 'inventory-integrity-mismatch'
        }
    }
    $inventoryAbsolute = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in @($manifest.fileInventory)) {
        $relative = [string]$entry.relativePath
        if (-not [IO.Path]::IsPathRooted($relative) -and -not $relative.Contains(':') -and
            $relative -notmatch '(^|[\\/])\.\.([\\/]|$)') {
            [void]$inventoryAbsolute.Add([IO.Path]::GetFullPath([IO.Path]::Combine($safeRoot, $relative.Replace('/', '\'))))
        }
    }
    if (-not $inventoryAbsolute.Contains($expectedBase) -or -not $inventoryAbsolute.Contains($expectedService)) {
        Add-BridgeReason -Reasons $reasons -Reason 'runtime-entrypoint-not-in-inventory'
    }
    $closureReceiptPath = if ($manifest.schemaVersion -eq 2) {
        Join-Path $safeRoot ([string]$manifest.closureReceipt)
    } else { $null }
    $pendingDirectories = [Collections.Generic.Queue[string]]::new()
    $pendingDirectories.Enqueue($safeRoot)
    while ($pendingDirectories.Count -gt 0) {
        $directory = $pendingDirectories.Dequeue()
        foreach ($childItem in ([IO.DirectoryInfo]::new($directory)).EnumerateFileSystemInfos()) {
            $childItem.Refresh()
            if (($childItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Add-BridgeReason -Reasons $reasons -Reason 'reparse-point-disallowed'
                continue
            }
            try {
                $aclReason = Test-BridgeTreeAcl -Path $childItem.FullName -RequireTrustedOwner $true
                if ($null -ne $aclReason) { Add-BridgeReason -Reasons $reasons -Reason $aclReason }
            } catch [UnauthorizedAccessException], [Security.SecurityException], [IO.IOException] {
                Add-BridgeReason -Reasons $reasons -Reason 'acl-unverified'
            }
            if (($childItem.Attributes -band [IO.FileAttributes]::Directory) -ne 0) {
                $pendingDirectories.Enqueue($childItem.FullName); continue
            }
            if (-not $childItem.FullName.Equals($safeManifest, [StringComparison]::OrdinalIgnoreCase) -and
                ($null -eq $closureReceiptPath -or -not $childItem.FullName.Equals($closureReceiptPath, [StringComparison]::OrdinalIgnoreCase)) -and
                -not $inventoryAbsolute.Contains($childItem.FullName)) {
                Add-BridgeReason -Reasons $reasons -Reason 'inventory-extra-file'
            }
        }
    }
    $current = $safeRoot
    while ($true) {
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Add-BridgeReason -Reasons $reasons -Reason 'reparse-point-disallowed'
        }
        try {
            $acl = Get-BridgePathAcl -Path $current
            $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
            $ownerTrusted = if ($current.Equals($safeRoot, [StringComparison]::OrdinalIgnoreCase)) {
                $ownerSid -in $script:TrustedOwnerSids
            } else {
                Test-BridgeOwnerTrustedForPath -Path $current -OwnerSid $ownerSid
            }
            if (-not $ownerTrusted) {
                Add-BridgeReason -Reasons $reasons -Reason 'acl-owner-untrusted'
            }
            $writeSafe = if ($current.Equals($safeRoot, [StringComparison]::OrdinalIgnoreCase)) {
                Test-BridgeProtectedAclDescriptor -Acl $acl
            } else {
                Test-BridgeAncestorAclHasNoUntrustedReplacement -Acl $acl -Path $current
            }
            if (-not $writeSafe) {
                Add-BridgeReason -Reasons $reasons -Reason 'acl-write-untrusted'
            }
        } catch [UnauthorizedAccessException], [Security.SecurityException], [IO.IOException] {
            Add-BridgeReason -Reasons $reasons -Reason 'acl-unverified'
        }
        $parent = Split-Path -Parent $current
        if ([string]::IsNullOrEmpty($parent) -or $parent.Equals($current, [StringComparison]::OrdinalIgnoreCase)) { break }
        $current = $parent
    }
    if ($reasons.Count -eq 0) {
        $result.state = 'verified'; $result.verified = $true; $result.serviceExecutable = $expectedService
    }
    return [pscustomobject]$result
}

function Get-BridgeServiceLaunchContract {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ManifestPath, [Parameter(Mandatory)][string]$ReleaseRoot)
    $contract = Get-BridgeServiceRuntimeContract -ManifestPath $ManifestPath -ReleaseRoot $ReleaseRoot
    $result = [ordered]@{
        schemaVersion = $contract.schemaVersion; state = 'blocked'; verified = $false
        failureReasons = [Collections.Generic.List[string]]::new(); manifestPath = $contract.manifestPath
        releaseRoot = $contract.releaseRoot; serviceExecutable = $null; readOnly = $true
        authorizationReusable = $false
    }
    if (-not $contract.verified -or $contract.schemaVersion -ne 2) {
        [void]$result.failureReasons.Add('runtime-entrypoint-unverified')
        return [pscustomobject]$result
    }
    $closureHelper = Join-Path $PSScriptRoot 'service-runtime-closure.ps1'
    try {
        if (-not (Test-Path -LiteralPath $closureHelper -PathType Leaf)) { throw [IO.FileNotFoundException]::new('BridgeRuntimeClosureHelperMissing') }
        . $closureHelper
        $raw = [IO.File]::ReadAllText($contract.manifestPath, [Text.UTF8Encoding]::new($false, $true))
        $manifest = $raw | ConvertFrom-Json -ErrorAction Stop
        if (-not (Test-BridgeServiceClosureReceipt -ReleaseRoot $contract.releaseRoot -Manifest $manifest)) {
            [void]$result.failureReasons.Add('runtime-closure-unverified')
            return [pscustomobject]$result
        }
    } catch {
        [void]$result.failureReasons.Add('runtime-closure-unverified')
        return [pscustomobject]$result
    }
    $result.state = 'verified'; $result.verified = $true
    $result.serviceExecutable = $contract.serviceExecutable
    return [pscustomobject]$result
}

$buildHelper = Join-Path $PSScriptRoot 'service-runtime-build.ps1'
if (Test-Path -LiteralPath $buildHelper -PathType Leaf) {
    . $buildHelper
}

if (-not $LibraryMode) {
    if ($BuildRelease) {
        if ($null -eq (Get-Command Get-BridgeReleaseBuildPlan -ErrorAction SilentlyContinue)) {
            throw [IO.FileNotFoundException]::new('BridgeServiceRuntimeBuildHelperMissing')
        }
        $buildArguments = @{
            SourceRoot = $SourceRoot; ProgramRoot = $ProgramRoot; TrustedUvPath = $TrustedUvPath
            ExpectedSourceDigest = $ExpectedSourceDigest; ExpectedLockDigest = $ExpectedLockDigest
            ExpectedUvSha256 = $ExpectedUvSha256; TimeoutSeconds = $TimeoutSeconds
            InstallationContextPath = $InstallationContextPath
            InstallationContextSha256 = $InstallationContextSha256
        }
        $contract = if ($Apply) {
            Invoke-BridgeProtectedReleaseBuild @buildArguments
        } else {
            Get-BridgeReleaseBuildPlan @buildArguments
        }
        if ($Json) { $contract | ConvertTo-Json -Depth 12 -Compress } else { $contract }
        if ($contract.state -notin @('planned', 'built')) { exit 2 }
        return
    }
    if ([string]::IsNullOrWhiteSpace($ManifestPath) -or [string]::IsNullOrWhiteSpace($ReleaseRoot)) {
        throw [ArgumentException]::new('BridgeServiceRuntimeArgumentsRequired: ManifestPath and ReleaseRoot are required.')
    }
    try {
        $contract = Get-BridgeServiceRuntimeContract -ManifestPath $ManifestPath -ReleaseRoot $ReleaseRoot
    } catch {
        $contract = [pscustomobject][ordered]@{
            schemaVersion = 1; state = 'unverified'; verified = $false
            failureReasons = @('runtime-contract-unverified')
            manifestPath = $ManifestPath; releaseRoot = $ReleaseRoot; readOnly = $true
            authorizationReusable = $false
            warning = 'Read-only snapshot failed; no authorization may be inferred.'
        }
    }
    if ($Json) { $contract | ConvertTo-Json -Depth 8 -Compress } else { $contract }
    if (-not $contract.verified) { exit 2 }
}
