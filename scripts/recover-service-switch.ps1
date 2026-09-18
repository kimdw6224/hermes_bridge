[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]*\.ts\.net$')][string]$ServeHost,
    [string]$TransactionDirectory = '',
    [switch]$Apply,
    [switch]$Json,
    [switch]$LibraryMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:RecoveryScriptRoot = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\', '/')
$script:RecoveryRequiredDoctorChecks = @(
    'gateway_service', 'privileged_helper_service', 'backend_listener', 'bearer_auth',
    'interactive_worker', 'token_acl', 'tailscale', 'protected_service_runtime',
    'gateway_service_object_acl', 'gateway_service_registry_acl',
    'privileged_service_object_acl', 'privileged_service_registry_acl', 'privileged_tool_surface'
)
$script:RecoveryUnverifiedCriticalChecks = @('transport_policy', 'worker_pipe_acl', 'privileged_pipe_acl')

function Get-BridgeRecoveryProgramDataRoot {
    [CmdletBinding()]
    param()
    if ([string]::IsNullOrWhiteSpace([string]$env:ProgramData)) {
        return [Environment]::GetFolderPath('CommonApplicationData')
    }
    return [IO.Path]::GetFullPath([string]$env:ProgramData).TrimEnd('\', '/')
}

function Get-BridgeRecoveryServiceProgramRoot {
    [CmdletBinding()]
    param()
    return [IO.Path]::Combine([Environment]::GetFolderPath('ProgramFiles'), 'HermesWindowsBridge')
}

function Test-BridgeRecoveryAdministrator {
    [CmdletBinding()]
    param()
    return [bool](& {
        param($CommonPath)
        . $CommonPath
        Test-BridgeAdministrator
    } (Join-Path $script:RecoveryScriptRoot 'lifecycle-common.ps1'))
}

function Get-BridgeRecoverySha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($algorithm.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
    }
}

function Test-BridgeRecoveryBytesEqual {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Left, [Parameter(Mandatory)][byte[]]$Right)
    if ($Left.Length -ne $Right.Length) { return $false }
    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -ne $Right[$index]) { return $false }
    }
    return $true
}

function Test-BridgeRecoveryExactFields {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Value, [Parameter(Mandatory)][string[]]$Required)
    $actual = @($Value.PSObject.Properties | ForEach-Object { [string]$_.Name } | Sort-Object)
    $expected = @($Required | Sort-Object)
    return $actual.Count -eq $expected.Count -and (($actual -join ',') -ceq ($expected -join ','))
}

function ConvertFrom-BridgeRecoveryJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][string]$Name)
    if ($Bytes.Length -eq 0 -or $Bytes.Length -gt 1048576) {
        throw [IO.InvalidDataException]::new("BridgeRecovery${Name}SizeInvalid")
    }
    try {
        $raw = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
        return $raw | ConvertFrom-Json -ErrorAction Stop
    } catch [Management.Automation.RuntimeException], [Text.DecoderFallbackException] {
        throw [IO.InvalidDataException]::new("BridgeRecovery${Name}JsonInvalid", $_.Exception)
    }
}

function Read-BridgeRecoveryFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw [Security.SecurityException]::new("BridgeRecovery${Name}Unsafe")
    }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -gt 1048576) { throw [IO.InvalidDataException]::new("BridgeRecovery${Name}SizeInvalid") }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) { throw [IO.EndOfStreamException]::new("BridgeRecovery${Name}ReadIncomplete") }
            $offset += $read
        }
        return $bytes
    } finally {
        $stream.Dispose()
    }
}

function Test-BridgeRecoveryProtectedPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Root)
    $runtimePath = Join-Path $script:RecoveryScriptRoot 'service-runtime.ps1'
    if (-not (Test-Path -LiteralPath $runtimePath -PathType Leaf)) { return $false }
    try {
        return [bool](& {
            param($RuntimePath, $CandidatePath, $AllowedRoot)
            . $RuntimePath -LibraryMode
            $item = Get-Item -LiteralPath $CandidatePath -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                -not (Test-BridgePathReparseFree -Root $AllowedRoot -Path $CandidatePath) -or
                $null -ne (Test-BridgeTreeAcl -Path $CandidatePath -RequireTrustedOwner $true)) {
                return $false
            }
            if (-not $item.PSIsContainer -and (Get-BridgeFileLinkCount -Path $CandidatePath) -ne 1) {
                return $false
            }
            return $true
        } $runtimePath $Path $Root)
    } catch [Security.SecurityException], [UnauthorizedAccessException], [IO.IOException], [Management.Automation.RuntimeException] {
        return $false
    }
}

function Test-BridgeRecoveryAncestorsNoReparse {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Path)
    try {
        $safeRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
        $safePath = [IO.Path]::GetFullPath($Path)
        if (-not $safePath.StartsWith(($safeRoot + '\'), [StringComparison]::OrdinalIgnoreCase) -and
            -not $safePath.Equals($safeRoot, [StringComparison]::OrdinalIgnoreCase)) { return $false }
        $current = $safeRoot
        while ($true) {
            if (((Get-Item -LiteralPath $current -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                return $false
            }
            if ($current.Equals($safePath, [StringComparison]::OrdinalIgnoreCase)) { return $true }
            $relative = $safePath.Substring($current.Length).TrimStart('\')
            $next = $relative.Split('\')[0]
            $current = Join-Path $current $next
        }
    } catch [UnauthorizedAccessException], [IO.IOException], [Management.Automation.RuntimeException] {
        return $false
    }
}

function Test-BridgeRecoveryDataRootBoundary {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DataRoot)
    try {
        $item = Get-Item -LiteralPath $DataRoot -Force -ErrorAction Stop
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
        $acl = Get-Acl -LiteralPath $DataRoot -ErrorAction Stop
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
        if ($null -eq $descriptor.DiscretionaryAcl) { return $false }
        $owner = ([Security.Principal.NTAccount]::new([string]$acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin @('S-1-5-18', 'S-1-5-32-544')) { return $false }
        $replacementRights = [Security.AccessControl.FileSystemRights]::Delete -bor
            [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
            [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
            [Security.AccessControl.FileSystemRights]::TakeOwnership
        foreach ($rule in @($acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' -and
                ($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 })) {
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            if ($sid -notin @('S-1-5-18', 'S-1-5-32-544') -and ($rule.FileSystemRights -band $replacementRights) -ne 0) {
                return $false
            }
        }
        return $true
    } catch [UnauthorizedAccessException], [IO.IOException], [Management.Automation.RuntimeException] {
        return $false
    }
}

function Test-BridgeRecoveryJournalParentBoundary {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
        if ($null -eq $descriptor.DiscretionaryAcl) { return $false }
        $owner = ([Security.Principal.NTAccount]::new([string]$acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin @('S-1-5-18', 'S-1-5-32-544')) { return $false }
        $accessSddl = $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
        if (-not $accessSddl.StartsWith('D:', [StringComparison]::Ordinal)) { return $false }
        $replacementRights = [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
            [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
        $writeRights = [Security.AccessControl.FileSystemRights]::WriteData -bor
            [Security.AccessControl.FileSystemRights]::AppendData -bor [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
            [Security.AccessControl.FileSystemRights]::WriteAttributes -bor [Security.AccessControl.FileSystemRights]::Delete -bor $replacementRights
        $localServiceRights = [int64]([Security.AccessControl.FileSystemRights]::Modify -bor [Security.AccessControl.FileSystemRights]::Synchronize)
        foreach ($rule in @($acl.Access | Where-Object {
                $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                ($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0
            })) {
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            if ($sid -in @('S-1-5-18', 'S-1-5-32-544')) { continue }
            if ($sid -ceq 'S-1-5-19' -and [int64]$rule.FileSystemRights -eq $localServiceRights) { continue }
            if (($rule.FileSystemRights -band $writeRights) -ne 0) {
                return $false
            }
        }
        return $true
    } catch [UnauthorizedAccessException], [IO.IOException], [Management.Automation.RuntimeException] {
        return $false
    }
}

function Assert-BridgeRecoveryJournalParentBoundaries {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Paths)
    if (-not (Test-BridgeRecoveryDataRootBoundary -DataRoot $Paths.dataRoot) -or
        -not (Test-BridgeRecoveryAncestorsNoReparse -Root $Paths.dataRoot -Path $Paths.transactionDirectory) -or
        -not (Test-BridgeRecoveryJournalParentBoundary -Path $Paths.bridgeRoot) -or
        -not (Test-BridgeRecoveryJournalParentBoundary -Path $Paths.backupsRoot)) {
        throw [Security.SecurityException]::new('BridgeRecoveryJournalPathUnprotected')
    }
}

function Initialize-BridgeRecoveryDirectoryPinApi {
    [CmdletBinding()]
    param()
    if ($null -ne ('HermesBridge.RecoveryDirectoryPin' -as [type])) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace HermesBridge {
  public static class RecoveryDirectoryPin {
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation {
      public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
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
    public static SafeFileHandle Open(string path) {
      SafeFileHandle handle = CreateFile(path, 0x00020081, 0x00000003, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
      if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
      FileInformation info;
      if (!GetFileInformationByHandle(handle, out info)) { handle.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error()); }
      if ((info.Attributes & 0x10) == 0 || (info.Attributes & 0x400) != 0) { handle.Dispose(); throw new IOException("BridgeRecoveryDirectoryPinUnsafe"); }
      return handle;
    }
  }
}
'@
}

function Enter-BridgeRecoveryDirectoryPins {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Paths)
    Initialize-BridgeRecoveryDirectoryPinApi
    $handles = [Collections.Generic.List[object]]::new()
    try {
        foreach ($path in @($Paths.dataRoot, $Paths.bridgeRoot, $Paths.backupsRoot, $Paths.transactionDirectory)) {
            $handles.Add([HermesBridge.RecoveryDirectoryPin]::Open([string]$path))
        }
        return $handles
    } catch {
        for ($index = $handles.Count - 1; $index -ge 0; $index--) { $handles[$index].Dispose() }
        throw [IO.IOException]::new('BridgeRecoveryDirectoryPinFailed', $_.Exception)
    }
}

function Assert-BridgeRecoveryDirectoryPinsHeld {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Pins)
    if ($Pins.Count -ne 4 -or @($Pins | Where-Object { $_.IsInvalid -or $_.IsClosed }).Count -ne 0) {
        throw [Security.SecurityException]::new('BridgeRecoveryDirectoryPinsRequired')
    }
}

function Assert-BridgeRecoveryJournalSecurity {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Paths, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Pins)
    Assert-BridgeRecoveryDirectoryPinsHeld -Pins $Pins
    Assert-BridgeRecoveryJournalParentBoundaries -Paths $Paths
    foreach ($path in @($Paths.transactionDirectory, $Paths.statePath)) {
        if (-not (Test-BridgeRecoveryProtectedPath -Path $path -Root $Paths.dataRoot)) {
            throw [Security.SecurityException]::new('BridgeRecoveryJournalPathUnprotected')
        }
    }
}

function Test-BridgeRecoveryRuntimeFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Paths)
    try {
        if (-not (Test-BridgeRecoveryJournalParentBoundary -Path $Paths.bridgeRoot) -or
            -not (Test-BridgeRecoveryAncestorsNoReparse -Root $Paths.dataRoot -Path $Path)) { return $false }
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
        $runtimePath = Join-Path $script:RecoveryScriptRoot 'service-runtime.ps1'
        $linkCount = & {
            param($RuntimePath, $CandidatePath)
            . $RuntimePath -LibraryMode
            Get-BridgeFileLinkCount -Path $CandidatePath
        } $runtimePath $Path
        if ($linkCount -ne 1) { return $false }
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
        if ($null -eq $descriptor.DiscretionaryAcl) { return $false }
        $owner = ([Security.Principal.NTAccount]::new([string]$acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin @('S-1-5-18', 'S-1-5-32-544')) { return $false }
        $writeRights = [Security.AccessControl.FileSystemRights]::WriteData -bor
            [Security.AccessControl.FileSystemRights]::AppendData -bor [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
            [Security.AccessControl.FileSystemRights]::WriteAttributes -bor [Security.AccessControl.FileSystemRights]::Delete -bor
            [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
        foreach ($rule in @($acl.Access | Where-Object {
                $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                ($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0
            })) {
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            if ($sid -notin @('S-1-5-18', 'S-1-5-19', 'S-1-5-32-544') -and ($rule.FileSystemRights -band $writeRights) -ne 0) {
                return $false
            }
        }
        return $true
    } catch [Security.SecurityException], [UnauthorizedAccessException], [IO.IOException], [Management.Automation.RuntimeException] {
        return $false
    }
}

function Get-BridgeRecoveryJournalPaths {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$StatePath)
    $dataRoot = Get-BridgeRecoveryProgramDataRoot
    $bridgeRoot = [IO.Path]::Combine($dataRoot, 'HermesWindowsBridge')
    $backupsRoot = [IO.Path]::Combine($bridgeRoot, 'backups')
    $canonicalState = [IO.Path]::GetFullPath($StatePath)
    $transactionDirectory = Split-Path -Parent $canonicalState
    $transactionName = Split-Path -Leaf $transactionDirectory
    if ($transactionName -cnotmatch '^install-[a-f0-9]{32}$' -or
        -not (Split-Path -Leaf $canonicalState).Equals('state.json', [StringComparison]::Ordinal) -or
        -not $transactionDirectory.Equals([IO.Path]::Combine($backupsRoot, $transactionName), [StringComparison]::OrdinalIgnoreCase)) {
        throw [Security.SecurityException]::new('BridgeRecoveryJournalPathInvalid')
    }
    if (-not (Test-Path -LiteralPath $dataRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $bridgeRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $backupsRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $transactionDirectory -PathType Container)) {
        throw [IO.DirectoryNotFoundException]::new('BridgeRecoveryJournalDirectoryMissing')
    }
    $paths = [pscustomobject]@{
        dataRoot = $dataRoot; bridgeRoot = $bridgeRoot; backupsRoot = $backupsRoot
        transactionDirectory = $transactionDirectory; statePath = $canonicalState
        originalStatePath = [IO.Path]::Combine($transactionDirectory, 'original-state.json')
        definitionsPath = [IO.Path]::Combine($transactionDirectory, 'service-definitions.json')
    }
    return $paths
}

function Test-BridgeRecoveryRunningState {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$State)
    if (-not (Test-BridgeRecoveryExactFields -Value $State -Required @('schemaVersion', 'status', 'startedUtc')) -or
        $State.schemaVersion -isnot [int] -or $State.schemaVersion -ne 1 -or [string]$State.status -cne 'running') {
        return $false
    }
    $parsed = [DateTime]::MinValue
    return [DateTime]::TryParse([string]$State.startedUtc, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind, [ref]$parsed)
}

function Get-BridgeRecoveryDefinitions {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $definitions = ConvertFrom-BridgeRecoveryJson -Bytes $Bytes -Name 'Definitions'
    if (-not (Test-BridgeRecoveryExactFields -Value $definitions -Required @('schemaVersion', 'releaseId', 'manifestSha256', 'pairState', 'definitions')) -or
        $definitions.schemaVersion -isnot [int] -or $definitions.schemaVersion -ne 1 -or
        [string]$definitions.releaseId -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$definitions.manifestSha256 -cnotmatch '^[a-f0-9]{64}$' -or [string]$definitions.pairState -cne 'safe-pair' -or
        @($definitions.definitions).Count -ne 2) {
        throw [IO.InvalidDataException]::new('BridgeRecoveryDefinitionsInvalid')
    }
    $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($definition in @($definitions.definitions)) {
        if (-not (Test-BridgeRecoveryExactFields -Value $definition -Required @('name', 'pathName', 'account', 'startMode', 'running', 'recoveryExact')) -or
            -not $names.Add([string]$definition.name) -or [string]::IsNullOrWhiteSpace([string]$definition.pathName) -or
            [string]::IsNullOrWhiteSpace([string]$definition.account) -or [string]::IsNullOrWhiteSpace([string]$definition.startMode) -or
            $definition.running -isnot [bool] -or -not [bool]$definition.running -or
            $definition.recoveryExact -isnot [bool] -or -not [bool]$definition.recoveryExact) {
            throw [IO.InvalidDataException]::new('BridgeRecoveryDefinitionsInvalid')
        }
    }
    if ($names.Count -ne 2 -or -not $names.Contains('HermesWindowsBridgeGateway') -or
        -not $names.Contains('HermesWindowsBridgePrivileged')) {
        throw [IO.InvalidDataException]::new('BridgeRecoveryDefinitionsInvalid')
    }
    return $definitions
}

function Get-BridgeRecoveryPointer {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ServiceProgramRoot, [Parameter(Mandatory)]$Definitions)
    $programRoot = [IO.Path]::GetFullPath($ServiceProgramRoot).TrimEnd('\', '/')
    $pointerPath = [IO.Path]::Combine($programRoot, 'active-release.json')
    if (-not (Test-BridgeRecoveryProtectedPath -Path $programRoot -Root ([Environment]::GetFolderPath('ProgramFiles'))) -or
        -not (Test-BridgeRecoveryProtectedPath -Path $pointerPath -Root ([Environment]::GetFolderPath('ProgramFiles')))) {
        throw [Security.SecurityException]::new('BridgeRecoveryPointerUnprotected')
    }
    $bytes = Read-BridgeRecoveryFile -Path $pointerPath -Name 'Pointer'
    $pointer = ConvertFrom-BridgeRecoveryJson -Bytes $bytes -Name 'Pointer'
    $expectedRelease = [IO.Path]::Combine($programRoot, 'releases', [string]$Definitions.releaseId)
    if (-not (Test-BridgeRecoveryExactFields -Value $pointer -Required @('schemaVersion', 'releaseRoot', 'manifestSha256')) -or
        $pointer.schemaVersion -isnot [int] -or $pointer.schemaVersion -ne 1 -or
        -not ([IO.Path]::GetFullPath([string]$pointer.releaseRoot).TrimEnd('\', '/')).Equals($expectedRelease, [StringComparison]::OrdinalIgnoreCase) -or
        [string]$pointer.manifestSha256 -cne [string]$Definitions.manifestSha256) {
        throw [Security.SecurityException]::new('BridgeRecoveryPointerBaselineMismatch')
    }
    return [pscustomobject]@{ path = $pointerPath; bytes = $bytes; sha256 = Get-BridgeRecoverySha256 -Bytes $bytes; value = $pointer }
}

function Get-BridgeRecoveryWorkerFingerprint {
    [CmdletBinding()]
    param()
    try {
        $xml = Export-ScheduledTask -TaskName 'HermesWindowsBridgeWorker' -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace([string]$xml)) { throw [IO.InvalidDataException]::new('BridgeRecoveryWorkerMissing') }
        return Get-BridgeRecoverySha256 -Bytes ([Text.UTF8Encoding]::new($false).GetBytes([string]$xml))
    } catch [Management.Automation.CommandNotFoundException], [UnauthorizedAccessException], [IO.IOException], [Management.Automation.RuntimeException] {
        throw [Security.SecurityException]::new('BridgeRecoveryWorkerUnverified', $_.Exception)
    }
}

function Get-BridgeRecoveryConfigFingerprint {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Paths)
    $parts = [Collections.Generic.List[string]]::new()
    foreach ($name in @('config.yaml', 'policy.yaml')) {
        $path = [IO.Path]::Combine($Paths.bridgeRoot, $name)
        if (-not (Test-BridgeRecoveryRuntimeFile -Path $path -Paths $Paths)) {
            throw [Security.SecurityException]::new('BridgeRecoveryConfigUnprotected')
        }
        $bytes = Read-BridgeRecoveryFile -Path $path -Name 'Config'
        if ($bytes.Length -eq 0) { throw [IO.InvalidDataException]::new('BridgeRecoveryConfigEmpty') }
        $parts.Add((Get-BridgeRecoverySha256 -Bytes $bytes))
    }
    return Get-BridgeRecoverySha256 -Bytes ([Text.UTF8Encoding]::new($false).GetBytes(($parts -join ':')))
}

function Enter-BridgeRecoveryReadLock {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ServiceProgramRoot)
    $lockPath = [IO.Path]::Combine($ServiceProgramRoot, 'service-release.lock')
    if (-not (Test-BridgeRecoveryProtectedPath -Path $lockPath -Root ([Environment]::GetFolderPath('ProgramFiles')))) {
        throw [Security.SecurityException]::new('BridgeRecoveryLockUnprotected')
    }
    try {
        return [IO.File]::Open($lockPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    } catch [IO.IOException] {
        throw [IO.IOException]::new('BridgeServiceReleaseTransactionBusy', $_.Exception)
    }
}

function Get-BridgeRecoveryServicePairInspection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ServiceProgramRoot, [Parameter(Mandatory)]$Definitions)
    $runtimePath = Join-Path $script:RecoveryScriptRoot 'service-runtime.ps1'
    $transactionPath = Join-Path $script:RecoveryScriptRoot 'service-runtime-transaction.ps1'
    return & {
        param($CommonPath, $RuntimePath, $TransactionPath, $SelectedProgramRoot, $ExpectedDefinitions)
        . $CommonPath
        . $RuntimePath -LibraryMode
        . $TransactionPath
        $release = Resolve-BridgeServiceReleaseSelection -ProgramRoot $SelectedProgramRoot
        if ([string]$release.releaseId -cne [string]$ExpectedDefinitions.releaseId -or
            [string]$release.manifestSha256 -cne [string]$ExpectedDefinitions.manifestSha256) {
            throw [Security.SecurityException]::new('BridgeRecoveryReleaseBaselineMismatch')
        }
        Get-BridgeServicePairInspection -ScriptRoot $script:RecoveryScriptRoot -Release $release
    } (Join-Path $script:RecoveryScriptRoot 'lifecycle-common.ps1') $runtimePath $transactionPath $ServiceProgramRoot $Definitions
}

function Test-BridgeRecoveryPairBaseline {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Inspection, [Parameter(Mandatory)]$Definitions)
    if ([string]$Inspection.previousState -cne 'safe-pair' -or @($Inspection.definitions).Count -ne 2) { return $false }
    $expected = @($Definitions.definitions | Sort-Object name)
    $observed = @($Inspection.definitions | Sort-Object name)
    if ($expected.Count -ne $observed.Count) { return $false }
    for ($index = 0; $index -lt $expected.Count; $index++) {
        if ([string]$expected[$index].name -cne [string]$observed[$index].name) { return $false }
        foreach ($field in @('pathName', 'account', 'startMode', 'running', 'recoveryExact')) {
            if ([string]$expected[$index].$field -cne [string]$observed[$index].observedDefinition.$field) { return $false }
        }
    }
    return $true
}

function Get-BridgeRecoveryDoctorReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ServeHost)
    $doctorPath = Join-Path $script:RecoveryScriptRoot 'doctor.ps1'
    if (-not (Test-Path -LiteralPath $doctorPath -PathType Leaf)) { throw [IO.FileNotFoundException]::new('BridgeRecoveryDoctorMissing') }
    $result = & {
        param($CommonPath, $Doctor, $TargetHost)
        . $CommonPath
        Invoke-BridgeChildProcess -FilePath ([IO.Path]::Combine($PSHOME, 'powershell.exe')) -ArgumentList @(
            '-NoProfile', '-NonInteractive', '-File', $Doctor, '-Security', '-Json', '-ServeHost', $TargetHost
        ) -WorkingDirectory (Split-Path -Parent $Doctor) -TimeoutSeconds 180
    } (Join-Path $script:RecoveryScriptRoot 'lifecycle-common.ps1') $doctorPath $ServeHost
    if ($result.exitCode -ne 0 -or [string]::IsNullOrWhiteSpace([string]$result.stdout)) {
        throw [Security.SecurityException]::new('BridgeRecoveryDoctorFailed')
    }
    try { return $result.stdout | ConvertFrom-Json -ErrorAction Stop }
    catch [Management.Automation.RuntimeException] { throw [IO.InvalidDataException]::new('BridgeRecoveryDoctorJsonInvalid', $_.Exception) }
}

function Get-BridgeRecoveryHealthSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Report)
    if ($Report.schemaVersion -isnot [int] -or $Report.schemaVersion -ne 1 -or
        [string]$Report.kind -cne 'hermes-windows-bridge-doctor' -or $Report.readOnly -isnot [bool] -or -not [bool]$Report.readOnly -or
        $Report.securityMode -isnot [bool] -or -not [bool]$Report.securityMode -or
        $null -eq $Report.PSObject.Properties['healthy'] -or $Report.healthy -isnot [bool] -or -not [bool]$Report.healthy) {
        throw [Security.SecurityException]::new('BridgeRecoveryDoctorContractInvalid')
    }
    $checks = @($Report.checks)
    $required = @()
    foreach ($id in $script:RecoveryRequiredDoctorChecks) {
        $matching = @($checks | Where-Object { [string]$_.id -ceq $id })
        if ($matching.Count -ne 1 -or [string]$matching[0].status -cne 'pass' -or $matching[0].critical -isnot [bool] -or -not [bool]$matching[0].critical) {
            throw [Security.SecurityException]::new("BridgeRecoveryDoctorCheckFailed:$id")
        }
        $required += $id
    }
    $criticalWarnings = @($checks | Where-Object { $_.critical -eq $true -and [string]$_.status -ceq 'warn' } |
        ForEach-Object { [string]$_.id } | Sort-Object -Unique)
    if (@($criticalWarnings | Where-Object { $_ -notin $script:RecoveryUnverifiedCriticalChecks }).Count -ne 0) {
        throw [Security.SecurityException]::new('BridgeRecoveryUnexpectedCriticalWarning')
    }
    return [pscustomobject]@{ requiredDoctorChecks = $required; unverifiedCriticalWarnings = $criticalWarnings }
}

function Get-BridgeRecoverySnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Paths,
        [Parameter(Mandatory)][string]$ServiceProgramRoot,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Pins
    )
    Assert-BridgeRecoveryJournalSecurity -Paths $Paths -Pins $Pins
    $stateBytes = Read-BridgeRecoveryFile -Path $Paths.statePath -Name 'State'
    $state = ConvertFrom-BridgeRecoveryJson -Bytes $stateBytes -Name 'State'
    if (-not (Test-BridgeRecoveryRunningState -State $state)) { throw [Security.SecurityException]::new('BridgeRecoveryJournalNotRunning') }
    if (-not (Test-BridgeRecoveryProtectedPath -Path $Paths.definitionsPath -Root $Paths.dataRoot)) {
        throw [Security.SecurityException]::new('BridgeRecoveryDefinitionsUnprotected')
    }
    $definitionBytes = Read-BridgeRecoveryFile -Path $Paths.definitionsPath -Name 'Definitions'
    $definitions = Get-BridgeRecoveryDefinitions -Bytes $definitionBytes
    $pointer = Get-BridgeRecoveryPointer -ServiceProgramRoot $ServiceProgramRoot -Definitions $definitions
    $originalStateSha = $null
    if (Test-Path -LiteralPath $Paths.originalStatePath -PathType Leaf) {
        if (-not (Test-BridgeRecoveryProtectedPath -Path $Paths.originalStatePath -Root $Paths.dataRoot)) {
            throw [Security.SecurityException]::new('BridgeRecoveryOriginalArchiveUnprotected')
        }
        $originalBytes = Read-BridgeRecoveryFile -Path $Paths.originalStatePath -Name 'OriginalState'
        if ((Get-BridgeRecoverySha256 -Bytes $originalBytes) -cne (Get-BridgeRecoverySha256 -Bytes $stateBytes)) {
            throw [Security.SecurityException]::new('BridgeRecoveryOriginalArchiveConflict')
        }
        $originalStateSha = Get-BridgeRecoverySha256 -Bytes $originalBytes
    }
    return [pscustomobject]@{
        stateBytes = $stateBytes; stateSha256 = Get-BridgeRecoverySha256 -Bytes $stateBytes; state = $state
        definitionBytes = $definitionBytes; definitionSha256 = Get-BridgeRecoverySha256 -Bytes $definitionBytes; definitions = $definitions
        pointerBytes = $pointer.bytes; pointerSha256 = $pointer.sha256; pointer = $pointer.value
        workerFingerprint = Get-BridgeRecoveryWorkerFingerprint; configFingerprint = Get-BridgeRecoveryConfigFingerprint -Paths $Paths
        originalStateSha256 = $originalStateSha
    }
}

function Assert-BridgeRecoverySnapshotUnchanged {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)]$Paths,
        [Parameter(Mandatory)][string]$ServiceProgramRoot,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Pins,
        [switch]$AllowOriginalArchive
    )
    $current = Get-BridgeRecoverySnapshot -Paths $Paths -ServiceProgramRoot $ServiceProgramRoot -Pins $Pins
    $originalMatches = [string]$current.originalStateSha256 -ceq [string]$Snapshot.originalStateSha256
    if ($AllowOriginalArchive -and $null -eq $Snapshot.originalStateSha256 -and
        [string]$current.originalStateSha256 -ceq [string]$Snapshot.stateSha256) {
        $originalMatches = $true
    }
    if ($current.stateSha256 -cne $Snapshot.stateSha256 -or $current.definitionSha256 -cne $Snapshot.definitionSha256 -or
        $current.pointerSha256 -cne $Snapshot.pointerSha256 -or $current.workerFingerprint -cne $Snapshot.workerFingerprint -or
        $current.configFingerprint -cne $Snapshot.configFingerprint -or
        -not $originalMatches) {
        throw [IO.IOException]::new('BridgeRecoveryConcurrentStateChanged')
    }
}

function Save-BridgeRecoveryOriginalState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Paths,
        [Parameter(Mandatory)][byte[]]$StateBytes,
        [Parameter(Mandatory)][string]$StateSha256,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Pins
    )
    Assert-BridgeRecoveryDirectoryPinsHeld -Pins $Pins
    if (Test-Path -LiteralPath $Paths.originalStatePath -PathType Leaf) {
        if (-not (Test-BridgeRecoveryProtectedPath -Path $Paths.originalStatePath -Root $Paths.dataRoot)) {
            throw [Security.SecurityException]::new('BridgeRecoveryOriginalArchiveUnprotected')
        }
    } else {
        try {
            $stream = [IO.File]::Open($Paths.originalStatePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $stream.Write($StateBytes, 0, $StateBytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        } catch [IO.IOException] {
            if (-not (Test-Path -LiteralPath $Paths.originalStatePath -PathType Leaf)) { throw }
        }
    }
    if (-not (Test-BridgeRecoveryProtectedPath -Path $Paths.originalStatePath -Root $Paths.dataRoot)) {
        throw [Security.SecurityException]::new('BridgeRecoveryOriginalArchiveUnprotected')
    }
    $archiveBytes = Read-BridgeRecoveryFile -Path $Paths.originalStatePath -Name 'OriginalState'
    if ((Get-BridgeRecoverySha256 -Bytes $archiveBytes) -cne $StateSha256 -or
        $archiveBytes.Length -ne $StateBytes.Length -or -not (Test-BridgeRecoveryBytesEqual -Left $archiveBytes -Right $StateBytes)) {
        throw [Security.SecurityException]::new('BridgeRecoveryOriginalArchiveConflict')
    }
}

function Get-BridgeRecoveryTerminalBody {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Snapshot, [Parameter(Mandatory)]$Health)
    return ([ordered]@{
        schemaVersion = 1; status = 'recovered'; recoveryVerified = $true
        previousReleaseId = [string]$Snapshot.definitions.releaseId
        previousManifestSha256 = [string]$Snapshot.definitions.manifestSha256
        originalStateFile = 'original-state.json'; originalStateSha256 = [string]$Snapshot.stateSha256
        recoveredUtc = [DateTime]::UtcNow.ToString('O')
        verification = [ordered]@{
            activePointerSha256 = [string]$Snapshot.pointerSha256
            serviceDefinitionsSha256 = [string]$Snapshot.definitionSha256
            configFingerprint = [string]$Snapshot.configFingerprint
            configTrust = 'runtime-localservice-modify'
            requiredDoctorChecks = @($Health.requiredDoctorChecks)
            unverifiedCriticalWarnings = @($Health.unverifiedCriticalWarnings)
        }
    } | ConvertTo-Json -Depth 6 -Compress)
}

function Publish-BridgeRecoveryTerminalState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Paths,
        [Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)][string]$Body,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Pins
    )
    Assert-BridgeRecoveryDirectoryPinsHeld -Pins $Pins
    $temporaryPath = [IO.Path]::Combine($Paths.transactionDirectory, ('state.recovery.{0}.tmp' -f [guid]::NewGuid().ToString('N')))
    try {
        [IO.File]::WriteAllText($temporaryPath, $Body, [Text.UTF8Encoding]::new($false))
        if (-not (Test-BridgeRecoveryProtectedPath -Path $temporaryPath -Root $Paths.dataRoot)) {
            throw [Security.SecurityException]::new('BridgeRecoveryTerminalTemporaryUnprotected')
        }
        Assert-BridgeRecoverySnapshotUnchanged -Snapshot $Snapshot -Paths $Paths -ServiceProgramRoot (Get-BridgeRecoveryServiceProgramRoot) -Pins $Pins
        [IO.File]::Replace($temporaryPath, $Paths.statePath, [System.Management.Automation.Language.NullString]::Value, $true)
    } finally {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) { [IO.File]::Delete($temporaryPath) }
    }
}

function Test-BridgeRecoveredJournal {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$StatePath)
    $pins = $null
    try {
        $paths = Get-BridgeRecoveryJournalPaths -StatePath $StatePath
        $pins = @(Enter-BridgeRecoveryDirectoryPins -Paths $paths)
        Assert-BridgeRecoveryJournalSecurity -Paths $paths -Pins $pins
        $stateBytes = Read-BridgeRecoveryFile -Path $paths.statePath -Name 'State'
        $state = ConvertFrom-BridgeRecoveryJson -Bytes $stateBytes -Name 'State'
        $stateFields = @('schemaVersion', 'status', 'recoveryVerified', 'previousReleaseId', 'previousManifestSha256', 'originalStateFile', 'originalStateSha256', 'recoveredUtc', 'verification')
        if (-not (Test-BridgeRecoveryExactFields -Value $state -Required $stateFields) -or $state.schemaVersion -isnot [int] -or
            $state.schemaVersion -ne 1 -or [string]$state.status -cne 'recovered' -or $state.recoveryVerified -isnot [bool] -or
            -not [bool]$state.recoveryVerified -or [string]$state.previousReleaseId -cnotmatch '^[a-f0-9]{64}$' -or
            [string]$state.previousManifestSha256 -cnotmatch '^[a-f0-9]{64}$' -or [string]$state.originalStateFile -cne 'original-state.json' -or
            [string]$state.originalStateSha256 -cnotmatch '^[a-f0-9]{64}$') { return $false }
        $recoveredUtc = [DateTime]::MinValue
        if (-not [DateTime]::TryParse([string]$state.recoveredUtc, [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind, [ref]$recoveredUtc)) { return $false }
        if (-not (Test-BridgeRecoveryProtectedPath -Path $paths.originalStatePath -Root $paths.dataRoot)) { return $false }
        $originalBytes = Read-BridgeRecoveryFile -Path $paths.originalStatePath -Name 'OriginalState'
        $original = ConvertFrom-BridgeRecoveryJson -Bytes $originalBytes -Name 'OriginalState'
        if (-not (Test-BridgeRecoveryRunningState -State $original) -or
            (Get-BridgeRecoverySha256 -Bytes $originalBytes) -cne [string]$state.originalStateSha256) { return $false }
        if (-not (Test-BridgeRecoveryProtectedPath -Path $paths.definitionsPath -Root $paths.dataRoot)) { return $false }
        $definitionBytes = Read-BridgeRecoveryFile -Path $paths.definitionsPath -Name 'Definitions'
        $definitions = Get-BridgeRecoveryDefinitions -Bytes $definitionBytes
        if ([string]$definitions.releaseId -cne [string]$state.previousReleaseId -or
            [string]$definitions.manifestSha256 -cne [string]$state.previousManifestSha256) { return $false }
        $verification = $state.verification
        if (-not (Test-BridgeRecoveryExactFields -Value $verification -Required @('activePointerSha256', 'serviceDefinitionsSha256', 'configFingerprint', 'configTrust', 'requiredDoctorChecks', 'unverifiedCriticalWarnings')) -or
            [string]$verification.activePointerSha256 -cnotmatch '^[a-f0-9]{64}$' -or
            [string]$verification.serviceDefinitionsSha256 -cne (Get-BridgeRecoverySha256 -Bytes $definitionBytes) -or
            [string]$verification.configFingerprint -cnotmatch '^[a-f0-9]{64}$' -or [string]$verification.configTrust -cne 'runtime-localservice-modify' -or
            (@($verification.requiredDoctorChecks) -join ',') -cne ($script:RecoveryRequiredDoctorChecks -join ',')) { return $false }
        $invalidWarnings = @($verification.unverifiedCriticalWarnings | Where-Object { $_ -notin $script:RecoveryUnverifiedCriticalChecks })
        if ($invalidWarnings.Count -ne 0) { return $false }
        return $true
    } catch [Security.SecurityException], [UnauthorizedAccessException], [IO.IOException], [IO.InvalidDataException], [Management.Automation.RuntimeException] {
        return $false
    } finally {
        if ($null -ne $pins) {
            for ($index = $pins.Count - 1; $index -ge 0; $index--) { $pins[$index].Dispose() }
        }
    }
}

function Invoke-BridgeServiceSwitchRecovery {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$TransactionDirectory,
        [Parameter(Mandatory)][string]$ServeHost,
        [switch]$Apply
    )
    $paths = Get-BridgeRecoveryJournalPaths -StatePath ([IO.Path]::Combine($TransactionDirectory, 'state.json'))
    $serviceProgramRoot = Get-BridgeRecoveryServiceProgramRoot
    $pins = @(Enter-BridgeRecoveryDirectoryPins -Paths $paths)
    try {
        Assert-BridgeRecoveryJournalSecurity -Paths $paths -Pins $pins
        $lock = Enter-BridgeRecoveryReadLock -ServiceProgramRoot $serviceProgramRoot
        try {
            $snapshot = Get-BridgeRecoverySnapshot -Paths $paths -ServiceProgramRoot $serviceProgramRoot -Pins $pins
            $inspection = Get-BridgeRecoveryServicePairInspection -ServiceProgramRoot $serviceProgramRoot -Definitions $snapshot.definitions
            if (-not (Test-BridgeRecoveryPairBaseline -Inspection $inspection -Definitions $snapshot.definitions)) {
                throw [Security.SecurityException]::new('BridgeRecoveryServiceBaselineMismatch')
            }
            $health = Get-BridgeRecoveryHealthSummary -Report (Get-BridgeRecoveryDoctorReport -ServeHost $ServeHost)
            Assert-BridgeRecoverySnapshotUnchanged -Snapshot $snapshot -Paths $paths -ServiceProgramRoot $serviceProgramRoot -Pins $pins -AllowOriginalArchive
            $readBack = Get-BridgeRecoveryServicePairInspection -ServiceProgramRoot $serviceProgramRoot -Definitions $snapshot.definitions
            if (-not (Test-BridgeRecoveryPairBaseline -Inspection $readBack -Definitions $snapshot.definitions)) {
                throw [Security.SecurityException]::new('BridgeRecoveryServiceBaselineChanged')
            }
            $result = [ordered]@{
                schemaVersion = 1; state = 'recovery-verified'; applied = $false; readOnly = (-not $Apply)
                transactionDirectory = $paths.transactionDirectory; previousReleaseId = $snapshot.definitions.releaseId
                previousManifestSha256 = $snapshot.definitions.manifestSha256; configFingerprint = $snapshot.configFingerprint
                configTrust = 'runtime-localservice-modify'; unverifiedCriticalWarnings = @($health.unverifiedCriticalWarnings)
            }
            if (-not $Apply) { return [pscustomobject]$result }
            if (-not (Test-BridgeRecoveryAdministrator)) { throw [UnauthorizedAccessException]::new('BridgeRecoveryAdministratorRequired') }
            if (-not $PSCmdlet.ShouldProcess($paths.statePath, 'Preserve running journal and record verified recovered terminal state')) {
                return [pscustomobject]$result
            }
            Assert-BridgeRecoverySnapshotUnchanged -Snapshot $snapshot -Paths $paths -ServiceProgramRoot $serviceProgramRoot -Pins $pins -AllowOriginalArchive
            Save-BridgeRecoveryOriginalState -Paths $paths -StateBytes $snapshot.stateBytes -StateSha256 $snapshot.stateSha256 -Pins $pins
            $snapshot.originalStateSha256 = $snapshot.stateSha256
            Assert-BridgeRecoverySnapshotUnchanged -Snapshot $snapshot -Paths $paths -ServiceProgramRoot $serviceProgramRoot -Pins $pins
            $terminalBody = Get-BridgeRecoveryTerminalBody -Snapshot $snapshot -Health $health
            Publish-BridgeRecoveryTerminalState -Paths $paths -Snapshot $snapshot -Body $terminalBody -Pins $pins
            if (-not (Test-BridgeRecoveredJournal -StatePath $paths.statePath)) {
                throw [IO.InvalidDataException]::new('BridgeRecoveryTerminalVerificationFailed')
            }
            $result.state = 'recovered'; $result.applied = $true; $result.readOnly = $false
            return [pscustomobject]$result
        } finally {
            $lock.Dispose()
        }
    } finally {
        for ($index = $pins.Count - 1; $index -ge 0; $index--) { $pins[$index].Dispose() }
    }
}

if (-not $LibraryMode) {
    try {
        if ([string]::IsNullOrWhiteSpace($TransactionDirectory)) { throw [ArgumentException]::new('BridgeRecoveryTransactionDirectoryRequired') }
        if ([string]::IsNullOrWhiteSpace($ServeHost)) { throw [ArgumentException]::new('BridgeRecoveryServeHostRequired') }
        $receipt = Invoke-BridgeServiceSwitchRecovery -TransactionDirectory $TransactionDirectory -ServeHost $ServeHost -Apply:$Apply
        if ($Json) { $receipt | ConvertTo-Json -Depth 6 } else { $receipt }
        exit 0
    } catch {
        $failure = [ordered]@{ schemaVersion = 1; state = 'failed'; applied = $false; error = $_.Exception.Message }
        if ($Json) { $failure | ConvertTo-Json -Compress } else { Write-Error $_ }
        exit 2
    }
}
