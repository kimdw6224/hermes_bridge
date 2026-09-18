[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Alias('Prepare')][switch]$ContextPrepare,
    [Alias('Apply')][switch]$ContextApply,
    [Alias('Json')][switch]$ContextJson,
    [switch]$LibraryMode,
    [Alias('InstallationContextPath')][string]$ContextPath = '',
    [Alias('InstallationContextSha256')][string]$ContextSha256 = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ContextFields = @('schemaVersion', 'nonce', 'port')
$script:BindingFields = @('schemaVersion', 'profile', 'contextNonce', 'configPath', 'configSha256', 'workerSid')
$script:WorkerBindingFields = @($script:BindingFields + @('policyPath', 'policySha256'))
$script:InstallationContextTrustedSids = @('S-1-5-18', 'S-1-5-32-544')
$script:InstallationContextMutationMask = [int64]0x500D0156

function Assert-BridgeInstallationContextPair {
    [CmdletBinding()]
    param([string]$Path, [string]$Sha256)
    if ([string]::IsNullOrWhiteSpace($Path) -xor [string]::IsNullOrWhiteSpace($Sha256)) {
        throw [ArgumentException]::new('BridgeInstallationContextPairRequired')
    }
    if ([string]::IsNullOrWhiteSpace($Path)) { throw [ArgumentException]::new('BridgeInstallationContextRequired') }
    if ($Sha256 -cnotmatch '^[a-f0-9]{64}$') { throw [ArgumentException]::new('BridgeInstallationContextSha256Invalid') }
}

$contextDependencyRoot = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\', '/')
$contextCommonPath = [IO.Path]::Combine($contextDependencyRoot, 'lifecycle-common.ps1')
$contextCommonItem = Get-Item -LiteralPath $contextCommonPath -Force -ErrorAction Stop
if ($contextCommonItem.PSIsContainer -or ($contextCommonItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    -not $contextCommonItem.FullName.Equals($contextCommonPath, [StringComparison]::OrdinalIgnoreCase)) {
    throw [IO.IOException]::new('BridgeInstallationContextDependencyUnsafe')
}
. $contextCommonItem.FullName

function Initialize-BridgeInstallationFileIdentityType {
    [CmdletBinding()]
    param()
    if ($null -eq ('HermesBridge.InstallationContextFileIdentity' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace HermesBridge {
  public static class InstallationContextFileIdentity {
    [StructLayout(LayoutKind.Sequential)] private struct Info {
      public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
      public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info);
    public static uint Links(string path) {
      using (SafeFileHandle handle = CreateFile(path, 0, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero)) {
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error()); Info info;
        if (!GetFileInformationByHandle(handle, out info)) throw new Win32Exception(Marshal.GetLastWin32Error()); return info.Links;
      }
    }
    public static string Identity(string path) {
      using (SafeFileHandle handle = CreateFile(path, 0, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero)) {
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error()); Info info;
        if (!GetFileInformationByHandle(handle, out info)) throw new Win32Exception(Marshal.GetLastWin32Error());
        ulong index = ((ulong)info.IndexHigh << 32) | info.IndexLow;
        return info.Volume.ToString("X8") + ":" + index.ToString("X16") + ":" + info.Links.ToString();
      }
    }
  }
}
'@
    }
}

function Get-BridgeInstallationFileLinkCount {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    Initialize-BridgeInstallationFileIdentityType
    return [int][HermesBridge.InstallationContextFileIdentity]::Links($Path)
}

function Get-BridgeInstallationNativeIdentity {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    Initialize-BridgeInstallationFileIdentityType
    return [string][HermesBridge.InstallationContextFileIdentity]::Identity($Path)
}

function Get-BridgeInstallationContextFileSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [ValidateRange(1, 65536)][int]$MaximumBytes = 32768)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        if ($stream.Length -gt $MaximumBytes) { throw [IO.InvalidDataException]::new('BridgeInstallationContextFileTooLarge') }
        $bytes = [byte[]]::new([int]$stream.Length); $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) { throw [IO.EndOfStreamException]::new('BridgeInstallationContextFileReadIncomplete') }
            $offset += $read
        }
        return [pscustomobject]@{
            bytes = $bytes
            text = ([Text.UTF8Encoding]::new($false, $true)).GetString($bytes)
            sha256 = ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
        }
    }
    finally { $algorithm.Dispose(); $stream.Dispose() }
}

function Test-BridgeInstallationContextJsonInteger {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Value)
    return (($Value -is [int]) -or ($Value -is [long]))
}

function Test-BridgeInstallationContextAclProtected {
    [CmdletBinding()]
    param([Parameter(Mandatory)][Security.AccessControl.FileSystemSecurity]$Acl)
    try {
        $owner = $Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin $script:InstallationContextTrustedSids) { return $false }
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($Acl.GetSecurityDescriptorBinaryForm(), 0)
        if ($null -eq $descriptor.DiscretionaryAcl) { return $false }
        foreach ($rule in $Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            $sid = $rule.IdentityReference.Value
            if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                $sid -notin $script:InstallationContextTrustedSids -and
                (([int64]$rule.FileSystemRights -band $script:InstallationContextMutationMask) -ne 0)) {
                return $false
            }
        }
        return $true
    } catch { return $false }
}

function Assert-BridgeInstallationContextProtectedFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$FailureReason
    )
    $safeRoot = Resolve-BridgeLocalRoot -Path $Root
    $safePath = Assert-BridgePathUnderRoot -Root $safeRoot -Path $Path
    $item = Get-Item -LiteralPath $safePath -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not $item.FullName.Equals($safePath, [StringComparison]::OrdinalIgnoreCase) -or
        (Get-BridgeInstallationFileLinkCount -Path $safePath) -ne 1 -or
        -not (Test-BridgeInstallationContextAclProtected -Acl (Get-Acl -LiteralPath $safePath -ErrorAction Stop))) {
        throw [Security.SecurityException]::new($FailureReason)
    }
    $current = Split-Path -Parent $safePath
    while ($true) {
        $directory = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (-not $directory.PSIsContainer -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not $directory.FullName.Equals($current, [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-BridgeInstallationContextAclProtected -Acl (Get-Acl -LiteralPath $current -ErrorAction Stop))) {
            throw [Security.SecurityException]::new($FailureReason)
        }
        if ($current.Equals($safeRoot, [StringComparison]::OrdinalIgnoreCase)) { break }
        $parent = Split-Path -Parent $current
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent.Equals($current, [StringComparison]::OrdinalIgnoreCase)) {
            throw [Security.SecurityException]::new($FailureReason)
        }
        $current = $parent
    }
    return $safePath
}

function Get-BridgeInstallationContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Sha256
    )
    Assert-BridgeInstallationContextPair -Path $Path -Sha256 $Sha256
    if (-not [IO.Path]::IsPathRooted($Path) -or $Path.StartsWith('\\')) {
        throw [ArgumentException]::new('BridgeInstallationContextPathInvalid')
    }
    $canonicalPath = [IO.Path]::GetFullPath($Path)
    if ($Path.TrimEnd('\', '/') -cne $canonicalPath.TrimEnd('\', '/')) {
        throw [ArgumentException]::new('BridgeInstallationContextPathNonCanonical')
    }
    $parent = Resolve-BridgeLocalRoot -Path (Split-Path -Parent $canonicalPath)
    $item = Get-Item -LiteralPath $canonicalPath -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not $item.FullName.Equals($canonicalPath, [StringComparison]::OrdinalIgnoreCase) -or
        (Get-BridgeInstallationFileLinkCount -Path $canonicalPath) -ne 1) {
        throw [IO.IOException]::new('BridgeInstallationContextFileUnsafe')
    }
    $snapshot = Get-BridgeInstallationContextFileSnapshot -Path $canonicalPath -MaximumBytes 4096
    $actualHash = [string]$snapshot.sha256
    if (-not $actualHash.Equals($Sha256, [StringComparison]::Ordinal)) {
        throw [Security.SecurityException]::new('BridgeInstallationContextHashMismatch')
    }
    $body = [string]$snapshot.text
    if ($body -notmatch '^\s*\{\s*"schemaVersion"\s*:\s*1\s*,\s*"nonce"\s*:\s*"[a-f0-9]{32}"\s*,\s*"port"\s*:\s*[0-9]+\s*\}\s*$') {
        throw [IO.InvalidDataException]::new('BridgeInstallationContextSchemaInvalid')
    }
    try { $record = $body | ConvertFrom-Json -ErrorAction Stop }
    catch { throw [IO.InvalidDataException]::new('BridgeInstallationContextJsonInvalid', $_.Exception) }
    if (-not (Test-BridgeInstallationContextJsonInteger -Value $record.schemaVersion) -or [int]$record.schemaVersion -ne 1 -or
        $record.nonce -isnot [string] -or [string]$record.nonce -cnotmatch '^[a-f0-9]{32}$' -or
        -not (Test-BridgeInstallationContextJsonInteger -Value $record.port) -or [int]$record.port -lt 49152 -or [int]$record.port -gt 65535) {
        throw [IO.InvalidDataException]::new('BridgeInstallationContextValuesInvalid')
    }
    $nonce = [string]$record.nonce
    $prefix = 'HermesWindowsBridgeEval-{0}' -f $nonce
    $programRoot = [IO.Path]::Combine([Environment]::GetFolderPath('ProgramFiles'), $prefix)
    $programDataRoot = [IO.Path]::Combine([Environment]::GetFolderPath('CommonApplicationData'), $prefix)
    $localDataRoot = [IO.Path]::Combine([Environment]::GetFolderPath('LocalApplicationData'), $prefix)
    return [pscustomobject][ordered]@{
        schemaVersion = 1; nonce = $nonce; prefix = $prefix; port = [int]$record.port
        serveHost = ('eval-{0}.ts.net' -f $nonce)
        contextPath = $canonicalPath; contextSha256 = $actualHash
        programRoot = $programRoot; programDataRoot = $programDataRoot
        runtimeRoot = [IO.Path]::Combine($programDataRoot, 'HermesWindowsBridge')
        localDataRoot = $localDataRoot; userRoot = [IO.Path]::Combine($localDataRoot, 'HermesWindowsBridge')
        gatewayServiceName = $prefix + '-Gateway'; privilegedServiceName = $prefix + '-Privileged'
        workerTaskName = $prefix + '-Worker'; workerPipe = '\\.\pipe\' + $prefix + '-Worker'
        privilegedPipe = '\\.\pipe\' + $prefix + '-Privileged'
        bindingsDirectory = [IO.Path]::Combine($programRoot, 'bindings')
        configPath = [IO.Path]::Combine($programDataRoot, 'HermesWindowsBridge', 'config.yaml')
        policyPath = [IO.Path]::Combine($programDataRoot, 'HermesWindowsBridge', 'policy.yaml')
        tokenPath = [IO.Path]::Combine($programDataRoot, 'HermesWindowsBridge', 'secrets', 'token')
        preparationJournalPath = [IO.Path]::Combine($programDataRoot, 'HermesWindowsBridge', 'installation-context-preparation.json')
    }
}

function Get-BridgeInstallationContextBinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][ValidateSet('gateway', 'privileged', 'worker')][string]$Profile
    )
    $path = [IO.Path]::Combine([string]$Context.bindingsDirectory, $Profile + '.json')
    $safePath = Assert-BridgeInstallationContextProtectedFile -Path $path -Root ([string]$Context.programRoot) `
        -FailureReason 'BridgeRuntimeBindingFileUnprotected'
    $snapshot = Get-BridgeInstallationContextFileSnapshot -Path $safePath
    $body = [string]$snapshot.text
    $bindingPattern = if ($Profile -ceq 'worker') {
        '^\{"schemaVersion":1,"profile":"worker","contextNonce":"[a-f0-9]{32}","configPath":"(?:[^"\\]|\\.)*","configSha256":"[a-f0-9]{64}","workerSid":"S-1-[0-9-]+","policyPath":"(?:[^"\\]|\\.)*","policySha256":"[a-f0-9]{64}"\}$'
    } else {
        '^\{"schemaVersion":1,"profile":"(?:gateway|privileged)","contextNonce":"[a-f0-9]{32}","configPath":"(?:[^"\\]|\\.)*","configSha256":"[a-f0-9]{64}","workerSid":"S-1-[0-9-]+"\}$'
    }
    if ($body -notmatch $bindingPattern) { throw [IO.InvalidDataException]::new('BridgeRuntimeBindingSchemaInvalid') }
    try { $binding = $body | ConvertFrom-Json -ErrorAction Stop }
    catch { throw [IO.InvalidDataException]::new('BridgeRuntimeBindingJsonInvalid', $_.Exception) }
    if (-not (Test-BridgeInstallationContextJsonInteger -Value $binding.schemaVersion) -or [int]$binding.schemaVersion -ne 1 -or
        [string]$binding.profile -cne $Profile -or [string]$binding.contextNonce -cne [string]$Context.nonce -or
        [string]$binding.configPath -cne [string]$Context.configPath -or [string]$binding.configSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$binding.workerSid -cnotmatch '^S-1-[0-9-]+$' -or
        ($Profile -ceq 'worker' -and ([string]$binding.policyPath -cne [string]$Context.policyPath -or [string]$binding.policySha256 -cnotmatch '^[a-f0-9]{64}$'))) {
        throw [IO.InvalidDataException]::new('BridgeRuntimeBindingSchemaInvalid')
    }
    $null = Assert-BridgeInstallationContextProtectedFile -Path ([string]$binding.configPath) -Root ([string]$Context.programDataRoot) `
        -FailureReason 'BridgeRuntimeBindingConfigUnprotected'
    if ($Profile -ceq 'worker') {
        $null = Assert-BridgeInstallationContextProtectedFile -Path ([string]$binding.policyPath) -Root ([string]$Context.programDataRoot) `
            -FailureReason 'BridgeRuntimeBindingPolicyUnprotected'
    }
    if ((Get-BridgeInstallationContextFileSnapshot -Path ([string]$binding.configPath)).sha256 -cne [string]$binding.configSha256 -or
        ($Profile -ceq 'worker' -and (Get-BridgeInstallationContextFileSnapshot -Path ([string]$binding.policyPath)).sha256 -cne [string]$binding.policySha256)) {
        throw [Security.SecurityException]::new('BridgeRuntimeBindingTargetHashMismatch')
    }
    return [pscustomobject][ordered]@{
        path = $safePath; sha256 = [string]$snapshot.sha256
        profile = $Profile; contextNonce = [string]$binding.contextNonce; configPath = [string]$binding.configPath
        configSha256 = [string]$binding.configSha256; workerSid = [string]$binding.workerSid
        policyPath = if ($Profile -ceq 'worker') { [string]$binding.policyPath } else { $null }
        policySha256 = if ($Profile -ceq 'worker') { [string]$binding.policySha256 } else { $null }
    }
}

function Set-BridgeInstallationBindingAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Profile, [Parameter(Mandatory)][string]$WorkerSid)
    $acl = [Security.AccessControl.FileSecurity]::new(); $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-BridgeFileRule -Sid 'S-1-5-18' -Rights FullControl))
    $acl.AddAccessRule((New-BridgeFileRule -Sid 'S-1-5-32-544' -Rights FullControl))
    if ($Profile -ceq 'gateway') { $acl.AddAccessRule((New-BridgeFileRule -Sid 'S-1-5-19' -Rights Read)) }
    if ($Profile -ceq 'worker') { $acl.AddAccessRule((New-BridgeFileRule -Sid $WorkerSid -Rights Read)) }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-BridgeInstallationPreparationJournalAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $acl = [Security.AccessControl.FileSecurity]::new(); $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-BridgeFileRule -Sid 'S-1-5-18' -Rights FullControl))
    $acl.AddAccessRule((New-BridgeFileRule -Sid 'S-1-5-32-544' -Rights FullControl))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-BridgeInstallationBindingsDirectoryAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$WorkerSid)
    $acl = [Security.AccessControl.DirectorySecurity]::new(); $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-18' -Rights FullControl))
    $acl.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-32-544' -Rights FullControl))
    $acl.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-19' -Rights ReadAndExecute))
    $acl.AddAccessRule((New-BridgeDirectoryRule -Sid $WorkerSid -Rights ReadAndExecute))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-BridgeInstallationReadonlyDirectoryAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$WorkerSid)
    $acl = [Security.AccessControl.DirectorySecurity]::new(); $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-18' -Rights FullControl))
    $acl.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-32-544' -Rights FullControl))
    $acl.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-19' -Rights ReadAndExecute))
    $acl.AddAccessRule((New-BridgeDirectoryRule -Sid $WorkerSid -Rights ReadAndExecute))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Test-BridgeInstallationReadonlyDirectoryAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$WorkerSid)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $false }
    $expected = [Security.AccessControl.DirectorySecurity]::new(); $expected.SetAccessRuleProtection($true, $false)
    $expected.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-18' -Rights FullControl))
    $expected.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-32-544' -Rights FullControl))
    $expected.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-19' -Rights ReadAndExecute))
    $expected.AddAccessRule((New-BridgeDirectoryRule -Sid $WorkerSid -Rights ReadAndExecute))
    $actual = Get-Acl -LiteralPath $Path -ErrorAction Stop
    return $actual.AreAccessRulesProtected -and
        $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -in @('S-1-5-18', 'S-1-5-32-544') -and
        ((Get-BridgeAclRuleSignatures -Rules @($actual.Access)) | ConvertTo-Json -Compress) -ceq
        ((Get-BridgeAclRuleSignatures -Rules @($expected.Access)) | ConvertTo-Json -Compress)
}

function Test-BridgeInstallationBindingsDirectoryAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$WorkerSid)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $false }
    $expected = [Security.AccessControl.DirectorySecurity]::new(); $expected.SetAccessRuleProtection($true, $false)
    $expected.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-18' -Rights FullControl))
    $expected.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-32-544' -Rights FullControl))
    $expected.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-19' -Rights ReadAndExecute))
    $expected.AddAccessRule((New-BridgeDirectoryRule -Sid $WorkerSid -Rights ReadAndExecute))
    $actual = Get-Acl -LiteralPath $Path -ErrorAction Stop
    return $actual.AreAccessRulesProtected -and
        $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -in @('S-1-5-18', 'S-1-5-32-544') -and
        ((Get-BridgeAclRuleSignatures -Rules @($actual.Access)) | ConvertTo-Json -Compress) -ceq
        ((Get-BridgeAclRuleSignatures -Rules @($expected.Access)) | ConvertTo-Json -Compress)
}

function Test-BridgeInstallationOwnedDirectoryAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('Readonly', 'Bindings', 'Browser', 'Audit', 'Secrets')][string]$Profile,
        [Parameter(Mandatory)][string]$WorkerSid
    )
    $descriptorMatches = if ($Profile -ceq 'Readonly') {
        Test-BridgeInstallationReadonlyDirectoryAcl -Path $Path -WorkerSid $WorkerSid
    } elseif ($Profile -ceq 'Bindings') {
        Test-BridgeInstallationBindingsDirectoryAcl -Path $Path -WorkerSid $WorkerSid
    } elseif ($Profile -ceq 'Browser') {
        Test-BridgeDirectoryAclExact -Path $Path -Profile Browser -UserSid $WorkerSid
    } elseif ($Profile -ceq 'Audit') {
        Test-BridgeDirectoryAclExact -Path $Path -Profile Audit
    } else { Test-BridgeDirectoryAclExact -Path $Path -Profile Secrets }
    if (-not $descriptorMatches) { return $false }
    return (Get-Acl -LiteralPath $Path -ErrorAction Stop).GetOwner([Security.Principal.SecurityIdentifier]).Value -in @('S-1-5-18', 'S-1-5-32-544')
}

function Set-BridgeInstallationTrustedOwner {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function New-BridgeInstallationContextConfigText {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$ProjectRoot)
    $template = [IO.File]::ReadAllText([IO.Path]::Combine($ProjectRoot, 'config', 'config.example.yaml'))
    $contextServeHost = 'eval-{0}.ts.net' -f [string]$Context.nonce
    $yaml = $template.Replace('main-pc.<tailnet>.ts.net', $contextServeHost).Replace('port: 8765', ('port: {0}' -f [int]$Context.port))
    $quote = { param([string]$Value) $Value | ConvertTo-Json -Compress }
    $yaml = $yaml -replace '(?m)^  worker_pipe: .*$', ('  worker_pipe: ' + (& $quote ([string]$Context.workerPipe)))
    $yaml = $yaml -replace '(?m)^  privileged_pipe: .*$', ('  privileged_pipe: ' + (& $quote ([string]$Context.privilegedPipe)))
    $yaml = $yaml -replace '(?m)^  program_data: .*$', ('  program_data: ' + (& $quote ([string]$Context.runtimeRoot)))
    $yaml = $yaml -replace '(?m)^  user_data: .*$', ('  user_data: ' + (& $quote ([string]$Context.userRoot)))
    $yaml = $yaml -replace '(?m)^  profile_dir: .*$', ('  profile_dir: ' + (& $quote ([IO.Path]::Combine($Context.userRoot, 'browser-profile'))))
    $yaml = $yaml -replace '(?m)^  emergency_stop_hotkey: .*$', '  emergency_stop_hotkey: "ctrl+alt+shift+f10"'
    $yaml = $yaml -replace '(?m)^paths:\r?\n', ('paths:' + [Environment]::NewLine + '  token_file: ' + (& $quote ([string]$Context.tokenPath)) + [Environment]::NewLine)
    return $yaml
}

function Write-BridgeInstallationContextPreparationJournal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Journal,
        [Parameter(Mandatory)][object[]]$RootRecords
    )
    $Journal.roots = @($RootRecords)
    [IO.File]::WriteAllText($Path, ($Journal | ConvertTo-Json -Depth 6 -Compress), [Text.UTF8Encoding]::new($false))
    Set-BridgeInstallationPreparationJournalAcl -Path $Path
    Set-BridgeInstallationTrustedOwner -Path $Path
}

function Invoke-BridgeInstallationContextPreparation {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$ProjectRoot)
    if (-not (Test-BridgeAdministrator)) { throw [UnauthorizedAccessException]::new('BridgeInstallationContextElevationRequired') }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $configText = New-BridgeInstallationContextConfigText -Context $Context -ProjectRoot $ProjectRoot
    $policyText = [IO.File]::ReadAllText([IO.Path]::Combine($ProjectRoot, 'config', 'policy.example.yaml'))
    $roots = @([string]$Context.programRoot, [string]$Context.programDataRoot, [string]$Context.localDataRoot)
    foreach ($root in $roots) {
        $parent = Split-Path -Parent $root
        [void](Resolve-BridgeLocalRoot -Path $parent)
        if ((Test-Path -LiteralPath $root) -and -not (Resolve-BridgeLocalRoot -Path $root).Equals($root, [StringComparison]::OrdinalIgnoreCase)) {
            throw [IO.IOException]::new('BridgeInstallationContextRootUnsafe')
        }
    }
    $requiredDirectories = @(
        [string]$Context.programRoot, [string]$Context.bindingsDirectory, [string]$Context.programDataRoot,
        [string]$Context.runtimeRoot, ([IO.Path]::Combine($Context.runtimeRoot, 'logs')), ([IO.Path]::Combine($Context.runtimeRoot, 'jobs')),
        ([IO.Path]::Combine($Context.runtimeRoot, 'secrets')), [string]$Context.localDataRoot, [string]$Context.userRoot,
        ([IO.Path]::Combine($Context.userRoot, 'browser-profile')), ([IO.Path]::Combine($Context.userRoot, 'logs'))
    )
    $existingRootCount = @($roots | Where-Object { Test-Path -LiteralPath $_ -PathType Container }).Count
    if ($existingRootCount -gt 0) {
        if ($existingRootCount -ne $roots.Count -or @($requiredDirectories | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Container) }).Count -ne 0 -or
            -not (Test-Path -LiteralPath $Context.configPath -PathType Leaf) -or -not (Test-Path -LiteralPath $Context.policyPath -PathType Leaf) -or
            [IO.File]::ReadAllText($Context.configPath, [Text.UTF8Encoding]::new($false)) -cne $configText -or
            [IO.File]::ReadAllText($Context.policyPath, [Text.UTF8Encoding]::new($false)) -cne $policyText -or
            @(
                (Test-BridgeInstallationOwnedDirectoryAcl -Path $Context.programRoot -Profile Readonly -WorkerSid $identity.User.Value),
                (Test-BridgeInstallationOwnedDirectoryAcl -Path $Context.bindingsDirectory -Profile Bindings -WorkerSid $identity.User.Value),
                (Test-BridgeInstallationOwnedDirectoryAcl -Path $Context.programDataRoot -Profile Readonly -WorkerSid $identity.User.Value),
                (Test-BridgeInstallationOwnedDirectoryAcl -Path $Context.runtimeRoot -Profile Readonly -WorkerSid $identity.User.Value),
                (Test-BridgeInstallationOwnedDirectoryAcl -Path ([IO.Path]::Combine($Context.runtimeRoot, 'logs')) -Profile Audit -WorkerSid $identity.User.Value),
                (Test-BridgeInstallationOwnedDirectoryAcl -Path ([IO.Path]::Combine($Context.runtimeRoot, 'jobs')) -Profile Audit -WorkerSid $identity.User.Value),
                (Test-BridgeInstallationOwnedDirectoryAcl -Path ([IO.Path]::Combine($Context.runtimeRoot, 'secrets')) -Profile Secrets -WorkerSid $identity.User.Value),
                (Test-BridgeInstallationOwnedDirectoryAcl -Path $Context.localDataRoot -Profile Browser -WorkerSid $identity.User.Value),
                (Test-BridgeInstallationOwnedDirectoryAcl -Path $Context.userRoot -Profile Browser -WorkerSid $identity.User.Value),
                (Test-BridgeInstallationOwnedDirectoryAcl -Path ([IO.Path]::Combine($Context.userRoot, 'browser-profile')) -Profile Browser -WorkerSid $identity.User.Value),
                (Test-BridgeInstallationOwnedDirectoryAcl -Path ([IO.Path]::Combine($Context.userRoot, 'logs')) -Profile Browser -WorkerSid $identity.User.Value)
            ) -contains $false) {
            throw [Security.SecurityException]::new('BridgeInstallationContextPreparedStateUnverified')
        }
        $null = Get-BridgeInstallationContextBinding -Context $Context -Profile 'gateway'
        $null = Get-BridgeInstallationContextBinding -Context $Context -Profile 'privileged'
        $null = Get-BridgeInstallationContextBinding -Context $Context -Profile 'worker'
        $preparedJournal = [string]$Context.preparationJournalPath
        if (-not (Test-Path -LiteralPath $preparedJournal -PathType Leaf)) {
            throw [Security.SecurityException]::new('BridgeInstallationContextJournalUnverified')
        }
        try { $preparedReceipt = [IO.File]::ReadAllText($preparedJournal, [Text.UTF8Encoding]::new($false)) | ConvertFrom-Json -ErrorAction Stop }
        catch { throw [Security.SecurityException]::new('BridgeInstallationContextJournalUnverified', $_.Exception) }
        $expectedRoots = @([string]$Context.programRoot, [string]$Context.programDataRoot, [string]$Context.localDataRoot)
        $receiptRoots = @($preparedReceipt.roots)
        if (-not (Test-BridgeInstallationContextJsonInteger -Value $preparedReceipt.schemaVersion) -or [int]$preparedReceipt.schemaVersion -ne 2 -or
            [string]$preparedReceipt.nonce -cne [string]$Context.nonce -or [string]$preparedReceipt.state -cne 'prepared' -or
            $preparedReceipt.reconciliationRequired -isnot [bool] -or [bool]$preparedReceipt.reconciliationRequired -or
            $receiptRoots.Count -ne $expectedRoots.Count) {
            throw [Security.SecurityException]::new('BridgeInstallationContextJournalUnverified')
        }
        for ($index = 0; $index -lt $expectedRoots.Count; $index++) {
            $receiptRoot = $receiptRoots[$index]
            if ([string]$receiptRoot.path -cne $expectedRoots[$index] -or $receiptRoot.absentBefore -isnot [bool] -or
                -not [bool]$receiptRoot.absentBefore -or $receiptRoot.created -isnot [bool] -or -not [bool]$receiptRoot.created -or
                [string]$receiptRoot.nativeIdentity -cnotmatch '^[0-9A-F]{8}:[0-9A-F]{16}:[1-9][0-9]*$' -or
                (Get-BridgeInstallationNativeIdentity -Path $expectedRoots[$index]) -cne [string]$receiptRoot.nativeIdentity) {
                throw [Security.SecurityException]::new('BridgeInstallationContextJournalUnverified')
            }
        }
        return [pscustomobject][ordered]@{ state = 'prepared'; nonce = $Context.nonce; journalPath = $preparedJournal; created = @(); tokenCreated = $false; reconciliationRequired = $false }
    }
    if (-not $PSCmdlet.ShouldProcess(([string]$Context.prefix), 'Prepare nonce-scoped runtime configuration and bindings')) { return }
    $created = [Collections.Generic.List[string]]::new()
    $rootRecords = @(
        [pscustomobject][ordered]@{ path = [string]$Context.programRoot; absentBefore = -not (Test-Path -LiteralPath $Context.programRoot); created = $false; nativeIdentity = $null },
        [pscustomobject][ordered]@{ path = [string]$Context.programDataRoot; absentBefore = -not (Test-Path -LiteralPath $Context.programDataRoot); created = $false; nativeIdentity = $null },
        [pscustomobject][ordered]@{ path = [string]$Context.localDataRoot; absentBefore = -not (Test-Path -LiteralPath $Context.localDataRoot); created = $false; nativeIdentity = $null }
    )
    if (@($rootRecords | Where-Object { -not $_.absentBefore }).Count -ne 0) {
        throw [Security.SecurityException]::new('BridgeInstallationContextPreparedStateUnverified')
    }
    $journalPath = [string]$Context.preparationJournalPath
    $journal = [pscustomobject][ordered]@{
        schemaVersion = 2; nonce = [string]$Context.nonce; state = 'preparing'; reconciliationRequired = $true
        roots = @(); created = @(); bindings = @('gateway', 'privileged', 'worker'); tokenCreated = $false
    }
    $journalPersisted = $false
    try {
        [void][IO.Directory]::CreateDirectory([string]$Context.runtimeRoot)
        foreach ($rootRecord in @($rootRecords[1])) {
            if (-not (Test-Path -LiteralPath $rootRecord.path -PathType Container)) { throw [IO.IOException]::new('BridgeInstallationContextRootCreationFailed') }
            $rootRecord.created = $true; $rootRecord.nativeIdentity = Get-BridgeInstallationNativeIdentity -Path $rootRecord.path
        }
        $created.Add([string]$Context.programDataRoot); $created.Add([string]$Context.runtimeRoot)
        $journal.created = $created.ToArray()
        Write-BridgeInstallationContextPreparationJournal -Path $journalPath -Journal $journal -RootRecords $rootRecords
        $journalPersisted = $true
        foreach ($directory in @($Context.programRoot, $Context.bindingsDirectory, ([IO.Path]::Combine($Context.runtimeRoot, 'logs')),
            ([IO.Path]::Combine($Context.runtimeRoot, 'jobs')), ([IO.Path]::Combine($Context.runtimeRoot, 'secrets')), $Context.localDataRoot,
            $Context.userRoot, ([IO.Path]::Combine($Context.userRoot, 'browser-profile')), ([IO.Path]::Combine($Context.userRoot, 'logs')))) {
            if (Test-Path -LiteralPath $directory) { throw [IO.IOException]::new('BridgeInstallationContextRootCreationConflict') }
            [void][IO.Directory]::CreateDirectory([string]$directory)
            $created.Add([string]$directory)
            foreach ($rootRecord in @($rootRecords | Where-Object { $_.path -ceq [string]$directory })) {
                $rootRecord.created = $true; $rootRecord.nativeIdentity = Get-BridgeInstallationNativeIdentity -Path $rootRecord.path
            }
            $journal.created = $created.ToArray()
            Write-BridgeInstallationContextPreparationJournal -Path $journalPath -Journal $journal -RootRecords $rootRecords
        }
        Set-BridgeInstallationReadonlyDirectoryAcl -Path ([string]$Context.programRoot) -WorkerSid $identity.User.Value
        Set-BridgeInstallationBindingsDirectoryAcl -Path ([string]$Context.bindingsDirectory) -WorkerSid $identity.User.Value
        Set-BridgeInstallationReadonlyDirectoryAcl -Path ([string]$Context.programDataRoot) -WorkerSid $identity.User.Value
        Set-BridgeInstallationReadonlyDirectoryAcl -Path ([string]$Context.runtimeRoot) -WorkerSid $identity.User.Value
        Set-BridgeAuditDirectoryAcl -Path ([IO.Path]::Combine($Context.runtimeRoot, 'logs')); Set-BridgeAuditDirectoryAcl -Path ([IO.Path]::Combine($Context.runtimeRoot, 'jobs'))
        Set-BridgeSecretsDirectoryAcl -Path ([IO.Path]::Combine($Context.runtimeRoot, 'secrets'))
        Set-BridgeBrowserDirectoryAcl -Path ([string]$Context.localDataRoot) -UserSid $identity.User.Value
        Set-BridgeBrowserDirectoryAcl -Path ([string]$Context.userRoot) -UserSid $identity.User.Value
        Set-BridgeBrowserDirectoryAcl -Path ([IO.Path]::Combine($Context.userRoot, 'browser-profile')) -UserSid $identity.User.Value
        Set-BridgeBrowserDirectoryAcl -Path ([IO.Path]::Combine($Context.userRoot, 'logs')) -UserSid $identity.User.Value
        foreach ($protectedPath in @([string]$Context.programRoot, [string]$Context.bindingsDirectory, [string]$Context.programDataRoot, [string]$Context.runtimeRoot,
            ([IO.Path]::Combine($Context.runtimeRoot, 'logs')), ([IO.Path]::Combine($Context.runtimeRoot, 'jobs')),
            ([IO.Path]::Combine($Context.runtimeRoot, 'secrets')), [string]$Context.localDataRoot, [string]$Context.userRoot,
            ([IO.Path]::Combine($Context.userRoot, 'browser-profile')), ([IO.Path]::Combine($Context.userRoot, 'logs')))) {
            Set-BridgeInstallationTrustedOwner -Path $protectedPath
        }
        foreach ($write in @(@{ path = $Context.configPath; body = $configText }, @{ path = $Context.policyPath; body = $policyText })) {
            if (Test-Path -LiteralPath $write.path -PathType Leaf) {
                if ([IO.File]::ReadAllText($write.path, [Text.UTF8Encoding]::new($false)) -cne $write.body) { throw [IO.IOException]::new('BridgeInstallationContextPreparedContentConflict') }
            } else { [IO.File]::WriteAllText($write.path, $write.body, [Text.UTF8Encoding]::new($false)); $created.Add($write.path) }
            Set-BridgeInstallationTrustedOwner -Path $write.path
            $journal.created = $created.ToArray()
            Write-BridgeInstallationContextPreparationJournal -Path $journalPath -Journal $journal -RootRecords $rootRecords
        }
        $configSha = (Get-BridgeInstallationContextFileSnapshot -Path ([string]$Context.configPath)).sha256
        $policySha = (Get-BridgeInstallationContextFileSnapshot -Path ([string]$Context.policyPath)).sha256
        foreach ($profile in @('gateway', 'privileged', 'worker')) {
            $bindingPath = [IO.Path]::Combine($Context.bindingsDirectory, $profile + '.json')
            $binding = [ordered]@{ schemaVersion = 1; profile = $profile; contextNonce = $Context.nonce; configPath = $Context.configPath; configSha256 = $configSha; workerSid = $identity.User.Value }
            if ($profile -ceq 'worker') { $binding.policyPath = $Context.policyPath; $binding.policySha256 = $policySha }
            $body = $binding | ConvertTo-Json -Compress
            if (Test-Path -LiteralPath $bindingPath -PathType Leaf) {
                if ([IO.File]::ReadAllText($bindingPath, [Text.UTF8Encoding]::new($false)) -cne $body) { throw [IO.IOException]::new('BridgeInstallationContextBindingConflict') }
            } else { [IO.File]::WriteAllText($bindingPath, $body, [Text.UTF8Encoding]::new($false)); $created.Add($bindingPath) }
            Set-BridgeInstallationBindingAcl -Path $bindingPath -Profile $profile -WorkerSid $identity.User.Value
            Set-BridgeInstallationTrustedOwner -Path $bindingPath
            $journal.created = $created.ToArray()
            Write-BridgeInstallationContextPreparationJournal -Path $journalPath -Journal $journal -RootRecords $rootRecords
        }
        $journal.state = 'prepared'; $journal.reconciliationRequired = $false; $journal.created = $created.ToArray()
        Write-BridgeInstallationContextPreparationJournal -Path $journalPath -Journal $journal -RootRecords $rootRecords
        if (([IO.File]::ReadAllText($journalPath, [Text.UTF8Encoding]::new($false)) | ConvertFrom-Json -ErrorAction Stop).state -cne 'prepared') { throw [IO.IOException]::new('BridgeInstallationContextJournalReadBackFailed') }
        return [pscustomobject][ordered]@{ state = 'prepared'; nonce = $Context.nonce; journalPath = $journalPath; created = $created.ToArray(); tokenCreated = $false; reconciliationRequired = $false }
    }
    catch {
        $journal.state = 'partial'; $journal.reconciliationRequired = $true; $journal.created = $created.ToArray()
        if ($journalPersisted -or (Test-Path -LiteralPath $journalPath -PathType Leaf)) {
            try { Write-BridgeInstallationContextPreparationJournal -Path $journalPath -Journal $journal -RootRecords $rootRecords } catch { }
        }
        $failure = [InvalidOperationException]::new('BridgeInstallationContextPreparationFailed')
        $failure.Data['journalPath'] = $journalPath
        $failure.Data['reconciliationRequired'] = $true
        $failure.Data['receipt'] = ($journal | ConvertTo-Json -Depth 6 -Compress)
        throw $failure
    }
}

if (-not $LibraryMode -and $ContextPrepare) {
    Assert-BridgeInstallationContextPair -Path $ContextPath -Sha256 $ContextSha256
    $context = Get-BridgeInstallationContext -Path $ContextPath -Sha256 $ContextSha256
    if ($ContextApply -and -not $WhatIfPreference) { $result = Invoke-BridgeInstallationContextPreparation -Context $context -ProjectRoot (Split-Path -Parent $PSScriptRoot) }
    else { $result = [pscustomobject][ordered]@{ state = 'planned'; nonce = $context.nonce; roots = @($context.programRoot, $context.programDataRoot, $context.localDataRoot); tokenCreated = $false } }
    if ($ContextJson) { $result | ConvertTo-Json -Depth 6 } else { $result }
}
