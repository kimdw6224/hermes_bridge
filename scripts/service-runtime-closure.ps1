Set-StrictMode -Version Latest

$script:BridgeClosureReceiptName = 'closure-receipt.json'
$script:BridgeClosureRequiredModules = @(
    'hermes_windows_bridge.gateway.windows_service',
    'hermes_windows_bridge.gateway.main',
    'hermes_windows_bridge.privileged.main',
    'servicemanager', 'win32api', 'win32con', 'win32event', 'win32file', 'win32pipe',
    'win32security', 'win32service', 'win32serviceutil', 'win32ts', 'pywintypes', 'ctypes'
)
$script:BridgeClosureProbeCode = @'
import ctypes,ctypes.wintypes as w,importlib,json,os,re,site,sys,psutil
names=['hermes_windows_bridge.gateway.windows_service','hermes_windows_bridge.gateway.main','hermes_windows_bridge.privileged.main','servicemanager','win32api','win32con','win32event','win32file','win32pipe','win32security','win32service','win32serviceutil','win32ts','pywintypes','ctypes']
origins=[]
for name in names:
 module=importlib.import_module(name); origins.append({'name':name,'path':os.path.realpath(module.__file__)})
files=sorted(set(os.path.realpath(module.__file__) for module in sys.modules.values() if getattr(module,'__file__',None)))
class MBI(ctypes.Structure): _fields_=[('BaseAddress',ctypes.c_void_p),('AllocationBase',ctypes.c_void_p),('AllocationProtect',w.DWORD),('PartitionId',w.WORD),('RegionSize',ctypes.c_size_t),('State',w.DWORD),('Protect',w.DWORD),('Type',w.DWORD)]
k=ctypes.WinDLL('kernel32',use_last_error=True); p=ctypes.WinDLL('psapi',use_last_error=True); k.GetCurrentProcess.restype=w.HANDLE
p.EnumProcessModules.argtypes=[w.HANDLE,ctypes.POINTER(w.HMODULE),w.DWORD,ctypes.POINTER(w.DWORD)]; p.EnumProcessModules.restype=w.BOOL
k.GetModuleFileNameW.argtypes=[w.HMODULE,w.LPWSTR,w.DWORD]; k.GetModuleFileNameW.restype=w.DWORD
k.VirtualQuery.argtypes=[ctypes.c_void_p,ctypes.POINTER(MBI),ctypes.c_size_t]; k.VirtualQuery.restype=ctypes.c_size_t
process=k.GetCurrentProcess()
def module_snapshot():
 capacity=256
 for _ in range(6):
  modules=(w.HMODULE*capacity)(); needed=w.DWORD()
  if not p.EnumProcessModules(process,modules,ctypes.sizeof(modules),ctypes.byref(needed)): raise ctypes.WinError(ctypes.get_last_error())
  if needed.value<=ctypes.sizeof(modules):
   result=[]
   if not needed.value or needed.value%ctypes.sizeof(w.HMODULE): raise RuntimeError('module-enumeration-size-invalid')
   for index in range(needed.value//ctypes.sizeof(w.HMODULE)):
    path=ctypes.create_unicode_buffer(32768); length=k.GetModuleFileNameW(modules[index],path,len(path))
    if not length or length>=len(path): raise ctypes.WinError(ctypes.get_last_error())
    value=path.value
    if not os.path.isabs(value): raise RuntimeError('module-path-invalid')
    result.append((int(modules[index]),value))
   if len(dict(result))!=len(result): raise RuntimeError('module-enumeration-duplicate')
   return sorted(result)
  capacity=(needed.value+ctypes.sizeof(w.HMODULE)-1)//ctypes.sizeof(w.HMODULE)
  if capacity>8192: raise RuntimeError('module-enumeration-oversize')
 raise RuntimeError('module-enumeration-unstable')
before=module_snapshot(); module_map=dict(before); uncovered_units=[]
for item in psutil.Process().memory_maps(grouped=False):
 match=re.fullmatch(r'0x([0-9A-Fa-f]+)',item.addr)
 if not match: uncovered_units.append(item.addr); continue
 info=MBI(); queried=k.VirtualQuery(ctypes.c_void_p(int(match.group(1),16)),ctypes.byref(info),ctypes.sizeof(info)); allocation=int(info.AllocationBase or 0)
 if queried!=ctypes.sizeof(info): uncovered_units.append(item.addr)
 elif info.Type==0x1000000 and (not item.path or info.State not in (0x1000,0x2000) or allocation not in module_map): uncovered_units.append(item.addr)
after=module_snapshot(); module_snapshots_stable=before==after
service=os.path.realpath(sys.executable)
base=os.path.realpath(sys._base_executable); image_path=ctypes.create_unicode_buffer(32768); image_length=k.GetModuleFileNameW(None,image_path,len(image_path))
if not image_length or image_length>=len(image_path): raise ctypes.WinError(ctypes.get_last_error())
process_image=os.path.realpath(image_path.value); process_image_count=sum(os.path.realpath(path).casefold()==process_image.casefold() for _,path in before)
if uncovered_units or not module_snapshots_stable or process_image.casefold()!=base.casefold() or process_image_count != 1: raise RuntimeError('module-closure-unverified')
dlls=sorted(set(path for _,path in before))
print(json.dumps({'enableUserSite':site.ENABLE_USER_SITE,'sysPath':sys.path,'moduleFiles':files,'loadedDlls':dlls,'moduleOrigins':origins,'baseExecutable':base,'serviceExecutable':service},separators=(',',':')))
'@.Trim()

function Test-BridgeClosureJsonStructure {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RawJson)
    $containers = [Collections.Generic.Stack[object]]::new()
    $inString = $false; $escaped = $false; $keyBuilder = [Text.StringBuilder]::new()
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
                if ($containers.Count -gt 0 -and $containers.Peek().kind -eq 'object' -and $containers.Peek().expectingKey) {
                    $lookahead = $index + 1
                    while ($lookahead -lt $RawJson.Length -and [char]::IsWhiteSpace($RawJson[$lookahead])) { $lookahead++ }
                    if ($lookahead -ge $RawJson.Length -or $RawJson[$lookahead] -ne ':' -or
                        -not $containers.Peek().keys.Add($keyBuilder.ToString())) { return $false }
                    $containers.Peek().expectingKey = $false
                }
                continue
            }
            if ($containers.Count -gt 0 -and $containers.Peek().kind -eq 'object' -and $containers.Peek().expectingKey) {
                [void]$keyBuilder.Append($character)
            }
            continue
        }
        if ($character -eq '"') { $inString = $true; $keyBuilder.Clear() | Out-Null; continue }
        if ($character -eq '{') {
            $containers.Push([pscustomobject]@{ kind = 'object'; expectingKey = $true; keys = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase) })
        } elseif ($character -eq '[') {
            $containers.Push([pscustomobject]@{ kind = 'array'; expectingKey = $false; keys = $null })
        } elseif ($character -in @('}', ']')) {
            if ($containers.Count -eq 0 -or ($character -eq '}' -and $containers.Peek().kind -ne 'object') -or
                ($character -eq ']' -and $containers.Peek().kind -ne 'array')) { return $false }
            [void]$containers.Pop()
        } elseif ($character -eq ',' -and $containers.Count -gt 0 -and $containers.Peek().kind -eq 'object') {
            $containers.Peek().expectingKey = $true
        }
        if ($containers.Count -gt 32) { return $false }
    }
    return -not $inString -and -not $escaped -and $containers.Count -eq 0
}

function Test-BridgeClosureAllowedPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ReleaseRoot, [Parameter(Mandatory)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    $windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    return (Test-BridgePathUnderRoot -Root $ReleaseRoot -Path $full) -or
        (Test-BridgePathUnderRoot -Root (Join-Path $windows 'System32') -Path $full) -or
        (Test-BridgePathUnderRoot -Root (Join-Path $windows 'WinSxS') -Path $full)
}

function ConvertTo-BridgeClosureFileRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ReleaseRoot, [Parameter(Mandatory)][string]$Path, [string]$Name = '')
    $full = [IO.Path]::GetFullPath($Path)
    $inRelease = Test-BridgePathUnderRoot -Root $ReleaseRoot -Path $full
    $windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    $systemRoot = if (Test-BridgePathUnderRoot -Root (Join-Path $windows 'System32') -Path $full) {
        Join-Path $windows 'System32'
    } elseif (Test-BridgePathUnderRoot -Root (Join-Path $windows 'WinSxS') -Path $full) {
        Join-Path $windows 'WinSxS'
    } else { '' }
    if (-not (Test-BridgeClosureAllowedPath -ReleaseRoot $ReleaseRoot -Path $full) -or
        -not (Test-Path -LiteralPath $full -PathType Leaf) -or
        -not (Test-BridgePathReparseFree -Root $(if ($inRelease) { $ReleaseRoot } else { $systemRoot }) -Path $full) -or
        ($inRelease -and (Get-BridgeFileLinkCount -Path $full) -ne 1)) { throw [Security.SecurityException]::new('BridgeRuntimeClosureFileInvalid') }
    $acl = Get-BridgePathAcl -Path $full
    $ownerSid = Get-BridgeSidValue -Identity $acl.Owner
    if (($inRelease -and (-not (Test-BridgeProtectedAclDescriptor -Acl $acl))) -or
        ((-not $inRelease) -and (-not (Test-BridgeOwnerTrustedForPath -Path $systemRoot -OwnerSid $ownerSid) -or
        -not (Test-BridgeAncestorAclHasNoUntrustedReplacement -Acl $acl -Path $systemRoot)))) {
        throw [Security.SecurityException]::new('BridgeRuntimeClosureFileAclInvalid')
    }
    $item = Get-Item -LiteralPath $full -Force
    $record = [ordered]@{ path = $full; sha256 = Get-BridgeFileSha256 -Path $full; size = [int64]$item.Length }
    if (-not [string]::IsNullOrEmpty($Name)) { $record = [ordered]@{ name = $Name; path = $full; sha256 = $record.sha256; size = $record.size } }
    return [pscustomobject]$record
}

function ConvertFrom-BridgeClosureProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ReleaseRoot,
        [Parameter(Mandatory)][string]$BaseExecutable,
        [Parameter(Mandatory)][string]$ServiceExecutable,
        [Parameter(Mandatory)][string]$ProbeJson
    )
    if ($ProbeJson.Length -gt 4194304 -or -not (Test-BridgeClosureJsonStructure -RawJson $ProbeJson)) { return $null }
    try { $probe = $ProbeJson | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
    $required = @('enableUserSite','sysPath','moduleFiles','loadedDlls','moduleOrigins','baseExecutable','serviceExecutable')
    $properties = @($probe.PSObject.Properties.Name)
    if (@($required | Where-Object { $_ -notin $properties }).Count -ne 0 -or
        @($properties | Where-Object { $_ -notin $required }).Count -ne 0 -or
        $probe.enableUserSite -isnot [bool] -or $probe.enableUserSite -ne $false -or
        $probe.sysPath -isnot [Array] -or $probe.moduleFiles -isnot [Array] -or
        $probe.loadedDlls -isnot [Array] -or $probe.moduleOrigins -isnot [Array] -or
        @($probe.sysPath).Count -eq 0 -or @($probe.moduleFiles).Count -eq 0 -or @($probe.loadedDlls).Count -eq 0 -or
        -not ([IO.Path]::GetFullPath([string]$probe.baseExecutable)).Equals([IO.Path]::GetFullPath($BaseExecutable), [StringComparison]::OrdinalIgnoreCase) -or
        -not ([IO.Path]::GetFullPath([string]$probe.serviceExecutable)).Equals([IO.Path]::GetFullPath($ServiceExecutable), [StringComparison]::OrdinalIgnoreCase)) { return $null }
    foreach ($path in @($probe.sysPath) + @($probe.moduleFiles) + @($probe.loadedDlls)) {
        if ($path -isnot [string] -or [string]::IsNullOrWhiteSpace($path) -or
            -not (Test-BridgeClosureAllowedPath -ReleaseRoot $ReleaseRoot -Path $path)) { return $null }
    }
    $origins = @($probe.moduleOrigins)
    if ($origins.Count -ne $script:BridgeClosureRequiredModules.Count) { return $null }
    foreach ($name in $script:BridgeClosureRequiredModules) {
        $matches = @($origins | Where-Object { (@($_.PSObject.Properties.Name) -join ',') -ceq 'name,path' -and $_.name -ceq $name })
        if ($matches.Count -ne 1 -or $matches[0].path -isnot [string] -or
            -not (Test-BridgeClosureAllowedPath -ReleaseRoot $ReleaseRoot -Path ([string]$matches[0].path))) { return $null }
    }
    return $probe
}

function New-BridgeServiceClosureReceipt {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ReleaseRoot, [Parameter(Mandatory)]$ManifestSeed, [Parameter(Mandatory)][string]$ProbeJson)
    $probe = ConvertFrom-BridgeClosureProbe -ReleaseRoot $ReleaseRoot -BaseExecutable $ManifestSeed.baseExecutable -ServiceExecutable $ManifestSeed.serviceExecutable -ProbeJson $ProbeJson
    if ($null -eq $probe) { throw [Security.SecurityException]::new('BridgeRuntimeImportClosureInvalid') }
    $inventory = @(Get-BridgeReleaseInventory -ReleaseRoot $ReleaseRoot)
    $moduleFiles = [Collections.Generic.List[object]]::new()
    $namedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($origin in $probe.moduleOrigins) {
        $moduleFiles.Add((ConvertTo-BridgeClosureFileRecord -ReleaseRoot $ReleaseRoot -Path $origin.path -Name $origin.name))
        [void]$namedPaths.Add([IO.Path]::GetFullPath([string]$origin.path))
    }
    foreach ($path in $probe.moduleFiles) {
        if ($namedPaths.Add([IO.Path]::GetFullPath([string]$path))) {
            $moduleFiles.Add((ConvertTo-BridgeClosureFileRecord -ReleaseRoot $ReleaseRoot -Path $path))
        }
    }
    $loadedDlls = @($probe.loadedDlls | ForEach-Object { ConvertTo-BridgeClosureFileRecord -ReleaseRoot $ReleaseRoot -Path $_ })
    return [pscustomobject][ordered]@{
        schemaVersion = 1; closureVerified = $true; probeExitCode = 0
        releaseId = $ManifestSeed.releaseId; sourceDigest = $ManifestSeed.sourceDigest; lockDigest = $ManifestSeed.lockDigest
        runtimeInventoryDigest = Get-BridgeInventoryDigest -Inventory $inventory
        baseExecutable = [IO.Path]::GetFullPath($ManifestSeed.baseExecutable)
        serviceExecutable = [IO.Path]::GetFullPath($ManifestSeed.serviceExecutable)
        probeArgv = @('-I','-B','-c',$script:BridgeClosureProbeCode)
        sysPath = @($probe.sysPath | ForEach-Object { [IO.Path]::GetFullPath([string]$_) })
        moduleFiles = @($moduleFiles | Sort-Object path)
        loadedDlls = @($loadedDlls | Sort-Object path)
    }
}

function Test-BridgeClosureTrustedExternalDll {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ReleaseRoot, [Parameter(Mandatory)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    $windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    if ((Test-BridgePathUnderRoot -Root $ReleaseRoot -Path $full) -or
        [IO.Path]::GetExtension($full) -ine '.dll' -or
        -not (Test-BridgeClosureAllowedPath -ReleaseRoot $ReleaseRoot -Path $full) -or
        -not (Test-Path -LiteralPath $full -PathType Leaf) -or
        -not (Test-BridgePathReparseFree -Root $windows -Path $full)) { return $false }
    $trusted = @($script:TrustedWriterSids) + @($script:TrustedInstallerSid)
    $current = $full
    while ($current.Equals($windows, [StringComparison]::OrdinalIgnoreCase) -or
        (Test-BridgePathUnderRoot -Root $windows -Path $current)) {
        $acl = Get-BridgePathAcl -Path $current
        if ((Get-BridgeSidValue -Identity $acl.Owner) -notin $trusted -or
            $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access) -match 'NO_ACCESS_CONTROL') { return $false }
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
                ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
            if ((Get-BridgeSidValue -Identity $rule.IdentityReference) -notin $trusted -and
                ([int64]$rule.FileSystemRights -band $script:WriteMask) -ne 0) { return $false }
        }
        $current = Split-Path -Parent $current
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $full -ErrorAction Stop
    return $signature.Status -eq 'Valid' -and $null -ne $signature.SignerCertificate -and
        $signature.SignerCertificate.Subject -match '(^|,\s*)O=Microsoft Corporation(,|$)'
}

function Test-BridgeServiceClosureReceipt {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ReleaseRoot, [Parameter(Mandatory)]$Manifest)
    try {
        if ($Manifest.schemaVersion -isnot [int] -or $Manifest.schemaVersion -ne 2 -or
            [string]$Manifest.closureReceipt -cne $script:BridgeClosureReceiptName -or
            [string]$Manifest.closureReceiptSha256 -cnotmatch '^[a-f0-9]{64}$') { return $false }
        $receiptPath = Join-Path ([IO.Path]::GetFullPath($ReleaseRoot)) $script:BridgeClosureReceiptName
        if (-not (Test-BridgePathReparseFree -Root $ReleaseRoot -Path $receiptPath) -or
            -not (Test-Path -LiteralPath $receiptPath -PathType Leaf) -or
            (Get-Item -LiteralPath $receiptPath -Force).Length -gt 4194304 -or
            (Get-BridgeFileSha256 -Path $receiptPath) -cne [string]$Manifest.closureReceiptSha256) { return $false }
        $raw = [IO.File]::ReadAllText($receiptPath, [Text.UTF8Encoding]::new($false, $true))
        if ($raw.Length -gt 4194304 -or -not (Test-BridgeClosureJsonStructure -RawJson $raw)) { return $false }
        $receipt = $raw | ConvertFrom-Json -ErrorAction Stop
        $fields = @('schemaVersion','closureVerified','probeExitCode','releaseId','sourceDigest','lockDigest','runtimeInventoryDigest','baseExecutable','serviceExecutable','probeArgv','sysPath','moduleFiles','loadedDlls')
        $properties = @($receipt.PSObject.Properties.Name)
        if (@($fields | Where-Object { $_ -notin $properties }).Count -ne 0 -or @($properties | Where-Object { $_ -notin $fields }).Count -ne 0 -or
            $receipt.schemaVersion -isnot [int] -or $receipt.schemaVersion -ne 1 -or $receipt.closureVerified -isnot [bool] -or $receipt.closureVerified -ne $true -or
            $receipt.probeExitCode -isnot [int] -or $receipt.probeExitCode -ne 0 -or
            [string]$receipt.releaseId -cnotmatch '^[a-f0-9]{64}$' -or [string]$receipt.sourceDigest -cnotmatch '^[a-f0-9]{64}$' -or
            [string]$receipt.lockDigest -cnotmatch '^[a-f0-9]{64}$' -or [string]$receipt.runtimeInventoryDigest -cnotmatch '^[a-f0-9]{64}$' -or
            [string]$receipt.releaseId -cne [string]$Manifest.releaseId -or [string]$receipt.sourceDigest -cne [string]$Manifest.sourceDigest -or
            [string]$receipt.lockDigest -cne [string]$Manifest.lockDigest -or
            -not ([IO.Path]::GetFullPath([string]$receipt.baseExecutable)).Equals([IO.Path]::GetFullPath([string]$Manifest.baseExecutable), [StringComparison]::OrdinalIgnoreCase) -or
            -not ([IO.Path]::GetFullPath([string]$receipt.serviceExecutable)).Equals([IO.Path]::GetFullPath([string]$Manifest.serviceExecutable), [StringComparison]::OrdinalIgnoreCase) -or
            (@($receipt.probeArgv) -join "`0") -cne (@('-I','-B','-c',$script:BridgeClosureProbeCode) -join "`0") -or
            [string]$receipt.runtimeInventoryDigest -cne (Get-BridgeInventoryDigest -Inventory @(Get-BridgeReleaseInventory -ReleaseRoot $ReleaseRoot))) { return $false }
        if ($receipt.sysPath -isnot [Array] -or $receipt.moduleFiles -isnot [Array] -or $receipt.loadedDlls -isnot [Array] -or
            @($receipt.sysPath).Count -eq 0 -or @($receipt.moduleFiles).Count -lt $script:BridgeClosureRequiredModules.Count -or
            @($receipt.loadedDlls).Count -eq 0) { return $false }
        foreach ($path in @($receipt.sysPath)) {
            if ($path -isnot [string] -or -not (Test-BridgeClosureAllowedPath -ReleaseRoot $ReleaseRoot -Path $path)) { return $false }
        }
        foreach ($collectionName in @('moduleFiles', 'loadedDlls')) {
            $entries = @($receipt.$collectionName)
            $seenPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($entry in $entries) {
                $entryFields = if ($entry.PSObject.Properties.Name -contains 'name') { @('name','path','sha256','size') } else { @('path','sha256','size') }
                if (@($entryFields | Where-Object { $_ -notin @($entry.PSObject.Properties.Name) }).Count -ne 0 -or
                    @($entry.PSObject.Properties.Name | Where-Object { $_ -notin $entryFields }).Count -ne 0 -or
                    -not (Test-BridgeClosureAllowedPath -ReleaseRoot $ReleaseRoot -Path ([string]$entry.path)) -or
                    -not (Test-Path -LiteralPath $entry.path -PathType Leaf) -or
                    [string]$entry.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
                    ($entry.size -isnot [int] -and $entry.size -isnot [long]) -or [int64]$entry.size -lt 0 -or
                    -not $seenPaths.Add([IO.Path]::GetFullPath([string]$entry.path))) { return $false }
                $bytesMatch = [string]$entry.sha256 -ceq (Get-BridgeFileSha256 -Path $entry.path) -and
                    [int64]$entry.size -eq (Get-Item -LiteralPath $entry.path -Force).Length
                # Windows 갱신은 과거 DLL 해시를 바꾸므로 보호된 OS 파일의 서명과 현재 권한을 다시 확인합니다.
                if (-not $bytesMatch -and ($collectionName -cne 'loadedDlls' -or
                    -not (Test-BridgeClosureTrustedExternalDll -ReleaseRoot $ReleaseRoot -Path ([string]$entry.path)))) { return $false }
            }
        }
        foreach ($name in $script:BridgeClosureRequiredModules) {
            if (@($receipt.moduleFiles | Where-Object {
                $_.PSObject.Properties.Name -contains 'name' -and $_.name -ceq $name
            }).Count -ne 1) { return $false }
        }
        return $true
    } catch { return $false }
}
