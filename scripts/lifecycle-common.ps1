Set-StrictMode -Version Latest

function New-BridgeToken {
    [CmdletBinding()]
    param()
    $bytes = [byte[]]::new(32)
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) } finally { $generator.Dispose() }
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Resolve-BridgeLocalRoot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path)

    if (-not [IO.Path]::IsPathRooted($Path)) {
        throw [ArgumentException]::new('BridgeRootRelative: path must be absolute.')
    }
    if ($Path.StartsWith('\\') -or $Path.StartsWith('//') -or
        $Path.StartsWith('\\?\') -or $Path.StartsWith('\\.\') -or $Path.StartsWith('\??\')) {
        throw [ArgumentException]::new('BridgeRootNonLocal: UNC and device paths are not allowed.')
    }
    if ($Path.Length -lt 3 -or $Path[1] -ne ':' -or $Path.Substring(2).Contains(':')) {
        throw [ArgumentException]::new('BridgeRootInvalidVolume: only local drive paths without ADS are allowed.')
    }
    $canonical = [IO.Path]::GetFullPath($Path)
    $volumeRoot = [IO.Path]::GetPathRoot($canonical)
    if ($canonical.TrimEnd('\', '/') -eq $volumeRoot.TrimEnd('\', '/')) {
        throw [ArgumentException]::new('BridgeRootDriveRoot: a drive root cannot be a runtime root.')
    }
    if ($Path.TrimEnd('\', '/') -cne $canonical.TrimEnd('\', '/')) {
        throw [ArgumentException]::new('BridgeRootCanonicalizationChanged: dot segments and non-canonical paths are not allowed.')
    }
    $current = $volumeRoot
    foreach ($segment in $canonical.Substring($volumeRoot.Length).Split([char[]]@('\', '/'), [StringSplitOptions]::RemoveEmptyEntries)) {
        $current = [IO.Path]::Combine($current, $segment)
        if (-not (Test-Path -LiteralPath $current)) { break }
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw [IO.IOException]::new("BridgeRootReparsePoint: reparse paths are not allowed: $current")
        }
        if ($item.FullName.TrimEnd('\', '/') -cne $current.TrimEnd('\', '/')) {
            throw [IO.IOException]::new('BridgeRootPathSwap: path changed during validation.')
        }
    }
    return $canonical.TrimEnd('\', '/')
}

function Assert-BridgePathUnderRoot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Path)
    $safeRoot = Resolve-BridgeLocalRoot -Path $Root
    $canonicalPath = [IO.Path]::GetFullPath($Path)
    if (-not $canonicalPath.StartsWith(($safeRoot + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) {
        throw [UnauthorizedAccessException]::new('BridgePathEscape: target is outside the approved root.')
    }
    [void](Resolve-BridgeLocalRoot -Path (Split-Path -Parent $canonicalPath))
    return $canonicalPath
}

function New-BridgeFileRule {
    param([Parameter(Mandatory)][string]$Sid, [Parameter(Mandatory)][Security.AccessControl.FileSystemRights]$Rights)
    return [Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($Sid), $Rights,
        [Security.AccessControl.AccessControlType]::Allow)
}

function Get-BridgeAclRuleSignatures {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rules)
    return @($Rules | ForEach-Object {
        $sid = $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        '{0}|{1}|{2}|{3}|{4}|{5}' -f $sid, [int]$_.FileSystemRights, $_.AccessControlType,
            $_.InheritanceFlags, $_.PropagationFlags, $_.IsInherited
    } | Sort-Object)
}

function Set-BridgeSecretAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$TokenPath)
    if (-not (Test-Path -LiteralPath $TokenPath -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new('BridgeTokenMissing: token file does not exist.', $TokenPath)
    }
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-BridgeFileRule -Sid 'S-1-5-18' -Rights FullControl))
    $acl.AddAccessRule((New-BridgeFileRule -Sid 'S-1-5-19' -Rights Read))
    $acl.AddAccessRule((New-BridgeFileRule -Sid 'S-1-5-32-544' -Rights FullControl))
    $setAclCommand = Get-Command -Name Set-Acl -CommandType Cmdlet -ErrorAction Stop
    & $setAclCommand -LiteralPath $TokenPath -AclObject $acl
}

function Test-BridgeSecretAclExact {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$TokenPath)
    if (-not (Test-Path -LiteralPath $TokenPath -PathType Leaf)) { return $false }
    $expected = [Security.AccessControl.FileSecurity]::new()
    $expected.SetAccessRuleProtection($true, $false)
    $expected.AddAccessRule((New-BridgeFileRule -Sid 'S-1-5-18' -Rights FullControl))
    $expected.AddAccessRule((New-BridgeFileRule -Sid 'S-1-5-19' -Rights Read))
    $expected.AddAccessRule((New-BridgeFileRule -Sid 'S-1-5-32-544' -Rights FullControl))
    $actual = Get-Acl -LiteralPath $TokenPath -ErrorAction Stop
    $actualRules = Get-BridgeAclRuleSignatures -Rules @($actual.Access)
    $expectedRules = Get-BridgeAclRuleSignatures -Rules @($expected.Access)
    return $actual.AreAccessRulesProtected -and
        ($actualRules | ConvertTo-Json -Compress) -ceq ($expectedRules | ConvertTo-Json -Compress)
}

function New-BridgeDirectoryRule {
    param([Parameter(Mandatory)][string]$Sid, [Parameter(Mandatory)][Security.AccessControl.FileSystemRights]$Rights)
    return [Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($Sid), $Rights,
        ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
        [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
}

function Set-BridgeDirectoryAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path,
        [Parameter(Mandatory)][ValidateSet('Secrets', 'Audit', 'Browser', 'Runtime')][string]$Profile,
        [string]$UserSid = ''
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw [IO.DirectoryNotFoundException]::new("BridgeDirectoryMissing: $Path")
    }
    if ($Profile -in @('Browser', 'Runtime') -and [string]::IsNullOrWhiteSpace($UserSid)) {
        throw [ArgumentException]::new('BridgeUserSidRequired: browser and runtime ACLs require a target user SID.')
    }
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-18' -Rights FullControl))
    $acl.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-32-544' -Rights FullControl))
    if ($Profile -eq 'Secrets') {
        $acl.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-19' -Rights Read))
    } elseif ($Profile -eq 'Audit') {
        $acl.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-19' -Rights Modify))
    } elseif ($Profile -eq 'Browser') {
        $acl.AddAccessRule((New-BridgeDirectoryRule -Sid $UserSid -Rights FullControl))
    } else {
        $acl.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-19' -Rights Modify))
        $acl.AddAccessRule((New-BridgeDirectoryRule -Sid $UserSid -Rights ReadAndExecute))
    }
    $setAclCommand = Get-Command -Name Set-Acl -CommandType Cmdlet -ErrorAction Stop
    & $setAclCommand -LiteralPath $Path -AclObject $acl
}

function Test-BridgeDirectoryAclExact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path,
        [Parameter(Mandatory)][ValidateSet('Secrets', 'Audit', 'Browser', 'Runtime')][string]$Profile,
        [string]$UserSid = ''
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $false }
    if ($Profile -in @('Browser', 'Runtime') -and [string]::IsNullOrWhiteSpace($UserSid)) { return $false }
    $expected = [Security.AccessControl.DirectorySecurity]::new()
    $expected.SetAccessRuleProtection($true, $false)
    $expected.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-18' -Rights FullControl))
    $expected.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-32-544' -Rights FullControl))
    if ($Profile -eq 'Secrets') {
        $expected.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-19' -Rights Read))
    } elseif ($Profile -eq 'Audit') {
        $expected.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-19' -Rights Modify))
    } elseif ($Profile -eq 'Browser') {
        $expected.AddAccessRule((New-BridgeDirectoryRule -Sid $UserSid -Rights FullControl))
    } else {
        $expected.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-19' -Rights Modify))
        $expected.AddAccessRule((New-BridgeDirectoryRule -Sid $UserSid -Rights ReadAndExecute))
    }
    $actual = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $actualRules = Get-BridgeAclRuleSignatures -Rules @($actual.Access)
    $expectedRules = Get-BridgeAclRuleSignatures -Rules @($expected.Access)
    return $actual.AreAccessRulesProtected -and
        ($actualRules | ConvertTo-Json -Compress) -ceq ($expectedRules | ConvertTo-Json -Compress)
}

function Set-BridgeSecretsDirectoryAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    Set-BridgeDirectoryAcl -Path $Path -Profile Secrets
}

function Set-BridgeRuntimeDirectoryAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$UserSid)
    Set-BridgeDirectoryAcl -Path $Path -Profile Runtime -UserSid $UserSid
}

function Set-BridgeAuditDirectoryAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    Set-BridgeDirectoryAcl -Path $Path -Profile Audit
}

function Set-BridgeBrowserDirectoryAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$UserSid)
    Set-BridgeDirectoryAcl -Path $Path -Profile Browser -UserSid $UserSid
}

function Get-BridgeSha256Hex {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return ([BitConverter]::ToString($hasher.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally { $hasher.Dispose() }
}

function New-BridgeBaseRuntimeRule {
    [CmdletBinding()]
    param()
    return New-BridgeDirectoryRule -Sid 'S-1-5-19' -Rights ReadAndExecute
}

function Test-BridgeBaseRuntimeRulePresent {
    [CmdletBinding()]
    param([Parameter(Mandatory)][Security.AccessControl.DirectorySecurity]$Acl)
    $expected = [string](Get-BridgeAclRuleSignatures -Rules @((New-BridgeBaseRuntimeRule)))
    $explicitRules = @($Acl.GetAccessRules(
        $true, $false, [Security.Principal.SecurityIdentifier]
    ))
    return $expected -in (Get-BridgeAclRuleSignatures -Rules $explicitRules)
}

function Get-BridgeRuntimeAccessMarkerPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RuntimeRoot)
    $safeRuntimeRoot = Resolve-BridgeLocalRoot -Path $RuntimeRoot
    return Assert-BridgePathUnderRoot -Root $safeRuntimeRoot -Path (
        [IO.Path]::Combine($safeRuntimeRoot, 'secrets', 'runtime-access.json')
    )
}

function Get-BridgeRuntimeAccessMarkerHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$SchemaVersion,
        [Parameter(Mandatory)][ValidateSet('pending', 'applied')][string]$Status,
        [Parameter(Mandatory)][string]$BaseRoot,
        [Parameter(Mandatory)][string]$BaseExecutable,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$PreAclHash
    )
    return Get-BridgeSha256Hex -Value (@(
        [string]$SchemaVersion, $Status, $BaseRoot, $BaseExecutable, $PreAclHash,
        'S-1-5-19', [string][int][Security.AccessControl.FileSystemRights]::ReadAndExecute,
        'ContainerInherit,ObjectInherit', 'None', 'Allow'
    ) -join "`n")
}

function Set-BridgeRuntimeAccessMarkerAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$MarkerPath)
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-BridgeFileRule -Sid 'S-1-5-18' -Rights FullControl))
    $acl.AddAccessRule((New-BridgeFileRule -Sid 'S-1-5-32-544' -Rights FullControl))
    Set-Acl -LiteralPath $MarkerPath -AclObject $acl
}

function Test-BridgeRuntimeAccessMarkerAclExact {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$MarkerPath)
    $expected = [Security.AccessControl.FileSecurity]::new()
    $expected.SetAccessRuleProtection($true, $false)
    $expected.AddAccessRule((New-BridgeFileRule -Sid 'S-1-5-18' -Rights FullControl))
    $expected.AddAccessRule((New-BridgeFileRule -Sid 'S-1-5-32-544' -Rights FullControl))
    $actual = Get-Acl -LiteralPath $MarkerPath -ErrorAction Stop
    $actualRules = @($actual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $expectedRules = @($expected.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    return $actual.AreAccessRulesProtected -and
        (Get-BridgeAclRuleSignatures -Rules $actualRules | ConvertTo-Json -Compress) -ceq
        (Get-BridgeAclRuleSignatures -Rules $expectedRules | ConvertTo-Json -Compress)
}

function Write-BridgeRuntimeAccessMarker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RuntimeRoot,
        [Parameter(Mandatory)][ValidateSet('pending', 'applied')][string]$Status,
        [Parameter(Mandatory)][string]$BaseRoot,
        [Parameter(Mandatory)][string]$BaseExecutable,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$PreAclHash
    )
    $markerPath = Get-BridgeRuntimeAccessMarkerPath -RuntimeRoot $RuntimeRoot
    $markerDirectory = Split-Path -Parent $markerPath
    if (-not (Test-Path -LiteralPath $markerDirectory -PathType Container)) {
        throw [IO.DirectoryNotFoundException]::new('BridgeRuntimeAccessMarkerDirectoryMissing: secrets directory is missing.')
    }
    $markerHash = Get-BridgeRuntimeAccessMarkerHash -SchemaVersion 1 -Status $Status `
        -BaseRoot $BaseRoot -BaseExecutable $BaseExecutable -PreAclHash $PreAclHash
    $document = [ordered]@{
        schemaVersion = 1; status = $Status; baseRoot = $BaseRoot; baseExecutable = $BaseExecutable
        preAclHash = $PreAclHash; markerHash = $markerHash
    } | ConvertTo-Json -Compress
    $temporaryPath = [IO.Path]::Combine($markerDirectory, ([IO.Path]::GetRandomFileName() + '.tmp'))
    try {
        [IO.File]::WriteAllText($temporaryPath, $document, [Text.UTF8Encoding]::new($false))
        Set-BridgeRuntimeAccessMarkerAcl -MarkerPath $temporaryPath
        # Windows PowerShell 5.1은 $null을 빈 문자열로 변환하므로 실제 null 문자열을 전달합니다.
        if (Test-Path -LiteralPath $markerPath) { [IO.File]::Replace($temporaryPath, $markerPath, [System.Management.Automation.Language.NullString]::Value, $true) }
        else { [IO.File]::Move($temporaryPath, $markerPath) }
        Set-BridgeRuntimeAccessMarkerAcl -MarkerPath $markerPath
    } finally {
        if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -Force }
    }
}

function Read-BridgeRuntimeAccessMarker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RuntimeRoot,
        [string]$MarkerPath = ''
    )
    $expectedPath = Get-BridgeRuntimeAccessMarkerPath -RuntimeRoot $RuntimeRoot
    if ([string]::IsNullOrWhiteSpace($MarkerPath)) { $MarkerPath = $expectedPath }
    $safeMarkerPath = Assert-BridgePathUnderRoot -Root $RuntimeRoot -Path $MarkerPath
    if (-not $safeMarkerPath.Equals($expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw [UnauthorizedAccessException]::new('BridgeRuntimeAccessMarkerPathMismatch: marker path is not owned by the bridge.')
    }
    if (-not (Test-Path -LiteralPath $safeMarkerPath -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new('BridgeRuntimeAccessMarkerMissing: runtime marker is missing.', $safeMarkerPath)
    }
    $markerItem = Get-Item -LiteralPath $safeMarkerPath -Force -ErrorAction Stop
    if (($markerItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw [IO.IOException]::new('BridgeRuntimeAccessMarkerReparsePoint: marker cannot be a reparse point.')
    }
    $marker = Get-Content -LiteralPath $safeMarkerPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $required = @('schemaVersion', 'status', 'baseRoot', 'baseExecutable', 'preAclHash', 'markerHash')
    if (@($required | Where-Object { $_ -notin $marker.PSObject.Properties.Name }).Count -ne 0 -or
        [int]$marker.schemaVersion -ne 1 -or [string]$marker.status -notin @('pending', 'applied') -or
        [string]$marker.preAclHash -notmatch '^[a-f0-9]{64}$' -or [string]$marker.markerHash -notmatch '^[a-f0-9]{64}$') {
        throw [IO.InvalidDataException]::new('BridgeRuntimeAccessMarkerInvalid: marker schema is invalid.')
    }
    $safeBaseRoot = Resolve-BridgeLocalRoot -Path ([string]$marker.baseRoot)
    $safeBaseExecutable = Assert-BridgePathUnderRoot -Root $safeBaseRoot -Path ([string]$marker.baseExecutable)
    if (-not (Test-Path -LiteralPath $safeBaseRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $safeBaseExecutable -PathType Leaf) -or
        -not (Split-Path -Parent $safeBaseExecutable).Equals($safeBaseRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw [IO.InvalidDataException]::new('BridgeRuntimeAccessMarkerRuntimeInvalid: recorded base runtime is not exact.')
    }
    $expectedHash = Get-BridgeRuntimeAccessMarkerHash -SchemaVersion 1 -Status ([string]$marker.status) `
        -BaseRoot $safeBaseRoot -BaseExecutable $safeBaseExecutable -PreAclHash ([string]$marker.preAclHash)
    if (-not $expectedHash.Equals([string]$marker.markerHash, [StringComparison]::Ordinal)) {
        throw [IO.InvalidDataException]::new('BridgeRuntimeAccessMarkerHashMismatch: marker integrity check failed.')
    }
    if (-not (Test-BridgeRuntimeAccessMarkerAclExact -MarkerPath $safeMarkerPath)) {
        throw [UnauthorizedAccessException]::new('BridgeRuntimeAccessMarkerAclInvalid: marker ACL is not restrictive.')
    }
    return [pscustomobject]@{
        schemaVersion = 1; status = [string]$marker.status; baseRoot = $safeBaseRoot
        baseExecutable = $safeBaseExecutable; preAclHash = [string]$marker.preAclHash
        markerHash = [string]$marker.markerHash; path = $safeMarkerPath
    }
}

function Grant-BridgeBaseRuntimeAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RuntimeRoot,
        [Parameter(Mandatory)][string]$BaseRoot,
        [Parameter(Mandatory)][string]$BaseExecutable
    )
    $safeBaseRoot = Resolve-BridgeLocalRoot -Path $BaseRoot
    $safeBaseExecutable = Assert-BridgePathUnderRoot -Root $safeBaseRoot -Path $BaseExecutable
    if (-not (Test-Path -LiteralPath $safeBaseRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $safeBaseExecutable -PathType Leaf) -or
        -not (Split-Path -Parent $safeBaseExecutable).Equals($safeBaseRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw [IO.InvalidDataException]::new('BridgeBaseRuntimeInvalid: base executable must be a direct child of its runtime root.')
    }
    $markerPath = Get-BridgeRuntimeAccessMarkerPath -RuntimeRoot $RuntimeRoot
    if (Test-Path -LiteralPath $markerPath -PathType Leaf) {
        $ownedMarker = Read-BridgeRuntimeAccessMarker -RuntimeRoot $RuntimeRoot
        if (-not $ownedMarker.baseRoot.Equals($safeBaseRoot, [StringComparison]::OrdinalIgnoreCase) -or
            -not $ownedMarker.baseExecutable.Equals($safeBaseExecutable, [StringComparison]::OrdinalIgnoreCase)) {
            throw [IO.InvalidDataException]::new('BridgeRuntimeAccessMarkerConflict: marker owns a different base runtime.')
        }
        $ownedAcl = Get-Acl -LiteralPath $safeBaseRoot -ErrorAction Stop
        if ($ownedMarker.status -ceq 'pending') {
            if (Test-BridgeBaseRuntimeRulePresent -Acl $ownedAcl) {
                throw [UnauthorizedAccessException]::new('BridgeBaseRuntimeAccessOwnershipAmbiguous: pending marker cannot own an existing ACE.')
            }
            Remove-Item -LiteralPath $markerPath -Force -ErrorAction Stop
        } elseif (-not (Test-BridgeBaseRuntimeRulePresent -Acl $ownedAcl)) {
            throw [UnauthorizedAccessException]::new('BridgeBaseRuntimeAccessMissing: owned LocalService ACE is absent.')
        } else {
            return [pscustomobject]@{ applied = $false; state = 'unchanged-owned'; markerPath = $markerPath }
        }
    }
    $baseAcl = Get-Acl -LiteralPath $safeBaseRoot -ErrorAction Stop
    if (Test-BridgeBaseRuntimeRulePresent -Acl $baseAcl) {
        return [pscustomobject]@{ applied = $false; state = 'unchanged-preexisting'; markerPath = $null }
    }
    $localServiceRules = @($baseAcl.GetAccessRules(
        $true, $false, [Security.Principal.SecurityIdentifier]
    ) | Where-Object {
        $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -ceq 'S-1-5-19'
    })
    if ($localServiceRules.Count -ne 0) {
        throw [UnauthorizedAccessException]::new('BridgeBaseRuntimeAccessConflict: a different explicit LocalService ACE already exists.')
    }
    $preAclHash = Get-BridgeSha256Hex -Value $baseAcl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
    Write-BridgeRuntimeAccessMarker -RuntimeRoot $RuntimeRoot -Status pending -BaseRoot $safeBaseRoot `
        -BaseExecutable $safeBaseExecutable -PreAclHash $preAclHash
    $accessWriteCompleted = $false
    try {
        $baseAcl.AddAccessRule((New-BridgeBaseRuntimeRule))
        Set-Acl -LiteralPath $safeBaseRoot -AclObject $baseAcl
        $accessWriteCompleted = $true
        if (-not (Test-BridgeBaseRuntimeRulePresent -Acl (Get-Acl -LiteralPath $safeBaseRoot -ErrorAction Stop))) {
            throw [UnauthorizedAccessException]::new('BridgeBaseRuntimeAccessVerificationFailed: exact LocalService RX ACE was not observed.')
        }
        Write-BridgeRuntimeAccessMarker -RuntimeRoot $RuntimeRoot -Status applied -BaseRoot $safeBaseRoot `
            -BaseExecutable $safeBaseExecutable -PreAclHash $preAclHash
    } catch {
        $grantError = $_
        $currentAcl = Get-Acl -LiteralPath $safeBaseRoot -ErrorAction Stop
        $rulePresent = Test-BridgeBaseRuntimeRulePresent -Acl $currentAcl
        if (-not $accessWriteCompleted -and $rulePresent) {
            throw [UnauthorizedAccessException]::new(
                'BridgeBaseRuntimeAccessOwnershipAmbiguous: failed ACL write cannot own the observed ACE.',
                $grantError.Exception
            )
        }
        if ($accessWriteCompleted -and $rulePresent) {
            [void]$currentAcl.RemoveAccessRuleSpecific((New-BridgeBaseRuntimeRule))
        }
        $rollbackHash = Get-BridgeSha256Hex -Value $currentAcl.GetSecurityDescriptorSddlForm(
            [Security.AccessControl.AccessControlSections]::Access
        )
        if (-not $rollbackHash.Equals($preAclHash, [StringComparison]::Ordinal)) {
            throw [UnauthorizedAccessException]::new(
                'BridgeBaseRuntimeAccessOwnershipAmbiguous: failed grant rollback does not match the recorded pre-install ACL.',
                $grantError.Exception
            )
        }
        if ($accessWriteCompleted -and $rulePresent) {
            Set-Acl -LiteralPath $safeBaseRoot -AclObject $currentAcl
        }
        if (Test-Path -LiteralPath $markerPath -PathType Leaf) { Remove-Item -LiteralPath $markerPath -Force }
        throw $grantError
    }
    return [pscustomobject]@{ applied = $true; state = 'applied-exact'; markerPath = $markerPath }
}

function Restore-BridgeBaseRuntimeAccess {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RuntimeRoot)
    $marker = Read-BridgeRuntimeAccessMarker -RuntimeRoot $RuntimeRoot
    $runtimeAcl = Get-Acl -LiteralPath $marker.baseRoot -ErrorAction Stop
    $rulePresent = Test-BridgeBaseRuntimeRulePresent -Acl $runtimeAcl
    if ($marker.status -ceq 'pending') {
        if ($rulePresent) {
            throw [UnauthorizedAccessException]::new('BridgeBaseRuntimeAccessOwnershipAmbiguous: pending marker cannot authorize ACE removal.')
        }
        Remove-Item -LiteralPath $marker.path -Force -ErrorAction Stop
        return [pscustomobject]@{ restored = $false; state = 'pending-marker-cleared' }
    }
    if ($rulePresent) { [void]$runtimeAcl.RemoveAccessRuleSpecific((New-BridgeBaseRuntimeRule)) }
    $candidateHash = Get-BridgeSha256Hex -Value $runtimeAcl.GetSecurityDescriptorSddlForm(
        [Security.AccessControl.AccessControlSections]::Access
    )
    if (-not $candidateHash.Equals($marker.preAclHash, [StringComparison]::Ordinal)) {
        throw [UnauthorizedAccessException]::new('BridgeBaseRuntimeAccessOwnershipAmbiguous: current ACL does not match the recorded pre-install ACL.')
    }
    if ($rulePresent) {
        Set-Acl -LiteralPath $marker.baseRoot -AclObject $runtimeAcl
        if (Test-BridgeBaseRuntimeRulePresent -Acl (Get-Acl -LiteralPath $marker.baseRoot -ErrorAction Stop)) {
            throw [UnauthorizedAccessException]::new('BridgeBaseRuntimeAccessRestoreFailed: owned ACE remains after exact removal.')
        }
    }
    try { Remove-Item -LiteralPath $marker.path -Force -ErrorAction Stop }
    catch {
        if ($rulePresent) {
            $rollbackAcl = Get-Acl -LiteralPath $marker.baseRoot -ErrorAction Stop
            $rollbackAcl.AddAccessRule((New-BridgeBaseRuntimeRule))
            Set-Acl -LiteralPath $marker.baseRoot -AclObject $rollbackAcl
        }
        throw [IO.IOException]::new('BridgeRuntimeAccessMarkerRemovalFailed: exact ACE removal was rolled back.', $_.Exception)
    }
    return [pscustomobject]@{ restored = $rulePresent; state = if ($rulePresent) { 'restored-exact' } else { 'already-absent' } }
}

function Test-BridgeAdministrator {
    [CmdletBinding()]
    param()
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-BridgePythonEntrypoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [Parameter(Mandatory)][ValidatePattern('^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)+$')][string]$Module
    )
    $modulePath = [IO.Path]::Combine($ProjectRoot, 'src', (($Module -replace '\.', [IO.Path]::DirectorySeparatorChar) + '.py'))
    try {
        $safePath = Assert-BridgePathUnderRoot -Root $ProjectRoot -Path $modulePath
        if (-not (Test-Path -LiteralPath $safePath -PathType Leaf)) { return $false }
        $item = Get-Item -LiteralPath $safePath -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not $item.FullName.Equals($safePath, [StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
        $source = Get-Content -LiteralPath $safePath -Raw -ErrorAction Stop
        return $source -match '(?m)^def main\(' -and $source -match '(?m)^if __name__ == ["'']__main__["'']:'
    } catch {
        return $false
    }
}

function Test-BridgeRegistrationAdapterContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ScriptRoot,
        [Parameter(Mandatory)][ValidateSet(
            'register-gateway-service.ps1',
            'register-privileged-service.ps1',
            'register-worker-task.ps1'
        )][string]$ScriptName,
        [string[]]$RequiredParameters = @('Apply', 'Json', 'AdapterMode', 'Operation')
    )
    try {
        $safeScriptRoot = Resolve-BridgeLocalRoot -Path $ScriptRoot
        $scriptPath = Assert-BridgePathUnderRoot -Root $safeScriptRoot -Path ([IO.Path]::Combine($safeScriptRoot, $ScriptName))
        if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { return $false }
        $item = Get-Item -LiteralPath $scriptPath -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not $item.FullName.Equals($scriptPath, [StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
        $tokens = $null
        $parseErrors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
        if ($parseErrors.Count -ne 0 -or $null -eq $ast.ParamBlock) { return $false }
        $parameterNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
        return @($RequiredParameters | Where-Object { $_ -notin $parameterNames }).Count -eq 0
    } catch {
        return $false
    }
}

function Write-BridgeTokenAtomic {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$TokenPath,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Token
    )
    $safeTokenPath = Assert-BridgePathUnderRoot -Root $Root -Path $TokenPath
    $directory = Split-Path -Parent $safeTokenPath
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        throw [IO.DirectoryNotFoundException]::new('BridgeTokenDirectoryMissing: create the validated token directory first.')
    }
    $temporaryPath = [IO.Path]::Combine($directory, ([IO.Path]::GetRandomFileName() + '.tmp'))
    $backupPath = $safeTokenPath + '.backup'
    $hadExisting = Test-Path -LiteralPath $safeTokenPath -PathType Leaf
    try {
        [IO.File]::WriteAllText($temporaryPath, $Token, [Text.UTF8Encoding]::new($false))
        [void](Assert-BridgePathUnderRoot -Root $Root -Path $safeTokenPath)
        if ($hadExisting) {
            [IO.File]::Replace($temporaryPath, $safeTokenPath, $backupPath, $true)
            Set-BridgeSecretAcl -TokenPath $backupPath
        } else {
            [IO.File]::Move($temporaryPath, $safeTokenPath)
        }
        Set-BridgeSecretAcl -TokenPath $safeTokenPath
        return [pscustomobject]@{ path = $safeTokenPath; replaced = $hadExisting; backupPath = if ($hadExisting) { $backupPath } else { $null }; tokenExposed = $false }
    } catch {
        $operationError = $_
        if ($hadExisting -and (Test-Path -LiteralPath $backupPath)) {
            try {
                if (Test-Path -LiteralPath $safeTokenPath) { Remove-Item -LiteralPath $safeTokenPath -Force }
                [IO.File]::Move($backupPath, $safeTokenPath)
                Set-BridgeSecretAcl -TokenPath $safeTokenPath
            } catch {
                throw [InvalidOperationException]::new('BridgeTokenRollbackFailed: token replacement and rollback failed.', $_.Exception)
            }
        } elseif (-not $hadExisting -and (Test-Path -LiteralPath $safeTokenPath)) {
            Remove-Item -LiteralPath $safeTokenPath -Force
        }
        throw $operationError
    } finally {
        if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -Force }
    }
}

function ConvertTo-BridgeWindowsArgument {
    param([AllowEmptyString()][string]$Argument)
    if ($Argument -notmatch '[\s"]') { return $Argument }
    $builder = [Text.StringBuilder]::new('"')
    $backslashes = 0
    foreach ($character in $Argument.ToCharArray()) {
        if ($character -eq '\') { $backslashes++; continue }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (($backslashes * 2) + 1)))
            [void]$builder.Append('"')
        } else {
            [void]$builder.Append(('\' * $backslashes))
            [void]$builder.Append($character)
        }
        $backslashes = 0
    }
    [void]$builder.Append(('\' * ($backslashes * 2)))
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Invoke-BridgeChildProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$FilePath,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ArgumentList,
        [string]$WorkingDirectory = '',
        [ValidateRange(1, 300)][int]$TimeoutSeconds = 30
    )
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        $startInfo.WorkingDirectory = $WorkingDirectory
    }
    if ($null -ne $startInfo.PSObject.Properties['ArgumentList']) {
        foreach ($argument in $ArgumentList) { [void]$startInfo.ArgumentList.Add($argument) }
    } else {
        # Windows PowerShell 5.1에서는 shell을 거치지 않고 CommandLineToArgvW 규칙으로 배열을 직렬화합니다.
        $encodedArguments = foreach ($argument in $ArgumentList) { ConvertTo-BridgeWindowsArgument -Argument $argument }
        $startInfo.Arguments = $encodedArguments -join ' '
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        [void]$process.Start()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill()
            throw [TimeoutException]::new("BridgeChildTimeout: child process exceeded ${TimeoutSeconds} seconds.")
        }
        return [pscustomobject]@{ exitCode = $process.ExitCode; stdout = $stdoutTask.GetAwaiter().GetResult(); stderr = $stderrTask.GetAwaiter().GetResult() }
    } finally { $process.Dispose() }
}

function Get-BridgeRuntimeContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [Parameter(Mandatory)][string]$PythonPath
    )
    $result = [ordered]@{ verified = $false; failureReason = 'runtime-contract-unverified'; contract = $null }
    try {
        $safeProjectRoot = Resolve-BridgeLocalRoot -Path $ProjectRoot
        $safePythonPath = Assert-BridgePathUnderRoot -Root $safeProjectRoot -Path $PythonPath
        if (-not (Test-Path -LiteralPath $safePythonPath -PathType Leaf)) {
            $result.failureReason = 'runtime-python-unverified'
            return [pscustomobject]$result
        }
        $probe = @'
import json
import pathlib
import sys
from hermes_windows_bridge.gateway.windows_service import GATEWAY_SERVICE
from hermes_windows_bridge.privileged.windows_service import PRIVILEGED_SERVICE
from hermes_windows_bridge.worker.main import build_worker_task_manifest
worker = build_worker_task_manifest(user_id="Bridge.Contract")
print(json.dumps({
    "runtime": {
        "executable": sys.executable,
        "baseExecutable": sys._base_executable,
        "baseRoot": str(pathlib.Path(sys._base_executable).parent),
    },
    "gateway": {"name": GATEWAY_SERVICE.name, "account": GATEWAY_SERVICE.account, "argv": list(GATEWAY_SERVICE.argv)},
    "privileged": {"name": PRIVILEGED_SERVICE.name, "account": PRIVILEGED_SERVICE.account, "argv": list(PRIVILEGED_SERVICE.argv)},
    "worker": {"name": worker.name, "trigger": worker.trigger, "logonType": worker.logon_type, "runLevel": worker.run_level, "argv": list(worker.argv)},
}, separators=(",", ":")))
'@
        $probeResult = Invoke-BridgeChildProcess -FilePath $safePythonPath -ArgumentList @('-c', $probe) -WorkingDirectory $safeProjectRoot -TimeoutSeconds 30
        if ($probeResult.exitCode -ne 0 -or [string]::IsNullOrWhiteSpace($probeResult.stdout)) {
            $result.failureReason = 'runtime-import-failed'
            return [pscustomobject]$result
        }
        $contract = $probeResult.stdout | ConvertFrom-Json -ErrorAction Stop
        $pythonExecutable = [IO.Path]::GetFullPath($safePythonPath)
        $workerExecutable = [IO.Path]::Combine((Split-Path -Parent $pythonExecutable), 'pythonw.exe')
        $runtimeExecutable = Assert-BridgePathUnderRoot -Root $safeProjectRoot -Path ([string]$contract.runtime.executable)
        $baseRoot = Resolve-BridgeLocalRoot -Path ([string]$contract.runtime.baseRoot)
        $baseExecutable = Assert-BridgePathUnderRoot -Root $baseRoot -Path ([string]$contract.runtime.baseExecutable)
        $verified =
            $runtimeExecutable.Equals($pythonExecutable, [StringComparison]::OrdinalIgnoreCase) -and
            (Test-Path -LiteralPath $baseExecutable -PathType Leaf) -and
            (Split-Path -Parent $baseExecutable).Equals($baseRoot, [StringComparison]::OrdinalIgnoreCase) -and
            $contract.gateway.name -ceq 'HermesWindowsBridgeGateway' -and
            $contract.gateway.account -ceq 'NT AUTHORITY\LocalService' -and
            (($contract.gateway.argv | ConvertTo-Json -Compress) -ceq (@($pythonExecutable, '-I', '-B', '-m', 'hermes_windows_bridge.gateway.windows_service') | ConvertTo-Json -Compress)) -and
            $contract.privileged.name -ceq 'HermesWindowsBridgePrivileged' -and
            $contract.privileged.account -ceq 'LocalSystem' -and
            (($contract.privileged.argv | ConvertTo-Json -Compress) -ceq (@($pythonExecutable, '-I', '-B', '-m', 'hermes_windows_bridge.privileged.main') | ConvertTo-Json -Compress)) -and
            $contract.worker.name -ceq 'HermesWindowsBridgeWorker' -and
            $contract.worker.trigger -ceq 'AtLogOn' -and
            $contract.worker.logonType -ceq 'InteractiveToken' -and
            $contract.worker.runLevel -ceq 'Limited' -and
            (Test-Path -LiteralPath $workerExecutable -PathType Leaf) -and
            (($contract.worker.argv | ConvertTo-Json -Compress) -ceq (@($workerExecutable, '-m', 'hermes_windows_bridge.worker.main') | ConvertTo-Json -Compress))
        $result.verified = $verified
        $result.failureReason = if ($verified) { $null } else { 'runtime-contract-mismatch' }
        $result.contract = $contract
    } catch {
        $result.failureReason = 'runtime-contract-unverified'
    }
    return [pscustomobject]$result
}

function Get-BridgeRegistrationAdapterFailure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$ExitCode,
        [AllowNull()][AllowEmptyString()][string]$StandardOutput,
        [AllowNull()][AllowEmptyString()][string]$StandardError
    )
    $failureReason = if ($ExitCode -eq 0) { 'empty-child-output' } else { 'unstructured-child-failure' }
    if (-not [string]::IsNullOrWhiteSpace($StandardOutput)) {
        try {
            $failureManifest = $StandardOutput | ConvertFrom-Json -ErrorAction Stop
            $candidateReason = [string]$failureManifest.failureReason
            if ($candidateReason -match '^[a-z][a-z0-9-]{0,79}$') { $failureReason = $candidateReason }
        } catch {
            $failureReason = 'invalid-child-failure-json'
        }
    }
    $diagnostic = ([string]$StandardError).Trim() -replace '[\r\n\t:;]+', ' '
    $diagnostic = [regex]::Replace(
        $diagnostic,
        '(?i)\b(bearer|token|secret|authorization)\b\s*[= ]\s*[^\s,]+',
        '$1=[REDACTED]'
    ) -replace '\s+', ' '
    if ([string]::IsNullOrWhiteSpace($diagnostic)) { $diagnostic = 'empty-stderr' }
    if ($diagnostic.Length -gt 240) { $diagnostic = $diagnostic.Substring(0, 240) }
    return [pscustomobject]@{ reason = $failureReason; diagnostic = $diagnostic }
}

function Invoke-BridgeRegistrationAdapter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ScriptRoot,
        [Parameter(Mandatory)][ValidateSet(
            'register-gateway-service.ps1',
            'register-privileged-service.ps1',
            'register-worker-task.ps1'
        )][string]$ScriptName,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [Parameter(Mandatory)][ValidateSet('Production', 'Simulate')][string]$AdapterMode,
        [Parameter(Mandatory)][ValidateSet('Register', 'Remove')][string]$Operation,
        [Parameter(Mandatory)][string]$ExpectedName,
        [Parameter(Mandatory)][string]$ExpectedAccount,
        [Parameter(Mandatory)][string[]]$ExpectedArgv
    )
    if (-not (Test-BridgeRegistrationAdapterContract -ScriptRoot $ScriptRoot -ScriptName $ScriptName)) {
        throw [InvalidOperationException]::new("BridgeRegistrationAdapterContractInvalid: $ScriptName")
    }
    $safeScriptRoot = Resolve-BridgeLocalRoot -Path $ScriptRoot
    $scriptPath = Assert-BridgePathUnderRoot -Root $safeScriptRoot -Path ([IO.Path]::Combine($safeScriptRoot, $ScriptName))
    $powershellPath = [IO.Path]::Combine($PSHOME, 'powershell.exe')
    $childArguments = @('-NoProfile', '-NonInteractive', '-File', $scriptPath) + $ArgumentList + @('-Apply', '-Json', '-Operation', $Operation)
    if ($AdapterMode -eq 'Simulate') { $childArguments += @('-AdapterMode', 'Simulate') }
    $adapterResult = Invoke-BridgeChildProcess -FilePath $powershellPath -ArgumentList $childArguments -WorkingDirectory $safeScriptRoot -TimeoutSeconds 60
    if ($adapterResult.exitCode -ne 0 -or [string]::IsNullOrWhiteSpace($adapterResult.stdout)) {
        $failure = Get-BridgeRegistrationAdapterFailure -ExitCode $adapterResult.exitCode -StandardOutput $adapterResult.stdout -StandardError $adapterResult.stderr
        throw [InvalidOperationException]::new("BridgeRegistrationAdapterFailed[$ScriptName;exit=$($adapterResult.exitCode);reason=$($failure.reason);stderr=$($failure.diagnostic)]")
    }
    try { $manifest = $adapterResult.stdout | ConvertFrom-Json -ErrorAction Stop }
    catch { throw [IO.InvalidDataException]::new("BridgeRegistrationAdapterOutputInvalid: $ScriptName did not return one JSON manifest.", $_.Exception) }
    if ($manifest.mode -cne 'apply' -or $manifest.operation -cne $Operation -or
        $manifest.applyRequiresAdministrator -ne $true -or
        $manifest.name -cne $ExpectedName -or $manifest.account -cne $ExpectedAccount -or
        (($manifest.argv | ConvertTo-Json -Compress) -cne ($ExpectedArgv | ConvertTo-Json -Compress))) {
        throw [IO.InvalidDataException]::new("BridgeRegistrationAdapterMismatch: $ScriptName returned a different security definition.")
    }
    if ($ScriptName -eq 'register-worker-task.ps1' -and
        ($manifest.trigger -cne 'AtLogOn' -or $manifest.logonType -cne 'InteractiveToken' -or $manifest.runLevel -cne 'Limited')) {
        throw [IO.InvalidDataException]::new('BridgeRegistrationAdapterPrivilegeMismatch: Worker must remain non-elevated and interactive-logon scoped.')
    }
    if ($ScriptName -ne 'register-worker-task.ps1' -and $manifest.interactive -ne $false) {
        throw [IO.InvalidDataException]::new('BridgeRegistrationAdapterPrivilegeMismatch: services must not be interactive.')
    }
    if ($ScriptName -eq 'register-privileged-service.ps1' -and $manifest.networkListener -ne $false) {
        throw [IO.InvalidDataException]::new('BridgeRegistrationAdapterNetworkMismatch: Privileged Helper must not expose a listener.')
    }
    if ($AdapterMode -eq 'Simulate') {
        if ($manifest.applied -ne $false -or $manifest.state -cne 'simulated' -or
            $manifest.dispatch.adapterMode -cne 'Simulate' -or $manifest.dispatch.operation -cne $Operation -or
            $manifest.dispatch.externalCalls -ne 0) {
            throw [IO.InvalidDataException]::new("BridgeRegistrationAdapterSimulationInvalid: $ScriptName reported a mutation.")
        }
    } elseif (($manifest.applied -ne $true -and $manifest.state -cne 'unchanged') -or
        $manifest.readBack.performed -ne $true -or $manifest.readBack.exact -ne $true) {
        throw [IO.InvalidDataException]::new("BridgeRegistrationAdapterApplyInvalid: $ScriptName did not report applied or unchanged.")
    }
    return $manifest
}
