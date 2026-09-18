Set-StrictMode -Version Latest
Add-Type -AssemblyName Microsoft.VisualBasic

$script:BridgeRuntimePythonVersion = '3.14.3'
$script:BridgeRuntimeArchitecture = 'x64'
$script:BridgePythonArchiveUrl = 'https://github.com/astral-sh/python-build-standalone/releases/download/20260325/cpython-3.14.3%2B20260325-x86_64-pc-windows-msvc-install_only_stripped.tar.gz'
$script:BridgePythonArchiveSha256 = '0cecd031831c1a9607bab3646b241c17ac627ff48a01ddf388dded692a44a9e5'
$script:BridgePythonManagedPayloadKey = 'cpython-3.14.3-windows-x86_64-none'
$script:BridgePythonManagedAliasKey = 'cpython-3.14-windows-x86_64-none'
$script:BridgeRuntimeSourcePatterns = @('src', 'scripts', 'pyproject.toml', 'uv.lock', '.python-version')
$commonHelper = Join-Path $PSScriptRoot 'service-runtime-build-common.ps1'
if (-not (Test-Path -LiteralPath $commonHelper -PathType Leaf)) {
    throw [IO.FileNotFoundException]::new('BridgeRuntimeBuildCommonMissing')
}
. $commonHelper
$closureHelper = Join-Path $PSScriptRoot 'service-runtime-closure.ps1'
if (-not (Test-Path -LiteralPath $closureHelper -PathType Leaf)) {
    throw [IO.FileNotFoundException]::new('BridgeRuntimeClosureHelperMissing')
}
. $closureHelper

function Get-BridgeBuildFileInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SourceRoot)
    $root = [IO.Path]::GetFullPath($SourceRoot)
    $files = [Collections.Generic.List[object]]::new()
    foreach ($name in $script:BridgeRuntimeSourcePatterns) {
        $candidate = Join-Path $root $name
        if (-not (Test-Path -LiteralPath $candidate)) { continue }
        $items = if (Test-Path -LiteralPath $candidate -PathType Container) {
            if (((Get-Item -LiteralPath $candidate -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw [Security.SecurityException]::new('BridgeRuntimeSourceReparseDisallowed')
            }
            if ($name -eq 'scripts') {
                @(Get-ChildItem -LiteralPath $candidate -File -Force -Filter '*.ps1')
            } else {
                $pending = [Collections.Generic.Queue[string]]::new(); $pending.Enqueue($candidate)
                $found = [Collections.Generic.List[object]]::new()
                while ($pending.Count -gt 0) {
                    $directory = $pending.Dequeue()
                    foreach ($child in Get-ChildItem -LiteralPath $directory -Force) {
                        if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                            throw [Security.SecurityException]::new('BridgeRuntimeSourceReparseDisallowed')
                        }
                        if ($child.PSIsContainer) { $pending.Enqueue($child.FullName) } else { $found.Add($child) }
                    }
                }
                @($found)
            }
        } else { @(Get-Item -LiteralPath $candidate -Force) }
        foreach ($item in $items) {
            $relative = $item.FullName.Substring($root.TrimEnd('\').Length + 1).Replace('\', '/')
            if ($relative -match '(^|/)(__pycache__|\.pytest_cache|\.ruff_cache)(/|$)' -or
                $relative -match '\.(pyc|pyo)$') { continue }
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                -not (Test-BridgePathReparseFree -Root $root -Path $item.FullName)) {
                throw [Security.SecurityException]::new('BridgeRuntimeSourceReparseDisallowed')
            }
            if ((Get-BridgeFileLinkCount -Path $item.FullName) -ne 1) {
                throw [Security.SecurityException]::new('BridgeRuntimeSourceHardlinkDisallowed')
            }
            $files.Add([pscustomobject][ordered]@{
                relativePath = $relative
                sha256 = Get-BridgeFileSha256 -Path $item.FullName
                size = [int64]$item.Length
            })
        }
    }
    # 승인 digest는 PowerShell 버전이나 현재 culture와 무관해야 합니다.
    $files.Sort([Comparison[object]]{
        param($left, $right)
        return [StringComparer]::Ordinal.Compare(
            [string]$left.relativePath,
            [string]$right.relativePath
        )
    })
    return @($files)
}

function Get-BridgeSourceSnapshotDigest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$UvVersion
    )
    $inventory = @(Get-BridgeBuildFileInventory -SourceRoot $SourceRoot)
    $canonical = [ordered]@{
        files = $inventory
        pythonVersion = $script:BridgeRuntimePythonVersion
        architecture = $script:BridgeRuntimeArchitecture
        uvVersion = $UvVersion
    } | ConvertTo-Json -Depth 6 -Compress
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($canonical)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $algorithm.Dispose() }
}

function Get-BridgeUvIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TrustedUvPath,
        [Parameter(Mandatory)][string]$ExpectedUvSha256
    )
    $path = [IO.Path]::GetFullPath($TrustedUvPath)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or
        $ExpectedUvSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        (Get-BridgeFileSha256 -Path $path) -cne $ExpectedUvSha256) {
        throw [Security.SecurityException]::new('BridgeRuntimeUvIdentityMismatch')
    }
    $versionOutput = & $path --version 2>&1
    if ($LASTEXITCODE -ne 0 -or [string]$versionOutput -cnotmatch '^uv (\d+\.\d+\.\d+) ') {
        throw [InvalidOperationException]::new('BridgeRuntimeUvVersionUnverified')
    }
    return [pscustomobject]@{ path = $path; sha256 = $ExpectedUvSha256; version = $Matches[1] }
}

function Test-BridgePythonArchive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ProtectedRoot
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf) -or
        -not (Test-BridgePathUnderRoot -Root $ProtectedRoot -Path $Path) -or
        -not (Test-BridgePathReparseFree -Root $ProtectedRoot -Path $Path) -or
        (Get-BridgeFileLinkCount -Path $Path) -ne 1) { return $false }
    return (Get-BridgeFileSha256 -Path $Path) -ceq $script:BridgePythonArchiveSha256
}

function Get-BridgeReleaseBuildPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$ProgramRoot,
        [Parameter(Mandatory)][string]$TrustedUvPath,
        [Parameter(Mandatory)][string]$ExpectedSourceDigest,
        [Parameter(Mandatory)][string]$ExpectedLockDigest,
        [Parameter(Mandatory)][string]$ExpectedUvSha256,
        [Parameter()][string]$InstallationContextPath,
        [Parameter()][AllowEmptyString()][ValidatePattern('^(?:[a-f0-9]{64})?$')][string]$InstallationContextSha256,
        [Parameter(Mandatory)][int]$TimeoutSeconds
    )
    $source = [IO.Path]::GetFullPath($SourceRoot)
    $program = [IO.Path]::GetFullPath($ProgramRoot)
    $installationContext = Get-BridgeRuntimeBuildInstallationContext -InstallationContextPath $InstallationContextPath `
        -InstallationContextSha256 $InstallationContextSha256
    $uvIdentity = Get-BridgeUvIdentity -TrustedUvPath $TrustedUvPath -ExpectedUvSha256 $ExpectedUvSha256
    $lockPath = Join-Path $source 'uv.lock'
    $lockDigest = if (Test-Path -LiteralPath $lockPath -PathType Leaf) { Get-BridgeFileSha256 -Path $lockPath } else { '' }
    $sourceDigest = Get-BridgeSourceSnapshotDigest -SourceRoot $source -UvVersion $uvIdentity.version
    $reasons = [Collections.Generic.List[string]]::new()
    if ($ExpectedSourceDigest -cnotmatch '^[a-f0-9]{64}$' -or $ExpectedSourceDigest -cne $sourceDigest) {
        $reasons.Add('source-digest-mismatch')
    }
    if ($ExpectedLockDigest -cnotmatch '^[a-f0-9]{64}$' -or $ExpectedLockDigest -cne $lockDigest) {
        $reasons.Add('lock-digest-mismatch')
    }
    if ($null -ne $installationContext -and -not $program.Equals([string]$installationContext.programRoot, [StringComparison]::OrdinalIgnoreCase)) {
        $reasons.Add('installation-context-program-root-mismatch')
    }
    $releaseId = $sourceDigest
    $release = Join-Path (Join-Path $program 'releases') $releaseId
    $staging = Join-Path (Join-Path $program 'staging') '<new-guid>'
    return [pscustomobject][ordered]@{
        schemaVersion = 2; state = $(if ($reasons.Count -eq 0) { 'planned' } else { 'blocked' })
        applied = $false; closureVerified = $false; failureReasons = @($reasons)
        sourceRoot = $source; programRoot = $program; releaseRoot = $release; stagingRoot = $staging
        contextNonce = $(if ($null -eq $installationContext) { $null } else { [string]$installationContext.nonce })
        sourceDigest = $sourceDigest; lockDigest = $lockDigest
        pythonVersion = $script:BridgeRuntimePythonVersion; architecture = $script:BridgeRuntimeArchitecture
        uv = $uvIdentity; timeoutSeconds = $TimeoutSeconds
        pythonArchive = [ordered]@{
            url = $script:BridgePythonArchiveUrl
            sha256 = $script:BridgePythonArchiveSha256
            uvCommit = '68209e5c61ce4b76c2e685bea7913876bc929dc9'
        }
        commands = @(
            @('python','install','3.14.3','--install-dir','<protected-managed-python-root>','--no-bin','--no-registry','--no-config'),
            @('build','--wheel','--out-dir','<protected-wheelhouse>','--no-sources','--no-config'),
            @('export','--frozen','--no-dev','--no-default-groups','--no-editable','--no-emit-project','--format','requirements.txt','--output-file','<protected-requirements>','--no-config'),
            @('venv','--python','<verified-unique-protected-python.exe>',(Join-Path $release 'venv'),'--no-python-downloads','--no-config'),
            @('pip','sync','--python',(Join-Path $release 'venv\Scripts\python.exe'),'--require-hashes','--link-mode','copy','<protected-requirements>','--no-python-downloads','--no-config'),
            @('pip','install','--python',(Join-Path $release 'venv\Scripts\python.exe'),'--no-deps','--link-mode','copy','<protected-project-wheel>','--no-python-downloads','--no-config')
        )
        warning = 'Plan only: no files, ACLs, processes, downloads, registry, or services were changed.'
    }
}

function Test-BridgePthClosure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ReleaseRoot,
        [Parameter(Mandatory)]$Provenance
    )
    $allowed = @{}
    foreach ($entry in @($Provenance.pthArtifacts)) {
        $entryProperties = @($entry.PSObject.Properties.Name)
        $requiredEntryProperties = if ([string]$entry.producer -ceq 'pywin32-wheel') {
            @('relativePath','sha256','producer','distribution','recordRelativePath','recordSha256')
        } else { @('relativePath','sha256','producer') }
        if (@($entryProperties | Where-Object { $_ -notin $requiredEntryProperties }).Count -ne 0 -or
            @($requiredEntryProperties | Where-Object { $_ -notin $entryProperties }).Count -ne 0 -or
            [string]$entry.relativePath -in $allowed.Keys -or
            [string]$entry.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
            [string]$entry.producer -notin @('uv-venv', 'pywin32-wheel')) { return $false }
        $allowed[[string]$entry.relativePath] = $entry
    }
    foreach ($file in Get-ChildItem -LiteralPath $ReleaseRoot -File -Recurse -Force | Where-Object {
        $_.Name -like '*.pth' -or $_.Name -like '*._pth' -or $_.Name -ceq 'pyvenv.cfg'
    }) {
        $relative = $file.FullName.Substring([IO.Path]::GetFullPath($ReleaseRoot).TrimEnd('\').Length + 1).Replace('\', '/')
        if (-not $allowed.ContainsKey($relative) -or
            (Get-BridgeFileSha256 -Path $file.FullName) -cne [string]$allowed[$relative].sha256) { return $false }
        if ($file.Name -match '^_editable' -or $file.Extension -eq '._pth') { return $false }
        $lines = [IO.File]::ReadAllLines($file.FullName, [Text.UTF8Encoding]::new($false, $true))
        if ($file.Name -eq 'pyvenv.cfg') {
            if ([string]$allowed[$relative].producer -ne 'uv-venv' -or
                @($lines | Where-Object { $_ -ceq 'include-system-site-packages = false' }).Count -ne 1) { return $false }
            continue
        }
        foreach ($line in $lines) {
            $value = $line.Trim()
            if ([string]::IsNullOrEmpty($value) -or $value.StartsWith('#')) { continue }
            if ($value.StartsWith('import ')) {
                $validHook = ($file.Name -eq 'pywin32.pth' -and $value -ceq 'import pywin32_bootstrap' -and
                    [string]$allowed[$relative].producer -eq 'pywin32-wheel' -and
                    (Test-BridgePywin32RecordBinding -ReleaseRoot $ReleaseRoot -PthFile $file -Artifact $allowed[$relative])) -or
                    ($file.Name -eq '_virtualenv.pth' -and $value -ceq 'import _virtualenv' -and
                    [string]$allowed[$relative].producer -eq 'uv-venv')
                if (-not $validHook) { return $false }
                continue
            }
            if ([IO.Path]::IsPathRooted($value)) { return $false }
            $target = [IO.Path]::GetFullPath((Join-Path $file.DirectoryName $value))
            if (-not (Test-BridgePathUnderRoot -Root $ReleaseRoot -Path $target)) { return $false }
        }
    }
    return $true
}

function Test-BridgePywin32RecordBinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ReleaseRoot,
        [Parameter(Mandatory)]$PthFile,
        [Parameter(Mandatory)]$Artifact
    )
    $recordRelative = [string]$Artifact.recordRelativePath
    if ([string]$Artifact.distribution -cne 'pywin32' -or
        $recordRelative -cnotmatch '^venv/Lib/site-packages/pywin32-[^/]+\.dist-info/RECORD$' -or
        [string]$Artifact.recordSha256 -cnotmatch '^[a-f0-9]{64}$') { return $false }
    $recordPath = Join-Path $ReleaseRoot $recordRelative.Replace('/', '\')
    $distInfo = Split-Path -Parent $recordPath
    $distInfoName = Split-Path -Leaf $distInfo
    $metadataPath = Join-Path $distInfo 'METADATA'
    $records = @(Get-ChildItem -LiteralPath (Join-Path $ReleaseRoot 'venv\Lib\site-packages') -Directory -Force |
        Where-Object { $_.Name -like 'pywin32-*.dist-info' } |
        ForEach-Object { Join-Path $_.FullName 'RECORD' } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
    if ($records.Count -ne 1 -or [IO.Path]::GetFullPath($records[0]) -cne [IO.Path]::GetFullPath($recordPath) -or
        -not (Test-BridgePathReparseFree -Root $ReleaseRoot -Path $recordPath) -or
        ((Get-Item -LiteralPath $recordPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        (Get-BridgeFileLinkCount -Path $recordPath) -ne 1 -or
        (Get-BridgeFileSha256 -Path $recordPath) -cne [string]$Artifact.recordSha256) { return $false }
    if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf) -or
        -not (Test-BridgePathReparseFree -Root $ReleaseRoot -Path $metadataPath) -or
        (Get-BridgeFileLinkCount -Path $metadataPath) -ne 1) { return $false }
    $metadataLines = [IO.File]::ReadAllLines($metadataPath, [Text.UTF8Encoding]::new($false, $true))
    if (@($metadataLines | Where-Object { $_ -ceq 'Name: pywin32' }).Count -ne 1) { return $false }
    $pthRows = @()
    $metadataRows = @()
    foreach ($line in [IO.File]::ReadAllLines($recordPath, [Text.UTF8Encoding]::new($false, $true))) {
        $parser = [Microsoft.VisualBasic.FileIO.TextFieldParser]::new([IO.StringReader]::new($line))
        try {
            $parser.SetDelimiters(',')
            try { $fields = @($parser.ReadFields()) }
            catch [Microsoft.VisualBasic.FileIO.MalformedLineException] { return $false }
        } finally { $parser.Dispose() }
        if ($fields.Count -ne 3) { return $false }
        $row = [pscustomobject]@{ path = $fields[0]; hash = $fields[1]; size = $fields[2] }
        if ([string]$row.path -ceq 'pywin32.pth') { $pthRows += $row }
        if ([string]$row.path -ceq "$distInfoName/METADATA") { $metadataRows += $row }
    }
    return (Test-BridgeWheelRecordEntry -Rows $pthRows -File $PthFile) -and
        (Test-BridgeWheelRecordEntry -Rows $metadataRows -File (Get-Item -LiteralPath $metadataPath -Force))
}

function Test-BridgeWheelRecordEntry {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Rows, [Parameter(Mandatory)]$File)
    if (@($Rows).Count -ne 1) { return $false }
    $hashValue = [string]@($Rows)[0].hash
    if ($hashValue -cnotmatch '^sha256=([A-Za-z0-9_-]{43})$') { return $false }
    $encodedDigest = $Matches[1]
    if ([string]@($Rows)[0].size -cnotmatch '^[0-9]+$' -or
        [int64]@($Rows)[0].size -ne [int64]$File.Length) { return $false }
    $encoded = $encodedDigest.Replace('-', '+').Replace('_', '/') + '='
    $recordDigest = ([BitConverter]::ToString([Convert]::FromBase64String($encoded))).Replace('-', '').ToLowerInvariant()
    return $recordDigest -ceq (Get-BridgeFileSha256 -Path $File.FullName)
}

function Test-BridgeBuildProvenance {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Provenance)
    $required = @(
        'schemaVersion','sourceDigest','lockDigest','uvVersion','uvSha256',
        'pythonVersion','architecture','pythonArchiveUrl','pythonArchiveSha256',
        'pythonTreeDigest','requirementsSha256','projectWheelSha256','pthArtifacts'
    )
    $properties = @($Provenance.PSObject.Properties.Name)
    if (@($properties | Where-Object { $_ -notin $required }).Count -ne 0 -or
        @($required | Where-Object { $_ -notin $properties }).Count -ne 0 -or
        $Provenance.schemaVersion -isnot [int] -or $Provenance.schemaVersion -ne 2) { return $false }
    foreach ($digest in @('sourceDigest','lockDigest','uvSha256','pythonArchiveSha256','pythonTreeDigest','requirementsSha256','projectWheelSha256')) {
        if ([string]$Provenance.$digest -cnotmatch '^[a-f0-9]{64}$') { return $false }
    }
    if ([string]$Provenance.pythonVersion -cne $script:BridgeRuntimePythonVersion -or
        [string]$Provenance.architecture -cne $script:BridgeRuntimeArchitecture -or
        [string]$Provenance.uvVersion -cnotmatch '^\d+\.\d+\.\d+$' -or
        [string]$Provenance.pythonArchiveUrl -cne $script:BridgePythonArchiveUrl -or
        [string]$Provenance.pythonArchiveSha256 -cne $script:BridgePythonArchiveSha256 -or
        $Provenance.pthArtifacts -isnot [Array]) { return $false }
    return $true
}

function Remove-BridgeManagedPythonMetadata {
    param([Parameter(Mandatory)][string]$ManagedRoot)
    $root = [IO.Path]::GetFullPath($ManagedRoot)
    if (-not (Test-BridgePathReparseFree -Root $root -Path $root)) {
        throw [IO.InvalidDataException]::new('BridgeRuntimePythonLayoutUnverified')
    }
    $children = @(Get-ChildItem -LiteralPath $root -Force)
    $expectedNames = @('.gitignore', '.lock', '.temp', $script:BridgePythonManagedAliasKey)
    $actualNames = @($children.Name | Sort-Object)
    if ([string]::Join("`n", $actualNames) -cne [string]::Join("`n", ($expectedNames | Sort-Object))) {
        throw [IO.InvalidDataException]::new('BridgeRuntimePythonLayoutUnverified')
    }
    foreach ($child in $children) {
        $isAlias = $child.Name -ceq $script:BridgePythonManagedAliasKey
        $isReparse = ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        if ($isAlias) {
            $expectedTarget = Join-Path $root $script:BridgePythonManagedPayloadKey
            $targets = @($child.Target)
            if (-not $isReparse -or $child.LinkType -cne 'Junction' -or $targets.Count -ne 1 -or
                [IO.Path]::GetFullPath([string]$targets[0]).TrimEnd('\') -cne $expectedTarget.TrimEnd('\')) {
                throw [IO.InvalidDataException]::new('BridgeRuntimePythonLayoutUnverified')
            }
            continue
        }
        if ($isReparse) { throw [IO.InvalidDataException]::new('BridgeRuntimePythonLayoutUnverified') }
        if ($child.PSIsContainer) {
            if ($child.Name -notin @('.temp', $script:BridgePythonManagedAliasKey) -or
                (Get-ChildItem -LiteralPath $child.FullName -Force | Select-Object -First 1)) {
                throw [IO.InvalidDataException]::new('BridgeRuntimePythonLayoutUnverified')
            }
            continue
        }
        if ($child.Name -notin @('.gitignore', '.lock') -or (Get-BridgeFileLinkCount -Path $child.FullName) -ne 1) {
            throw [IO.InvalidDataException]::new('BridgeRuntimePythonLayoutUnverified')
        }
        $actualBytes = [IO.File]::ReadAllBytes($child.FullName)
        $contentMatches = ($child.Name -ceq '.gitignore' -and $actualBytes.Length -eq 1 -and $actualBytes[0] -eq 42) -or
            ($child.Name -ceq '.lock' -and $actualBytes.Length -eq 0)
        if (-not $contentMatches) {
            throw [IO.InvalidDataException]::new('BridgeRuntimePythonLayoutUnverified')
        }
    }
    # uv의 설치 payload 밖 관리 표식만 정확히 지워 release tree에 남지 않게 합니다.
    [IO.File]::Delete((Join-Path $root '.gitignore'))
    [IO.File]::Delete((Join-Path $root '.lock'))
    [IO.Directory]::Delete((Join-Path $root '.temp'), $false)
    # Directory.Delete는 junction 자체만 제거하며 이미 옮긴 payload target은 순회하지 않습니다.
    [IO.Directory]::Delete((Join-Path $root $script:BridgePythonManagedAliasKey), $false)
    [IO.Directory]::Delete($root, $false)
}

function Get-BridgeManagedPythonPayload {
    param([Parameter(Mandatory)][string]$ManagedRoot)
    $root = [IO.Path]::GetFullPath($ManagedRoot)
    $payload = Join-Path $root $script:BridgePythonManagedPayloadKey
    $python = Join-Path $payload 'python.exe'
    if (-not (Test-Path -LiteralPath $python -PathType Leaf) -or
        -not (Test-BridgePathReparseFree -Root $root -Path $python) -or
        (Get-BridgeFileLinkCount -Path $python) -ne 1) {
        throw [IO.InvalidDataException]::new('BridgeRuntimePythonLayoutUnverified')
    }
    return $payload
}

function Get-BridgeRuntimeBuildInstallationContext {
    [CmdletBinding()]
    param(
        [Parameter()][string]$InstallationContextPath,
        [Parameter()][AllowEmptyString()][ValidatePattern('^(?:[a-f0-9]{64})?$')][string]$InstallationContextSha256
    )
    $hasPath = -not [string]::IsNullOrWhiteSpace($InstallationContextPath)
    $hasSha = -not [string]::IsNullOrWhiteSpace($InstallationContextSha256)
    if (-not $hasPath -and -not $hasSha) { return $null }
    if ($hasPath -ne $hasSha) {
        throw [ArgumentException]::new('BridgeRuntimeInstallationContextPairRequired')
    }
    $requestedPath = $InstallationContextPath
    $requestedSha256 = $InstallationContextSha256
    $contextScript = Join-Path $PSScriptRoot 'installation-context.ps1'
    if (-not (Test-Path -LiteralPath $contextScript -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new('BridgeRuntimeInstallationContextHelperMissing')
    }
    . $contextScript -LibraryMode
    $context = Get-BridgeInstallationContext -Path $requestedPath -Sha256 $requestedSha256
    $workerBinding = Get-BridgeInstallationContextBinding -Context $context -Profile worker
    $null = Get-BridgeInstallationContextBinding -Context $context -Profile gateway
    $null = Get-BridgeInstallationContextBinding -Context $context -Profile privileged
    $requiredDirectories = @(
        [string]$context.programRoot, [string]$context.bindingsDirectory, [string]$context.programDataRoot,
        [string]$context.runtimeRoot, ([IO.Path]::Combine($context.runtimeRoot, 'logs')),
        ([IO.Path]::Combine($context.runtimeRoot, 'jobs')), ([IO.Path]::Combine($context.runtimeRoot, 'secrets')),
        [string]$context.localDataRoot, [string]$context.userRoot,
        ([IO.Path]::Combine($context.userRoot, 'browser-profile')), ([IO.Path]::Combine($context.userRoot, 'logs'))
    )
    $workerSid = [string]$workerBinding.workerSid
    $protectedDirectories = @(
        (Test-BridgeInstallationOwnedDirectoryAcl -Path $context.programRoot -Profile Readonly -WorkerSid $workerSid),
        (Test-BridgeInstallationOwnedDirectoryAcl -Path $context.bindingsDirectory -Profile Bindings -WorkerSid $workerSid),
        (Test-BridgeInstallationOwnedDirectoryAcl -Path $context.programDataRoot -Profile Readonly -WorkerSid $workerSid),
        (Test-BridgeInstallationOwnedDirectoryAcl -Path $context.runtimeRoot -Profile Readonly -WorkerSid $workerSid),
        (Test-BridgeInstallationOwnedDirectoryAcl -Path ([IO.Path]::Combine($context.runtimeRoot, 'logs')) -Profile Audit -WorkerSid $workerSid),
        (Test-BridgeInstallationOwnedDirectoryAcl -Path ([IO.Path]::Combine($context.runtimeRoot, 'jobs')) -Profile Audit -WorkerSid $workerSid),
        (Test-BridgeInstallationOwnedDirectoryAcl -Path ([IO.Path]::Combine($context.runtimeRoot, 'secrets')) -Profile Secrets -WorkerSid $workerSid),
        (Test-BridgeInstallationOwnedDirectoryAcl -Path $context.localDataRoot -Profile Browser -WorkerSid $workerSid),
        (Test-BridgeInstallationOwnedDirectoryAcl -Path $context.userRoot -Profile Browser -WorkerSid $workerSid),
        (Test-BridgeInstallationOwnedDirectoryAcl -Path ([IO.Path]::Combine($context.userRoot, 'browser-profile')) -Profile Browser -WorkerSid $workerSid),
        (Test-BridgeInstallationOwnedDirectoryAcl -Path ([IO.Path]::Combine($context.userRoot, 'logs')) -Profile Browser -WorkerSid $workerSid)
    )
    $journalPath = Assert-BridgeInstallationContextProtectedFile -Path $context.preparationJournalPath `
        -Root $context.programDataRoot -FailureReason 'BridgeRuntimeInstallationContextPreparedStateUnverified'
    try { $journal = (Get-BridgeInstallationContextFileSnapshot -Path $journalPath).text | ConvertFrom-Json -ErrorAction Stop }
    catch { throw [Security.SecurityException]::new('BridgeRuntimeInstallationContextPreparedStateUnverified', $_.Exception) }
    $expectedRoots = @([string]$context.programRoot, [string]$context.programDataRoot, [string]$context.localDataRoot)
    $journalRoots = @($journal.roots)
    $journalValid = (Test-BridgeInstallationContextJsonInteger -Value $journal.schemaVersion) -and
        [int]$journal.schemaVersion -eq 2 -and [string]$journal.nonce -ceq [string]$context.nonce -and
        [string]$journal.state -ceq 'prepared' -and $journal.reconciliationRequired -is [bool] -and
        -not [bool]$journal.reconciliationRequired -and $journalRoots.Count -eq $expectedRoots.Count
    if ($journalValid) {
        for ($index = 0; $index -lt $expectedRoots.Count; $index++) {
            $journalRoot = $journalRoots[$index]
            if ([string]$journalRoot.path -cne $expectedRoots[$index] -or $journalRoot.absentBefore -isnot [bool] -or
                -not [bool]$journalRoot.absentBefore -or $journalRoot.created -isnot [bool] -or -not [bool]$journalRoot.created -or
                [string]$journalRoot.nativeIdentity -cnotmatch '^[0-9A-F]{8}:[0-9A-F]{16}:[1-9][0-9]*$' -or
                (Get-BridgeInstallationNativeIdentity -Path $expectedRoots[$index]) -cne [string]$journalRoot.nativeIdentity) {
                $journalValid = $false
                break
            }
        }
    }
    if (@($requiredDirectories | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Container) }).Count -ne 0 -or
        $protectedDirectories -contains $false -or -not $journalValid) {
        throw [Security.SecurityException]::new('BridgeRuntimeInstallationContextPreparedStateUnverified')
    }
    return $context
}

function Invoke-BridgeProtectedReleaseBuild {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$ProgramRoot,
        [Parameter(Mandatory)][string]$TrustedUvPath,
        [Parameter(Mandatory)][string]$ExpectedSourceDigest,
        [Parameter(Mandatory)][string]$ExpectedLockDigest,
        [Parameter(Mandatory)][string]$ExpectedUvSha256,
        [Parameter()][string]$InstallationContextPath,
        [Parameter()][AllowEmptyString()][ValidatePattern('^(?:[a-f0-9]{64})?$')][string]$InstallationContextSha256,
        [Parameter(Mandatory)][int]$TimeoutSeconds
    )
    $plan = Get-BridgeReleaseBuildPlan @PSBoundParameters
    if ($plan.state -ne 'planned') { return $plan }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw [UnauthorizedAccessException]::new('BridgeRuntimeBuildRequiresAdministrator')
    }
    $installationContext = Get-BridgeRuntimeBuildInstallationContext -InstallationContextPath $InstallationContextPath `
        -InstallationContextSha256 $InstallationContextSha256
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    $expectedProgramRoot = if ($null -eq $installationContext) {
        Join-Path $programFiles 'HermesWindowsBridge'
    } else { [string]$installationContext.programRoot }
    if (-not ([IO.Path]::GetFullPath($ProgramRoot)).Equals($expectedProgramRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw [Security.SecurityException]::new('BridgeRuntimeProgramRootInvalid')
    }
    foreach ($directory in @($ProgramRoot, (Join-Path $ProgramRoot 'staging'), (Join-Path $ProgramRoot 'releases'))) {
        if (-not (Test-Path -LiteralPath $directory)) { New-BridgeProtectedDirectory -Path $directory }
        elseif ($null -ne (Test-BridgeTreeAcl -Path $directory -RequireTrustedOwner $true)) {
            throw [Security.SecurityException]::new('BridgeRuntimeProgramRootUnprotected')
        }
    }
    $lockPath = Join-Path $ProgramRoot 'runtime-build.lock'
    $lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $stagingRoot = Join-Path (Join-Path $ProgramRoot 'staging') ([guid]::NewGuid().ToString('N'))
    try {
        New-BridgeProtectedDirectory -Path $stagingRoot
        foreach ($name in @('snapshot','wheelhouse','temp','cache','python-mirror')) {
            New-BridgeProtectedDirectory -Path (Join-Path $stagingRoot $name)
        }
        $snapshot = Join-Path $stagingRoot 'snapshot'
        foreach ($entry in Get-BridgeBuildFileInventory -SourceRoot $SourceRoot) {
            $source = Join-Path $SourceRoot ([string]$entry.relativePath).Replace('/', '\')
            $sourceInfo = Get-Item -LiteralPath $source -Force
            if (($sourceInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                (Get-BridgeFileLinkCount -Path $source) -ne 1 -or
                $sourceInfo.Length -ne [int64]$entry.size -or
                (Get-BridgeFileSha256 -Path $source) -cne [string]$entry.sha256) {
                throw [Security.SecurityException]::new('BridgeRuntimeSourceChangedBeforeCopy')
            }
            $destination = Join-Path $snapshot ([string]$entry.relativePath).Replace('/', '\')
            $destinationParent = Split-Path -Parent $destination
            if (-not (Test-Path -LiteralPath $destinationParent)) { [void][IO.Directory]::CreateDirectory($destinationParent) }
            [IO.File]::Copy($source, $destination, $false)
            if ((Get-BridgeFileSha256 -Path $destination) -cne [string]$entry.sha256) {
                throw [Security.SecurityException]::new('BridgeRuntimeSnapshotCopyMismatch')
            }
        }
        $snapshotDigest = Get-BridgeSourceSnapshotDigest -SourceRoot $snapshot -UvVersion $plan.uv.version
        if ($snapshotDigest -cne $ExpectedSourceDigest -or
            (Get-BridgeFileSha256 -Path (Join-Path $snapshot 'uv.lock')) -cne $ExpectedLockDigest) {
            throw [Security.SecurityException]::new('BridgeRuntimeSnapshotDigestMismatch')
        }
        $protectedUv = Join-Path $stagingRoot 'uv.exe'
        [IO.File]::Copy($plan.uv.path, $protectedUv, $false)
        if ((Get-BridgeFileSha256 -Path $protectedUv) -cne $ExpectedUvSha256) {
            throw [Security.SecurityException]::new('BridgeRuntimeUvSnapshotMismatch')
        }
        $archiveName = [IO.Path]::GetFileName(([uri]$script:BridgePythonArchiveUrl).LocalPath)
        $mirrorRelease = Join-Path (Join-Path $stagingRoot 'python-mirror') '20260325'
        New-BridgeProtectedDirectory -Path $mirrorRelease
        $archivePath = Join-Path $mirrorRelease $archiveName
        Save-BridgeBoundedDownload -Url $script:BridgePythonArchiveUrl -Destination $archivePath -TimeoutSeconds $TimeoutSeconds -MaximumBytes 104857600
        if (-not (Test-BridgePythonArchive -Path $archivePath -ProtectedRoot $stagingRoot)) {
            throw [Security.SecurityException]::new('BridgeRuntimePythonArchiveDigestMismatch')
        }
        $releaseRoot = [string]$plan.releaseRoot
        if (Test-Path -LiteralPath $releaseRoot) { throw [IO.IOException]::new('BridgeRuntimeReleaseAlreadyExists') }
        New-BridgeProtectedDirectory -Path $releaseRoot
        $environment = Get-BridgeBuildEnvironment -ProtectedRoot $stagingRoot
        $managedRoot = Join-Path $releaseRoot 'managed-python'
        $steps = [Collections.Generic.List[object]]::new()
        $steps.Add(@('python','install',$script:BridgeRuntimePythonVersion,'--install-dir',$managedRoot,'--no-bin','--no-registry','--no-config'))
        foreach ($arguments in $steps) {
            $child = Invoke-BridgeBoundedProcess -FilePath $protectedUv -Arguments $arguments -WorkingDirectory $snapshot -Environment $environment -TimeoutSeconds $TimeoutSeconds
            if ($child.exitCode -ne 0) { throw [InvalidOperationException]::new('BridgeRuntimeUvPythonInstallFailed') }
        }
        $pythonPayload = Get-BridgeManagedPythonPayload -ManagedRoot $managedRoot
        $pythonRoot = Join-Path $releaseRoot 'python'
        [IO.Directory]::Move($pythonPayload, $pythonRoot)
        Remove-BridgeManagedPythonMetadata -ManagedRoot $managedRoot
        $basePython = Join-Path $pythonRoot 'python.exe'
        $versionProbe = Invoke-BridgeBoundedProcess -FilePath $basePython -Arguments @('-I','-B','-c','import platform,sys;print(platform.machine());print(sys.version_info[:3])') -WorkingDirectory $releaseRoot -Environment $environment -TimeoutSeconds 30
        if ($versionProbe.exitCode -ne 0 -or $versionProbe.stdout -notmatch 'AMD64|x86_64' -or $versionProbe.stdout -notmatch '3, 14, 3') {
            throw [IO.InvalidDataException]::new('BridgeRuntimePythonIdentityMismatch')
        }
        $wheelhouse = Join-Path $stagingRoot 'wheelhouse'; $requirements = Join-Path $stagingRoot 'requirements.txt'
        $buildSteps = @(
            @('build','--wheel','--out-dir',$wheelhouse,'--python',$basePython,'--no-sources','--no-config'),
            @('export','--frozen','--no-dev','--no-default-groups','--no-editable','--no-emit-project','--format','requirements.txt','--output-file',$requirements,'--no-config')
        )
        foreach ($arguments in $buildSteps) {
            $child = Invoke-BridgeBoundedProcess -FilePath $protectedUv -Arguments $arguments -WorkingDirectory $snapshot -Environment $environment -TimeoutSeconds $TimeoutSeconds
            if ($child.exitCode -ne 0) { throw [InvalidOperationException]::new('BridgeRuntimeUvBuildStepFailed') }
        }
        $wheels = @(Get-ChildItem -LiteralPath $wheelhouse -Filter '*.whl' -File)
        if ($wheels.Count -ne 1) { throw [IO.InvalidDataException]::new('BridgeRuntimeProjectWheelUnverified') }
        $servicePython = Join-Path $releaseRoot 'venv\Scripts\python.exe'
        $installSteps = @(
            @('venv','--python',$basePython,(Join-Path $releaseRoot 'venv'),'--no-python-downloads','--no-config'),
            @('pip','sync','--python',$servicePython,'--require-hashes','--link-mode','copy',$requirements,'--no-python-downloads','--no-config'),
            @('pip','install','--python',$servicePython,'--no-deps','--link-mode','copy',$wheels[0].FullName,'--no-python-downloads','--no-config')
        )
        foreach ($arguments in $installSteps) {
            $child = Invoke-BridgeBoundedProcess -FilePath $protectedUv -Arguments $arguments -WorkingDirectory $snapshot -Environment $environment -TimeoutSeconds $TimeoutSeconds
            if ($child.exitCode -ne 0) { throw [InvalidOperationException]::new('BridgeRuntimeUvInstallStepFailed') }
        }
        $pthArtifacts = [Collections.Generic.List[object]]::new()
        foreach ($file in Get-ChildItem -LiteralPath $releaseRoot -File -Recurse -Force | Where-Object {
            $_.Name -like '*.pth' -or $_.Name -like '*._pth' -or $_.Name -ceq 'pyvenv.cfg'
        }) {
            $producer = if ($file.Name -in @('_virtualenv.pth','pyvenv.cfg')) { 'uv-venv' }
                elseif ($file.Name -eq 'pywin32.pth') { 'pywin32-wheel' } else { 'wheel-path' }
            $artifact = [ordered]@{
                relativePath = $file.FullName.Substring($releaseRoot.TrimEnd('\').Length + 1).Replace('\', '/')
                sha256 = Get-BridgeFileSha256 -Path $file.FullName; producer = $producer
            }
            if ($producer -eq 'pywin32-wheel') {
                $records = @(Get-ChildItem -LiteralPath $file.DirectoryName -Directory -Force |
                    Where-Object { $_.Name -like 'pywin32-*.dist-info' } |
                    ForEach-Object { Join-Path $_.FullName 'RECORD' } |
                    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
                    ForEach-Object { Get-Item -LiteralPath $_ -Force })
                if ($records.Count -ne 1) { throw [Security.SecurityException]::new('BridgeRuntimePywin32RecordInvalid') }
                $artifact.distribution = 'pywin32'
                $artifact.recordRelativePath = $records[0].FullName.Substring($releaseRoot.TrimEnd('\').Length + 1).Replace('\', '/')
                $artifact.recordSha256 = Get-BridgeFileSha256 -Path $records[0].FullName
            }
            $pthArtifacts.Add([pscustomobject]$artifact)
        }
        $pythonInventory = Get-BridgeReleaseInventory -ReleaseRoot $pythonRoot
        $provenance = [pscustomobject][ordered]@{
            schemaVersion = 2; sourceDigest = $snapshotDigest; lockDigest = $ExpectedLockDigest
            uvVersion = $plan.uv.version; uvSha256 = $ExpectedUvSha256
            pythonVersion = $script:BridgeRuntimePythonVersion; architecture = $script:BridgeRuntimeArchitecture
            pythonArchiveUrl = $script:BridgePythonArchiveUrl
            pythonArchiveSha256 = $script:BridgePythonArchiveSha256
            pythonTreeDigest = Get-BridgeInventoryDigest -Inventory $pythonInventory
            requirementsSha256 = Get-BridgeFileSha256 -Path $requirements
            projectWheelSha256 = Get-BridgeFileSha256 -Path $wheels[0].FullName
            pthArtifacts = @($pthArtifacts)
        }
        if (-not (Test-BridgeBuildProvenance -Provenance $provenance) -or
            -not (Test-BridgePthClosure -ReleaseRoot $releaseRoot -Provenance $provenance)) {
            throw [Security.SecurityException]::new('BridgeRuntimeStaticClosureInvalid')
        }
        $provenancePath = Join-Path $releaseRoot 'build-provenance.json'
        [IO.File]::WriteAllText($provenancePath, ($provenance | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
        $inventory = Get-BridgeReleaseInventory -ReleaseRoot $releaseRoot
        $manifest = [pscustomobject][ordered]@{
            schemaVersion = 2; releaseId = $plan.sourceDigest; sourceDigest = $snapshotDigest
            lockDigest = $ExpectedLockDigest; pythonVersion = $script:BridgeRuntimePythonVersion
            architecture = $script:BridgeRuntimeArchitecture; uvVersion = $plan.uv.version
            fileInventory = $inventory; baseExecutable = $basePython; serviceExecutable = $servicePython
            closureReceipt = $script:BridgeClosureReceiptName; closureReceiptSha256 = ('0' * 64)
        }
        $probeResult = Invoke-BridgeBoundedProcess -FilePath $servicePython -Arguments @('-I','-B','-c',$script:BridgeClosureProbeCode) -WorkingDirectory $releaseRoot -Environment $environment -TimeoutSeconds 60
        if ($probeResult.exitCode -ne 0) { throw [Security.SecurityException]::new('BridgeRuntimeImportClosureInvalid') }
        $receipt = New-BridgeServiceClosureReceipt -ReleaseRoot $releaseRoot -ManifestSeed $manifest -ProbeJson $probeResult.stdout
        $receiptPath = Join-Path $releaseRoot $script:BridgeClosureReceiptName
        [IO.File]::WriteAllText($receiptPath, ($receipt | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
        $manifest.closureReceiptSha256 = Get-BridgeFileSha256 -Path $receiptPath
        $manifestPath = Join-Path $releaseRoot 'release-manifest.json'
        [IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
        $fileContract = Get-BridgeServiceRuntimeContract -ManifestPath $manifestPath -ReleaseRoot $releaseRoot
        if (-not $fileContract.verified -or -not (Test-BridgeServiceClosureReceipt -ReleaseRoot $releaseRoot -Manifest $manifest)) {
            throw [Security.SecurityException]::new('BridgeRuntimeManifestContractInvalid')
        }
        return [pscustomobject][ordered]@{
            schemaVersion = 2; state = 'built'; applied = $true; closureVerified = $true
            failureReasons = @(); releaseRoot = $releaseRoot; manifestPath = $manifestPath
            stagingRoot = $stagingRoot; sourceDigest = $snapshotDigest; lockDigest = $ExpectedLockDigest
            pythonArchiveSha256 = $script:BridgePythonArchiveSha256
            warning = 'Built and validated under the held build lock; service activation remains a separate approved task.'
        }
    } finally { $lock.Dispose() }
}
