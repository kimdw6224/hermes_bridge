Set-StrictMode -Version Latest

# Windows PowerShell 5.1은 System.Net.Http를 자동 로드하지 않으므로 다운로드 전에 명시적으로 결속합니다.
Add-Type -AssemblyName System.Net.Http -ErrorAction Stop

$processHelper = Join-Path $PSScriptRoot 'service-runtime-process.ps1'
if (-not (Test-Path -LiteralPath $processHelper -PathType Leaf)) {
    throw [IO.FileNotFoundException]::new('BridgeRuntimeProcessHelperMissing')
}
. $processHelper

function New-BridgeProtectedDirectory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @(
        @('S-1-5-18', [Security.AccessControl.FileSystemRights]::FullControl),
        @('S-1-5-32-544', [Security.AccessControl.FileSystemRights]::FullControl),
        @('S-1-5-19', [Security.AccessControl.FileSystemRights]::ReadAndExecute),
        @('S-1-5-32-545', [Security.AccessControl.FileSystemRights]::ReadAndExecute),
        @('S-1-5-11', [Security.AccessControl.FileSystemRights]::ReadAndExecute)
    )) {
        $sid = [Security.Principal.SecurityIdentifier]::new([string]$rule[0])
        $access = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, $rule[1],
            [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($access)
    }
    # 부모의 쓰기 가능한 기본 ACL을 잠깐 상속하지 않도록 생성 API에 보호 ACL을 함께 전달합니다.
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetFullPath($Path), $acl)
    $reason = Test-BridgeTreeAcl -Path $Path -RequireTrustedOwner $true
    if ($null -ne $reason) { throw [Security.SecurityException]::new("BridgeRuntimeProtectedDirectoryFailed:$reason") }
}

function Get-BridgeBuildEnvironment {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProtectedRoot)
    $windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    return [ordered]@{
        SystemRoot = $windows; WINDIR = $windows; ComSpec = (Join-Path $windows 'System32\cmd.exe')
        TEMP = (Join-Path $ProtectedRoot 'temp'); TMP = (Join-Path $ProtectedRoot 'temp')
        UV_CACHE_DIR = (Join-Path $ProtectedRoot 'cache'); UV_NO_CONFIG = '1'; UV_NO_PROGRESS = '1'
        UV_PYTHON_INSTALL_MIRROR = ([uri](Join-Path $ProtectedRoot 'python-mirror')).AbsoluteUri.TrimEnd('/')
        UV_PYTHON_NO_REGISTRY = '1'
        PYTHONNOUSERSITE = '1'; PYTHONDONTWRITEBYTECODE = '1'; PIP_CONFIG_FILE = 'NUL'
        PIP_DISABLE_PIP_VERSION_CHECK = '1'; PATH = (Join-Path $windows 'System32')
    }
}

function ConvertTo-BridgeCommandLine {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Arguments)
    throw [NotSupportedException]::new('BridgeRuntimeCommandLineIsOwnedByNativeRunner')
}

function Invoke-BridgeBoundedProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [Parameter(Mandatory)]$Environment,
        [Parameter(Mandatory)][int]$TimeoutSeconds
    )
    $result = [HermesBridge.BoundedProcess]::Run($FilePath, $Arguments, $WorkingDirectory, $Environment, $TimeoutSeconds)
    return [pscustomobject]@{ exitCode = $result.ExitCode; stdout = $result.Stdout; stderr = $result.Stderr }
}

function Save-BridgeBoundedDownload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][int]$TimeoutSeconds,
        [Parameter(Mandatory)][int64]$MaximumBytes
    )
    $handler = [Net.Http.HttpClientHandler]::new(); $handler.UseProxy = $false
    $client = [Net.Http.HttpClient]::new($handler); $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
    $cancellation = $null; $response = $null; $inputStream = $null; $outputStream = $null
    try {
        $stopwatch = [Diagnostics.Stopwatch]::StartNew()
        [int64]$timeoutMilliseconds = [int64]$TimeoutSeconds * 1000
        $cancellation = [Threading.CancellationTokenSource]::new()
        $cancellation.CancelAfter([TimeSpan]::FromSeconds($TimeoutSeconds))
        $requestTask = $client.GetAsync($Url, [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cancellation.Token)
        $remaining = $timeoutMilliseconds - $stopwatch.ElapsedMilliseconds
        if ($remaining -le 0 -or -not $requestTask.Wait([int]$remaining)) {
            $cancellation.Cancel()
            throw [TimeoutException]::new('BridgeRuntimeDownloadTimedOut')
        }
        $response = $requestTask.Result
        [void]$response.EnsureSuccessStatusCode()
        if ($null -ne $response.Content.Headers.ContentLength -and
            $response.Content.Headers.ContentLength -gt $MaximumBytes) {
            throw [IO.InvalidDataException]::new('BridgeRuntimeDownloadTooLarge')
        }
        $streamTask = $response.Content.ReadAsStreamAsync()
        $remaining = $timeoutMilliseconds - $stopwatch.ElapsedMilliseconds
        if ($remaining -le 0 -or -not $streamTask.Wait([int]$remaining)) {
            $cancellation.Cancel()
            throw [TimeoutException]::new('BridgeRuntimeDownloadTimedOut')
        }
        $inputStream = $streamTask.Result
        $outputStream = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $buffer = [byte[]]::new(65536); [int64]$total = 0
        while ($true) {
            $remaining = $timeoutMilliseconds - $stopwatch.ElapsedMilliseconds
            if ($remaining -le 0) {
                $cancellation.Cancel()
                throw [TimeoutException]::new('BridgeRuntimeDownloadTimedOut')
            }
            $readTask = $inputStream.ReadAsync($buffer, 0, $buffer.Length, $cancellation.Token)
            if (-not $readTask.Wait([int]$remaining)) {
                $cancellation.Cancel()
                throw [TimeoutException]::new('BridgeRuntimeDownloadTimedOut')
            }
            $count = $readTask.Result
            if ($count -eq 0) { break }
            $total += $count
            if ($total -gt $MaximumBytes) { throw [IO.InvalidDataException]::new('BridgeRuntimeDownloadTooLarge') }
            $outputStream.Write($buffer, 0, $count)
        }
    } finally {
        if ($null -ne $outputStream) { $outputStream.Dispose() }
        if ($null -ne $inputStream) { $inputStream.Dispose() }
        if ($null -ne $response) { $response.Dispose() }
        if ($null -ne $cancellation) { $cancellation.Dispose() }
        $client.Dispose(); $handler.Dispose()
    }
}
