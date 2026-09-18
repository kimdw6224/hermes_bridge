$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\..\scripts\lifecycle-common.ps1')
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('hermes-marker-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path (Join-Path $fixtureRoot 'secrets'))
# 테스트 프로세스가 기록을 다시 읽도록 ACL 적용만 격리하고 실제 파일 교체는 실행합니다.
function Set-BridgeRuntimeAccessMarkerAcl { param([string]$MarkerPath) }
try {
    $arguments = @{
        RuntimeRoot = $fixtureRoot
        BaseRoot = $fixtureRoot
        BaseExecutable = (Join-Path $fixtureRoot 'python.exe')
        PreAclHash = ('0' * 64)
    }
    Write-BridgeRuntimeAccessMarker @arguments -Status pending
    Write-BridgeRuntimeAccessMarker @arguments -Status applied
    $markerPath = Get-BridgeRuntimeAccessMarkerPath -RuntimeRoot $fixtureRoot
    $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
    if ($marker.status -cne 'applied') { throw 'Marker replacement failed' }
    if (@(Get-ChildItem -LiteralPath (Join-Path $fixtureRoot 'secrets') -File).Count -ne 1) {
        throw 'Unexpected temporary or backup file'
    }
    'PASS: actual pending-to-applied marker replacement'
} finally {
    Get-ChildItem -LiteralPath (Join-Path $fixtureRoot 'secrets') -File | Remove-Item -Force
    [IO.Directory]::Delete((Join-Path $fixtureRoot 'secrets'))
    [IO.Directory]::Delete($fixtureRoot)
}
