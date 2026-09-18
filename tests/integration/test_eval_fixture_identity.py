"""Evaluation fixture source identity regressions."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Final, TypedDict

from pydantic import TypeAdapter

PROJECT_ROOT: Final = Path(__file__).resolve().parents[2]
HARNESS_PATH: Final = (
    PROJECT_ROOT
    / ".omo"
    / "evidence"
    / "service-protection-eval-vm-20260908"
    / "security"
    / "guest-security-checks.ps1"
)
RUNTIME_PATH: Final = PROJECT_ROOT / "scripts" / "service-runtime.ps1"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
UV_PATH: Final = shutil.which("uv.exe")
assert POWERSHELL_PATH is not None
assert UV_PATH is not None


class FixtureIdentityResult(TypedDict):
    firstMarkerContainsNonce: bool
    secondMarkerContainsNonce: bool
    sourceDigestsDiffer: bool


FIXTURE_IDENTITY_RESULT_ADAPTER: Final = TypeAdapter(FixtureIdentityResult)


def test_fixture_build_binds_source_digest_to_each_security_nonce(tmp_path: Path) -> None:
    """서로 다른 security nonce는 서로 다른 fixture release identity를 만듭니다."""
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    source_runtime = tmp_path / "source" / "scripts" / "service-runtime.ps1"
    _ = source_runtime.parent.mkdir(parents=True)
    _ = source_runtime.write_text(
        """
function Get-BridgeReleaseBuildPlan {
    param(
        $SourceRoot, $ProgramRoot, $TrustedUvPath, $ExpectedUvSha256,
        $ExpectedSourceDigest, $ExpectedLockDigest, $TimeoutSeconds
    )
    [pscustomobject]@{
        sourceDigest = ('a' * 64)
        lockDigest = ('b' * 64)
        releaseRoot = (Join-Path $SourceRoot 'planned')
    }
}
function Invoke-BridgeProtectedReleaseBuild {
    param(
        $SourceRoot, $ProgramRoot, $TrustedUvPath, $ExpectedUvSha256,
        $ExpectedSourceDigest, $ExpectedLockDigest, $TimeoutSeconds
    )
    [pscustomobject]@{
        state = 'built'
        closureVerified = $true
        releaseRoot = (Join-Path $SourceRoot 'planned')
        manifestPath = 'manifest'
        stagingRoot = 'staging'
    }
}
""".strip(),
        encoding="utf-8",
    )

    command = r"""
$ErrorActionPreference = 'Stop'
Import-Module Microsoft.PowerShell.Utility -ErrorAction Stop
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_SECURITY_HARNESS, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) { throw 'SecurityHarnessParseFailed' }
$definition = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'New-IsolatedBuildFixture'
}, $true))
if ($definition.Count -ne 1) { throw 'SecurityHarnessFunctionMissing:New-IsolatedBuildFixture' }
$ExpectedUvSha256 = (
    Get-FileHash -LiteralPath $env:HERMES_QA_TRUSTED_UV -Algorithm SHA256
).Hash.ToUpperInvariant()
$TrustedUvPath = $env:HERMES_QA_TRUSTED_UV
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$ExpectedProgramRoot = Join-Path $programFiles 'HermesWindowsBridge'
function Fail-SecurityCheck { param([string]$Reason) throw $Reason }
function Get-RemainingSeconds { return 900 }
. ([scriptblock]::Create($definition[0].Extent.Text))
$source = [pscustomobject]@{
    verifiedFiles = @([pscustomobject]@{
        relativePath = 'scripts/service-runtime.ps1'
        sourcePath = $env:HERMES_QA_SOURCE_RUNTIME
    })
}
$firstNonce = [guid]'11111111-1111-1111-1111-111111111111'
$secondNonce = [guid]'22222222-2222-2222-2222-222222222222'
$script:VerifiedOutputRoot = $env:HERMES_QA_FIRST_ROOT
$Nonce = $firstNonce
$first = New-IsolatedBuildFixture -Source $source
$script:VerifiedOutputRoot = $env:HERMES_QA_SECOND_ROOT
$Nonce = $secondNonce
$second = New-IsolatedBuildFixture -Source $source
$markerRelativePath = 'scripts\security-fixture-marker.ps1'
$firstMarker = [IO.File]::ReadAllText((Join-Path $first.sourceRoot $markerRelativePath))
$secondMarker = [IO.File]::ReadAllText((Join-Path $second.sourceRoot $markerRelativePath))
. $env:HERMES_QA_RUNTIME -LibraryMode
$digestArguments = @{ UvVersion = 'fixture-test' }
$firstDigest = Get-BridgeSourceSnapshotDigest -SourceRoot $first.sourceRoot @digestArguments
$secondDigest = Get-BridgeSourceSnapshotDigest -SourceRoot $second.sourceRoot @digestArguments
[ordered]@{
    firstMarkerContainsNonce = $firstMarker.Contains($firstNonce.Guid)
    secondMarkerContainsNonce = $secondMarker.Contains($secondNonce.Guid)
    sourceDigestsDiffer = ($firstDigest -cne $secondDigest)
} | ConvertTo-Json -Compress
"""

    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={
            **os.environ,
            "HERMES_QA_FIRST_ROOT": str(first_root),
            "HERMES_QA_RUNTIME": str(RUNTIME_PATH),
            "HERMES_QA_SECOND_ROOT": str(second_root),
            "HERMES_QA_SECURITY_HARNESS": str(HARNESS_PATH),
            "HERMES_QA_SOURCE_RUNTIME": str(source_runtime),
            "HERMES_QA_TRUSTED_UV": UV_PATH,
        },
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=20,
    )

    assert result.returncode == 0, result.stderr
    assert FIXTURE_IDENTITY_RESULT_ADAPTER.validate_json(result.stdout) == {
        "firstMarkerContainsNonce": True,
        "secondMarkerContainsNonce": True,
        "sourceDigestsDiffer": True,
    }
