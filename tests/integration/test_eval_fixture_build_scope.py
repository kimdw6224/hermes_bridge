"""Evaluation-VM fixture build scope regressions."""

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
assert POWERSHELL_PATH is not None


class FixtureBuildScopeResult(TypedDict):
    planReceivedExpectedUvHash: bool
    buildReceivedExpectedUvHash: bool


FIXTURE_BUILD_SCOPE_RESULT_ADAPTER: Final = TypeAdapter(FixtureBuildScopeResult)


def test_fixture_build_preserves_uv_hash_across_runtime_dot_source(tmp_path: Path) -> None:
    """실제 runtime dot-source 뒤에도 plan과 build가 caller의 UV hash를 받습니다."""
    fixture_root = tmp_path / "fixture-root"
    source_runtime = fixture_root / "source" / "scripts" / "service-runtime.ps1"
    _ = source_runtime.parent.mkdir(parents=True)
    _ = source_runtime.write_bytes(RUNTIME_PATH.read_bytes())
    trusted_uv = tmp_path / "trusted-uv.exe"
    _ = trusted_uv.write_bytes(b"evaluation-only-uv")

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
$ExpectedUvSha256 = (Get-FileHash -LiteralPath $env:HERMES_QA_TRUSTED_UV -Algorithm SHA256).
    Hash.ToUpperInvariant()
$TrustedUvPath = $env:HERMES_QA_TRUSTED_UV
$ExpectedProgramRoot = Join-Path ([Environment]::GetFolderPath(
    [Environment+SpecialFolder]::ProgramFiles
)) 'HermesWindowsBridge'
$script:VerifiedOutputRoot = $env:HERMES_QA_FIXTURE_ROOT
$script:PlanExpectedUvSha256 = $null
$script:BuildExpectedUvSha256 = $null
function Fail-SecurityCheck { param([string]$Reason) throw $Reason }
function Get-RemainingSeconds { return 900 }
function Get-BridgeReleaseBuildPlan {
    param(
        [string]$SourceRoot,
        [string]$ProgramRoot,
        [string]$TrustedUvPath,
        [string]$ExpectedUvSha256,
        [string]$ExpectedSourceDigest,
        [string]$ExpectedLockDigest,
        [int]$TimeoutSeconds
    )
    $script:PlanExpectedUvSha256 = $ExpectedUvSha256
    return [pscustomobject]@{
        sourceDigest = ('a' * 64)
        lockDigest = ('b' * 64)
        releaseRoot = (Join-Path $env:HERMES_QA_FIXTURE_ROOT 'planned-release')
    }
}
function Invoke-BridgeProtectedReleaseBuild {
    param(
        [string]$SourceRoot,
        [string]$ProgramRoot,
        [string]$TrustedUvPath,
        [string]$ExpectedUvSha256,
        [string]$ExpectedSourceDigest,
        [string]$ExpectedLockDigest,
        [int]$TimeoutSeconds
    )
    $script:BuildExpectedUvSha256 = $ExpectedUvSha256
    return [pscustomobject]@{
        state = 'built'
        closureVerified = $true
        releaseRoot = (Join-Path $env:HERMES_QA_FIXTURE_ROOT 'planned-release')
        manifestPath = (Join-Path $env:HERMES_QA_FIXTURE_ROOT 'manifest.json')
        stagingRoot = (Join-Path $env:HERMES_QA_FIXTURE_ROOT 'staging')
    }
}
. ([scriptblock]::Create($definition[0].Extent.Text))
$source = [pscustomobject]@{
    verifiedFiles = @(
        [pscustomobject]@{
            relativePath = 'scripts/service-runtime.ps1'
            sourcePath = $env:HERMES_QA_SOURCE_RUNTIME
        }
    )
}
$_ = New-IsolatedBuildFixture -Source $source
$expected = $ExpectedUvSha256.ToLowerInvariant()
[ordered]@{
    planReceivedExpectedUvHash = ($script:PlanExpectedUvSha256 -ceq $expected)
    buildReceivedExpectedUvHash = ($script:BuildExpectedUvSha256 -ceq $expected)
} | ConvertTo-Json -Compress
"""

    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={
            **os.environ,
            "HERMES_QA_FIXTURE_ROOT": str(fixture_root),
            "HERMES_QA_SECURITY_HARNESS": str(HARNESS_PATH),
            "HERMES_QA_SOURCE_RUNTIME": str(source_runtime),
            "HERMES_QA_TRUSTED_UV": str(trusted_uv),
        },
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert FIXTURE_BUILD_SCOPE_RESULT_ADAPTER.validate_json(result.stdout) == {
        "planReceivedExpectedUvHash": True,
        "buildReceivedExpectedUvHash": True,
    }
