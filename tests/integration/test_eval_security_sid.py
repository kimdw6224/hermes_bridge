"""Evaluation-VM security SID interop regressions."""

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
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None


class SidInteropResult(TypedDict):
    currentMatchesIdentity: bool
    legacyMatchesIdentity: bool


SID_INTEROP_RESULT_ADAPTER: Final = TypeAdapter(SidInteropResult)


def test_security_access_probe_uses_unicode_sid_conversion() -> None:
    """현재 token에서 production Unicode SID만 identity SID와 일치합니다."""
    command = r"""
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_SECURITY_HARNESS, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) { throw 'SecurityHarnessParseFailed' }
$definition = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Initialize-EvalSecurityNative'
}, $true))
if ($definition.Count -ne 1) {
    throw 'SecurityHarnessFunctionMissing:Initialize-EvalSecurityNative'
}
. ([scriptblock]::Create($definition[0].Extent.Text))
Initialize-EvalSecurityNative
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$output = $null
try {
    $expected = [string]$identity.User.Value
    $flags = [Reflection.BindingFlags]'Static,NonPublic'
    $method = [HermesEval.SecurityAccessProbe].GetMethod('Sid', $flags)
    if ($null -eq $method) { throw 'SecurityAccessProbeSidMethodMissing' }
    $current = [string]$method.Invoke($null, [object[]]@($identity.Token))
    $legacyFunctionText = $definition[0].Extent.Text.
        Replace('Initialize-EvalSecurityNative', 'Initialize-LegacyEvalSecurityNative').
        Replace('HermesEval.SecurityAccessProbe', 'HermesEvalLegacy.LegacySecurityAccessProbe').
        Replace('namespace HermesEval {', 'namespace HermesEvalLegacy {')
    $legacyFunctionText = $legacyFunctionText.Replace(
        ('public static class Security' + 'AccessProbe'),
        ('public static class LegacySecurity' + 'AccessProbe')
    )
    $unicodeDeclaration = (
        '[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] ' +
        'static extern bool ConvertSidToStringSid'
    )
    $legacyDeclaration = (
        '[DllImport("advapi32.dll", SetLastError=true)] ' +
        'static extern bool ConvertSidToStringSid'
    )
    $legacyFunctionText = $legacyFunctionText.Replace($unicodeDeclaration, $legacyDeclaration)
    . ([scriptblock]::Create($legacyFunctionText))
    Initialize-LegacyEvalSecurityNative
    $legacyMethod = [HermesEvalLegacy.LegacySecurityAccessProbe].GetMethod('Sid', $flags)
    if ($null -eq $legacyMethod) { throw 'LegacySecurityAccessProbeSidMethodMissing' }
    $legacy = [string]$legacyMethod.Invoke($null, [object[]]@($identity.Token))
    $output = [ordered]@{
        currentMatchesIdentity = $current.Equals($expected, [StringComparison]::OrdinalIgnoreCase)
        legacyMatchesIdentity = $legacy.Equals($expected, [StringComparison]::OrdinalIgnoreCase)
    }
} finally {
    $identity.Dispose()
}
$output | ConvertTo-Json -Compress
"""

    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={**os.environ, "HERMES_QA_SECURITY_HARNESS": str(HARNESS_PATH)},
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert SID_INTEROP_RESULT_ADAPTER.validate_json(result.stdout) == {
        "currentMatchesIdentity": True,
        "legacyMatchesIdentity": False,
    }
