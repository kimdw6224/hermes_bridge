"""Evaluation diagnostic nested-completion exit regressions."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Final, Literal

import pytest

PROJECT_ROOT: Final = Path(__file__).resolve().parents[2]
SCRIPT_PATH: Final = (
    PROJECT_ROOT
    / ".omo"
    / "evidence"
    / "service-protection-eval-vm-20260908"
    / "security"
    / "diagnose-security-gate.ps1"
)
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None

NestedCompletion = Literal["result_null", "false", "null", "missing", "true"]


def _run_final_exit_contract(completion: NestedCompletion) -> int:
    """Production final if/exit AST를 nested diagnostic 결과로 실행합니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_DIAGNOSTIC_SCRIPT, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) { throw 'DiagnosticParseFailed' }
$success = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.IfStatementAst] -and
        $node.Extent.Text -match '\$report\.completed\s+-and\s+\$report\.cleanup'
}, $true))
$failureExit = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.ExitStatementAst] -and
        $node.Extent.Text -eq 'exit 2'
}, $true))
if ($success.Count -ne 1 -or $failureExit.Count -ne 1) {
    throw 'DiagnosticFinalExitContractMissing'
}
$result = switch ($env:HERMES_QA_NESTED_COMPLETION) {
    'result_null' { $null; break }
    'false' { [pscustomobject]@{ completed = $false }; break }
    'null' { [pscustomobject]@{ completed = $null }; break }
    'missing' { [pscustomobject]@{}; break }
    'true' { [pscustomobject]@{ completed = $true }; break }
    default { throw 'DiagnosticScenarioInvalid' }
}
$report = [pscustomobject]@{ completed = $true; cleanup = $true; result = $result }
$finalContract = $success[0].Extent.Text + [Environment]::NewLine + $failureExit[0].Extent.Text
& ([scriptblock]::Create($finalContract))
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={
            **os.environ,
            "HERMES_QA_DIAGNOSTIC_SCRIPT": str(SCRIPT_PATH),
            "HERMES_QA_NESTED_COMPLETION": completion,
        },
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=15,
    )

    assert result.stdout == ""
    assert result.stderr == ""
    return result.returncode


@pytest.mark.parametrize(
    ("completion", "expected_exit"),
    [("result_null", 2), ("false", 2), ("null", 2), ("missing", 2), ("true", 0)],
)
def test_diagnostic_exit_requires_nested_completed_true(
    completion: NestedCompletion,
    expected_exit: int,
) -> None:
    """Outer cleanup 성공만으로 nested guest 실패를 성공 처리하지 않습니다."""
    assert _run_final_exit_contract(completion) == expected_exit
