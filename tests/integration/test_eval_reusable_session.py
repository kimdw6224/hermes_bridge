"""Evaluation security reusable-session ownership regressions."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Final, Literal, TypedDict

from pydantic import TypeAdapter

PROJECT_ROOT: Final = Path(__file__).resolve().parents[2]
SECURITY_ROOT: Final = (
    PROJECT_ROOT / ".omo" / "evidence" / "service-protection-eval-vm-20260908" / "security"
)
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None

ScriptName = Literal["run-security-checks.ps1", "diagnose-security-gate.ps1"]
SessionMode = Literal["owned", "caller"]


class SessionResult(TypedDict):
    """Session acquisition과 cleanup 호출을 나타냅니다."""

    created: int
    removed: int
    callerOwned: bool


SESSION_RESULT_ADAPTER: Final = TypeAdapter(SessionResult)


def _run_session_ownership(script_name: ScriptName, mode: SessionMode) -> SessionResult:
    """Production session helper AST를 no-I/O PowerShell seam에서 실행합니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_SESSION_SCRIPT, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) { throw 'SessionScriptParseFailed' }
$connect = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -match '^Connect-(Evaluation|Diagnostic)Session$'
}, $true))
$remove = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -match '^Remove-Owned(Evaluation|Diagnostic)Session$'
}, $true))
if ($connect.Count -ne 1 -or $remove.Count -ne 1) { throw 'SessionHelpersMissing' }
$script:created = 0; $script:removed = 0
function Get-Credential { return [pscustomobject]@{ opaque = $true } }
function New-PSSession {
    param([guid]$VMId, $Credential)
    $script:created++
    return [pscustomobject]@{ VMId = $VMId }
}
function Remove-PSSession { $script:removed++ }
. ([scriptblock]::Create($connect[0].Extent.Text))
. ([scriptblock]::Create($remove[0].Extent.Text))
$vmId = [guid]'2275c148-f4ba-4f1e-85bb-2695c6439bb6'
$existing = if ($env:HERMES_QA_SESSION_MODE -eq 'caller') {
    [pscustomobject]@{
        VMId = $vmId
        Runspace = [pscustomobject]@{
            RunspaceStateInfo = [pscustomobject]@{
                State = [Management.Automation.Runspaces.RunspaceState]::Opened
            }
        }
    }
} else { $null }
$result = & $connect[0].Name -VmId $vmId -ExistingSession $existing
[void](& $remove[0].Name -Session $result.session -CallerOwned ([bool]$result.callerOwned))
[ordered]@{
    created = $script:created
    removed = $script:removed
    callerOwned = [bool]$result.callerOwned
} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={
            **os.environ,
            "HERMES_QA_SESSION_MODE": mode,
            "HERMES_QA_SESSION_SCRIPT": str(SECURITY_ROOT / script_name),
        },
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    return SESSION_RESULT_ADAPTER.validate_json(result.stdout)


def test_owned_session_is_created_and_removed_for_each_security_entrypoint() -> None:
    """Caller session이 없으면 script가 만든 session만 cleanup합니다."""
    for script_name in ("run-security-checks.ps1", "diagnose-security-gate.ps1"):
        assert _run_session_ownership(script_name, "owned") == {
            "created": 1,
            "removed": 1,
            "callerOwned": False,
        }


def test_caller_session_is_neither_created_nor_removed_for_each_security_entrypoint() -> None:
    """열린 caller session은 credential prompt와 cleanup 대상이 아닙니다."""
    for script_name in ("run-security-checks.ps1", "diagnose-security-gate.ps1"):
        assert _run_session_ownership(script_name, "caller") == {
            "created": 0,
            "removed": 0,
            "callerOwned": True,
        }
