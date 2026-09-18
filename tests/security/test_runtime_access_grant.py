"""Behavioral tests for base-runtime ACL grant ownership."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Final

PROJECT_ROOT: Final = Path(__file__).parents[2]
COMMON_SCRIPT: Final = PROJECT_ROOT / "scripts" / "lifecycle-common.ps1"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None


def _runtime_paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    runtime_root = tmp_path / "bridge-runtime"
    _ = (runtime_root / "secrets").mkdir(parents=True)
    base_root = tmp_path / "python-base"
    _ = base_root.mkdir()
    base_executable = base_root / "python.exe"
    _ = base_executable.write_bytes(b"")
    return runtime_root, base_root, base_executable


def _environment(runtime_root: Path, base_root: Path, executable: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["HERMES_TEST_COMMON"] = str(COMMON_SCRIPT)
    environment["HERMES_TEST_RUNTIME"] = str(runtime_root)
    environment["HERMES_TEST_BASE"] = str(base_root)
    environment["HERMES_TEST_EXE"] = str(executable)
    return environment


def test_preexisting_exact_ace_is_not_claimed_or_mutated(tmp_path: Path) -> None:
    runtime_root, base_root, executable = _runtime_paths(tmp_path)
    command = r"""
. $env:HERMES_TEST_COMMON
$script:acl = [Security.AccessControl.DirectorySecurity]::new()
$script:acl.SetAccessRuleProtection($true, $false)
$script:acl.AddAccessRule((New-BridgeBaseRuntimeRule))
$script:setCalls = 0
function Get-Acl { [CmdletBinding()] param([string]$LiteralPath) return $script:acl }
function Set-Acl {
    [CmdletBinding()]
    param([string]$LiteralPath, [Security.AccessControl.DirectorySecurity]$AclObject)
    $script:setCalls++
}
$result = Grant-BridgeBaseRuntimeAccess -RuntimeRoot $env:HERMES_TEST_RUNTIME `
    -BaseRoot $env:HERMES_TEST_BASE -BaseExecutable $env:HERMES_TEST_EXE
[pscustomobject]@{
    state = $result.state
    applied = $result.applied
    setCalls = $script:setCalls
    markerExists = Test-Path -LiteralPath (
        Get-BridgeRuntimeAccessMarkerPath $env:HERMES_TEST_RUNTIME
    )
} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=_environment(runtime_root, base_root, executable),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        '{"state":"unchanged-preexisting","applied":false,'
        '"setCalls":0,"markerExists":false}'
    )


def test_failed_grant_does_not_remove_concurrent_exact_ace(tmp_path: Path) -> None:
    runtime_root, base_root, executable = _runtime_paths(tmp_path)
    command = r"""
. $env:HERMES_TEST_COMMON
$initialAcl = [Security.AccessControl.DirectorySecurity]::new()
$initialAcl.SetAccessRuleProtection($true, $false)
$initialAcl.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-18' -Rights FullControl))
$script:currentSddl = $initialAcl.GetSecurityDescriptorSddlForm(
    [Security.AccessControl.AccessControlSections]::Access
)
$script:baseSetCalls = 0
function Get-Acl {
    [CmdletBinding()]
    param([string]$LiteralPath)
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm($script:currentSddl)
    return $acl
}
function Set-Acl {
    [CmdletBinding()]
    param([string]$LiteralPath, [Security.AccessControl.FileSystemSecurity]$AclObject)
    if ($LiteralPath -ceq $env:HERMES_TEST_BASE) {
        $script:baseSetCalls++
        $concurrent = [Security.AccessControl.DirectorySecurity]::new()
        $concurrent.SetSecurityDescriptorSddlForm($script:currentSddl)
        $concurrent.AddAccessRule((New-BridgeBaseRuntimeRule))
        $script:currentSddl = $concurrent.GetSecurityDescriptorSddlForm(
            [Security.AccessControl.AccessControlSections]::Access
        )
        throw 'simulated-set-acl-failure-after-concurrent-change'
    }
}
$failure = $null
try {
    Grant-BridgeBaseRuntimeAccess -RuntimeRoot $env:HERMES_TEST_RUNTIME `
        -BaseRoot $env:HERMES_TEST_BASE -BaseExecutable $env:HERMES_TEST_EXE | Out-Null
} catch {
    $failure = $_.Exception.Message
}
$current = Get-Acl -LiteralPath $env:HERMES_TEST_BASE
[pscustomobject]@{
    error = $failure
    baseSetCalls = $script:baseSetCalls
    rulePresent = Test-BridgeBaseRuntimeRulePresent -Acl $current
    markerExists = Test-Path -LiteralPath (
        Get-BridgeRuntimeAccessMarkerPath $env:HERMES_TEST_RUNTIME
    )
} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=_environment(runtime_root, base_root, executable),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert "BridgeBaseRuntimeAccessOwnershipAmbiguous" in result.stdout
    assert '"baseSetCalls":1' in result.stdout
    assert '"rulePresent":true' in result.stdout
    assert '"markerExists":true' in result.stdout
