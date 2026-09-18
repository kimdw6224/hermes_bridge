"""Behavioral tests for exact base-runtime ACL ownership recovery."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import ClassVar, Final

import pytest
from pydantic import BaseModel, ConfigDict, Field

PROJECT_ROOT: Final = Path(__file__).parents[2]
COMMON_SCRIPT: Final = PROJECT_ROOT / "scripts" / "lifecycle-common.ps1"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None


class RestoreReport(BaseModel):
    """Observable effects from an in-memory ACL restore simulation."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    state: str | None
    error: str | None
    set_acl_calls: int = Field(alias="setAclCalls")
    marker_removals: int = Field(alias="markerRemovals")
    rule_present_after: bool = Field(alias="rulePresentAfter")


def _run_restore(
    tmp_path: Path,
    *,
    status: str,
    include_rule: bool,
    add_concurrent_rule: bool = False,
) -> subprocess.CompletedProcess[str]:
    runtime_root = tmp_path / "bridge-runtime"
    marker_path = runtime_root / "secrets" / "runtime-access.json"
    base_root = tmp_path / "python-base"
    base_executable = base_root / "python.exe"
    _ = marker_path.parent.mkdir(parents=True)
    _ = base_root.mkdir()
    _ = base_executable.write_bytes(b"")
    command = r"""
. $env:HERMES_TEST_COMMON
$preAcl = [Security.AccessControl.DirectorySecurity]::new()
$preAcl.SetAccessRuleProtection($true, $false)
$preAcl.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-18' -Rights FullControl))
$preSddl = $preAcl.GetSecurityDescriptorSddlForm(
    [Security.AccessControl.AccessControlSections]::Access
)
$preHash = Get-BridgeSha256Hex -Value $preSddl
$script:currentAcl = [Security.AccessControl.DirectorySecurity]::new()
$script:currentAcl.SetSecurityDescriptorSddlForm($preSddl)
if ($env:HERMES_TEST_INCLUDE_RULE -ceq 'true') {
    $script:currentAcl.AddAccessRule((New-BridgeBaseRuntimeRule))
}
if ($env:HERMES_TEST_CONCURRENT_RULE -ceq 'true') {
    $script:currentAcl.AddAccessRule((New-BridgeDirectoryRule -Sid 'S-1-5-32-545' -Rights Read))
}
$script:currentSddl = $script:currentAcl.GetSecurityDescriptorSddlForm(
    [Security.AccessControl.AccessControlSections]::Access
)
$markerHash = Get-BridgeRuntimeAccessMarkerHash -SchemaVersion 1 -Status $env:HERMES_TEST_STATUS `
    -BaseRoot $env:HERMES_TEST_BASE -BaseExecutable $env:HERMES_TEST_EXE -PreAclHash $preHash
$markerDocument = [ordered]@{
    schemaVersion = 1
    status = $env:HERMES_TEST_STATUS
    baseRoot = $env:HERMES_TEST_BASE
    baseExecutable = $env:HERMES_TEST_EXE
    preAclHash = $preHash
    markerHash = $markerHash
} | ConvertTo-Json -Compress
[IO.File]::WriteAllText($env:HERMES_TEST_MARKER, $markerDocument)
$markerAcl = [Security.AccessControl.FileSecurity]::new()
$markerAcl.SetAccessRuleProtection($true, $false)
$markerAcl.AddAccessRule((New-BridgeFileRule -Sid 'S-1-5-18' -Rights FullControl))
$markerAcl.AddAccessRule((New-BridgeFileRule -Sid 'S-1-5-32-544' -Rights FullControl))
$script:setAclCalls = 0
$script:markerRemovals = 0
function Get-Acl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LiteralPath)
    if ($LiteralPath -ceq $env:HERMES_TEST_MARKER) { return $markerAcl }
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm($script:currentSddl)
    return $acl
}
function Set-Acl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][Security.AccessControl.DirectorySecurity]$AclObject
    )
    $script:setAclCalls++
    $script:currentSddl = $AclObject.GetSecurityDescriptorSddlForm(
        [Security.AccessControl.AccessControlSections]::Access
    )
}
function Remove-Item {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LiteralPath, [switch]$Force)
    $script:markerRemovals++
}
$state = $null
$failure = $null
try {
    $state = (Restore-BridgeBaseRuntimeAccess -RuntimeRoot $env:HERMES_TEST_RUNTIME).state
} catch {
    $failure = $_.Exception.Message
}
[pscustomobject]@{
    state = $state
    error = $failure
    setAclCalls = $script:setAclCalls
    markerRemovals = $script:markerRemovals
    rulePresentAfter = Test-BridgeBaseRuntimeRulePresent -Acl (
        Get-Acl -LiteralPath $env:HERMES_TEST_BASE
    )
} | ConvertTo-Json -Compress
"""
    environment = os.environ.copy()
    environment["HERMES_TEST_COMMON"] = str(COMMON_SCRIPT)
    environment["HERMES_TEST_RUNTIME"] = str(runtime_root)
    environment["HERMES_TEST_MARKER"] = str(marker_path)
    environment["HERMES_TEST_BASE"] = str(base_root)
    environment["HERMES_TEST_EXE"] = str(base_executable)
    environment["HERMES_TEST_STATUS"] = status
    environment["HERMES_TEST_INCLUDE_RULE"] = str(include_rule).lower()
    environment["HERMES_TEST_CONCURRENT_RULE"] = str(add_concurrent_rule).lower()
    return subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_applied_marker_removes_only_owned_exact_ace(tmp_path: Path) -> None:
    result = _run_restore(tmp_path, status="applied", include_rule=True)
    report = RestoreReport.model_validate_json(result.stdout)

    assert result.returncode == 0, result.stderr
    assert report.state == "restored-exact"
    assert report.error is None
    assert report.set_acl_calls == 1
    assert report.marker_removals == 1
    assert not report.rule_present_after


def test_pending_marker_never_authorizes_existing_ace_removal(tmp_path: Path) -> None:
    result = _run_restore(tmp_path, status="pending", include_rule=True)
    report = RestoreReport.model_validate_json(result.stdout)

    assert result.returncode == 0, result.stderr
    assert report.state is None
    assert report.error is not None
    assert "BridgeBaseRuntimeAccessOwnershipAmbiguous" in report.error
    assert report.set_acl_calls == 0
    assert report.marker_removals == 0
    assert report.rule_present_after


@pytest.mark.parametrize("include_rule", [False, True])
def test_acl_hash_mismatch_preserves_concurrent_acl_state(
    tmp_path: Path,
    *,
    include_rule: bool,
) -> None:
    result = _run_restore(
        tmp_path,
        status="applied",
        include_rule=include_rule,
        add_concurrent_rule=True,
    )
    report = RestoreReport.model_validate_json(result.stdout)

    assert result.returncode == 0, result.stderr
    assert report.state is None
    assert report.error is not None
    assert "BridgeBaseRuntimeAccessOwnershipAmbiguous" in report.error
    assert report.set_acl_calls == 0
    assert report.marker_removals == 0
    assert report.rule_present_after is include_rule
