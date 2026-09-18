"""Privileged service registration contracts without a production SCM mutation."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import ClassVar, Final

from pydantic import BaseModel, ConfigDict

PROJECT_ROOT: Final = Path(__file__).parents[2]
SCRIPTS_ROOT: Final = PROJECT_ROOT / "scripts"
PRIVILEGED_SCRIPT: Final = SCRIPTS_ROOT / "register-privileged-service.ps1"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None


class ChildFailure(BaseModel):
    """Redacted reason exposed by the parent registration adapter."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    reason: str
    diagnostic: str


def test_privileged_create_uses_null_localsystem_and_complete_cim_contract() -> None:
    # Given: Win32_Service.Create uses a distinct LocalSystem representation at creation time.
    source = PRIVILEGED_SCRIPT.read_text(encoding="utf-8")

    # When: the fixed CIM argument contract is read without invoking SCM.
    create_call = source[source.index("$createArguments = @{"):]

    # Then: the manifest label is not passed as an account, and all method inputs are explicit.
    assert "StartName = $null" in create_call
    assert "StartName = $manifest.account" not in create_call
    for argument in (
        "Name = $manifest.name",
        "DisplayName = $manifest.name",
        "PathName = $binaryPath",
        "StartMode = 'Automatic'",
        "DesktopInteract = $false",
        "StartPassword = $null",
        "LoadOrderGroup = $null",
        "LoadOrderGroupDependencies = $null",
        "ServiceDependencies = $null",
    ):
        assert argument in create_call
    assert "service-account-invalid" in create_call
    assert "'NT AUTHORITY\\SYSTEM'" in source


def test_privileged_create_uses_windows_powershell_uint8_cim_arguments() -> None:
    # Given: the installed Windows PowerShell 5.1 CIM metadata, read without invoking SCM.
    metadata_command = r"""
$method = (Get-CimClass -ClassName Win32_Service -ErrorAction Stop).CimClassMethods['Create']
$method.Parameters |
    Sort-Object Name |
    ForEach-Object { '{0}:{1}' -f $_.Name, $_.CimType }
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", metadata_command],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    # When: the script's Create arguments are compared to the live CIM declaration.
    source = PRIVILEGED_SCRIPT.read_text(encoding="utf-8")
    create_call = source[source.index("$createArguments = @{"):]

    # Then: the source contract agrees with every live Create input type; numeric inputs are UInt8.
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "DesktopInteract:Boolean",
        "DisplayName:String",
        "ErrorControl:UInt8",
        "LoadOrderGroup:String",
        "LoadOrderGroupDependencies:StringArray",
        "Name:String",
        "PathName:String",
        "ServiceDependencies:StringArray",
        "ServiceType:UInt8",
        "StartMode:String",
        "StartName:String",
        "StartPassword:String",
    ]
    assert "ServiceType = [byte]16" in create_call
    assert "ErrorControl = [byte]1" in create_call


def test_privileged_create_failure_reason_survives_parent_adapter_redaction() -> None:
    # Given: the child reports the documented invalid-service-account result without secrets.
    command = """
& {
    . $env:HERMES_TEST_COMMON_PATH
    Get-BridgeRegistrationAdapterFailure -ExitCode 3 `
        -StandardOutput '{"failureReason":"service-account-invalid"}' `
        -StandardError 'Win32_Service.Create return=22 token=not-for-output' |
        ConvertTo-Json -Compress
}
"""
    environment = os.environ.copy()
    environment["HERMES_TEST_COMMON_PATH"] = str(SCRIPTS_ROOT / "lifecycle-common.ps1")

    # When: the same bounded parent-side failure adapter parses the mock child result.
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    # Then: the actionable reason remains while token-shaped text is redacted.
    assert result.returncode == 0, result.stderr
    assert ChildFailure.model_validate_json(result.stdout) == ChildFailure(
        reason="service-account-invalid",
        diagnostic="Win32_Service.Create return=22 token=[REDACTED]",
    )
