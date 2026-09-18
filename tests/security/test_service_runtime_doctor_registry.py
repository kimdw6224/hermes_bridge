"""Windows PowerShell Registry provider regression for the doctor ACL reader."""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
from pathlib import Path
from typing import ClassVar, Final, Literal

import pytest
from pydantic import BaseModel, ConfigDict, Field

PROJECT_ROOT: Final = Path(__file__).parents[2]
DOCTOR_PATH: Final = PROJECT_ROOT / "scripts" / "doctor.ps1"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None


class RegistryReaderReport(BaseModel):
    """Sanitized result from the read-only Registry ACL reader."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    result: Literal["verified", "unverified"]
    descriptor_type: str = Field(alias="descriptorType")


def _run_registry_reader(service_name: str) -> RegistryReaderReport:
    """Run the production reader against a stable, non-bridge Windows service key."""
    environment = os.environ.copy()
    # uv child 환경의 PSModulePath는 Windows inbox module 자동 로드를 가릴 수 있습니다.
    _ = environment.pop("PSModulePath", None)
    environment["HERMES_TEST_DOCTOR"] = str(DOCTOR_PATH)
    environment["HERMES_TEST_SERVICE_NAME"] = service_name
    command = r"""
$tokens=$null;$errors=$null
$env:PSModulePath=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\Modules'
$null=Import-Module Microsoft.PowerShell.Security -ErrorAction Stop
$ast=[Management.Automation.Language.Parser]::ParseFile($env:HERMES_TEST_DOCTOR,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'doctor-parse-failed'}
$definition=$ast.Find({param($node)
 $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
 $node.Name -eq 'Get-BridgeServiceRegistrySecurityDescriptor'
},$true)
if($null -eq $definition){throw 'registry-reader-missing'}
. ([scriptblock]::Create($definition.Extent.Text))
$read=Get-BridgeServiceRegistrySecurityDescriptor -Name $env:HERMES_TEST_SERVICE_NAME
[pscustomobject]@{
 result=[string]$read.result
 descriptorType=if($null -eq $read.descriptor){''}else{$read.descriptor.GetType().FullName}
}|ConvertTo-Json -Compress
"""
    encoded_command = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    return RegistryReaderReport.model_validate_json(result.stdout)


@pytest.mark.parametrize(
    ("service_name", "expected_result", "expected_descriptor_type"),
    [
        ("Schedule", "verified", "System.Security.AccessControl.RawSecurityDescriptor"),
        ("Sched*", "unverified", ""),
        ("HermesWindowsBridgeDoesNotExist", "unverified", ""),
    ],
)
def test_registry_acl_reader_preserves_literal_service_name_semantics_with_windows_powershell(
    service_name: str,
    expected_result: Literal["verified", "unverified"],
    expected_descriptor_type: str,
) -> None:
    # Given: 존재 key, wildcard를 포함한 이름, 존재하지 않는 service name입니다.
    # When: doctor의 실제 Registry ACL reader를 실행합니다.
    read = _run_registry_reader(service_name)

    # Then: 실제 key만 descriptor를 반환하고 wildcard는 실제 wildcard로 확장하지 않습니다.
    assert read.result == expected_result
    assert read.descriptor_type == expected_descriptor_type
