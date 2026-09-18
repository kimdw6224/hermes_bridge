"""Regression coverage for the service-host Apply context handoff."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import ClassVar, Final

from pydantic import BaseModel, ConfigDict, Field

PROJECT_ROOT: Final = Path(__file__).parents[2]
HOST_SCRIPT: Final = PROJECT_ROOT / "scripts" / "service-host.ps1"
VERIFIER_SCRIPT: Final = PROJECT_ROOT / "scripts" / "verify-release.ps1"
POWERSHELL: Final = shutil.which("powershell.exe")
assert POWERSHELL is not None


class BuildReceipt(BaseModel):
    """The pair captured at the protected host build boundary."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    state: str
    context_path: str = Field(validation_alias="contextPath")
    context_sha256: str = Field(validation_alias="contextSha256")


class RuntimeLoaderReceipt(BaseModel):
    """Values observed by the real runtime-library loading statement."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    received_path: str = Field(validation_alias="receivedPath")
    received_sha256: str = Field(validation_alias="receivedSha256")
    saved_path: str = Field(validation_alias="savedPath")
    saved_sha256: str = Field(validation_alias="savedSha256")


def test_apply_reuses_context_pair_after_plan_loads_context_module(tmp_path: Path) -> None:
    """Preserve the original pair when plan loading clears caller-scope parameters."""

    context_path = tmp_path / "installation-context.json"
    context_sha256 = "a" * 64
    command = " ".join(
        (
            "$tokens=$null;$errors=$null;",
            f"$ast=[Management.Automation.Language.Parser]::ParseFile('{HOST_SCRIPT}',",
            "[ref]$tokens,[ref]$errors);",
            "if ($errors.Count -ne 0) { throw 'HostScriptParseFailed' };",
            "$entry=$ast.Find({param($node) $node -is ",
            "[Management.Automation.Language.IfStatementAst] -and ",
            "$node.Extent.Text -match 'BridgeServiceHostBuildRequired' -and ",
            "$node.Extent.Text -match 'Invoke-BridgeServiceHostBuild'},$true);",
            "if ($null -eq $entry) { throw 'HostBuildEntryMissing' };",
            "$entryStatements=@($entry.Clauses[0].Item2.Statements |",
            "ForEach-Object { $_.Extent.Text });",
            "$entryBody=[scriptblock]::Create($entryStatements -join [Environment]::NewLine);",
            "function Get-BridgeServiceHostBuildPlan {",
            "param($SourceRoot,$ProgramRoot,$ReleaseRoot,$ExpectedManifestSha256,",
            "$InstallationContextPath,$InstallationContextSha256);",
            "Set-Variable -Name InstallationContextPath -Value '' -Scope 1;",
            "Set-Variable -Name InstallationContextSha256 -Value '' -Scope 1;",
            "[pscustomobject]@{state='planned'}",
            "};",
            "function Invoke-BridgeServiceHostBuild {",
            "param($SourceRoot,$ProgramRoot,$ReleaseRoot,$ExpectedManifestSha256,",
            "[Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$InstallationContextPath,",
            "[Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$InstallationContextSha256);",
            "[pscustomobject]@{state='built';contextPath=$InstallationContextPath;",
            "contextSha256=$InstallationContextSha256}",
            "};",
            "$LibraryMode=$false;$BuildHost=$true;$Apply=$true;$Json=$true;",
            "$SourceRoot='source';$ProgramRoot='program';$ReleaseRoot='release';",
            "$ExpectedManifestSha256='';",
            f"$InstallationContextPath='{context_path}';",
            f"$InstallationContextSha256='{context_sha256}';",
            "& $entryBody",
        )
    )

    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    receipt = BuildReceipt.model_validate_json(result.stdout)

    assert result.returncode == 0, result.stderr
    assert receipt.state == "built"
    assert receipt.context_path == str(context_path)
    assert receipt.context_sha256 == context_sha256


def test_internal_build_runtime_loader_receives_saved_context_pair(tmp_path: Path) -> None:
    """Keep schema-2 binding inputs after the actual runtime dot-source statement."""

    runtime_validator = tmp_path / "service-runtime.ps1"
    context_path = tmp_path / "installation-context.json"
    context_sha256 = "b" * 64
    _ = runtime_validator.write_text(
        """
param([string]$InstallationContextPath, [string]$InstallationContextSha256)
$script:BridgeTestReceivedPath=$InstallationContextPath
$script:BridgeTestReceivedSha256=$InstallationContextSha256
Set-Variable -Name InstallationContextPath -Value '' -Scope 1
Set-Variable -Name InstallationContextSha256 -Value '' -Scope 1
""",
        encoding="utf-8",
    )
    command = " ".join(
        (
            "$tokens=$null;$errors=$null;",
            f"$ast=[Management.Automation.Language.Parser]::ParseFile('{HOST_SCRIPT}',",
            "[ref]$tokens,[ref]$errors);",
            "$invoke=$ast.Find({param($node) $node -is ",
            "[Management.Automation.Language.FunctionDefinitionAst] -and ",
            "$node.Name -eq 'Invoke-BridgeServiceHostBuild'},$true);",
            "$loader=$invoke.Find({param($node) $node -is ",
            "[Management.Automation.Language.CommandAst] -and ",
            "$node.InvocationOperator -eq 'Dot' -and ",
            "$node.Extent.Text -match '^\\. \\$runtimeValidator'},$true);",
            "if ($null -eq $loader) { throw 'RuntimeLoaderMissing' };",
            f"$runtimeValidator='{runtime_validator}';$manifestPath='manifest';",
            "$plan=[pscustomobject]@{releaseRoot='release'};",
            "$SourceRoot='source';$ProgramRoot='program';",
            f"$requestedInstallationContextPath='{context_path}';",
            f"$requestedInstallationContextSha256='{context_sha256}';",
            "& ([scriptblock]::Create($loader.Extent.Text));",
            "[pscustomobject]@{receivedPath=$script:BridgeTestReceivedPath;",
            "receivedSha256=$script:BridgeTestReceivedSha256;",
            "savedPath=$requestedInstallationContextPath;",
            "savedSha256=$requestedInstallationContextSha256}|ConvertTo-Json -Compress",
        )
    )

    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    receipt = RuntimeLoaderReceipt.model_validate_json(result.stdout)

    assert result.returncode == 0, result.stderr
    assert receipt.received_path == str(context_path)
    assert receipt.received_sha256 == context_sha256
    assert receipt.saved_path == str(context_path)
    assert receipt.saved_sha256 == context_sha256


def test_schema2_path_validation_runs_on_windows_powershell_without_modern_path_api() -> None:
    """Accept a drive-absolute binding and reject rooted or drive-relative values on WinPS5."""

    command = " ".join(
        (
            f". '{HOST_SCRIPT}' -LibraryMode;",
            "$method=[IO.Path].GetMethod('IsPathFullyQualified',[Type[]]@([string]));",
            "[pscustomobject]@{",
            "methodPresent=($null -ne $method);",
            "absolute=(Test-BridgeHostAbsoluteLocalPath -Path 'C:\\bindings\\gateway.json');",
            "rooted=(Test-BridgeHostAbsoluteLocalPath -Path '\\bindings\\gateway.json');",
            "driveRelative=(Test-BridgeHostAbsoluteLocalPath -Path 'C:bindings\\gateway.json')",
            "}|ConvertTo-Json -Compress",
        )
    )
    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        '{"methodPresent":false,"absolute":true,"rooted":false,"driveRelative":false}'
    )


def test_schema2_verifier_accepts_drive_absolute_binding_on_windows_powershell(
    tmp_path: Path,
) -> None:
    """Use the production verifier path on WinPS5 without IsPathFullyQualified."""

    release_root = tmp_path / "release"
    _ = release_root.mkdir()
    manifest = release_root / "release-manifest.json"
    _ = manifest.write_bytes(b"{}")
    manifest_sha256 = hashlib.sha256(manifest.read_bytes()).hexdigest()
    verifier = tmp_path / "verify-release.ps1"
    _ = shutil.copy2(VERIFIER_SCRIPT, verifier)
    _ = (tmp_path / "host-config.json").write_text(
        json.dumps(
            {
                "schemaVersion": 2,
                "profile": "gateway",
                "releaseRoot": str(release_root),
                "manifestSha256": manifest_sha256,
                "runtimeBindingPath": "C:\\bindings\\gateway.json",
                "runtimeBindingSha256": "a" * 64,
            }
        ),
        encoding="utf-8",
    )
    _ = (tmp_path / "service-runtime.ps1").write_text(
        """
param([string]$ManifestPath, [string]$ReleaseRoot, [switch]$LibraryMode)
function Get-BridgeServiceLaunchContract {
    [pscustomobject]@{verified=$true;serviceExecutable='fixture.exe'}
}
""",
        encoding="utf-8",
    )
    _ = (tmp_path / "service-runtime-closure.ps1").write_text("", encoding="utf-8")

    result = subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(verifier),
            "-ReleaseRoot",
            str(release_root),
            "-ManifestSha256",
            manifest_sha256,
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert '"verified":true' in result.stdout

