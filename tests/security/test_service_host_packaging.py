"""Host anchor package security contract."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import ClassVar, Final

from pydantic import BaseModel, ConfigDict, Field

PROJECT_ROOT: Final = Path(__file__).parents[2]
SCRIPT_PATH: Final = PROJECT_ROOT / "scripts" / "service-host.ps1"
POWERSHELL: Final = shutil.which("powershell.exe")
DOTNET: Final = shutil.which("dotnet.exe")
HOST_PROJECT: Final = (
    PROJECT_ROOT / "service-host" / "HermesBridge.ServiceHost" / "HermesBridge.ServiceHost.csproj"
)
assert POWERSHELL is not None
assert DOTNET is not None


class HostPlan(BaseModel):
    """Typed non-mutating host build plan."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    state: str
    applied: bool
    project_path: str = Field(alias="projectPath")
    commands: tuple[tuple[str, ...], ...]


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", *arguments],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )


def test_dry_run_build_plan_is_non_mutating_and_pins_self_contained_x64(tmp_path: Path) -> None:
    result = _run(
        "-File",
        str(SCRIPT_PATH),
        "-BuildHost",
        "-SourceRoot",
        str(tmp_path),
        "-ProgramRoot",
        str(tmp_path / "program"),
        "-ReleaseRoot",
        str(tmp_path / "release"),
        "-Json",
    )

    plan = HostPlan.model_validate_json(result.stdout)
    assert result.returncode == 0, result.stderr
    assert plan.state == "planned"
    assert not plan.applied
    expected_suffix = "service-host\\HermesBridge.ServiceHost\\HermesBridge.ServiceHost.csproj"
    expected_publish = (
        "dotnet",
        "publish",
        plan.project_path,
        "-c",
        "Release",
        "-r",
        "win-x64",
        "--self-contained",
        "true",
        "--no-restore",
    )
    assert plan.project_path.endswith(expected_suffix)
    assert plan.commands[0] == ("dotnet", "restore", plan.project_path, "-r", "win-x64")
    assert plan.commands[1] == expected_publish
    assert not (tmp_path / "program").exists()


def test_contract_rejects_profile_mismatch_without_host_discovery(tmp_path: Path) -> None:
    host_root = tmp_path / ("a" * 64) / "gateway"
    command = (
        f". '{SCRIPT_PATH}' -LibraryMode; "
        f"Get-BridgeServiceHostContract -HostRoot '{host_root}' -Profile privileged "
        f"-ReleaseRoot '{tmp_path / 'release'}' | ConvertTo-Json -Compress"
    )
    result = _run("-Command", command)

    assert result.returncode == 0, result.stderr
    assert '"verified":false' in result.stdout
    assert '"host-anchor-invalid"' in result.stdout


def test_native_build_logs_do_not_pollute_receipt_output(tmp_path: Path) -> None:
    fake_dotnet = tmp_path / "dotnet.ps1"
    _ = fake_dotnet.write_text(
        "Write-Output 'build progress'; $global:LASTEXITCODE = 7", encoding="utf-8"
    )
    command = (
        "$tokens = $null; $errors = $null; "
        f"$ast = [Management.Automation.Language.Parser]::ParseFile('{SCRIPT_PATH}', "
        "[ref]$tokens, [ref]$errors); "
        "$commands = @($ast.FindAll({ param($node) "
        "$node -is [Management.Automation.Language.CommandAst] -and "
        "$node.Extent.Text -match '^& \\$dotnetPath (restore|publish) ' }, $true)); "
        "if ($commands.Count -ne 2) { throw 'BuildCommandCount' }; "
        f"$dotnetPath = '{fake_dotnet}'; "
        "$stagedProject = 'fixture.csproj'; $stageProfile = 'fixture-output'; "
        "foreach ($command in $commands) { "
        "$statement = $command.Parent; "
        "while ($statement.Parent -isnot [Management.Automation.Language.StatementBlockAst]) "
        "{ $statement = $statement.Parent }; "
        "$output = @(& ([scriptblock]::Create($statement.Extent.Text))); "
        "if ($output.Count -ne 0) { throw 'ReceiptOutputPolluted' }; "
        "if ($LASTEXITCODE -ne 7) { throw 'BuildExitCodeLost' } }; "
        "'build-output-isolated'"
    )
    result = _run("-Command", command)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "build-output-isolated"


def test_build_preserves_manifest_path_when_loading_runtime_library(tmp_path: Path) -> None:
    project = tmp_path / "service-host" / "HermesBridge.ServiceHost"
    project.mkdir(parents=True)
    _ = (project / "HermesBridge.ServiceHost.csproj").write_text("<Project />", encoding="utf-8")
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    _ = (candidate / "release-manifest.json").write_text("{}", encoding="utf-8")
    command = (
        f". '{SCRIPT_PATH}' -LibraryMode; "
        "$program = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) "
        "'HermesWindowsBridge'; "
        f"try {{ Invoke-BridgeServiceHostBuild -SourceRoot '{tmp_path}' "
        f"-ProgramRoot $program -ReleaseRoot '{candidate}' | Out-Null; exit 4 }} "
        "catch { if ($_.Exception.Message -eq 'BridgeServiceHostRuntimeUnverified') "
        "{ 'runtime-validator-reached'; exit 0 }; throw }"
    )
    result = _run("-Command", command)
    assert result.returncode == 0, result.stderr
    assert "runtime-validator-reached" in result.stdout


def test_host_contract_library_load_preserves_manifest_path(tmp_path: Path) -> None:
    command = (
        "$tokens = $null; $errors = $null; "
        f"$ast = [Management.Automation.Language.Parser]::ParseFile('{SCRIPT_PATH}', "
        "[ref]$tokens, [ref]$errors); "
        "$function = $ast.Find({ param($node) "
        "$node -is [Management.Automation.Language.FunctionDefinitionAst] -and "
        "$node.Name -eq 'Get-BridgeServiceHostContract' }, $true); "
        "$load = $function.Find({ param($node) "
        "$node -is [Management.Automation.Language.CommandAst] -and "
        "$node.InvocationOperator -eq 'Dot' -and "
        "$node.Extent.Text -match 'service-runtime\\.ps1' }, $true); "
        f"$safeHostRoot = '{PROJECT_ROOT / 'scripts'}'; "
        f"$safeReleaseRoot = '{tmp_path}'; "
        "$manifestPath = Join-Path $safeReleaseRoot 'release-manifest.json'; "
        "$expected = $manifestPath; "
        ". ([scriptblock]::Create($load.Extent.Text)); "
        "if ($manifestPath -cne $expected) { throw 'ManifestPathOverwritten' }; "
        "'manifest-path-preserved'"
    )
    result = _run("-Command", command)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "manifest-path-preserved"


def test_verifier_passes_pinned_manifest_to_runtime_validator(tmp_path: Path) -> None:
    verifier = tmp_path / "verify-release.ps1"
    _ = shutil.copy2(PROJECT_ROOT / "scripts" / verifier.name, verifier)
    manifest = tmp_path / "release-manifest.json"
    _ = manifest.write_bytes(b"{}")
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    _ = (tmp_path / "host-config.json").write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "profile": "gateway",
                "releaseRoot": str(tmp_path),
                "manifestSha256": digest,
            }
        ),
        encoding="utf-8",
    )
    _ = (tmp_path / "service-runtime.ps1").write_text(
        """param([string]$ManifestPath, [string]$ReleaseRoot, [switch]$LibraryMode)
function Get-BridgeServiceLaunchContract {
param([Parameter(Mandatory)][string]$ManifestPath, [string]$ReleaseRoot)
$expectedManifestPath = Join-Path $ReleaseRoot 'release-manifest.json'
if ($ManifestPath -cne $expectedManifestPath) { throw 'WrongManifestPath' };
[pscustomobject]@{ verified = $true; serviceExecutable = 'fixture.exe' } }
""",
        encoding="utf-8",
    )
    _ = (tmp_path / "service-runtime-closure.ps1").write_text("", encoding="utf-8")
    result = _run("-File", str(verifier), "-ReleaseRoot", str(tmp_path), "-ManifestSha256", digest)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["verified"] is True


def test_verifier_rejects_malformed_config_with_sanitized_exit(tmp_path: Path) -> None:
    verifier = PROJECT_ROOT / "scripts" / "verify-release.ps1"
    host_dir = tmp_path / "host"
    _ = host_dir.mkdir()
    copied = host_dir / "verify-release.ps1"
    _ = copied.write_text(verifier.read_text(encoding="utf-8"), encoding="utf-8")
    _ = (host_dir / "host-config.json").write_text("{bad", encoding="utf-8")
    result = _run(
        "-File",
        str(copied),
        "-ReleaseRoot",
        str(tmp_path / "release"),
        "-ManifestSha256",
        "a" * 64,
    )

    assert result.returncode == 2
    assert '"verified":false' in result.stdout
    assert '"host-config-invalid"' in result.stdout


def test_verifier_rejects_manifest_digest_before_runtime_validation(tmp_path: Path) -> None:
    verifier = PROJECT_ROOT / "scripts" / "verify-release.ps1"
    host_dir = tmp_path / "host"
    release_root = tmp_path / "release"
    _ = host_dir.mkdir()
    _ = release_root.mkdir()
    _ = (host_dir / "verify-release.ps1").write_text(
        verifier.read_text(encoding="utf-8"), encoding="utf-8"
    )
    config = {
        "schemaVersion": 1,
        "profile": "gateway",
        "releaseRoot": str(release_root),
        "manifestSha256": "a" * 64,
    }
    _ = (host_dir / "host-config.json").write_text(json.dumps(config), encoding="utf-8")
    _ = (release_root / "release-manifest.json").write_text("{}", encoding="utf-8")

    result = _run(
        "-File",
        str(host_dir / "verify-release.ps1"),
        "-ReleaseRoot",
        str(release_root),
        "-ManifestSha256",
        "a" * 64,
    )

    assert result.returncode == 2
    assert '"verified":false' in result.stdout
    assert '"manifest-digest-mismatch"' in result.stdout


def test_staged_host_snapshot_restores_for_publish_runtime_identifier(tmp_path: Path) -> None:
    source_root = HOST_PROJECT.parent
    snapshot_root = tmp_path / "source"
    staged_project = snapshot_root / HOST_PROJECT.parent.name / HOST_PROJECT.name
    output_root = tmp_path / "publish"
    _ = snapshot_root.mkdir()
    _ = shutil.copy2(PROJECT_ROOT / "service-host" / "global.json", snapshot_root / "global.json")
    for source in source_root.rglob("*"):
        if not source.is_file() or {"bin", "obj"}.intersection(source.parts):
            continue
        target = snapshot_root / HOST_PROJECT.parent.name / source.relative_to(source_root)
        target.parent.mkdir(parents=True, exist_ok=True)
        _ = shutil.copy2(source, target)

    restore = subprocess.run(
        [DOTNET, "restore", str(staged_project), "-r", "win-x64"],
        cwd=snapshot_root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    publish = subprocess.run(
        [
            DOTNET,
            "publish",
            str(staged_project),
            "-c",
            "Release",
            "-r",
            "win-x64",
            "--self-contained",
            "true",
            "--no-restore",
            "--output",
            str(output_root),
        ],
        cwd=snapshot_root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )

    assert restore.returncode == 0, restore.stderr
    assert publish.returncode == 0, publish.stderr
    assert (output_root / "HermesBridge.ServiceHost.exe").is_file()


def test_host_directory_acl_grants_localservice_read_execute_without_write() -> None:
    command = " ".join(
        (
            f". '{SCRIPT_PATH}' -LibraryMode;",
            "$acl = New-BridgeHostDirectorySecurity;",
            "$sid = [Security.Principal.SecurityIdentifier]::new('S-1-5-19');",
            "$accessType = [Security.AccessControl.AccessControlType]::Allow;",
            "$expected = [int64][Security.AccessControl.FileSystemRights]::ReadAndExecute;",
            "$rights = [int64]0;",
            "foreach ($rule in $acl.GetAccessRules($true, $true, $sid.GetType())) {",
            "$sameIdentity = $rule.IdentityReference.Value -ceq $sid.Value;",
            "$isAllow = $rule.AccessControlType -eq $accessType;",
            "if ($sameIdentity -and $isAllow) {",
            "$rights = $rights -bor [int64]$rule.FileSystemRights",
            "} };",
            "$readExecute = (($rights -band $expected) -eq $expected);",
            "$write = (($rights -band [int64]0x500D0156) -ne 0);",
            "$result = [pscustomobject]@{readExecute = $readExecute; write = $write};",
            "$result | ConvertTo-Json -Compress",
        )
    )
    result = _run("-Command", command)

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"readExecute": True, "write": False}


def test_host_build_preserves_staging_and_checks_move_boundaries() -> None:
    source = SCRIPT_PATH.read_text(encoding="utf-8")

    assert "Remove-Item -LiteralPath $stageRoot -Recurse -Force" not in source
    assert "stagingRoot = $stageRoot" in source
    assert "BridgeServiceHostMoveBoundaryInvalid" in source
    assert "Test-BridgeHostReparseFree -Path $stageRoot" in source
    assert "Test-BridgeHostReparseFree -Path $hostsRoot" in source


def test_schema2_host_contract_requires_the_paired_context_and_fixed_binding() -> None:
    source = SCRIPT_PATH.read_text(encoding="utf-8")

    assert "InstallationContextPath" in source
    assert "InstallationContextSha256" in source
    assert "BridgeServiceHostInstallationContextPairRequired" in source
    assert "$requestedPath = $InstallationContextPath" in source
    assert "$requestedSha256 = $InstallationContextSha256" in source
    assert ". $contextScript -LibraryMode" in source
    assert "function Get-BridgeServiceHostInstallationBinding" in source
    assert "Get-BridgeInstallationContextBinding -Context $context -Profile $Profile" in source
    binding_resolver_prefix = (
        "Get-BridgeServiceHostInstallationBinding -InstallationContextPath "
    )
    expected_binding_resolver = f"{binding_resolver_prefix}{'$'}InstallationContextPath"
    assert expected_binding_resolver in source
    assert "Get-BridgeInstallationContextBinding -Context $context -Profile $Profile" in source
    assert "runtimeBindingPath" in source
    assert "runtimeBindingSha256" in source
    assert "gatewayServiceName" in source
    assert "privilegedServiceName" in source
    assert "runtimeBindingPath = [string]$binding.path" in source
    assert "--runtime-binding" not in source


def test_legacy_host_builder_allows_an_absent_context_pair_but_not_partial_pair() -> None:
    source = SCRIPT_PATH.read_text(encoding="utf-8")

    optional_context_hash = (
        "[AllowEmptyString()][ValidatePattern('^(?:[a-f0-9]{64})?$')]"
        "[string]$InstallationContextSha256"
    )
    assert source.count(optional_context_hash) == 4
    assert "$hasPath -ne $hasSha" in source
