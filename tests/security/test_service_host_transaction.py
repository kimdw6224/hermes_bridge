"""Host-aware protected service transaction contracts."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path
from typing import ClassVar, Final

from pydantic import BaseModel, ConfigDict, Field

PROJECT_ROOT: Final = Path(__file__).parents[2]
INSTALL_SCRIPT: Final = PROJECT_ROOT / "scripts" / "install.ps1"
TRANSACTION_SCRIPT: Final = PROJECT_ROOT / "scripts" / "service-runtime-transaction.ps1"
DOCTOR_SCRIPT: Final = PROJECT_ROOT / "scripts" / "doctor.ps1"
POWERSHELL: Final = shutil.which("powershell.exe")
assert POWERSHELL is not None


class ActiveReleasePointer(BaseModel):
    """Schema 2 active pointer persisted through the PowerShell transaction boundary."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(alias="schemaVersion")
    release_root: str = Field(alias="releaseRoot")
    manifest_sha256: str = Field(alias="manifestSha256")
    gateway_host_root: str = Field(alias="gatewayHostRoot")
    privileged_host_root: str = Field(alias="privilegedHostRoot")


class ResolvedRelease(BaseModel):
    """Host anchors returned by the active-pointer resolver."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    release_root: str = Field(alias="releaseRoot")
    gateway_host_root: str = Field(alias="gatewayServiceHostRoot")
    privileged_host_root: str = Field(alias="privilegedServiceHostRoot")


class TransactionRoundTrip(BaseModel):
    """Pointer and resolver values emitted by the PowerShell integration probe."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    pointer: ActiveReleasePointer
    resolved: ResolvedRelease


class ChildRuntimeCheck(BaseModel):
    """Doctor result for the host-to-release child process relationship."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    id: str
    status: str
    critical: bool
    detail: str


def test_schema_two_pointer_round_trips_exact_host_anchors(tmp_path: Path) -> None:
    # Given: host package contract을 제공하는 protected release 선택 helper입니다.
    scripts_root = tmp_path / "scripts"
    scripts_root.mkdir()
    transaction_copy = scripts_root / TRANSACTION_SCRIPT.name
    _ = shutil.copyfile(TRANSACTION_SCRIPT, transaction_copy)
    manifest_sha256 = hashlib.sha256(b"{}").hexdigest()
    _ = (scripts_root / "service-runtime.ps1").write_text(
        """param([switch]$LibraryMode)
function Get-BridgeServiceLaunchContract {
 param([string]$ManifestPath,[string]$ReleaseRoot)
 [pscustomobject]@{verified=$true;serviceExecutable=(Join-Path $ReleaseRoot 'python.exe')}
}
""",
        encoding="utf-8-sig",
    )
    host_path = scripts_root / "service-host.ps1"
    host_source = """param([switch]$LibraryMode)
function Get-BridgeServiceHostContract {
 param([string]$HostRoot,[string]$Profile,[string]$ReleaseRoot)
 $exe=Join-Path $HostRoot 'HermesBridge.ServiceHost.exe'
 [pscustomobject]@{
  state='verified';verified=$true;profile=$Profile;hostRoot=$HostRoot;releaseRoot=$ReleaseRoot
  hostDigest=('a'*64);manifestSha256='MANIFEST_SHA256'
  releaseExecutable=(Join-Path $ReleaseRoot 'python.exe')
  hostExecutable=$exe;argv=@($exe,'--profile',$Profile)
 }
}
"""
    _ = host_path.write_text(
        host_source.replace("MANIFEST_SHA256", manifest_sha256),
        encoding="utf-8-sig",
    )
    release_id = "a" * 64
    program_root = tmp_path / "program"
    release_root = program_root / "releases" / release_id
    release_root.mkdir(parents=True)
    _ = (release_root / "release-manifest.json").write_text("{}", encoding="utf-8")
    gateway_root = tmp_path / "hosts" / "gateway"
    privileged_root = tmp_path / "hosts" / "privileged"
    gateway_root.mkdir(parents=True)
    privileged_root.mkdir(parents=True)

    # When: 실제 Windows PowerShell file replace와 resolver를 통해 schema 2 pointer를 왕복합니다.
    transaction_path = str(transaction_copy).replace("'", "''")
    program_path = str(program_root).replace("'", "''")
    release_path = str(release_root).replace("'", "''")
    gateway_path = str(gateway_root).replace("'", "''")
    privileged_path = str(privileged_root).replace("'", "''")
    expression = (
        "function Test-BridgeTreeAcl { return $null };"
        "function Get-BridgeFileLinkCount { return 1 };"
        f". '{transaction_path}';"
        "$release=[pscustomobject]@{"
        f"releaseRoot='{release_path}';manifestSha256='{manifest_sha256}';"
        f"gatewayServiceHostRoot='{gateway_path}';privilegedServiceHostRoot='{privileged_path}'}};"
        f"Publish-BridgeActiveReleasePointer -ProgramRoot '{program_path}' -Release $release;"
        f"$pointer=Get-Content -LiteralPath '{program_path}\\active-release.json' -Raw;"
        f"$resolved=Resolve-BridgeServiceReleaseSelection -ProgramRoot '{program_path}';"
        "[pscustomobject]@{pointer=($pointer|ConvertFrom-Json);resolved=[pscustomobject]@{"
        "releaseRoot=$resolved.releaseRoot;gatewayServiceHostRoot=$resolved.gatewayServiceHostRoot;"
        "privilegedServiceHostRoot=$resolved.privilegedServiceHostRoot}}"
        "|ConvertTo-Json -Depth 6 -Compress"
    )
    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", expression],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )

    # Then: release identity와 profile별 immutable anchor가 그대로 남습니다.
    assert result.returncode == 0, result.stderr
    payload = TransactionRoundTrip.model_validate_json(result.stdout)
    pointer = payload.pointer
    resolved = payload.resolved
    assert pointer.schema_version == 2
    assert pointer.manifest_sha256 == manifest_sha256
    assert Path(pointer.release_root) == release_root
    assert Path(pointer.gateway_host_root) == gateway_root
    assert Path(pointer.privileged_host_root) == privileged_root
    assert Path(resolved.release_root) == release_root
    assert Path(resolved.gateway_host_root) == gateway_root
    assert Path(resolved.privileged_host_root) == privileged_root


def test_install_refuses_partial_host_selection_without_mutation() -> None:
    # Given: Gateway host만 명시된 dry-run install request입니다.
    sentinel = r"C:\HOST_SELECTION_MUST_NOT_BE_PARTIAL"

    # When: actual installer parameter boundary를 실행합니다.
    result = subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(INSTALL_SCRIPT),
            "-GatewayServiceHostRoot",
            sentinel,
            "-Json",
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )

    # Then: 보호 host contract을 우회하는 부분 선택은 adapter나 runtime write 전에 거부됩니다.
    assert result.returncode != 0
    assert "BridgeServiceHostRootsIncomplete" in result.stderr
    assert sentinel not in result.stdout


def test_doctor_rejects_unexpected_host_child_command(tmp_path: Path) -> None:
    # Given: host process 아래에 검증된 release Python과 다른 child command가 있습니다.
    _ = (tmp_path / "service-host.ps1").write_text(
        """param([switch]$LibraryMode)
function Get-BridgeServiceHostContract {
 param([string]$HostRoot,[string]$Profile,[string]$ReleaseRoot)
 $hostExecutable=Join-Path $HostRoot 'HermesBridge.ServiceHost.exe'
 $releaseExecutable=Join-Path $ReleaseRoot 'python.exe'
 [pscustomobject]@{state='verified';verified=$true;hostExecutable=$hostExecutable;releaseExecutable=$releaseExecutable}
}
""",
        encoding="utf-8-sig",
    )
    doctor_path = str(DOCTOR_SCRIPT).replace("'", "''")
    root = str(tmp_path).replace("'", "''")
    release_root = str(tmp_path / "release").replace("'", "''")
    expression = f"""
$tokens=$null
$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('{doctor_path}',[ref]$tokens,[ref]$errors)
$definitions=@()
$replacement="'{root}'"
foreach($name in @('New-CheckResult','Get-ProtectedServiceHostChildCheck')){{
 $node=$ast.Find({{
  param($item)
  $item -is [Management.Automation.Language.FunctionDefinitionAst] -and $item.Name -eq $name
 }},$true)
 $definitions+=($node.Extent.Text.Replace('$PSScriptRoot',$replacement))
}}
. ([scriptblock]::Create(($definitions -join [Environment]::NewLine)))
function Get-CimInstance {{
 param($ClassName,$Filter,$ErrorAction)
 if($ClassName -ceq 'Win32_Service'){{
  $script:profile=if($Filter -like '*Gateway*'){{'gateway'}}else{{'privileged'}}
  return [pscustomobject]@{{State='Running';ProcessId=500}}
 }}
 if($Filter -like 'ProcessId=*'){{
  $hostPath=Join-Path '{root}' 'HermesBridge.ServiceHost.exe'
  $hostCommandLine='"' + $hostPath + '" --profile ' + $script:profile
  return [pscustomobject]@{{ExecutablePath=$hostPath;CommandLine=$hostCommandLine}}
 }}
 return [pscustomobject]@{{ExecutablePath='C:\\wrong\\python.exe';CommandLine='wrong'}}
}}
$release=[pscustomobject]@{{
 releaseRoot='{release_root}'
 gatewayServiceHostRoot='{root}'
 privilegedServiceHostRoot='{root}'
}}
Get-ProtectedServiceHostChildCheck -Id 'runtime' -Release $release|ConvertTo-Json -Compress
""".strip()

    # When: doctor의 read-only CIM observation을 actual PowerShell에서 실행합니다.
    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", expression],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )

    # Then: schema 2 host 아래의 임의 child는 critical failure입니다.
    assert result.returncode == 0, result.stderr
    check = ChildRuntimeCheck.model_validate_json(result.stdout)
    assert check.status == "fail"
    assert check.critical is True
    assert "identity" in check.detail
