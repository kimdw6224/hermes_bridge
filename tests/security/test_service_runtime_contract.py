"""Protected service runtime manifest and filesystem contract tests."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import ClassVar, Final

import pytest
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

PROJECT_ROOT: Final = Path(__file__).parents[2]
SCRIPT_PATH: Final = PROJECT_ROOT / "scripts" / "service-runtime.ps1"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None


class ContractResult(BaseModel):
    """Stable read-only validator output."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    schema_version: int = Field(alias="schemaVersion")
    state: str
    verified: bool
    failure_reasons: tuple[str, ...] = Field(alias="failureReasons")
    manifest_path: str = Field(alias="manifestPath")
    release_root: str = Field(alias="releaseRoot")
    read_only: bool = Field(alias="readOnly")
    authorization_reusable: bool = Field(alias="authorizationReusable")


class OsAclRow(BaseModel):
    """Observed canonical Windows ancestor ACL policy result."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    path: str
    owner_trusted: bool = Field(alias="ownerTrusted")
    write_trusted: bool = Field(alias="writeTrusted")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_manifest(
    release_root: Path,
    **updates: str | int | bool | list[dict[str, str | int]],
) -> Path:
    service_executable = release_root / "venv" / "Scripts" / "python.exe"
    base_executable = release_root / "python" / "python.exe"
    service_executable.parent.mkdir(parents=True)
    base_executable.parent.mkdir(parents=True)
    _ = service_executable.write_bytes(b"service-python")
    _ = base_executable.write_bytes(b"base-python")
    inventory = [
        {
            "relativePath": "python/python.exe",
            "sha256": _sha256(base_executable),
            "size": base_executable.stat().st_size,
        },
        {
            "relativePath": "venv/Scripts/python.exe",
            "sha256": _sha256(service_executable),
            "size": service_executable.stat().st_size,
        },
    ]
    manifest: dict[str, str | int | bool | list[dict[str, str | int]]] = {
        "schemaVersion": 1,
        "releaseId": "a" * 64,
        "sourceDigest": "b" * 64,
        "lockDigest": "c" * 64,
        "pythonVersion": "3.14.3",
        "architecture": "x64",
        "uvVersion": "0.12.8",
        "fileInventory": inventory,
        "baseExecutable": str(base_executable),
        "serviceExecutable": str(service_executable),
    }
    manifest.update(updates)
    manifest_path = release_root / "release-manifest.json"
    _ = manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest_path


def _run_contract(manifest_path: Path, release_root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(SCRIPT_PATH),
            "-ManifestPath",
            str(manifest_path),
            "-ReleaseRoot",
            str(release_root),
            "-Json",
        ],
        cwd=PROJECT_ROOT,
        env=os.environ.copy(),
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )


def test_malformed_manifest_is_blocked_without_mutation(tmp_path: Path) -> None:
    release_root = tmp_path / "release"
    release_root.mkdir()
    manifest_path = release_root / "release-manifest.json"
    _ = manifest_path.write_text('{"schemaVersion":1,"unexpected":true}', encoding="utf-8")
    before = manifest_path.read_bytes()

    result = _run_contract(manifest_path, release_root)

    assert result.stdout, result.stderr
    contract = ContractResult.model_validate_json(result.stdout)
    assert result.returncode == 2
    assert contract.state == "blocked"
    assert not contract.verified
    assert "manifest-schema-invalid" in contract.failure_reasons
    assert contract.read_only
    assert not contract.authorization_reusable
    assert manifest_path.read_bytes() == before


def test_duplicate_top_level_key_is_blocked(tmp_path: Path) -> None:
    release_root = tmp_path / ("a" * 64)
    manifest_path = _write_manifest(release_root)
    raw = manifest_path.read_text(encoding="utf-8")
    _ = manifest_path.write_text(
        raw.replace('"schemaVersion": 1', '"schemaVersion": 1, "schemaVersion": 1'),
        encoding="utf-8",
    )

    result = _run_contract(manifest_path, release_root)

    contract = ContractResult.model_validate_json(result.stdout)
    assert result.returncode == 2
    assert "manifest-schema-invalid" in contract.failure_reasons


def test_duplicate_inventory_key_is_blocked(tmp_path: Path) -> None:
    release_root = tmp_path / ("a" * 64)
    manifest_path = _write_manifest(release_root)
    raw = manifest_path.read_text(encoding="utf-8")
    _ = manifest_path.write_text(
        raw.replace('"size": 11', '"size": 11, "size": 11', 1),
        encoding="utf-8",
    )

    result = _run_contract(manifest_path, release_root)

    contract = ContractResult.model_validate_json(result.stdout)
    assert result.returncode == 2
    assert "manifest-schema-invalid" in contract.failure_reasons


@pytest.mark.parametrize("schema_version", ["1", True])
def test_schema_version_requires_json_integer(tmp_path: Path, schema_version: str | bool) -> None:  # noqa: FBT001
    release_root = tmp_path / ("a" * 64)
    manifest_path = _write_manifest(release_root, schemaVersion=schema_version)

    result = _run_contract(manifest_path, release_root)

    contract = ContractResult.model_validate_json(result.stdout)
    assert result.returncode == 2
    assert "manifest-schema-invalid" in contract.failure_reasons


def test_stale_release_directory_name_is_blocked(tmp_path: Path) -> None:
    release_root = tmp_path / ("d" * 64)
    manifest_path = _write_manifest(release_root)

    result = _run_contract(manifest_path, release_root)

    contract = ContractResult.model_validate_json(result.stdout)
    assert result.returncode == 2
    assert "release-id-path-mismatch" in contract.failure_reasons


@pytest.mark.parametrize("replacement", ['"size": 11.5', '"size": "11"'])
def test_inventory_size_requires_json_integer(tmp_path: Path, replacement: str) -> None:
    release_root = tmp_path / ("a" * 64)
    manifest_path = _write_manifest(release_root)
    raw = manifest_path.read_text(encoding="utf-8")
    _ = manifest_path.write_text(raw.replace('"size": 11', replacement, 1), encoding="utf-8")

    result = _run_contract(manifest_path, release_root)

    contract = ContractResult.model_validate_json(result.stdout)
    assert result.returncode == 2
    assert "manifest-schema-invalid" in contract.failure_reasons


def test_inventory_requires_json_array(tmp_path: Path) -> None:
    release_root = tmp_path / ("a" * 64)
    manifest_path = _write_manifest(release_root)
    raw = manifest_path.read_text(encoding="utf-8")
    raw = raw.replace('"fileInventory": [', '"fileInventory": ', 1)
    raw = raw.replace('}], "baseExecutable"', '}, "baseExecutable"', 1)
    _ = manifest_path.write_text(raw, encoding="utf-8")

    result = _run_contract(manifest_path, release_root)

    contract = ContractResult.model_validate_json(result.stdout)
    assert result.returncode == 2
    assert "manifest-schema-invalid" in contract.failure_reasons


def test_oversized_manifest_is_blocked_before_json_parse(tmp_path: Path) -> None:
    release_root = tmp_path / ("a" * 64)
    release_root.mkdir()
    manifest_path = release_root / "release-manifest.json"
    _ = manifest_path.write_bytes(b"{" + (b" " * 4_194_304) + b"}")

    result = _run_contract(manifest_path, release_root)

    contract = ContractResult.model_validate_json(result.stdout)
    assert result.returncode == 2
    assert contract.failure_reasons == ("manifest-schema-invalid",)


def test_release_root_junction_is_blocked_before_manifest_read(tmp_path: Path) -> None:
    target_root = tmp_path / "target" / ("a" * 64)
    _ = _write_manifest(target_root)
    junction_root = tmp_path / "junction" / ("a" * 64)
    junction_root.parent.mkdir()
    command = f"New-Item -ItemType Junction -Path '{junction_root}' -Target '{target_root}'"
    creation = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
    )
    if creation.returncode != 0:
        pytest.fail(f"junction fixture could not be created: {creation.stderr}")

    result = _run_contract(junction_root / "release-manifest.json", junction_root)

    contract = ContractResult.model_validate_json(result.stdout)
    assert result.returncode == 2
    assert contract.failure_reasons == ("reparse-point-disallowed",)


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("releaseId", "stale", "manifest-schema-invalid"),
        ("architecture", "arm64", "manifest-schema-invalid"),
        ("serviceExecutable", "C:\\Windows\\System32\\cmd.exe", "path-outside-release"),
    ],
)
def test_manifest_semantic_failures_are_blocked(
    tmp_path: Path,
    field: str,
    value: str,
    reason: str,
) -> None:
    release_root = tmp_path / ("a" * 64)
    manifest_path = _write_manifest(release_root, **{field: value})

    result = _run_contract(manifest_path, release_root)

    assert result.stdout, result.stderr
    contract = ContractResult.model_validate_json(result.stdout)
    assert result.returncode == 2
    assert reason in contract.failure_reasons


def test_inventory_tamper_and_path_escape_are_blocked(tmp_path: Path) -> None:
    release_root = tmp_path / ("a" * 64)
    manifest_path = _write_manifest(release_root)
    raw = manifest_path.read_text(encoding="utf-8")
    _ = manifest_path.write_text(
        raw.replace('"relativePath": "python/python.exe"', '"relativePath": "../outside.exe"'),
        encoding="utf-8",
    )

    result = _run_contract(manifest_path, release_root)

    assert result.stdout, result.stderr
    contract = ContractResult.model_validate_json(result.stdout)
    assert result.returncode == 2
    assert "inventory-path-invalid" in contract.failure_reasons


def test_external_hardlink_is_blocked(tmp_path: Path) -> None:
    release_root = tmp_path / ("a" * 64)
    manifest_path = _write_manifest(release_root)
    base_executable = release_root / "python" / "python.exe"
    outside_link = tmp_path / "outside-python.exe"
    try:
        os.link(base_executable, outside_link)
    except OSError as error:
        pytest.fail(f"hardlink fixture could not be created: {error}")

    result = _run_contract(manifest_path, release_root)

    contract = ContractResult.model_validate_json(result.stdout)
    assert result.returncode == 2
    assert "hardlink-disallowed" in contract.failure_reasons


def test_unlisted_importable_file_is_blocked(tmp_path: Path) -> None:
    release_root = tmp_path / ("a" * 64)
    manifest_path = _write_manifest(release_root)
    extra = release_root / "venv" / "Lib" / "site-packages" / "hostile.pth"
    extra.parent.mkdir(parents=True)
    _ = extra.write_text("import hostile\n", encoding="utf-8")

    result = _run_contract(manifest_path, release_root)

    contract = ContractResult.model_validate_json(result.stdout)
    assert result.returncode == 2
    assert "inventory-extra-file" in contract.failure_reasons


def test_real_user_owned_release_fixture_is_blocked(tmp_path: Path) -> None:
    release_root = tmp_path / ("a" * 64)
    manifest_path = _write_manifest(release_root)

    result = _run_contract(manifest_path, release_root)

    contract = ContractResult.model_validate_json(result.stdout)
    assert result.returncode == 2
    assert not contract.verified
    assert "acl-owner-untrusted" in contract.failure_reasons
    assert "runtime-contract-unverified" not in contract.failure_reasons
    assert contract.state == "blocked"
    assert not contract.authorization_reusable


def test_validator_source_has_no_process_or_mutation_commands() -> None:
    source = SCRIPT_PATH.read_text(encoding="utf-8")

    assert "Start-Process" not in source
    assert "Invoke-WebRequest" not in source
    assert "Set-Acl" not in source
    assert "New-Service" not in source
    assert "Start-Service" not in source


def test_synthetic_protected_acl_policy_accepts_only_admin_system_write() -> None:
    command = """
. $env:HERMES_TEST_SCRIPT -LibraryMode
$trusted = [Security.AccessControl.DirectorySecurity]::new()
$trusted.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;LS)')
$untrusted = [Security.AccessControl.DirectorySecurity]::new()
$untrusted.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;AU)')
[pscustomobject]@{
    trusted = Test-BridgeProtectedAclDescriptor -Acl $trusted
    untrusted = Test-BridgeProtectedAclDescriptor -Acl $untrusted
} | ConvertTo-Json -Compress
"""
    environment = os.environ.copy()
    environment["HERMES_TEST_SCRIPT"] = str(SCRIPT_PATH)

    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"trusted": True, "untrusted": False}


def test_synthetic_acl_rejects_untrusted_owner_and_inheritable_write() -> None:
    command = """
. $env:HERMES_TEST_SCRIPT -LibraryMode
$owner = [Security.AccessControl.DirectorySecurity]::new()
$owner.SetSecurityDescriptorSddlForm('O:AUG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
$inheritOnly = [Security.AccessControl.DirectorySecurity]::new()
$inheritOnly.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;GW;;;AU)')
[pscustomobject]@{
    owner = Test-BridgeProtectedAclDescriptor -Acl $owner
    inheritOnly = Test-BridgeProtectedAclDescriptor -Acl $inheritOnly
} | ConvertTo-Json -Compress
"""
    environment = os.environ.copy()
    environment["HERMES_TEST_SCRIPT"] = str(SCRIPT_PATH)

    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"owner": False, "inheritOnly": False}


def test_ancestor_owner_policy_rejects_user_and_fake_trustedinstaller_paths() -> None:
    command = r"""
. $env:HERMES_TEST_SCRIPT -LibraryMode
$trustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$canonicalProgramFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$env:ProgramFiles = 'C:\hostile'
[pscustomobject]@{
    administrator = Test-BridgeOwnerTrustedForPath -Path 'C:\hostile' -OwnerSid 'S-1-5-32-544'
    user = Test-BridgeOwnerTrustedForPath -Path 'C:\hostile' -OwnerSid 'S-1-5-21-1-2-3-1001'
    fakeTrustedInstaller = Test-BridgeOwnerTrustedForPath `
        -Path 'C:\hostile' -OwnerSid $trustedInstaller
    canonicalTrustedInstaller = Test-BridgeOwnerTrustedForPath `
        -Path $canonicalProgramFiles -OwnerSid $trustedInstaller
} | ConvertTo-Json -Compress
"""
    environment = os.environ.copy()
    environment["HERMES_TEST_SCRIPT"] = str(SCRIPT_PATH)

    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "administrator": True,
        "user": False,
        "fakeTrustedInstaller": False,
        "canonicalTrustedInstaller": True,
    }


def test_production_validator_rejects_user_owned_ancestor(tmp_path: Path) -> None:
    release_root = tmp_path / ("a" * 64)
    manifest_path = _write_manifest(release_root)
    command = """
. $env:HERMES_TEST_SCRIPT -LibraryMode
$trusted = [Security.AccessControl.DirectorySecurity]::new()
$trusted.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;LS)')
$userOwned = [Security.AccessControl.DirectorySecurity]::new()
$userOwned.SetSecurityDescriptorSddlForm('O:AUG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;LS)')
function Get-BridgePathAcl {
    param([string]$Path)
    if ([IO.Path]::GetFullPath($Path).Equals(
        $env:HERMES_TEST_PARENT,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        return $userOwned
    }
    return $trusted
}
Get-BridgeServiceRuntimeContract `
    -ManifestPath $env:HERMES_TEST_MANIFEST -ReleaseRoot $env:HERMES_TEST_ROOT |
    ConvertTo-Json -Depth 8 -Compress
"""
    environment = os.environ.copy()
    environment["HERMES_TEST_SCRIPT"] = str(SCRIPT_PATH)
    environment["HERMES_TEST_MANIFEST"] = str(manifest_path)
    environment["HERMES_TEST_ROOT"] = str(release_root)
    environment["HERMES_TEST_PARENT"] = str(release_root.parent)

    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )

    contract = ContractResult.model_validate_json(result.stdout)
    assert result.returncode == 0, result.stderr
    assert not contract.verified
    assert "acl-owner-untrusted" in contract.failure_reasons


def test_real_canonical_os_ancestor_acl_has_no_replacement_rights() -> None:
    command = r"""
. $env:HERMES_TEST_SCRIPT -LibraryMode
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
$paths = @(
    $programFiles, $windows, (Join-Path $windows 'System32'),
    (Join-Path $windows 'WinSxS'), [IO.Path]::GetPathRoot($programFiles)
) | Select-Object -Unique
$results = foreach ($path in $paths) {
    $acl = Get-BridgePathAcl -Path $path
    [pscustomobject]@{
        path = $path
        ownerTrusted = Test-BridgeOwnerTrustedForPath `
            -Path $path -OwnerSid (Get-BridgeSidValue $acl.Owner)
            writeTrusted = Test-BridgeAncestorAclHasNoUntrustedReplacement -Acl $acl -Path $path
    }
}
$results | ConvertTo-Json -Depth 4 -Compress
"""
    environment = os.environ.copy()
    environment["HERMES_TEST_SCRIPT"] = str(SCRIPT_PATH)

    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert result.returncode == 0, result.stderr
    rows = TypeAdapter(list[OsAclRow]).validate_json(result.stdout)
    assert len(rows) >= 5
    assert all(row.owner_trusted for row in rows)
    assert all(row.write_trusted for row in rows)


def test_trustedinstaller_writer_exception_does_not_escape_canonical_path() -> None:
    command = r"""
. $env:HERMES_TEST_SCRIPT -LibraryMode
$trustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetSecurityDescriptorSddlForm("O:BAG:BAD:P(A;;GA;;;$trustedInstaller)")
$hostile = [Security.AccessControl.DirectorySecurity]::new()
$hostile.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;GA;;;AU)')
[pscustomobject]@{
    arbitrary = Test-BridgeAncestorAclHasNoUntrustedReplacement `
        -Acl $acl -Path 'C:\hostile'
    canonicalTi = Test-BridgeAncestorAclHasNoUntrustedReplacement `
        -Acl $acl -Path $programFiles
    canonicalAu = Test-BridgeAncestorAclHasNoUntrustedReplacement `
        -Acl $hostile -Path $programFiles
} | ConvertTo-Json -Compress
"""
    environment = os.environ.copy()
    environment["HERMES_TEST_SCRIPT"] = str(SCRIPT_PATH)

    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "arbitrary": False,
        "canonicalTi": True,
        "canonicalAu": False,
    }


def test_canonical_volume_root_excludes_only_self_delete_from_replacement() -> None:
    command = r"""
. $env:HERMES_TEST_SCRIPT -LibraryMode
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$volumeRoot = [IO.Path]::GetPathRoot($programFiles)
function Test-Rule([string]$sddl, [string]$path) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm($sddl)
    Test-BridgeAncestorAclHasNoUntrustedReplacement -Acl $acl -Path $path
}
[pscustomobject]@{
    observedRoot = Test-Rule 'O:SYG:SYD:P(A;;0x1301bf;;;AU)' $volumeRoot
    rootDeleteChild = Test-Rule 'O:SYG:SYD:P(A;;0x40;;;AU)' $volumeRoot
    rootWriteDac = Test-Rule 'O:SYG:SYD:P(A;;0x40000;;;AU)' $volumeRoot
    rootWriteOwner = Test-Rule 'O:SYG:SYD:P(A;;0x80000;;;AU)' $volumeRoot
    rootGenericAll = Test-Rule 'O:SYG:SYD:P(A;;GA;;;AU)' $volumeRoot
    rootGenericWrite = Test-Rule 'O:SYG:SYD:P(A;;GW;;;AU)' $volumeRoot
    nonRootDelete = Test-Rule 'O:SYG:SYD:P(A;;SD;;;AU)' $programFiles
    arbitraryDelete = Test-Rule 'O:SYG:SYD:P(A;;SD;;;AU)' 'C:\hostile'
} | ConvertTo-Json -Compress
"""
    environment = os.environ.copy()
    environment["HERMES_TEST_SCRIPT"] = str(SCRIPT_PATH)

    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "observedRoot": True,
        "rootDeleteChild": False,
        "rootWriteDac": False,
        "rootWriteOwner": False,
        "rootGenericAll": False,
        "rootGenericWrite": False,
        "nonRootDelete": False,
        "arbitraryDelete": False,
    }


def test_null_dacl_is_rejected_but_empty_protected_dacl_is_not_writeable() -> None:
    command = r"""
. $env:HERMES_TEST_SCRIPT -LibraryMode
$nullDacl = [Security.AccessControl.DirectorySecurity]::new()
$nullDacl.SetSecurityDescriptorSddlForm('O:BAD:NO_ACCESS_CONTROL')
$emptyDacl = [Security.AccessControl.DirectorySecurity]::new()
$emptyDacl.SetSecurityDescriptorSddlForm('O:BAD:P')
[pscustomobject]@{
    nullDacl = Test-BridgeAclHasNoUntrustedWrite -Acl $nullDacl
    emptyDacl = Test-BridgeAclHasNoUntrustedWrite -Acl $emptyDacl
} | ConvertTo-Json -Compress
"""
    environment = os.environ.copy()
    environment["HERMES_TEST_SCRIPT"] = str(SCRIPT_PATH)

    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"nullDacl": False, "emptyDacl": True}
