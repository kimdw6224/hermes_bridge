"""Protected service runtime build-plan and closure contract tests."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import ClassVar, Final

import pytest
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

PROJECT_ROOT: Final = Path(__file__).parents[2]
SCRIPT_PATH: Final = PROJECT_ROOT / "scripts" / "service-runtime.ps1"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
PWSH_PATH: Final = shutil.which("pwsh.exe")
UV_PATH: Final = shutil.which("uv.exe")
TASKLIST_PATH: Final = Path("C:/Windows/System32/tasklist.exe")
assert POWERSHELL_PATH is not None
assert PWSH_PATH is not None
assert UV_PATH is not None


def _uv_version() -> str:
    result = subprocess.run(
        [UV_PATH, "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    match = re.fullmatch(r"uv (?P<version>\d+\.\d+\.\d+)(?:\s.*)?", result.stdout.strip())
    assert match is not None, result.stdout
    return match.group("version")


UV_VERSION: Final = _uv_version()


class BuildPlan(BaseModel):
    """Typed task2 dry-run receipt."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    state: str
    applied: bool
    closure_verified: bool = Field(alias="closureVerified")
    failure_reasons: tuple[str, ...] = Field(alias="failureReasons")
    commands: tuple[tuple[str, ...], ...]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run_library(expression: str) -> subprocess.CompletedProcess[str]:
    command = f". '{SCRIPT_PATH}' -LibraryMode; {expression}"
    return subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _make_source(root: Path) -> None:
    (root / "src" / "package").mkdir(parents=True)
    (root / "scripts").mkdir()
    _ = (root / "src" / "package" / "main.py").write_text("VALUE = 1\n", encoding="utf-8")
    _ = (root / "scripts" / "install.ps1").write_text("$true\n", encoding="utf-8")
    _ = (root / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
    _ = (root / "uv.lock").write_text("version = 1\n", encoding="utf-8")


def test_source_digest_is_stable_and_changes_with_source(tmp_path: Path) -> None:
    _make_source(tmp_path)
    expression = (
        f"Get-BridgeSourceSnapshotDigest -SourceRoot '{tmp_path}' -UvVersion '{UV_VERSION}'"
    )
    first = _run_library(expression)
    second = _run_library(expression)
    assert first.returncode == 0, first.stderr
    assert first.stdout.strip() == second.stdout.strip()
    _ = (tmp_path / "src" / "package" / "main.py").write_text("VALUE = 2\n", encoding="utf-8")
    changed = _run_library(expression)
    assert changed.stdout.strip() != first.stdout.strip()


def test_source_digest_uses_same_ordinal_order_across_powershell_runtimes(
    tmp_path: Path,
) -> None:
    _make_source(tmp_path)
    _ = (tmp_path / "scripts" / "service-runtime.ps1").write_text(
        "$true\n", encoding="utf-8"
    )
    _ = (tmp_path / "scripts" / "service-runtime-build-common.ps1").write_text(
        "$true\n", encoding="utf-8"
    )
    _ = (tmp_path / "scripts" / "서비스.ps1").write_text("$true\n", encoding="utf-8")
    expression = (
        "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); "
        f". '{SCRIPT_PATH}' -LibraryMode; "
        f"$inventory=@(Get-BridgeBuildFileInventory -SourceRoot '{tmp_path}'); "
        "[pscustomobject]@{"
        "digest=(Get-BridgeSourceSnapshotDigest -SourceRoot '"
        f"{tmp_path}' -UvVersion '{UV_VERSION}'); "
        "paths=@($inventory.relativePath)} | ConvertTo-Json -Compress"
    )

    windows_powershell = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", expression],
        check=False,
        capture_output=True,
        text=False,
        timeout=30,
    )
    powershell = subprocess.run(
        [PWSH_PATH, "-NoProfile", "-NonInteractive", "-Command", expression],
        check=False,
        capture_output=True,
        text=False,
        timeout=30,
    )

    assert windows_powershell.returncode == 0, windows_powershell.stderr
    assert powershell.returncode == 0, powershell.stderr
    windows_receipt = TypeAdapter(dict[str, str | list[str]]).validate_json(
        windows_powershell.stdout
    )
    powershell_receipt = TypeAdapter(dict[str, str | list[str]]).validate_json(
        powershell.stdout
    )
    assert windows_receipt == powershell_receipt
    assert windows_receipt["paths"] == [
        "pyproject.toml",
        "scripts/install.ps1",
        "scripts/service-runtime-build-common.ps1",
        "scripts/service-runtime.ps1",
        "scripts/서비스.ps1",
        "src/package/main.py",
        "uv.lock",
    ]


def test_source_digest_excludes_python_cache(tmp_path: Path) -> None:
    _make_source(tmp_path)
    expression = (
        f"Get-BridgeSourceSnapshotDigest -SourceRoot '{tmp_path}' -UvVersion '{UV_VERSION}'"
    )
    before = _run_library(expression).stdout.strip()
    cache = tmp_path / "src" / "package" / "__pycache__"
    cache.mkdir()
    _ = (cache / "main.pyc").write_bytes(b"ignored")
    assert _run_library(expression).stdout.strip() == before


def test_dry_run_plan_has_pinned_noneditable_copy_commands(tmp_path: Path) -> None:
    _make_source(tmp_path)
    source_digest = _run_library(
        f"Get-BridgeSourceSnapshotDigest -SourceRoot '{tmp_path}' -UvVersion '{UV_VERSION}'"
    ).stdout.strip()
    lock_digest = _sha256(tmp_path / "uv.lock")
    command = [
        POWERSHELL_PATH,
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(SCRIPT_PATH),
        "-BuildRelease",
        "-SourceRoot",
        str(tmp_path),
        "-ProgramRoot",
        str(tmp_path / "program"),
        "-TrustedUvPath",
        UV_PATH,
        "-ExpectedUvSha256",
        _sha256(Path(UV_PATH)),
        "-ExpectedSourceDigest",
        source_digest,
        "-ExpectedLockDigest",
        lock_digest,
        "-Json",
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    receipt = BuildPlan.model_validate_json(result.stdout)
    assert receipt.state == "planned"
    assert receipt.applied is False
    assert receipt.closure_verified is False
    flattened = [argument for argv in receipt.commands for argument in argv]
    assert [
        item for item in flattened if item in {"3.14.3", "--no-bin", "--no-registry"}
    ] == ["3.14.3", "--no-bin", "--no-registry"]
    assert "--no-editable" in flattened
    assert "--require-hashes" in flattened
    assert flattened.count("copy") == 2
    export_command = next(command for command in receipt.commands if command[0] == "export")
    assert "--frozen" in export_command
    assert "--no-emit-project" in export_command
    assert "--no-sources" not in export_command
    assert not (tmp_path / "program").exists()


@pytest.mark.parametrize("digest_name", ["source", "lock"])
def test_plan_blocks_digest_mismatch(tmp_path: Path, digest_name: str) -> None:
    _make_source(tmp_path)
    source_digest = _run_library(
        f"Get-BridgeSourceSnapshotDigest -SourceRoot '{tmp_path}' -UvVersion '{UV_VERSION}'"
    ).stdout.strip()
    lock_digest = _sha256(tmp_path / "uv.lock")
    if digest_name == "source":
        source_digest = "0" * 64
    else:
        lock_digest = "0" * 64
    expression = (
        f"Get-BridgeReleaseBuildPlan -SourceRoot '{tmp_path}' -ProgramRoot '{tmp_path / 'p'}' "
        f"-TrustedUvPath '{UV_PATH}' -ExpectedUvSha256 '{_sha256(Path(UV_PATH))}' "
        f"-ExpectedSourceDigest '{source_digest}' -ExpectedLockDigest '{lock_digest}' "
        "-TimeoutSeconds 60 | ConvertTo-Json -Depth 10 -Compress"
    )
    result = _run_library(expression)
    receipt = BuildPlan.model_validate_json(result.stdout)
    assert receipt.state == "blocked"
    assert f"{digest_name}-digest-mismatch" in receipt.failure_reasons


def test_uv_binary_hash_mismatch_fails_closed(tmp_path: Path) -> None:
    _make_source(tmp_path)
    result = _run_library(
        f"Get-BridgeUvIdentity -TrustedUvPath '{UV_PATH}' -ExpectedUvSha256 '{'0' * 64}'"
    )
    assert result.returncode != 0
    assert "BridgeRuntimeUvIdentityMismatch" in result.stderr


def test_pth_rejects_editable_and_external_path(tmp_path: Path) -> None:
    site_packages = tmp_path / "venv" / "Lib" / "site-packages"
    site_packages.mkdir(parents=True)
    editable = site_packages / "_editable_fixture.pth"
    _ = editable.write_text("import editable_hook\n", encoding="utf-8")
    empty_provenance = "([pscustomobject]@{pthArtifacts=@()})"
    result = _run_library(
        f"Test-BridgePthClosure -ReleaseRoot '{tmp_path}' -Provenance {empty_provenance}"
    )
    assert result.stdout.strip() == "False"
    editable.unlink()
    _ = (site_packages / "external.pth").write_text("C:\\Users\\DW\\project\n", encoding="utf-8")
    result = _run_library(
        f"Test-BridgePthClosure -ReleaseRoot '{tmp_path}' -Provenance {empty_provenance}"
    )
    assert result.stdout.strip() == "False"


def test_pth_accepts_hash_pinned_uv_venv_artifacts(tmp_path: Path) -> None:
    site_packages = tmp_path / "venv" / "Lib" / "site-packages"
    site_packages.mkdir(parents=True)
    virtualenv = site_packages / "_virtualenv.pth"
    _ = virtualenv.write_text("import _virtualenv\n", encoding="utf-8")
    config = tmp_path / "venv" / "pyvenv.cfg"
    _ = config.write_text(
        "home = C:\\protected\\python\ninclude-system-site-packages = false\n",
        encoding="utf-8",
    )
    artifacts = (
        "@([pscustomobject]@{relativePath='venv/Lib/site-packages/_virtualenv.pth';"
        f"sha256='{_sha256(virtualenv)}';producer='uv-venv'}},"
        "[pscustomobject]@{relativePath='venv/pyvenv.cfg';"
        f"sha256='{_sha256(config)}';producer='uv-venv'}})"
    )
    expression = " ".join(
        (
            f"Test-BridgePthClosure -ReleaseRoot '{tmp_path}'",
            f"-Provenance ([pscustomobject]@{{pthArtifacts={artifacts}}})",
        )
    )
    result = _run_library(expression)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "True"


def test_pth_scan_ignores_non_configuration_release_files(tmp_path: Path) -> None:
    site_packages = tmp_path / "venv" / "Lib" / "site-packages"
    site_packages.mkdir(parents=True)
    _ = (site_packages / "module.py").write_text("VALUE = 1\n", encoding="utf-8")

    expression = " ".join(
        (
            f"Test-BridgePthClosure -ReleaseRoot '{tmp_path}'",
            "-Provenance ([pscustomobject]@{pthArtifacts=@()})",
        )
    )
    result = _run_library(expression)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "True"


def test_build_provenance_requires_strict_schema_two_and_archive_digest() -> None:
    result = _run_library(
        "Test-BridgeBuildProvenance -Provenance ([pscustomobject]@{schemaVersion=2})"
    )
    assert result.stdout.strip() == "False"


def test_python_archive_requires_pinned_actual_bytes(tmp_path: Path) -> None:
    archive = tmp_path / "python.tar.gz"
    _ = archive.write_bytes(b"not-the-pinned-archive")
    result = _run_library(
        f"Test-BridgePythonArchive -Path '{archive}' -ProtectedRoot '{tmp_path}'"
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"


def test_windows_powershell_loads_http_types_for_download_adapter() -> None:
    handler_type = "System.Net.Http.HttpClientHandler"
    client_type = "System.Net.Http.HttpClient"
    expression = "".join(
        (
            f"[pscustomobject]@{{handler=($null -ne ('{handler_type}' -as [type]));",
            f"client=($null -ne ('{client_type}' -as [type]))}} ",
            "| ConvertTo-Json -Compress",
        )
    )
    result = _run_library(expression)
    assert result.returncode == 0, result.stderr
    receipt = TypeAdapter(dict[str, bool]).validate_json(result.stdout)
    assert receipt == {"handler": True, "client": True}


def test_windows_powershell_resolves_build_error_types() -> None:
    invalid_data_type = "System.IO.InvalidDataException"
    expression = "".join(
        (
            f"[pscustomobject]@{{invalidData=($null -ne ('{invalid_data_type}' -as [type]))}} ",
            "| ConvertTo-Json -Compress",
        )
    )
    result = _run_library(expression)
    assert result.returncode == 0, result.stderr
    assert TypeAdapter(dict[str, bool]).validate_json(result.stdout) == {
        "invalidData": True
    }


def test_uv_managed_python_metadata_is_removed_only_for_observed_safe_layout(
    tmp_path: Path,
) -> None:
    managed_root = tmp_path / "managed-python"
    (managed_root / ".temp").mkdir(parents=True)
    payload = managed_root / "cpython-3.14.3-windows-x86_64-none"
    payload.mkdir()
    alias = managed_root / "cpython-3.14-windows-x86_64-none"
    creation = subprocess.run(
        [str(Path(os.environ["COMSPEC"])), "/c", "mklink", "/J", str(alias), str(payload)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert creation.returncode == 0, creation.stderr
    moved_payload = tmp_path / "python"
    _ = payload.rename(moved_payload)
    _ = (managed_root / ".gitignore").write_bytes(b"*")
    _ = (managed_root / ".lock").write_bytes(b"")

    result = _run_library(
        "".join(
            (
                f"Remove-BridgeManagedPythonMetadata -ManagedRoot '{managed_root}'; ",
                f"Test-Path -LiteralPath '{managed_root}'",
            )
        )
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"
    assert moved_payload.is_dir()


@pytest.mark.parametrize(
    ("relative_path", "content"),
    [
        ("unexpected.exe", b"payload"),
        (".gitignore", b"not-empty"),
        ("cpython-3.14-windows-x86_64-none/unexpected.txt", b"payload"),
    ],
)
def test_uv_managed_python_metadata_rejects_unexpected_residue(
    tmp_path: Path,
    relative_path: str,
    content: bytes,
) -> None:
    managed_root = tmp_path / "managed-python"
    managed_root.mkdir()
    residue = managed_root / relative_path
    residue.parent.mkdir(parents=True, exist_ok=True)
    _ = residue.write_bytes(content)

    result = _run_library(
        f"Remove-BridgeManagedPythonMetadata -ManagedRoot '{managed_root}'"
    )

    assert result.returncode != 0
    assert "BridgeRuntimePythonLayoutUnverified" in result.stderr


def test_uv_managed_python_metadata_rejects_reparse_directory(tmp_path: Path) -> None:
    managed_root = tmp_path / "managed-python"
    outside = tmp_path / "outside"
    managed_root.mkdir()
    outside.mkdir()
    creation = subprocess.run(
        [
            str(Path(os.environ["COMSPEC"])),
            "/c",
            "mklink",
            "/J",
            str(managed_root / ".temp"),
            str(outside),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert creation.returncode == 0, creation.stderr
    (managed_root / "cpython-3.14-windows-x86_64-none").mkdir()
    _ = (managed_root / ".gitignore").write_bytes(b"\n")
    _ = (managed_root / ".lock").write_bytes(b"")

    result = _run_library(
        f"Remove-BridgeManagedPythonMetadata -ManagedRoot '{managed_root}'"
    )

    assert result.returncode != 0
    assert "BridgeRuntimePythonLayoutUnverified" in result.stderr


def test_uv_managed_python_metadata_rejects_alias_to_external_target(
    tmp_path: Path,
) -> None:
    managed_root = tmp_path / "managed-python"
    outside = tmp_path / "outside"
    managed_root.mkdir()
    outside.mkdir()
    alias = managed_root / "cpython-3.14-windows-x86_64-none"
    creation = subprocess.run(
        [str(Path(os.environ["COMSPEC"])), "/c", "mklink", "/J", str(alias), str(outside)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert creation.returncode == 0, creation.stderr
    (managed_root / ".temp").mkdir()
    _ = (managed_root / ".gitignore").write_bytes(b"*")
    _ = (managed_root / ".lock").write_bytes(b"")

    result = _run_library(
        f"Remove-BridgeManagedPythonMetadata -ManagedRoot '{managed_root}'"
    )

    assert result.returncode != 0
    assert "BridgeRuntimePythonLayoutUnverified" in result.stderr
    assert outside.is_dir()


def test_uv_managed_python_payload_requires_exact_install_path(tmp_path: Path) -> None:
    managed_root = tmp_path / "managed-python"
    expected = managed_root / "cpython-3.14.3-windows-x86_64-none"
    expected.mkdir(parents=True)
    python = expected / "python.exe"
    _ = python.write_bytes(b"fixture")
    accepted = _run_library(
        f"Get-BridgeManagedPythonPayload -ManagedRoot '{managed_root}'"
    )
    assert accepted.returncode == 0, accepted.stderr
    assert Path(accepted.stdout.strip()) == expected

    unexpected_root = tmp_path / "unexpected-managed"
    unexpected = unexpected_root / "unexpected"
    unexpected.mkdir(parents=True)
    _ = (unexpected / "python.exe").write_bytes(b"fixture")
    rejected = _run_library(
        f"Get-BridgeManagedPythonPayload -ManagedRoot '{unexpected_root}'"
    )
    assert rejected.returncode != 0
    assert "BridgeRuntimePythonLayoutUnverified" in rejected.stderr


def test_child_environment_drops_inherited_python_uv_and_pip_overrides(tmp_path: Path) -> None:
    expression = (
        f"$env:PYTHONPATH='unsafe'; $env:UV_INDEX='unsafe'; $env:PIP_INDEX_URL='unsafe'; "
        f"Get-BridgeBuildEnvironment -ProtectedRoot '{tmp_path}' | ConvertTo-Json -Compress"
    )
    result = _run_library(expression)
    assert result.returncode == 0, result.stderr
    environment = TypeAdapter(dict[str, str]).validate_json(result.stdout)
    assert "PYTHONPATH" not in environment
    assert "UV_INDEX" not in environment
    assert "PIP_INDEX_URL" not in environment
    assert environment["PYTHONNOUSERSITE"] == "1"
    assert environment["UV_NO_CONFIG"] == "1"


def test_bounded_process_captures_exit_and_times_out(tmp_path: Path) -> None:
    environment = f"Get-BridgeBuildEnvironment -ProtectedRoot '{tmp_path}'"
    success = _run_library(
        " ".join(
            (
                f"$e={environment}; Invoke-BridgeBoundedProcess -FilePath '{POWERSHELL_PATH}'",
                f"-Arguments @('-NoProfile','-Command','exit 7') -WorkingDirectory '{tmp_path}'",
                "-Environment $e -TimeoutSeconds 5 | ConvertTo-Json -Compress",
            )
        )
    )
    assert success.returncode == 0, success.stderr
    process_result = TypeAdapter(dict[str, str | int]).validate_json(success.stdout)
    assert process_result["exitCode"] == 7
    timeout = _run_library(
        " ".join(
            (
                f"$e={environment}; Invoke-BridgeBoundedProcess -FilePath '{POWERSHELL_PATH}'",
                "-Arguments @('-NoProfile','-Command','Start-Sleep -Seconds 3')",
                f"-WorkingDirectory '{tmp_path}' -Environment $e -TimeoutSeconds 1",
            )
        )
    )
    assert timeout.returncode != 0
    assert "BridgeRuntimeChildTimeout" in timeout.stderr


def test_bounded_process_supplies_real_stdin_eof_handle(tmp_path: Path) -> None:
    environment = f"Get-BridgeBuildEnvironment -ProtectedRoot '{tmp_path}'"
    expression = " ".join(
        (
            f"$e={environment}; Invoke-BridgeBoundedProcess -FilePath '{POWERSHELL_PATH}'",
            "-Arguments @('-NoProfile','-Command',",
            "'$v=[Console]::In.ReadToEnd();[Console]::Out.Write(\"eof:{0}\",$v.Length)')",
            f"-WorkingDirectory '{tmp_path}' -Environment $e -TimeoutSeconds 5",
            "| ConvertTo-Json -Compress",
        )
    )
    result = _run_library(expression)
    assert result.returncode == 0, result.stderr
    process_result = TypeAdapter(dict[str, str | int]).validate_json(result.stdout)
    assert process_result["exitCode"] == 0
    assert process_result["stdout"] == "eof:0"


def test_bounded_process_rejects_newline_free_output(tmp_path: Path) -> None:
    expression = " ".join(
        (
            f"$e=Get-BridgeBuildEnvironment -ProtectedRoot '{tmp_path}';",
            f"Invoke-BridgeBoundedProcess -FilePath '{POWERSHELL_PATH}'",
            "-Arguments @('-NoProfile','-Command','$x=\"x\"*1100000;[Console]::Out.Write($x)')",
            f"-WorkingDirectory '{tmp_path}' -Environment $e -TimeoutSeconds 10",
        )
    )
    result = _run_library(expression)
    assert result.returncode != 0
    assert "BridgeRuntimeChildOutputTooLarge" in result.stderr


def test_bounded_process_timeout_removes_descendant(tmp_path: Path) -> None:
    marker = tmp_path / "descendant.txt"
    pid_file = tmp_path / "descendant-pid.txt"
    child_script = tmp_path / "child.ps1"
    parent_script = tmp_path / "parent.ps1"
    _ = child_script.write_text(
        f"Start-Sleep -Seconds 4\nSet-Content -LiteralPath '{marker}' -Value alive\n",
        encoding="utf-8",
    )
    _ = parent_script.write_text(
        (
            f"$p=Start-Process '{POWERSHELL_PATH}' -WindowStyle Hidden -PassThru "
            f"-ArgumentList @('-NoProfile','-File','{child_script}')\n"
            f"Set-Content -LiteralPath '{pid_file}' -Value $p.Id\n"
            "Start-Sleep -Seconds 20\n"
        ),
        encoding="utf-8",
    )
    expression = " ".join(
        (
            f"$e=Get-BridgeBuildEnvironment -ProtectedRoot '{tmp_path}';",
            f"Invoke-BridgeBoundedProcess -FilePath '{POWERSHELL_PATH}'",
            f"-Arguments @('-NoProfile','-File','{parent_script}')",
            f"-WorkingDirectory '{tmp_path}' -Environment $e -TimeoutSeconds 1",
        )
    )
    result = _run_library(expression)
    assert result.returncode != 0
    time.sleep(5)
    assert not marker.exists()
    descendant_pid = int(pid_file.read_text(encoding="utf-8").strip())
    pid_probe = subprocess.run(
        [str(TASKLIST_PATH), "/FI", f"PID eq {descendant_pid}", "/FO", "CSV", "/NH"],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert str(descendant_pid) not in pid_probe.stdout
