"""Evaluation VM용 deterministic Task 6 input bundle 준비 계약을 검증합니다."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Final, TypedDict

from pydantic import BaseModel, ConfigDict, Field

PROJECT_ROOT: Final = Path(__file__).resolve().parents[2]
SCRIPT_PATH: Final = (
    PROJECT_ROOT
    / ".omo"
    / "evidence"
    / "service-protection-eval-vm-20260908"
    / "lifecycle"
    / "prepare-eval-bundle.ps1"
)
CANONICAL_ROOT: Final = (
    PROJECT_ROOT / ".omo" / "evidence" / "service-protection-6-sandbox"
)
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None
CMD_PATH: Final = Path(os.environ["SYSTEMROOT"]) / "System32" / "cmd.exe"
REQUIRED_SCRIPTS: Final = (
    "doctor.ps1",
    "install.ps1",
    "lifecycle-common.ps1",
    "register-gateway-service.ps1",
    "register-privileged-service.ps1",
    "register-worker-task.ps1",
    "service-object-security.ps1",
    "service-runtime-build-common.ps1",
    "service-runtime-build.ps1",
    "service-runtime-closure.ps1",
    "service-runtime-process.ps1",
    "service-runtime-transaction.ps1",
    "service-runtime.ps1",
    "uninstall.ps1",
)


class InventoryEntry(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    relative_path: str = Field(alias="relativePath")
    sha256: str
    size: int


class PreparationResult(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    state: str
    bundle_root: str = Field(alias="bundleRoot")
    input_inventory_sha256: str = Field(alias="inputInventorySha256")
    files: tuple[InventoryEntry, ...]
    binding_sha256: str | None = Field(default=None, alias="bindingSha256")


class Binding(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    schema_version: int = Field(alias="schemaVersion")
    nonce: str
    deadline_utc: str = Field(alias="deadlineUtc")
    product_hashes: dict[str, str] = Field(alias="productHashes")
    uv_sha256: str = Field(alias="uvSha256")
    source_inventory_sha256: str = Field(alias="sourceInventorySha256")
    input_inventory_sha256: str = Field(alias="inputInventorySha256")
    input_files: tuple[InventoryEntry, ...] = Field(alias="inputFiles")


class SourceEntry(TypedDict):
    relativePath: str
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class FixturePaths:
    source: Path
    lifecycle: Path
    expected: Path
    uv: Path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_fixture(root: Path) -> FixturePaths:
    source = root / "source"
    for relative, content in {
        "src/hermes_windows_bridge/__init__.py": "VALUE = 1\n",
        "src/hermes_windows_bridge/__pycache__/ignored.pyc": "cache",
        "src/hermes_windows_bridge/nested/.env": "SECRET=forbidden\n",
        "src/hermes_windows_bridge/nested/notes.txt": "not-runtime-source\n",
        "scripts/extra.ps1": "'extra'\n",
        "config/config.example.yaml": "port: 1\n",
        "config/policy.example.yaml": "rules: []\n",
        "pyproject.toml": "[project]\nname='fixture'\n",
        "uv.lock": "version = 1\n",
        ".python-version": "3.14.3\n",
        ".env": "SECRET=forbidden\n",
    }.items():
        path = source / relative
        _ = path.parent.mkdir(parents=True, exist_ok=True)
        _ = path.write_text(content, encoding="utf-8")
    for name in REQUIRED_SCRIPTS:
        _ = (source / "scripts" / name).write_text(f"'{name}'\n", encoding="utf-8")
    canonical = source / ".omo" / "evidence" / "service-protection-6-sandbox"
    _ = canonical.mkdir(parents=True)
    for name in ("task6-guest-preflight.ps1", "task6-guest-lifecycle-v2.ps1"):
        _ = shutil.copyfile(CANONICAL_ROOT / name, canonical / name)
    uv = root / "trusted" / "uv.exe"
    _ = uv.parent.mkdir()
    _ = uv.write_bytes(b"fixture-uv")
    expected_files: list[SourceEntry] = []
    for path in sorted(source.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(source).as_posix()
        approved = (
            path.is_file()
            and (
                (
                    relative.startswith("src/")
                    and "__pycache__" not in relative
                    and path.suffix == ".py"
                )
                or relative in {f"scripts/{name}" for name in REQUIRED_SCRIPTS}
                or relative in {
                    "config/config.example.yaml",
                    "config/policy.example.yaml",
                    "pyproject.toml",
                    "uv.lock",
                    ".python-version",
                }
            )
        )
        if approved:
            expected_files.append(
                {"relativePath": relative, "sha256": _sha256(path), "size": path.stat().st_size}
            )
    expected = root / "expected-source-inputs.json"
    _ = expected.write_text(
        json.dumps(
            {"schemaVersion": 1, "sourceRoot": str(source.resolve()), "files": expected_files},
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    lifecycle = root / "lifecycle"
    _ = lifecycle.mkdir()
    _ = shutil.copyfile(SCRIPT_PATH, lifecycle / SCRIPT_PATH.name)
    _ = (lifecycle / "bundles").mkdir()
    return FixturePaths(source=source, lifecycle=lifecycle, expected=expected, uv=uv)


def _run(
    paths: FixturePaths, nonce: uuid.UUID, *, mode: str = "Plan"
) -> subprocess.CompletedProcess[str]:
    child_environment = os.environ.copy()
    child_environment["PSModulePath"] = (
        r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
    )
    return subprocess.run(
        [
            POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(paths.lifecycle / SCRIPT_PATH.name),
            "-Mode",
            mode,
            "-Nonce",
            str(nonce),
            "-DeadlineUtc",
            "2099-01-01T00:00:00Z",
            "-SourceRoot",
            str(paths.source),
            "-ExpectedSourceInputsPath",
            str(paths.expected),
            "-TrustedUvPath",
            str(paths.uv),
            "-ExpectedUvSha256",
            _sha256(paths.uv),
        ],
        check=False,
        capture_output=True,
        env=child_environment,
        text=True,
        timeout=30,
    )


def test_plan_is_read_only_and_reports_deterministic_inventory(tmp_path: Path) -> None:
    paths = _write_fixture(tmp_path)
    nonce = uuid.uuid4()

    result = _run(paths, nonce)

    assert result.returncode == 0, result.stderr
    plan = PreparationResult.model_validate_json(result.stdout)
    assert plan.state == "planned"
    assert not Path(plan.bundle_root).exists()
    assert [entry.relative_path for entry in plan.files] == sorted(
        entry.relative_path for entry in plan.files
    )
    assert not any("__pycache__" in entry.relative_path for entry in plan.files)
    assert not any(entry.relative_path.endswith((".pyc", ".env")) for entry in plan.files)
    assert not any(entry.relative_path.endswith("notes.txt") for entry in plan.files)


def test_prepare_writes_bound_transferable_input(tmp_path: Path) -> None:
    paths = _write_fixture(tmp_path)
    nonce = uuid.uuid4()

    result = _run(paths, nonce, mode="Prepare")

    assert result.returncode == 0, result.stderr
    prepared = PreparationResult.model_validate_json(result.stdout)
    binding_path = Path(prepared.bundle_root) / "task6-input-binding.json"
    binding = Binding.model_validate_json(binding_path.read_text(encoding="utf-8-sig"))
    assert binding.nonce == str(nonce)
    assert binding.uv_sha256 == _sha256(Path(prepared.bundle_root) / "uv.exe")
    assert binding.input_inventory_sha256 == prepared.input_inventory_sha256
    assert prepared.binding_sha256 == _sha256(binding_path)
    assert [entry.relative_path for entry in binding.input_files] == sorted(
        entry.relative_path for entry in binding.input_files
    )
    for entry in binding.input_files:
        copied = Path(prepared.bundle_root) / Path(entry.relative_path)
        assert copied.stat().st_size == entry.size
        assert _sha256(copied) == entry.sha256
    assert not (Path(prepared.bundle_root) / ".env").exists()
    assert not (Path(prepared.bundle_root) / "get-eval-interactive-token-evidence.ps1").exists()


def test_prepare_rejects_tamper_and_existing_bundle(tmp_path: Path) -> None:
    paths = _write_fixture(tmp_path)
    tampered_nonce = uuid.uuid4()
    _ = (paths.source / "scripts" / "install.ps1").write_text(
        "'tampered'\n", encoding="utf-8"
    )

    tampered = _run(paths, tampered_nonce, mode="Prepare")

    assert tampered.returncode != 0
    assert not (paths.lifecycle / "bundles" / str(tampered_nonce)).exists()
    collision_nonce = uuid.uuid4()
    collision = paths.lifecycle / "bundles" / str(collision_nonce)
    _ = collision.mkdir()
    marker = collision / "preserve.txt"
    _ = marker.write_text("unchanged", encoding="utf-8")
    existing = _run(paths, collision_nonce, mode="Prepare")
    assert existing.returncode != 0
    assert marker.read_text(encoding="utf-8") == "unchanged"


def test_prepare_rejects_reparse_source_descendant(tmp_path: Path) -> None:
    paths = _write_fixture(tmp_path)
    target = tmp_path / "outside"
    _ = target.mkdir()
    junction = paths.source / "src" / "linked"
    command = subprocess.run(
        [str(CMD_PATH), "/d", "/c", "mklink", "/J", str(junction), str(target)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert command.returncode == 0, command.stderr
    nonce = uuid.uuid4()
    try:
        result = _run(paths, nonce, mode="Prepare")
        assert result.returncode != 0
        assert not (paths.lifecycle / "bundles" / str(nonce)).exists()
    finally:
        junction.rmdir()
