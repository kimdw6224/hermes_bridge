"""Wheel RECORD binding tests for protected pywin32 startup hooks."""

from __future__ import annotations

import base64
import hashlib
import shutil
import subprocess
from pathlib import Path
from typing import Final

PROJECT_ROOT: Final = Path(__file__).parents[2]
SCRIPT_PATH: Final = PROJECT_ROOT / "scripts" / "service-runtime.ps1"
BUILD_SCRIPT_PATH: Final = PROJECT_ROOT / "scripts" / "service-runtime-build.ps1"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _record_hash(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _fixture(release_root: Path, *, duplicate_distribution: bool = False) -> tuple[Path, Path]:
    site_packages = release_root / "venv" / "Lib" / "site-packages"
    site_packages.mkdir(parents=True)
    pth = site_packages / "pywin32.pth"
    _ = pth.write_text("import pywin32_bootstrap\n", encoding="utf-8")
    record = site_packages / "pywin32-312.dist-info" / "RECORD"
    record.parent.mkdir()
    metadata = record.parent / "METADATA"
    _ = metadata.write_text(
        "Metadata-Version: 2.4\nName: pywin32\nVersion: 312\n",
        encoding="utf-8",
    )
    _ = record.write_text(
        "".join(
            (
                f"pywin32.pth,sha256={_record_hash(pth)},{pth.stat().st_size}\n",
                "pywin32-312.dist-info/METADATA,",
                f"sha256={_record_hash(metadata)},{metadata.stat().st_size}\n",
            )
        ),
        encoding="utf-8",
    )
    if duplicate_distribution:
        duplicate = site_packages / "pywin32-999.dist-info" / "RECORD"
        duplicate.parent.mkdir()
        _ = duplicate.write_text(record.read_text(encoding="utf-8"), encoding="utf-8")
    return pth, record


def _validate(release_root: Path, pth: Path, record: Path) -> subprocess.CompletedProcess[str]:
    artifact = "".join(
        (
            "[pscustomobject]@{relativePath='venv/Lib/site-packages/pywin32.pth';",
            f"sha256='{_sha256(pth)}';producer='pywin32-wheel';",
            "distribution='pywin32';",
            "recordRelativePath='venv/Lib/site-packages/pywin32-312.dist-info/RECORD';",
            f"recordSha256='{_sha256(record)}'}}",
        )
    )
    command = " ".join(
        (
            f". '{SCRIPT_PATH}' -LibraryMode; . '{BUILD_SCRIPT_PATH}';",
            f"Test-BridgePthClosure -ReleaseRoot '{release_root}'",
            f"-Provenance ([pscustomobject]@{{pthArtifacts=@({artifact})}})",
        )
    )
    return subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_pywin32_pth_requires_matching_wheel_record(tmp_path: Path) -> None:
    pth, record = _fixture(tmp_path)

    result = _validate(tmp_path, pth, record)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "True"


def test_pywin32_pth_rejects_record_entry_digest_mismatch(tmp_path: Path) -> None:
    pth, record = _fixture(tmp_path)
    _ = record.write_text(
        f"pywin32.pth,sha256={'A' * 43},{pth.stat().st_size}\n",
        encoding="utf-8",
    )

    result = _validate(tmp_path, pth, record)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"


def test_pywin32_pth_self_attestation_cannot_replace_unchanged_record(tmp_path: Path) -> None:
    pth, record = _fixture(tmp_path)
    _ = pth.write_text("import pywin32_bootstrap\n# tampered\n", encoding="utf-8")

    result = _validate(tmp_path, pth, record)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"


def test_pywin32_pth_rejects_duplicate_distribution_records(tmp_path: Path) -> None:
    pth, record = _fixture(tmp_path, duplicate_distribution=True)

    result = _validate(tmp_path, pth, record)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"


def test_pywin32_pth_rejects_self_attested_distribution_name(tmp_path: Path) -> None:
    pth, record = _fixture(tmp_path)
    metadata = record.parent / "METADATA"
    _ = metadata.write_text(
        "Metadata-Version: 2.4\nName: unrelated-package\nVersion: 312\n",
        encoding="utf-8",
    )
    _ = record.write_text(
        "".join(
            (
                f"pywin32.pth,sha256={_record_hash(pth)},{pth.stat().st_size}\n",
                "pywin32-312.dist-info/METADATA,",
                f"sha256={_record_hash(metadata)},{metadata.stat().st_size}\n",
            )
        ),
        encoding="utf-8",
    )

    result = _validate(tmp_path, pth, record)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"


def test_pywin32_pth_rejects_record_rows_with_extra_columns(tmp_path: Path) -> None:
    pth, record = _fixture(tmp_path)
    metadata = record.parent / "METADATA"
    _ = record.write_text(
        "".join(
            (
                f"pywin32.pth,sha256={_record_hash(pth)},{pth.stat().st_size},extra\n",
                "pywin32-312.dist-info/METADATA,",
                f"sha256={_record_hash(metadata)},{metadata.stat().st_size}\n",
            )
        ),
        encoding="utf-8",
    )

    result = _validate(tmp_path, pth, record)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"
