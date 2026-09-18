"""Cross-runtime determinism tests for protected release inventory."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import ClassVar, Final

from pydantic import BaseModel, ConfigDict, TypeAdapter

PROJECT_ROOT: Final = Path(__file__).parents[2]
SCRIPT_PATH: Final = PROJECT_ROOT / "scripts" / "service-runtime.ps1"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
PWSH_PATH: Final = shutil.which("pwsh.exe")
assert POWERSHELL_PATH is not None
assert PWSH_PATH is not None


class InventoryReceipt(BaseModel):
    """Typed release inventory digest receipt."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    paths: tuple[str, ...]
    digest: str


def _inventory(binary: str, release_root: Path) -> tuple[list[str], str]:
    expression = (
        "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); "
        f". '{SCRIPT_PATH}' -LibraryMode; "
        f"$inventory=@(Get-BridgeReleaseInventory -ReleaseRoot '{release_root}'); "
        "[pscustomobject]@{paths=@($inventory.relativePath);"
        "digest=(Get-BridgeInventoryDigest -Inventory $inventory)}|ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        [binary, "-NoProfile", "-NonInteractive", "-Command", expression],
        check=False,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="strict")
    receipt = TypeAdapter(InventoryReceipt).validate_json(
        result.stdout.decode("utf-8", errors="strict")
    )
    return list(receipt.paths), receipt.digest


def test_release_inventory_uses_ordinal_order_across_powershell_runtimes(
    tmp_path: Path,
) -> None:
    for relative_path in (
        "service-runtime.ps1",
        "service-runtime-build-common.ps1",
        "서비스.ps1",
    ):
        path = tmp_path / relative_path
        _ = path.write_text(relative_path, encoding="utf-8")

    windows_paths, windows_digest = _inventory(POWERSHELL_PATH, tmp_path)
    powershell_paths, powershell_digest = _inventory(PWSH_PATH, tmp_path)

    expected_paths = [
        "service-runtime-build-common.ps1",
        "service-runtime.ps1",
        "서비스.ps1",
    ]
    assert windows_paths == expected_paths
    assert powershell_paths == expected_paths
    assert windows_digest == powershell_digest
