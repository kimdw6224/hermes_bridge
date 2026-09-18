"""Native protected-runtime path guard regression tests."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Final

PROJECT_ROOT: Final = Path(__file__).parents[2]
SCRIPT_PATH: Final = PROJECT_ROOT / "scripts" / "service-runtime.ps1"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None


def _run_path_guard(root: Path, paths: tuple[Path, ...]) -> subprocess.CompletedProcess[str]:
    """Run the public path guard against a typed list of local paths."""
    environment = os.environ.copy()
    environment["HERMES_PATH_GUARD_SCRIPT"] = str(SCRIPT_PATH)
    environment["HERMES_PATH_GUARD_ROOT"] = str(root)
    environment["HERMES_PATH_GUARD_PATHS"] = ";".join(str(path) for path in paths)
    command = r"""
. $env:HERMES_PATH_GUARD_SCRIPT -LibraryMode
$paths=$env:HERMES_PATH_GUARD_PATHS.Split(';')
@($paths | ForEach-Object {
 Test-BridgePathReparseFree -Root $env:HERMES_PATH_GUARD_ROOT -Path $_
}) | ConvertTo-Json -Compress
"""
    return subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )


def test_reparse_guard_accepts_regular_and_missing_descendants_but_rejects_external_path(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    regular = root.joinpath(*("deep" for _ in range(12)), "entry.bin")
    regular.parent.mkdir(parents=True)
    _ = regular.write_bytes(b"fixture")
    missing = regular.parent / "not-created" / "entry.bin"
    external = tmp_path / "outside" / "entry.bin"

    result = _run_path_guard(root, (regular, missing, external))

    # 존재하지 않는 descendant는 inventory 단계에서 별도로 판정합니다.
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [True, True, False]


def test_unmapped_owner_sid_is_read_directly_and_remains_untrusted() -> None:
    environment = os.environ.copy()
    environment["HERMES_PATH_GUARD_SCRIPT"] = str(SCRIPT_PATH)
    command = r"""
. $env:HERMES_PATH_GUARD_SCRIPT -LibraryMode
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetSecurityDescriptorSddlForm('O:S-1-5-21-111-222-333-444G:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
[pscustomobject]@{
 owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
 protected=Test-BridgeProtectedAclDescriptor -Acl $acl
}|ConvertTo-Json -Compress
"""

    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "owner": "S-1-5-21-111-222-333-444",
        "protected": False,
    }
