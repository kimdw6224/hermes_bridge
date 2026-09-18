"""Authenticated named-pipe ACL doctor source-contract regression test."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Final

PROJECT_ROOT: Final = Path(__file__).parents[2]
FIXTURE_PATH: Final = PROJECT_ROOT / "tests" / "smoke" / "doctor-pipe-acl-check.ps1"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None


def test_pipe_acl_source_uses_authenticated_status_observation_only() -> None:
    # Given: legacy provider surface를 제거한 current doctor source입니다.
    # When: 실제 PowerShell diagnostic classification fixture를 실행합니다.
    result = subprocess.run(
        [
            POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(FIXTURE_PATH),
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    # Then: direct pipe provider 대신 authenticated status-only observation만 허용합니다.
    assert result.returncode == 0, result.stderr
