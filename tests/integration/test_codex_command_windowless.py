"""실제 자식 프로세스의 콘솔 부재와 입력 EOF를 검증합니다."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from hermes_windows_bridge.tools.codex import run_bounded_command

if TYPE_CHECKING:
    from pathlib import Path


def test_real_command_probe_has_no_console_and_receives_eof(tmp_path: Path) -> None:
    # Given: 외부 인증 없이 Windows 콘솔 상태만 조회하는 자식입니다.
    probe = (
        "import ctypes, sys; "
        "print(int(ctypes.windll.kernel32.GetConsoleWindow() == 0)); "
        "print(int(sys.stdin.read() == ''))"
    )

    # When: 제품의 동일 실행기로 실제 Python 자식을 생성합니다.
    result = run_bounded_command((sys.executable, "-c", probe), tmp_path, 5)

    # Then: 콘솔 핸들이 없고 입력 대기 없이 EOF로 완료됩니다.
    assert result.exit_code == 0
    assert result.stdout.splitlines() == ["1", "1"]
    assert result.stderr == ""
