"""상태 조회용 자식 프로세스가 창과 입력 대기를 만들지 않는 계약입니다."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING, TypedDict, Unpack

from hermes_windows_bridge.tools.codex import run_bounded_command

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


class _RunOptions(TypedDict, total=False):
    cwd: Path
    capture_output: bool
    timeout: int
    check: bool
    creationflags: int
    stdin: int


def test_command_probe_disables_console_and_interactive_input(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    # Given: 실제 창을 띄우지 않고 subprocess 경계의 실행 옵션을 관측합니다.
    observed: list[_RunOptions] = []

    def capture_run(
        argv: tuple[str, ...], **options: Unpack[_RunOptions],
    ) -> subprocess.CompletedProcess[bytes]:
        observed.append(options)
        return subprocess.CompletedProcess(argv, 0, b"ready", b"")

    monkeypatch.setattr(subprocess, "run", capture_run)

    # When: Codex/Git 상태 조회가 공유하는 실행기를 호출합니다.
    result = run_bounded_command(("fixture.exe", "--version"), tmp_path, 5)

    # Then: 콘솔 생성과 사용자 입력 대기를 모두 차단합니다.
    assert result.exit_code == 0
    assert result.stdout == "ready"
    assert observed[0].get("creationflags", 0) & subprocess.CREATE_NO_WINDOW
    assert observed[0].get("stdin") == subprocess.DEVNULL
