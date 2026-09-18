"""Worker의 windowless Python launch 계약을 검증합니다."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Final

from hermes_windows_bridge.worker.main import build_worker_task_manifest

PROJECT_ROOT: Final = Path(__file__).parents[2]
WORKER_MODULE: Final = "hermes_windows_bridge.worker.main"


def test_worker_manifest_uses_windowless_sibling_interpreter() -> None:
    # Given: 로그인 사용자용 interactive Worker manifest입니다.
    worker = build_worker_task_manifest(user_id="CONTOSO\\alice")

    # When: Worker 실행 argv를 관찰합니다.
    argv = worker.argv

    # Then: 동일 venv의 windowed interpreter로 module 계약을 유지합니다.
    assert argv == (
        str(Path(sys.executable).with_name("pythonw.exe")),
        "-m",
        WORKER_MODULE,
    )


def test_windowless_worker_interpreter_starts_without_standard_streams(tmp_path: Path) -> None:
    # Given: 콘솔을 할당하지 않는 동일 venv의 Worker interpreter입니다.
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    receipt = tmp_path / "pythonw-receipt.txt"
    probe = (
        "import pathlib,sys;"
        f"pathlib.Path({str(receipt)!r}).write_text("
        "str(sys.stdin is None and sys.stdout is None and sys.stderr is None),encoding='utf-8')"
    )

    # When: 표준 스트림 redirect 없이 실제 windowed interpreter를 시작합니다.
    result = subprocess.run(
        [pythonw, "-c", probe],
        cwd=PROJECT_ROOT,
        check=False,
        timeout=10,
    )

    # Then: console stream 없이도 entry process가 정상 완료됩니다.
    assert result.returncode == 0
    assert receipt.read_text(encoding="utf-8") == "True"
