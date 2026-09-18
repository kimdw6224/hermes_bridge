"""패키지 스캐폴드의 외부 계약을 검증합니다."""

from __future__ import annotations

import importlib
import subprocess
import sys
from pathlib import Path


def test_package_exposes_version_when_imported() -> None:
    # Given: src-layout 패키지가 설치된 실행 환경입니다.
    package_name = "hermes_windows_bridge"

    # When: 공개 패키지를 import합니다.
    package = importlib.import_module(package_name)

    # Then: 배포 버전과 일치하는 공개 버전을 제공합니다.
    assert getattr(package, "__version__", None) == "0.1.0"


def test_module_help_succeeds_when_requested() -> None:
    # Given: 모듈 진입점을 실행할 Python 인터프리터입니다.
    command = [sys.executable, "-m", "hermes_windows_bridge", "--help"]

    # When: 사용자가 도움말을 요청합니다.
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        cwd=Path.cwd(),
    )

    # Then: CLI가 성공하고 안정적인 프로그램 이름을 표시합니다.
    assert result.returncode == 0
    assert "hermes-windows-bridge" in result.stdout
