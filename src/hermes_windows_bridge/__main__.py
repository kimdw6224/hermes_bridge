"""Hermes Windows Bridge 명령줄 진입점입니다."""

from __future__ import annotations

import argparse
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Sequence

PROGRAM_NAME: Final = "hermes-windows-bridge"


def main(argv: Sequence[str] | None = None) -> int:
    """명령줄 인수를 파싱하고 종료 코드를 반환합니다."""
    parser = argparse.ArgumentParser(
        prog=PROGRAM_NAME,
        description="Hermes Windows Bridge",
    )
    _ = parser.parse_args(argv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
