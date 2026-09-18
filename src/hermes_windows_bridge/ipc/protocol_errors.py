"""일반 IPC response 상태와 correlation의 typed 오류입니다."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, override

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class ResponseStateError(ValueError):
    """응답의 성공 상태와 error code가 모순됩니다."""

    ok: bool
    error_code: str | None

    @override
    def __str__(self) -> str:
        """모순된 응답 상태를 표시합니다."""
        return f"invalid response state: ok={self.ok}, error_code={self.error_code!r}"


@dataclass(frozen=True, slots=True)
class CorrelationError(Exception):
    """응답이 대기 중인 요청과 연관되지 않습니다."""

    expected: UUID
    received: UUID | None

    @override
    def __str__(self) -> str:
        """요청과 응답 ID의 차이를 표시합니다."""
        return f"response correlation mismatch: expected {self.expected}, received {self.received}"
