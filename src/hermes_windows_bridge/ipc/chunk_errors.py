"""Job output chunk 경계의 typed 오류입니다."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, override

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class ChunkBoundsError(ValueError):
    """Chunk window가 전송 또는 offset 범위를 벗어났습니다."""

    offset: int
    size: int

    @override
    def __str__(self) -> str:
        """거부된 chunk window를 표시합니다."""
        return f"invalid output chunk window: offset={self.offset}, size={self.size}"


@dataclass(frozen=True, slots=True)
class ChunkOffsetError(ValueError):
    """응답의 next offset이 실제 UTF-8 byte 길이와 다릅니다."""

    expected: int
    received: int

    @override
    def __str__(self) -> str:
        """기대한 offset과 받은 offset을 표시합니다."""
        return (
            "output chunk next offset mismatch: "
            f"expected {self.expected}, received {self.received}"
        )


@dataclass(frozen=True, slots=True)
class ChunkCorrelationError(Exception):
    """Chunk 응답이 요청한 job 또는 offset과 다릅니다."""

    expected_job_id: UUID
    received_job_id: UUID
    expected_offset: int
    received_offset: int

    @override
    def __str__(self) -> str:
        """Job과 offset correlation 차이를 표시합니다."""
        return (
            "output chunk correlation mismatch: "
            f"expected job={self.expected_job_id}, offset={self.expected_offset}; "
            f"received job={self.received_job_id}, offset={self.received_offset}"
        )
