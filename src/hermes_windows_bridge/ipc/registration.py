"""Worker registration generation의 stale-state 경계입니다."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, override


class Registration(Protocol):
    """Generation 비교에 필요한 최소 registration 계약입니다."""

    generation: int


@dataclass(frozen=True, slots=True)
class RegistrationConflictError(Exception):
    """Worker 등록이 현재 등록과 중복되거나 stale 상태입니다."""

    current_generation: int
    received_generation: int

    @override
    def __str__(self) -> str:
        """현재와 받은 registration generation을 표시합니다."""
        return (
            "worker registration is duplicate or stale: "
            f"current={self.current_generation}, received={self.received_generation}"
        )


def accept_registration[RegistrationT: Registration](
    current: RegistrationT | None,
    candidate: RegistrationT,
) -> RegistrationT:
    """현재보다 새로운 generation의 Worker 등록만 수락합니다."""
    if current is not None and candidate.generation <= current.generation:
        raise RegistrationConflictError(
            current_generation=current.generation,
            received_generation=candidate.generation,
        )
    return candidate
