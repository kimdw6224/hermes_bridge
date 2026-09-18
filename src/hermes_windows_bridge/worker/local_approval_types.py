"""Local approval surface와 Win32 backend가 공유하는 typed contract입니다."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Literal, Protocol

if TYPE_CHECKING:
    from datetime import datetime
    from threading import Event
    from uuid import UUID

__all__ = (
    "DesktopAvailability",
    "LocalApprovalRequest",
    "LocalDialogBackend",
    "LocalDialogDecision",
    "LocalPowerApprovalSummary",
)


class DesktopAvailability(StrEnum):
    """승인 dialog를 표시할 수 있는 interactive desktop 상태입니다."""

    AVAILABLE = "available"
    LOCKED = "locked"
    SECURE_DESKTOP = "secure_desktop"
    UNAVAILABLE = "unavailable"


class LocalDialogDecision(StrEnum):
    """사람이 local dialog에서 선택할 수 있는 결과입니다."""

    APPROVE = "approve"
    DENY = "deny"
    CANCEL = "cancel"


@dataclass(frozen=True, slots=True)
class LocalPowerApprovalSummary:
    """Dialog에 표시할 validated power 정보입니다."""

    action: Literal["reboot", "shutdown"]
    delay_seconds: int
    reason: str


@dataclass(frozen=True, slots=True)
class LocalApprovalRequest:
    """Dialog가 보여 줄 immutable correlation 정보입니다."""

    approval_id: UUID
    operation_id: UUID
    tool_name: str
    payload_digest: str
    expires_at: datetime
    summary: LocalPowerApprovalSummary | None = None


class LocalDialogBackend(Protocol):
    """Worker-owned local dialog의 좁은 blocking contract입니다."""

    def present(
        self, request: LocalApprovalRequest, cancellation: Event
    ) -> LocalDialogDecision:
        """명시적 사용자 선택 또는 cancellation 결과를 반환합니다."""
        ...
