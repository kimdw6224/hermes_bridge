"""Worker 전용의 fail-closed local Windows 승인 surface입니다."""

# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from threading import Event
from typing import TYPE_CHECKING, assert_never, final

from anyio import fail_after, to_thread

if TYPE_CHECKING:
    from hermes_windows_bridge.models.policy import ApprovalRecord

from hermes_windows_bridge.worker.local_approval_types import (
    DesktopAvailability,
    LocalApprovalRequest,
    LocalDialogBackend,
    LocalDialogDecision,
    LocalPowerApprovalSummary,
)
from hermes_windows_bridge.worker.local_approval_win32 import Win32TaskDialogBackend

__all__ = (
    "DesktopAvailability",
    "LocalApprovalRequest",
    "LocalApprovalSurface",
    "LocalDialogBackend",
    "LocalDialogDecision",
    "LocalPowerApprovalSummary",
    "Win32TaskDialogBackend",
)


type DesktopProbe = Callable[[], DesktopAvailability]
type Clock = Callable[[], datetime]


@final
class LocalApprovalSurface:
    """Gateway와 무관하게 bounded local 승인 dialog를 lifecycle 관리합니다."""

    def __init__(
        self,
        dialog: LocalDialogBackend,
        *,
        desktop_probe: DesktopProbe,
        clock: Clock = lambda: datetime.now(UTC),
    ) -> None:
        """Real Win32 backend 또는 test backend와 desktop probe를 결합합니다."""
        self._dialog = dialog
        self._desktop_probe = desktop_probe
        self._clock = clock

    async def resolve(self, record: ApprovalRecord) -> bool:
        """현재 desktop에서만 frozen record의 명시적 local approval을 받습니다."""
        availability = self._desktop_probe()
        match availability:
            case DesktopAvailability.AVAILABLE:
                pass
            case (
                DesktopAvailability.LOCKED
                | DesktopAvailability.SECURE_DESKTOP
                | DesktopAvailability.UNAVAILABLE
            ):
                return False
            case unreachable:
                assert_never(unreachable)
        request = LocalApprovalRequest(
            approval_id=record.approval_id,
            operation_id=record.operation_id,
            tool_name=record.tool_name,
            payload_digest=record.payload_digest,
            expires_at=record.expires_at,
        )
        remaining = (request.expires_at - self._clock()).total_seconds()
        if remaining <= 0:
            return False
        cancellation = Event()
        try:
            with fail_after(remaining):
                decision = await to_thread.run_sync(
                    self._dialog.present,
                    request,
                    cancellation,
                    abandon_on_cancel=True,
                )
        except TimeoutError:
            return False
        finally:
            # Thread는 callback timer에서 이 signal을 보고 자신의 dialog만 닫습니다.
            cancellation.set()
        if self._clock() >= request.expires_at:
            return False
        match decision:
            case LocalDialogDecision.APPROVE:
                return True
            case LocalDialogDecision.DENY | LocalDialogDecision.CANCEL:
                return False
            case unreachable:
                assert_never(unreachable)
