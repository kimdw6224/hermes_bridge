"""Worker 내부 local approval wire handler입니다."""

# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Event, Lock
from typing import TYPE_CHECKING, assert_never, final, override

from hermes_windows_bridge.ipc.local_approval import (
    LocalApprovalWireRequest,
    LocalApprovalWireResult,
    parse_local_approval_wire_request,
    wire_result_payload,
)
from hermes_windows_bridge.ipc.protocol import IpcRequest, JsonPayload  # noqa: TC001
from hermes_windows_bridge.worker.local_approval_types import (
    DesktopAvailability,
    LocalApprovalRequest,
    LocalDialogBackend,
    LocalDialogDecision,
    LocalPowerApprovalSummary,
)

if TYPE_CHECKING:
    from uuid import UUID

    from hermes_windows_bridge.worker.operations import OperationHandler

__all__ = ("LocalApprovalHandler",)

type DesktopProbe = Callable[[], DesktopAvailability]
type Clock = Callable[[], datetime]


@final
class LocalApprovalHandler:
    """Dialog 결과만 반환하며 approval receipt를 생성·소비하지 않는 Worker handler입니다."""

    def __init__(
        self,
        dialog: LocalDialogBackend,
        *,
        desktop_probe: DesktopProbe,
        clock: Clock = lambda: datetime.now(UTC),
    ) -> None:
        """한 request의 cancel event와 bounded dialog lifecycle을 관리합니다."""
        self._dialog = dialog
        self._desktop_probe = desktop_probe
        self._clock = clock
        self._lock = Lock()
        self._active: dict[UUID, Event] = {}
        self._closed = False

    def __call__(self, request: IpcRequest) -> JsonPayload:
        """Strict wire request를 fail-closed local dialog 결과로 변환합니다."""
        wire = parse_local_approval_wire_request(request.payload)
        if wire.request_id != request.request_id:
            raise LocalApprovalRequestIdMismatchError(
                expected=request.request_id,
                received=wire.request_id,
            )
        cancellation = Event()
        with self._lock:
            if self._closed:
                raise LocalApprovalHandlerClosedError
            if self._active:
                raise LocalApprovalHandlerBusyError
            self._active[request.request_id] = cancellation
        try:
            result = self._resolve(request, wire, cancellation)
            return wire_result_payload(result)
        finally:
            with self._lock:
                _ = self._active.pop(request.request_id, None)

    def cancel(self, request_id: UUID) -> bool:
        """현재 dialog 중 exact request ID 하나만 취소합니다."""
        with self._lock:
            cancellation = self._active.get(request_id)
            if cancellation is None:
                return False
            cancellation.set()
            return True

    def close(self) -> None:
        """새 dialog를 막고 active dialog가 callback으로 닫히도록 signal합니다."""
        with self._lock:
            self._closed = True
            cancellations = tuple(self._active.values())
        for cancellation in cancellations:
            cancellation.set()

    def _resolve(
        self,
        request: IpcRequest,
        wire: LocalApprovalWireRequest,
        cancellation: Event,
    ) -> LocalApprovalWireResult:
        now = self._clock()
        effective_expiry = min(
            wire.expires_at,
            now + timedelta(milliseconds=request.timeout_ms),
        )
        approved = False
        availability = self._desktop_probe()
        match availability:
            case DesktopAvailability.AVAILABLE:
                if effective_expiry > now:
                    decision = self._dialog.present(
                        LocalApprovalRequest(
                            approval_id=wire.approval_id,
                            operation_id=wire.operation_id,
                            tool_name=wire.tool_name,
                            payload_digest=wire.payload_digest,
                            expires_at=effective_expiry,
                            summary=LocalPowerApprovalSummary(
                                action=wire.summary.action,
                                delay_seconds=wire.summary.delay_seconds,
                                reason=wire.summary.reason,
                            ),
                        ),
                        cancellation,
                    )
                    approved = (
                        decision is LocalDialogDecision.APPROVE
                        and not cancellation.is_set()
                        and self._clock() < effective_expiry
                    )
            case (
                DesktopAvailability.LOCKED
                | DesktopAvailability.SECURE_DESKTOP
                | DesktopAvailability.UNAVAILABLE
            ):
                approved = False
            case unreachable:
                assert_never(unreachable)
        return LocalApprovalWireResult(
            request_id=wire.request_id,
            approval_id=wire.approval_id,
            operation_id=wire.operation_id,
            tool_name=wire.tool_name,
            action=wire.summary.action,
            payload_digest=wire.payload_digest,
            expires_at=wire.expires_at,
            approved=approved,
        )


@dataclass(frozen=True, slots=True)
class LocalApprovalRequestIdMismatchError(ValueError):
    """Outer IPC request ID와 local approval wire ID가 다를 때 발생합니다."""

    expected: UUID
    received: UUID

    @override
    def __str__(self) -> str:
        return (
            "local approval request ID mismatch: "
            f"expected {self.expected}, received {self.received}"
        )


class LocalApprovalHandlerBusyError(RuntimeError):
    """한 Worker가 동시에 둘 이상의 local approval dialog를 열지 못할 때 발생합니다."""


class LocalApprovalHandlerClosedError(RuntimeError):
    """Worker shutdown 뒤 새로운 local approval request가 들어왔을 때 발생합니다."""


_OPERATION_HANDLER_CONTRACT: type[OperationHandler] = LocalApprovalHandler
