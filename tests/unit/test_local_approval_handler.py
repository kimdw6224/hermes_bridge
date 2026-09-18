from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from threading import Event
from typing import TYPE_CHECKING
from uuid import UUID

import pytest

from hermes_windows_bridge.ipc.local_approval import (
    LocalApprovalPowerSummary,
    LocalApprovalWireRequest,
    LocalApprovalWireResult,
)
from hermes_windows_bridge.ipc.protocol import IpcRequest, PeerRole
from hermes_windows_bridge.worker.local_approval import (
    DesktopAvailability,
    LocalApprovalRequest,
    LocalDialogDecision,
)
from hermes_windows_bridge.worker.local_approval_handler import LocalApprovalHandler

if TYPE_CHECKING:
    from collections.abc import Mapping

NOW = datetime(2026, 9, 7, tzinfo=UTC)
REQUEST_ID = UUID("018f0000-0000-7000-8000-000000000111")
APPROVAL_ID = UUID("018f0000-0000-7000-8000-000000000112")
OPERATION_ID = UUID("018f0000-0000-7000-8000-000000000113")


def _result(payload: Mapping[str, object]) -> LocalApprovalWireResult:
    return LocalApprovalWireResult.model_validate_json(json.dumps(payload))


def _wire(request_id: UUID = REQUEST_ID) -> LocalApprovalWireRequest:
    return LocalApprovalWireRequest(
        request_id=request_id,
        approval_id=APPROVAL_ID,
        operation_id=OPERATION_ID,
        tool_name="system_reboot",
        payload_digest="b" * 64,
        expires_at=NOW + timedelta(seconds=10),
        summary=LocalApprovalPowerSummary(
            action="reboot",
            delay_seconds=5,
            reason="maintenance",
        ),
    )


def _request(
    wire: LocalApprovalWireRequest | None = None, *, timeout_ms: int = 1_000
) -> IpcRequest:
    payload = (wire or _wire()).model_dump(mode="json")
    return IpcRequest(
        request_id=REQUEST_ID,
        target=PeerRole.WORKER,
        operation="local_approval",
        payload=payload,
        timeout_ms=timeout_ms,
    )


@dataclass(frozen=True, slots=True)
class _RecordingDialog:
    decision: LocalDialogDecision
    requests: list[LocalApprovalRequest] = field(default_factory=list)

    def present(
        self, request: LocalApprovalRequest, cancellation: Event
    ) -> LocalDialogDecision:
        del cancellation
        self.requests.append(request)
        return self.decision


@dataclass(frozen=True, slots=True)
class _BlockingDialog:
    entered: Event = field(default_factory=Event)
    cancelled: Event = field(default_factory=Event)

    def present(
        self, request: LocalApprovalRequest, cancellation: Event
    ) -> LocalDialogDecision:
        del request
        self.entered.set()
        assert cancellation.wait(1)
        self.cancelled.set()
        return LocalDialogDecision.APPROVE


def test_handler_returns_approved_result_with_exact_correlation_and_safe_summary() -> None:
    # Given: explicit approve dialog와 typed reboot wire request입니다.
    dialog = _RecordingDialog(LocalDialogDecision.APPROVE)
    handler = LocalApprovalHandler(
        dialog,
        desktop_probe=lambda: DesktopAvailability.AVAILABLE,
        clock=lambda: NOW,
    )

    # When: Worker internal handler가 request를 실행합니다.
    result = _result(handler(_request()))

    # Then: approved result는 exact correlation만 반환하고 dialog에는 safe summary만 보입니다.
    assert result.approved is True
    assert result.request_id == REQUEST_ID
    assert result.approval_id == APPROVAL_ID
    assert result.operation_id == OPERATION_ID
    assert result.payload_digest == "b" * 64
    summary = dialog.requests[0].summary
    assert summary is not None
    assert summary.reason == "maintenance"
    assert summary.delay_seconds == 5


@pytest.mark.parametrize(
    "availability",
    [
        DesktopAvailability.LOCKED,
        DesktopAvailability.SECURE_DESKTOP,
        DesktopAvailability.UNAVAILABLE,
    ],
)
def test_handler_denies_without_dialog_for_noninteractive_desktop(
    availability: DesktopAvailability,
) -> None:
    # Given: local dialog를 표시할 수 없는 Worker desktop입니다.
    dialog = _RecordingDialog(LocalDialogDecision.APPROVE)
    handler = LocalApprovalHandler(dialog, desktop_probe=lambda: availability, clock=lambda: NOW)

    # When: approval wire request를 처리합니다.
    result = _result(handler(_request()))

    # Then: fail-closed result이며 dialog는 생성되지 않습니다.
    assert result.approved is False
    assert dialog.requests == []


def test_handler_uses_earlier_of_ipc_timeout_and_wire_expiry() -> None:
    # Given: wire expiry보다 더 짧은 IPC request timeout입니다.
    dialog = _RecordingDialog(LocalDialogDecision.APPROVE)
    handler = LocalApprovalHandler(
        dialog,
        desktop_probe=lambda: DesktopAvailability.AVAILABLE,
        clock=lambda: NOW,
    )

    # When: handler가 dialog deadline을 구성합니다.
    result = _result(handler(_request(timeout_ms=125)))

    # Then: 승인되더라도 dialog에는 최소 deadline만 전달됩니다.
    assert result.approved is True
    assert dialog.requests[0].expires_at == NOW + timedelta(milliseconds=125)


def test_handler_rejects_mismatched_request_id_and_extra_payload() -> None:
    # Given: outer IPC ID와 다른 payload request ID 및 extra field입니다.
    dialog = _RecordingDialog(LocalDialogDecision.APPROVE)
    handler = LocalApprovalHandler(
        dialog,
        desktop_probe=lambda: DesktopAvailability.AVAILABLE,
        clock=lambda: NOW,
    )
    mismatched = _request(_wire(UUID("018f0000-0000-7000-8000-000000000119")))
    extra = _request().model_copy(update={"payload": {**_request().payload, "extra": "x"}})

    # When/Then: ID correlation과 closed payload schema 위반이 dialog 전에 거부됩니다.
    with pytest.raises(ValueError, match="request ID mismatch"):
        _ = handler(mismatched)
    with pytest.raises(ValueError, match="Extra inputs are not permitted"):
        _ = handler(extra)
    assert dialog.requests == []


def test_handler_cancels_only_matching_active_request_and_discards_late_approval() -> None:
    # Given: cancel event를 기다린 뒤 approve를 반환하는 active dialog입니다.
    dialog = _BlockingDialog()
    handler = LocalApprovalHandler(
        dialog,
        desktop_probe=lambda: DesktopAvailability.AVAILABLE,
        clock=lambda: NOW,
    )

    # When: stale ID와 exact request ID를 차례로 cancel합니다.
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(handler, _request())
        assert dialog.entered.wait(1)
        stale = handler.cancel(UUID(int=1))
        matched = handler.cancel(REQUEST_ID)
        result = _result(future.result(timeout=1))

    # Then: exact cancel만 dialog를 닫고 late approve는 false로 반환됩니다.
    assert stale is False
    assert matched is True
    assert dialog.cancelled.is_set()
    assert result.approved is False
