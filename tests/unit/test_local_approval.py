from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from threading import Event
from uuid import UUID

import anyio
import pytest
from anyio import to_thread

from hermes_windows_bridge.models.policy import ApprovalRecord, ApprovalState
from hermes_windows_bridge.worker.local_approval import (
    DesktopAvailability,
    LocalApprovalRequest,
    LocalApprovalSurface,
    LocalDialogDecision,
)

NOW = datetime(2026, 9, 7, tzinfo=UTC)
APPROVAL_ID = UUID("018f0000-0000-7000-8000-000000000081")
OPERATION_ID = UUID("018f0000-0000-7000-8000-000000000082")


def _record() -> ApprovalRecord:
    return ApprovalRecord(
        approval_id=APPROVAL_ID,
        operation_id=OPERATION_ID,
        tool_name="system_shutdown",
        canonical_payload=b'{"delay_seconds":0,"reason":"maintenance"}',
        payload_digest="1" * 64,
        requested_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
        state=ApprovalState.PENDING,
    )


@dataclass(frozen=True, slots=True)
class _RecordingDialog:
    decision: LocalDialogDecision
    calls: list[int] = field(default_factory=lambda: [0])
    request_operation_ids: list[UUID] = field(default_factory=list)
    request_tools: list[str] = field(default_factory=list)
    request_digests: list[str] = field(default_factory=list)

    def present(
        self, request: LocalApprovalRequest, cancellation: Event
    ) -> LocalDialogDecision:
        self.calls[0] += 1
        self.request_operation_ids.append(request.operation_id)
        self.request_tools.append(request.tool_name)
        self.request_digests.append(request.payload_digest)
        del cancellation
        return self.decision


@dataclass(frozen=True, slots=True)
class _BlockingApproveDialog:
    started: Event = field(default_factory=Event)
    closed: Event = field(default_factory=Event)

    def present(
        self, request: LocalApprovalRequest, cancellation: Event
    ) -> LocalDialogDecision:
        del request
        self.started.set()
        assert cancellation.wait(1)
        self.closed.set()
        return LocalDialogDecision.APPROVE


def test_local_approval_binds_dialog_to_exact_frozen_record() -> None:
    # Given: explicit local 승인과 immutable frozen record입니다.
    dialog = _RecordingDialog(LocalDialogDecision.APPROVE)
    surface = LocalApprovalSurface(
        dialog,
        desktop_probe=lambda: DesktopAvailability.AVAILABLE,
        clock=lambda: NOW,
    )

    # When: local surface가 record를 표시합니다.
    approved = anyio.run(surface.resolve, _record())

    # Then: 정확한 operation/tool/digest만 dialog에 전달되고 승인됩니다.
    assert approved is True
    assert dialog.calls == [1]
    assert dialog.request_operation_ids == [OPERATION_ID]
    assert dialog.request_tools == ["system_shutdown"]
    assert dialog.request_digests == ["1" * 64]


@pytest.mark.parametrize(
    "availability",
    [
        DesktopAvailability.LOCKED,
        DesktopAvailability.SECURE_DESKTOP,
        DesktopAvailability.UNAVAILABLE,
    ],
)
def test_local_approval_denies_without_dialog_when_desktop_is_not_available(
    availability: DesktopAvailability,
) -> None:
    # Given: locked, secure desktop 또는 unavailable Worker desktop입니다.
    dialog = _RecordingDialog(LocalDialogDecision.APPROVE)
    surface = LocalApprovalSurface(
        dialog,
        desktop_probe=lambda: availability,
        clock=lambda: NOW,
    )

    # When: local 승인 fallback을 요청합니다.
    approved = anyio.run(surface.resolve, _record())

    # Then: 실제 dialog를 만들지 않고 fail-closed 합니다.
    assert approved is False
    assert dialog.calls == [0]


def test_local_approval_rejects_late_dialog_approval_after_expiry() -> None:
    # Given: dialog는 approve를 반환하지만 return 직후 request가 만료됩니다.
    times = iter((NOW, NOW + timedelta(seconds=31)))
    dialog = _RecordingDialog(LocalDialogDecision.APPROVE)
    surface = LocalApprovalSurface(
        dialog,
        desktop_probe=lambda: DesktopAvailability.AVAILABLE,
        clock=lambda: next(times),
    )

    # When: bounded surface가 결과를 받습니다.
    approved = anyio.run(surface.resolve, _record())

    # Then: 늦은 approve는 receipt로 변환되지 않습니다.
    assert approved is False
    assert dialog.calls == [1]


def test_local_approval_cancellation_closes_owned_dialog_and_discards_late_approval() -> None:
    # Given: cancellation event까지 block한 뒤에만 approve를 반환하는 owned dialog입니다.
    dialog = _BlockingApproveDialog()
    surface = LocalApprovalSurface(
        dialog,
        desktop_probe=lambda: DesktopAvailability.AVAILABLE,
        clock=lambda: NOW,
    )

    async def cancel_resolution() -> None:
        # When: caller가 pending approval task를 취소합니다.
        async with anyio.create_task_group() as task_group:
            _ = task_group.start_soon(surface.resolve, _record())
            started = await to_thread.run_sync(dialog.started.wait, 1)
            assert started is True
            task_group.cancel_scope.cancel()

    # Then: event-driven cleanup이 dialog를 닫고 late approve는 caller에 전달되지 않습니다.
    anyio.run(cancel_resolution)
    closed = dialog.closed.wait(1)
    assert closed is True
