from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
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
    from threading import Event


@dataclass(frozen=True, slots=True)
class _DenyDialog:
    requests: list[LocalApprovalRequest] = field(default_factory=list)

    def present(
        self, request: LocalApprovalRequest, cancellation: Event
    ) -> LocalDialogDecision:
        del cancellation
        self.requests.append(request)
        return LocalDialogDecision.DENY


@pytest.mark.integration
def test_worker_handler_consumes_only_local_approval_wire_without_real_pipe_or_ui() -> None:
    # Given: JSON-safe wire request와 injected deny dialog contract입니다.
    now = datetime(2026, 9, 7, tzinfo=UTC)
    wire = LocalApprovalWireRequest(
        request_id=UUID("018f0000-0000-7000-8000-000000000121"),
        approval_id=UUID("018f0000-0000-7000-8000-000000000122"),
        operation_id=UUID("018f0000-0000-7000-8000-000000000123"),
        tool_name="system_shutdown",
        payload_digest="c" * 64,
        expires_at=now + timedelta(seconds=5),
        summary=LocalApprovalPowerSummary(
            action="shutdown",
            delay_seconds=0,
            reason="maintenance",
        ),
    )
    request = IpcRequest(
        request_id=wire.request_id,
        target=PeerRole.WORKER,
        operation="local_approval",
        payload=wire.model_dump(mode="json"),
        timeout_ms=500,
    )
    dialog = _DenyDialog()
    handler = LocalApprovalHandler(
        dialog,
        desktop_probe=lambda: DesktopAvailability.AVAILABLE,
        clock=lambda: now,
    )

    # When: Worker-owned handler가 typed request를 처리합니다.
    result = LocalApprovalWireResult.model_validate_json(json.dumps(handler(request)))

    # Then: denial과 correlation만 반환하며 pipe, UI, power action은 수행하지 않습니다.
    assert result.approved is False
    assert result.request_id == wire.request_id
    assert result.operation_id == wire.operation_id
    summary = dialog.requests[0].summary
    assert summary is not None
    assert summary.action == "shutdown"
