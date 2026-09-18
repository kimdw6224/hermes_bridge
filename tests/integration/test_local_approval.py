from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID

import anyio
import pytest

from hermes_windows_bridge.models.policy import ApprovalRecord, ApprovalState
from hermes_windows_bridge.worker.local_approval import (
    DesktopAvailability,
    LocalApprovalRequest,
    LocalApprovalSurface,
    LocalDialogDecision,
)

if TYPE_CHECKING:
    from threading import Event


@dataclass(frozen=True, slots=True)
class _ContractDialog:
    requests: list[LocalApprovalRequest] = field(default_factory=list)

    def present(
        self, request: LocalApprovalRequest, cancellation: Event
    ) -> LocalDialogDecision:
        del cancellation
        self.requests.append(request)
        return LocalDialogDecision.DENY


@pytest.mark.integration
def test_local_surface_uses_worker_dialog_contract_without_windows_ui() -> None:
    # Given: 실제 Win32 호출 없이 contract를 구현한 local Worker dialog입니다.
    record = ApprovalRecord(
        approval_id=UUID("018f0000-0000-7000-8000-000000000091"),
        operation_id=UUID("018f0000-0000-7000-8000-000000000092"),
        tool_name="system_reboot",
        canonical_payload=b'{"delay_seconds":0,"reason":"maintenance"}',
        payload_digest="2" * 64,
        requested_at=datetime(2026, 9, 7, tzinfo=UTC),
        expires_at=datetime(2026, 9, 7, tzinfo=UTC) + timedelta(seconds=30),
        state=ApprovalState.PENDING,
    )
    dialog = _ContractDialog()
    surface = LocalApprovalSurface(
        dialog,
        desktop_probe=lambda: DesktopAvailability.AVAILABLE,
        clock=lambda: datetime(2026, 9, 7, tzinfo=UTC),
    )

    # When: Gateway wiring 없이 local component protocol을 실행합니다.
    approved = anyio.run(surface.resolve, record)

    # Then: deny는 power action 없이 false이고 exact frozen correlation만 전달됩니다.
    assert approved is False
    assert dialog.requests == [
        LocalApprovalRequest(
            approval_id=record.approval_id,
            operation_id=record.operation_id,
            tool_name="system_reboot",
            payload_digest="2" * 64,
            expires_at=record.expires_at,
        )
    ]
