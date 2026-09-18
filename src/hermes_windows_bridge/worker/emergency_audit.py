"""로컬 비상 정지 activation만 남기는 Worker 전용 redacted 감사 sink입니다."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final, final
from uuid import uuid4

from hermes_windows_bridge.gateway.audit import (
    AuditInput,
    AuditJsonlStore,
    AuditOutcome,
    AuditRecorder,
)

if TYPE_CHECKING:
    from pathlib import Path

_LOCAL_EMERGENCY_STOP_RETENTION: Final = timedelta(hours=24)
_LOCAL_EMERGENCY_STOP_TOOL_NAME: Final = "local_emergency_stop"


@final
class LocalEmergencyStopAudit:
    """Marker 활성화 뒤 local-only metadata를 별도 Worker root에 기록합니다."""

    def __init__(self, root: Path) -> None:
        """Gateway audit와 공유하지 않는 Worker 전용 store를 만듭니다."""
        self._store = AuditJsonlStore(root, retention=_LOCAL_EMERGENCY_STOP_RETENTION)
        self._recorder = AuditRecorder(store=self._store)

    def record_activation(self) -> None:
        """원문 키 조합 없이 local hotkey activation metadata만 기록합니다."""
        now = datetime.now(UTC)
        _ = self._recorder.record(
            AuditInput(
                event_id=uuid4(),
                occurred_at=now,
                tool_name=_LOCAL_EMERGENCY_STOP_TOOL_NAME,
                operation_id=None,
                payload={"source": "local_hotkey"},
                outcome=AuditOutcome.SUCCEEDED,
            )
        )
        _ = self._store.cleanup_expired_sensitive_artifacts(now)
