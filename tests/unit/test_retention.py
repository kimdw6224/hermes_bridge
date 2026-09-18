from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from uuid import uuid4

from hermes_windows_bridge.gateway.audit import (
    AuditInput,
    AuditJsonlStore,
    AuditOutcome,
    AuditRecorder,
)

if TYPE_CHECKING:
    from pathlib import Path


class TestRetention:
    def test_cleanup_removes_expired_sensitive_artifacts_preserves_metadata(
        self, tmp_path: Path
    ) -> None:
        # Given: redacted metadata와 만료된 legacy diagnostic body가 같은 private root에 있습니다.
        store = AuditJsonlStore(tmp_path, retention=timedelta(hours=1))
        recorder = AuditRecorder(store=store)
        event = recorder.record(
            AuditInput(
                event_id=uuid4(),
                occurred_at=datetime(2026, 9, 6, tzinfo=UTC),
                tool_name="computer_observe",
                operation_id=None,
                payload={"token": "never-persisted"},
                outcome=AuditOutcome.SUCCEEDED,
                stdout="raw-output-must-not-reach-jsonl",
                screenshot_body=b"raw-image-must-not-reach-jsonl",
            )
        )
        metadata = store.path_for(event.occurred_at)
        body = tmp_path / f"{event.event_id}.screenshot.body"
        _ = body.write_bytes(b"expired-sensitive-image")
        old_timestamp = (datetime.now(UTC) - timedelta(hours=2)).timestamp()
        body.touch()
        body.chmod(0o600)
        os.utime(body, (old_timestamp, old_timestamp))

        # When: explicit retention cleanup을 실행하면
        receipt = store.cleanup_expired_sensitive_artifacts(datetime.now(UTC))

        # Then: 원문 body만 삭제되고 JSONL metadata에는 원문이 전혀 없습니다.
        assert receipt.deleted_paths == (body,)
        assert not body.exists()
        serialized = metadata.read_text(encoding="utf-8")
        assert "never-persisted" not in serialized
        assert "raw-output-must-not-reach-jsonl" not in serialized
        assert "raw-image-must-not-reach-jsonl" not in serialized
        assert str(event.event_id) in serialized
