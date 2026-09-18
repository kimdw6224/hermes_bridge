from __future__ import annotations

from typing import TYPE_CHECKING

from hermes_windows_bridge.worker.emergency_audit import LocalEmergencyStopAudit

if TYPE_CHECKING:
    from pathlib import Path


def test_local_emergency_stop_audit_persists_only_redacted_local_metadata(tmp_path: Path) -> None:
    # Given: Gateway와 공유하지 않는 임시 Worker audit root입니다.
    root = tmp_path / "worker-audit"
    audit = LocalEmergencyStopAudit(root)

    # When: local emergency stop activation을 기록합니다.
    audit.record_activation()

    # Then: 고정된 event 종류만 redacted JSONL로 남습니다.
    records = tuple(root.glob("audit-*.jsonl"))
    assert len(records) == 1
    content = records[0].read_text(encoding="utf-8")
    assert '"tool_name":"local_emergency_stop"' in content
    assert "local_hotkey" not in content
    assert "Ctrl" not in content
