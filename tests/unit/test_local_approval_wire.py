from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from pydantic import ValidationError

from hermes_windows_bridge.ipc.local_approval import (
    LocalApprovalPowerSummary,
    LocalApprovalWireRequest,
)

NOW = datetime(2026, 9, 7, tzinfo=UTC)


def _request() -> LocalApprovalWireRequest:
    return LocalApprovalWireRequest(
        request_id=UUID("018f0000-0000-7000-8000-000000000101"),
        approval_id=UUID("018f0000-0000-7000-8000-000000000102"),
        operation_id=UUID("018f0000-0000-7000-8000-000000000103"),
        tool_name="system_shutdown",
        payload_digest="a" * 64,
        expires_at=NOW + timedelta(seconds=30),
        summary=LocalApprovalPowerSummary(
            action="shutdown",
            delay_seconds=0,
            reason="maintenance",
        ),
    )


def test_local_approval_wire_is_immutable_and_contains_only_typed_power_summary() -> None:
    # Given: exact correlation과 typed shutdown summary입니다.
    request = _request()

    # When: wire 모델을 JSON mode로 직렬화합니다.
    payload = request.model_dump(mode="json")

    # Then: 원문 canonical payload 없이 immutable correlation과 summary만 남습니다.
    assert request.model_copy() == request
    assert payload["operation_id"] == str(request.operation_id)
    assert payload["summary"] == {
        "action": "shutdown",
        "delay_seconds": 0,
        "reason": "maintenance",
    }
    assert "canonical_payload" not in payload


def test_local_approval_wire_rejects_action_tool_mismatch_and_naive_expiry() -> None:
    # Given: reboot summary에 shutdown tool을 결합한 payload와 naive expiry입니다.
    mismatched = _request().model_dump()
    mismatched["summary"] = {
        "action": "reboot",
        "delay_seconds": 0,
        "reason": "maintenance",
    }
    naive = _request().model_dump()
    naive["expires_at"] = "2026-09-07T00:00:00"

    # When/Then: action/tool correlation과 timezone-aware expiry가 각각 거부됩니다.
    with pytest.raises(ValidationError):
        _ = LocalApprovalWireRequest.model_validate(mismatched)
    with pytest.raises(ValidationError):
        _ = LocalApprovalWireRequest.model_validate(naive)


def test_local_approval_wire_rejects_extra_and_unbounded_power_fields() -> None:
    # Given: unknown field와 policy bound 밖 delay/reason을 가진 untrusted payload입니다.
    extra = _request().model_dump()
    extra["extra"] = "forbidden"
    invalid_summary = _request().model_dump()
    invalid_summary["summary"] = {
        "action": "shutdown",
        "delay_seconds": 301,
        "reason": "",
    }

    # When/Then: strict wire boundary가 모두 reject합니다.
    with pytest.raises(ValidationError):
        _ = LocalApprovalWireRequest.model_validate(extra)
    with pytest.raises(ValidationError):
        _ = LocalApprovalWireRequest.model_validate(invalid_summary)
