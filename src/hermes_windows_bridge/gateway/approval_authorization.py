"""승인 정책 평가와 one-shot consume을 호출-local audit provenance로 묶습니다."""

# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, assert_never

from hermes_windows_bridge.gateway import policy as policy_api
from hermes_windows_bridge.gateway.audit import ApprovalAuditMetadata
from hermes_windows_bridge.gateway.policy import (
    ApprovalAttempt,
    ApprovalManager,
    UnknownToolError,
)
from hermes_windows_bridge.models.policy import (
    ApprovalLifecycleError,
    ApprovalNotFoundError,
    PolicyDecision,
)

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from hermes_windows_bridge.ipc.protocol import JsonPayload

type AuthorizationResult = ApprovalAuditMetadata | str | None


class AuthorizationCall(Protocol):
    """승인 평가에 필요한 dispatch call의 최소 shape입니다."""

    operation_id: UUID
    tool_name: str
    payload: JsonPayload
    requested_at: datetime
    approval_id: UUID | None


def authorize(call: AuthorizationCall, approvals: ApprovalManager) -> AuthorizationResult:
    """검증된 receipt를 소비한 경우에만 provenance를 반환합니다."""
    try:
        decision = policy_api.evaluate_tool(call.tool_name)
    except UnknownToolError:
        return "policy_denied"
    match decision:
        case PolicyDecision.ALLOW:
            return None
        case PolicyDecision.DENY:
            return "policy_denied"
        case PolicyDecision.REQUIRE_APPROVAL:
            if call.approval_id is None:
                return "approval_required"
            try:
                approved = approvals.consume(
                    ApprovalAttempt(
                        approval_id=call.approval_id,
                        operation_id=call.operation_id,
                        tool_name=call.tool_name,
                        payload=call.payload,
                        attempted_at=call.requested_at,
                    )
                )
            except (ApprovalLifecycleError, ApprovalNotFoundError):
                return "approval_invalid"
            return ApprovalAuditMetadata(
                approval_id=call.approval_id,
                method=approved.approval_method,
                frozen_payload_digest=approved.payload_digest,
            )
        case unreachable:
            assert_never(unreachable)
