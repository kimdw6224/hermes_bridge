"""Dispatch 이전에 적용하는 정책과 독립 사용자 승인 수명주기입니다."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, assert_never, override
from uuid import UUID, uuid4

from pydantic import ValidationError

from hermes_windows_bridge.gateway.approval_coordinator import (
    ApprovalCoordinator,
    ApprovalReceipt,
    ApprovalSurface,
    ApprovalSurfaceUnavailableError,
)
from hermes_windows_bridge.models.policy import (
    ApprovalAttempt,
    ApprovalBindingMismatchError,
    ApprovalConsumedError,
    ApprovalDecision,
    ApprovalDeniedError,
    ApprovalExpiredError,
    ApprovalMethod,
    ApprovalNotFoundError,
    ApprovalPayloadMismatchError,
    ApprovalPendingError,
    ApprovalRecord,
    ApprovalState,
    ApprovalStateError,
    ApprovalSubmission,
    ApprovedPayload,
    OperationClass,
    PolicyDecision,
    ToolAnnotations,
    ToolPolicy,
    canonicalize_payload,
    payload_digest,
)

__all__ = [
    "PROHIBITED_TOOL_NAMES", "ApprovalAttempt", "ApprovalBindingMismatchError",
    "ApprovalConsumedError", "ApprovalCoordinator",
    "ApprovalDecision", "ApprovalDeniedError", "ApprovalExpiredError", "ApprovalManager",
    "ApprovalMethod", "ApprovalPayloadMismatchError", "ApprovalReceipt", "ApprovalSubmission",
    "ApprovalSurface", "ApprovalSurfaceUnavailableError", "OperationClass", "PolicyDecision",
    "PolicyDeniedError", "ToolAnnotations", "UnknownToolError", "ValidationError", "evaluate_tool",
    "registered_tool_names", "tool_policy_registry",
]

PROHIBITED_TOOL_NAMES: Final = frozenset(
    "approval_grant approval_deny approval_list approve deny".split()  # noqa: SIM905
)
HARD_DENY_OPERATION_NAMES: Final = frozenset("credential_store_export windows_logon_bypass uac_secure_desktop_automation arbitrary_system_shell raw_disk_device_access".split())  # noqa: E501, SIM905
_READ_ONLY: Final = frozenset("status fs_list fs_stat fs_read process_list computer_observe uia_find browser_status browser_snapshot browser_extract codex_status job_status job_output".split())  # noqa: E501, SIM905
_DESTRUCTIVE: Final = frozenset(
    "fs_delete process_kill job_start job_cancel system_reboot system_shutdown".split()  # noqa: SIM905
)
_PRIVILEGED: Final = frozenset("system_reboot system_shutdown".split())  # noqa: SIM905
_EXPIRED: Final = ApprovalState.EXPIRED
_OPEN_WORLD: Final = frozenset("shell_run browser_status browser_open browser_navigate browser_snapshot browser_click browser_type browser_extract browser_close codex_run job_start".split())  # noqa: E501, SIM905
_IDEMPOTENT: Final = _READ_ONLY | _DESTRUCTIVE | frozenset(
    "fs_write fs_mkdir computer_move browser_close system_lock system_sleep".split()  # noqa: SIM905
)
_TOOL_NAMES: Final = tuple("status shell_run fs_list fs_stat fs_read fs_write fs_move fs_copy fs_delete fs_mkdir process_list process_start process_kill app_open computer_observe computer_click computer_move computer_scroll computer_type computer_hotkey computer_key uia_find uia_action browser_status browser_open browser_navigate browser_snapshot browser_click browser_type browser_extract browser_close codex_status codex_run job_start job_status job_output job_cancel system_lock system_reboot system_shutdown system_sleep".split())  # noqa: E501, SIM905


def _operation_class(tool_name: str) -> OperationClass:
    if tool_name in _READ_ONLY:
        return OperationClass.READ_ONLY
    if tool_name in _PRIVILEGED:
        return OperationClass.PRIVILEGED
    if tool_name in _DESTRUCTIVE:
        return OperationClass.DESTRUCTIVE
    return OperationClass.USER_MUTATION


_TOOL_POLICIES: Final = tuple(
    ToolPolicy(
        name=name,
        operation_class=_operation_class(name),
        annotations=ToolAnnotations(
            readOnlyHint=name in _READ_ONLY,
            destructiveHint=name in _DESTRUCTIVE,
            idempotentHint=name in _IDEMPOTENT,
            openWorldHint=name in _OPEN_WORLD,
        ),
        # destructiveHint는 행위 성격이고 승인은 spec 12의 독립 범주입니다.
        approval_required=name in (_PRIVILEGED | frozenset({"job_start"})),
    )
    for name in _TOOL_NAMES
)
_POLICY_BY_NAME: Final = {entry.name: entry for entry in _TOOL_POLICIES}


def tool_policy_registry() -> tuple[ToolPolicy, ...]:
    """등록 가능한 모든 도구의 immutable 정책을 반환합니다."""
    return _TOOL_POLICIES


def registered_tool_names() -> frozenset[str]:
    """모델에 노출 가능한 도구명만 반환합니다."""
    return frozenset(_POLICY_BY_NAME)


def evaluate_tool(
    tool_name: str,
    claimed_annotations: ToolAnnotations | None = None,
) -> PolicyDecision:
    """Annotation/destructive 분류와 독립된 approval_required 정책을 평가합니다."""
    del claimed_annotations
    if tool_name in PROHIBITED_TOOL_NAMES:
        raise UnknownToolError(tool_name=tool_name)
    if tool_name in HARD_DENY_OPERATION_NAMES:
        return PolicyDecision.DENY
    entry = _POLICY_BY_NAME.get(tool_name)
    if entry is None:
        raise UnknownToolError(tool_name=tool_name)
    if entry.approval_required:
        return PolicyDecision.REQUIRE_APPROVAL
    return PolicyDecision.ALLOW


class ApprovalManager:
    """독립 승인 결정을 mutable 상태로 관리하고 exact payload를 한 번만 소비합니다."""

    def __init__(self) -> None:
        """빈 승인 상태 저장소를 초기화합니다."""
        self._records: dict[UUID, ApprovalRecord] = {}

    def request(self, submission: ApprovalSubmission) -> ApprovalRecord:
        """검증된 요청의 canonical payload를 immutable record로 고정합니다."""
        decision = evaluate_tool(submission.tool_name)
        match decision:
            case PolicyDecision.DENY:
                raise PolicyDeniedError(tool_name=submission.tool_name)
            case PolicyDecision.ALLOW | PolicyDecision.REQUIRE_APPROVAL:
                pass
            case _:
                assert_never(decision)
        canonical_payload = canonicalize_payload(submission.payload)
        record = ApprovalRecord(
            approval_id=uuid4(),
            operation_id=submission.operation_id,
            tool_name=submission.tool_name,
            canonical_payload=canonical_payload,
            payload_digest=payload_digest(canonical_payload),
            requested_at=submission.requested_at,
            expires_at=submission.expires_at,
            state=ApprovalState.PENDING,
        )
        self._records[record.approval_id] = record
        return record

    def decide(self, decision: ApprovalDecision) -> ApprovalRecord:
        """독립 elicitation/local 사용자 결정을 pending record에 적용합니다."""
        record = self._get(decision.approval_id)
        if decision.decided_at >= record.expires_at:
            self._records[record.approval_id] = record.model_copy(update={"state": _EXPIRED})
            raise ApprovalExpiredError(approval_id=record.approval_id)
        if record.state is not ApprovalState.PENDING:
            raise ApprovalStateError(approval_id=record.approval_id, state=record.state)
        state = ApprovalState.APPROVED if decision.approved else ApprovalState.DENIED
        updated = record.model_copy(update={"state": state, "method": decision.method})
        self._records[record.approval_id] = updated
        return updated

    def consume(self, attempt: ApprovalAttempt) -> ApprovedPayload:
        """승인된 exact payload를 한 번만 dispatch 가능 상태로 전환합니다."""
        record = self._get(attempt.approval_id)
        if attempt.attempted_at >= record.expires_at:
            self._records[record.approval_id] = record.model_copy(update={"state": _EXPIRED})
            raise ApprovalExpiredError(approval_id=record.approval_id)
        canonical_payload = canonicalize_payload(attempt.payload)
        if (
            attempt.operation_id is not None and record.operation_id != attempt.operation_id
        ) or (attempt.tool_name is not None and record.tool_name != attempt.tool_name):
            raise ApprovalBindingMismatchError(approval_id=record.approval_id)
        if canonical_payload != record.canonical_payload:
            raise ApprovalPayloadMismatchError(approval_id=record.approval_id)
        match record.state:
            case ApprovalState.APPROVED:
                method = record.method
                if method is None:
                    raise ApprovalStateError(approval_id=record.approval_id, state=record.state)
                self._records[record.approval_id] = record.model_copy(
                    update={"state": ApprovalState.CONSUMED}
                )
                return ApprovedPayload(
                    operation_id=record.operation_id,
                    tool_name=record.tool_name,
                    canonical_payload=record.canonical_payload,
                    payload_digest=record.payload_digest,
                    approval_method=method,
                )
            case ApprovalState.CONSUMED:
                raise ApprovalConsumedError(approval_id=record.approval_id)
            case ApprovalState.DENIED:
                raise ApprovalDeniedError(approval_id=record.approval_id)
            case ApprovalState.EXPIRED:
                raise ApprovalExpiredError(approval_id=record.approval_id)
            case ApprovalState.PENDING:
                raise ApprovalPendingError(approval_id=record.approval_id)
            case _:
                assert_never(record.state)

    def _get(self, approval_id: UUID) -> ApprovalRecord:
        record = self._records.get(approval_id)
        if record is None:
            raise ApprovalNotFoundError(approval_id=approval_id)
        return record

@dataclass(frozen=True, slots=True)
class UnknownToolError(LookupError):
    """등록되지 않았거나 원격 노출이 금지된 도구입니다."""

    tool_name: str

    @override
    def __str__(self) -> str:
        """거부된 도구명을 포함합니다."""
        return f"unknown tool: {self.tool_name}"


@dataclass(frozen=True, slots=True)
class PolicyDeniedError(PermissionError):
    """승인 여부와 관계없이 hard-deny된 작업입니다."""

    tool_name: str

    @override
    def __str__(self) -> str:
        """거부된 작업명을 포함합니다."""
        return f"operation is hard-denied: {self.tool_name}"
