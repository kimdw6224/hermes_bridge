from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from hermes_windows_bridge.gateway import policy

NOW = datetime(2026, 9, 5, tzinfo=UTC)
OPERATION_ID = UUID("018f0000-0000-7000-8000-000000000001")


class TestToolPolicy:
    def test_every_registered_tool_has_complete_annotations(self) -> None:
        # Given: 전체 Bridge 도구 정책 레지스트리
        registry = policy.tool_policy_registry()

        # When: 각 도구의 annotation을 직렬화하면
        annotations = [entry.annotations.model_dump(by_alias=True) for entry in registry]

        # Then: 네 가지 MCP 힌트가 모두 명시되어 있다.
        assert annotations
        assert all(
            set(item) >= {"readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"}
            for item in annotations
        )

    @pytest.mark.parametrize("tool_name", ["system_reboot", "system_shutdown"])
    def test_privileged_power_action_requires_approval_despite_forged_annotations(
        self, tool_name: str
    ) -> None:
        # Given: readOnlyHint를 거짓으로 조작한 고위험 도구명
        forged = policy.ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        )

        # When: Bridge 내부 정책으로 분류하면
        decision = policy.evaluate_tool(tool_name, forged)

        # Then: annotation과 무관하게 별도 사용자 승인이 필요하다.
        assert decision is policy.PolicyDecision.REQUIRE_APPROVAL

    def test_fs_delete_is_only_destructive_until_task_10_adds_bulk_threshold_context(self) -> None:
        # Given: bulk context가 아직 계산되지 않은 fs_delete 기본 정책
        tool_policy = next(
            entry for entry in policy.tool_policy_registry() if entry.name == "fs_delete"
        )

        # When: Task 4 정적 정책을 평가하면
        decision = policy.evaluate_tool("fs_delete")

        # Then: destructive 분류는 유지하되 Task 10의 bulk threshold 전에는 승인을 요구하지 않는다.
        assert tool_policy.operation_class is policy.OperationClass.DESTRUCTIVE
        assert tool_policy.annotations.destructive_hint is True
        assert tool_policy.approval_required is False
        assert decision is policy.PolicyDecision.ALLOW

    def test_arbitrary_job_start_is_destructive_open_world_and_requires_approval(self) -> None:
        tool_policy = next(
            entry for entry in policy.tool_policy_registry() if entry.name == "job_start"
        )

        assert tool_policy.operation_class is policy.OperationClass.DESTRUCTIVE
        assert tool_policy.annotations.read_only_hint is False
        assert tool_policy.annotations.destructive_hint is True
        assert tool_policy.annotations.open_world_hint is True
        assert tool_policy.approval_required is True
        assert policy.evaluate_tool("job_start") is policy.PolicyDecision.REQUIRE_APPROVAL

    @pytest.mark.parametrize("tool_name", ["process_kill", "job_cancel"])
    def test_destructive_lifecycle_action_is_allowed_when_not_in_approval_categories(
        self, tool_name: str
    ) -> None:
        # Given: spec 12 approval.required_for에 없는 process/job 종료 작업
        tool_policy = next(
            entry for entry in policy.tool_policy_registry() if entry.name == tool_name
        )

        # When: 기본 정책을 평가하면
        decision = policy.evaluate_tool(tool_name)

        # Then: destructive metadata는 유지되고 별도 승인 없이 허용된다.
        assert tool_policy.operation_class is policy.OperationClass.DESTRUCTIVE
        assert tool_policy.annotations.destructive_hint is True
        assert tool_policy.approval_required is False
        assert decision is policy.PolicyDecision.ALLOW


class TestApprovalLifecycle:
    def test_hard_denied_operation_cannot_enter_approval_flow(self) -> None:
        # Given: 승인을 받아도 허용하면 안 되는 hard-deny 작업
        manager = policy.ApprovalManager()

        # When/Then: 승인 요청 생성 자체가 fail-closed 한다.
        with pytest.raises(policy.PolicyDeniedError):
            _ = manager.request(
                policy.ApprovalSubmission(
                    operation_id=OPERATION_ID,
                    tool_name="arbitrary_system_shell",
                    payload={"command": "whoami"},
                    requested_at=NOW,
                    expires_at=NOW + timedelta(minutes=5),
                )
            )

    def test_approval_freezes_exact_payload_and_is_one_shot(self) -> None:
        # Given: 사용자 승인이 필요한 payload와 승인 요청
        manager = policy.ApprovalManager()
        request = manager.request(
            policy.ApprovalSubmission(
                operation_id=OPERATION_ID,
                tool_name="system_reboot",
                payload={"delay_s": 30, "reason": "maintenance"},
                requested_at=NOW,
                expires_at=NOW + timedelta(minutes=5),
            )
        )
        _ = manager.decide(
            policy.ApprovalDecision(
                approval_id=request.approval_id,
                approved=True,
                method=policy.ApprovalMethod.ELICITATION,
                decided_at=NOW + timedelta(seconds=1),
            )
        )

        # When: 승인된 동일 payload를 소비하면
        approved = manager.consume(
            policy.ApprovalAttempt(
                approval_id=request.approval_id,
                payload={"reason": "maintenance", "delay_s": 30},
                attempted_at=NOW + timedelta(seconds=2),
            )
        )

        # Then: canonical payload가 반환되고 같은 승인은 다시 소비할 수 없다.
        assert approved.canonical_payload == b'{"delay_s":30,"reason":"maintenance"}'
        with pytest.raises(policy.ApprovalConsumedError):
            _ = manager.consume(
                policy.ApprovalAttempt(
                    approval_id=request.approval_id,
                    payload={"delay_s": 30, "reason": "maintenance"},
                    attempted_at=NOW + timedelta(seconds=3),
                )
            )

    def test_changed_or_expired_payload_is_rejected(self) -> None:
        # Given: 승인된 뒤 만료된 요청
        manager = policy.ApprovalManager()
        request = manager.request(
            policy.ApprovalSubmission(
                operation_id=OPERATION_ID,
                tool_name="system_shutdown",
                payload={"delay_s": 10},
                requested_at=NOW,
                expires_at=NOW + timedelta(seconds=5),
            )
        )
        _ = manager.decide(
            policy.ApprovalDecision(
                approval_id=request.approval_id,
                approved=True,
                method=policy.ApprovalMethod.LOCAL,
                decided_at=NOW + timedelta(seconds=1),
            )
        )

        # When/Then: 변경 payload와 만료 시점 소비는 각각 거부된다.
        with pytest.raises(policy.ApprovalPayloadMismatchError):
            _ = manager.consume(
                policy.ApprovalAttempt(
                    approval_id=request.approval_id,
                    payload={"delay_s": 11},
                    attempted_at=NOW + timedelta(seconds=2),
                )
            )
        with pytest.raises(policy.ApprovalExpiredError):
            _ = manager.consume(
                policy.ApprovalAttempt(
                    approval_id=request.approval_id,
                    payload={"delay_s": 10},
                    attempted_at=NOW + timedelta(seconds=6),
                )
            )

    def test_denied_request_cannot_resume_without_new_approval(self) -> None:
        # Given: 사용자가 거부한 승인 요청
        manager = policy.ApprovalManager()
        request = manager.request(
            policy.ApprovalSubmission(
                operation_id=OPERATION_ID,
                tool_name="system_reboot",
                payload={"delay_s": 0},
                requested_at=NOW,
                expires_at=NOW + timedelta(minutes=5),
            )
        )
        _ = manager.decide(
            policy.ApprovalDecision(
                approval_id=request.approval_id,
                approved=False,
                method=policy.ApprovalMethod.LOCAL,
                decided_at=NOW + timedelta(seconds=1),
            )
        )

        # When/Then: resume에 해당하는 소비는 거부된다.
        with pytest.raises(policy.ApprovalDeniedError):
            _ = manager.consume(
                policy.ApprovalAttempt(
                    approval_id=request.approval_id,
                    payload={"delay_s": 0},
                    attempted_at=NOW + timedelta(seconds=2),
                )
            )

    def test_wrong_operation_does_not_burn_valid_receipt(self) -> None:
        # Given: exact tool/payload에 승인된 receipt입니다.
        manager = policy.ApprovalManager()
        request = manager.request(
            policy.ApprovalSubmission(
                operation_id=OPERATION_ID,
                tool_name="system_reboot",
                payload={"delay_s": 0},
                requested_at=NOW,
                expires_at=NOW + timedelta(minutes=5),
            )
        )
        _ = manager.decide(
            policy.ApprovalDecision(
                approval_id=request.approval_id,
                approved=True,
                method=policy.ApprovalMethod.LOCAL,
                decided_at=NOW + timedelta(seconds=1),
            )
        )

        # When/Then: 다른 operation의 시도는 거부되고 원래 receipt는 여전히 소비됩니다.
        with pytest.raises(policy.ApprovalBindingMismatchError):
            _ = manager.consume(
                policy.ApprovalAttempt(
                    approval_id=request.approval_id,
                    operation_id=uuid4(),
                    tool_name="system_reboot",
                    payload={"delay_s": 0},
                    attempted_at=NOW + timedelta(seconds=2),
                )
            )
        approved = manager.consume(
            policy.ApprovalAttempt(
                approval_id=request.approval_id,
                operation_id=OPERATION_ID,
                tool_name="system_reboot",
                payload={"delay_s": 0},
                attempted_at=NOW + timedelta(seconds=3),
            )
        )
        assert approved.operation_id == OPERATION_ID


def test_malformed_approval_input_fails_at_boundary() -> None:
    # Given/When/Then: canonical JSON이 아닌 NaN 입력은 typed boundary에서 거부된다.
    with pytest.raises(policy.ValidationError):
        _ = policy.ApprovalSubmission(
            operation_id=OPERATION_ID,
            tool_name="system_reboot",
            payload={"delay_s": float("nan")},
            requested_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
        )
