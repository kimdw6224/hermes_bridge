"""Terminal job state를 감사 결과로 fail-closed 변환합니다."""

# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

from typing import assert_never

from hermes_windows_bridge.gateway.audit import AuditErrorCode, AuditOutcome
from hermes_windows_bridge.gateway.job_models import JobState


class InvalidTerminalJobStateError(ValueError):
    """Active job 상태를 완료 audit으로 기록하려 했습니다."""



type TerminalAuditStatus = tuple[AuditOutcome, AuditErrorCode | None]


def for_terminal_state(state: JobState) -> TerminalAuditStatus:
    """Terminal state만 audit에 기록하도록 total mapping합니다."""
    match state:
        case JobState.SUCCEEDED:
            return AuditOutcome.SUCCEEDED, None
        case JobState.FAILED:
            return AuditOutcome.FAILED, AuditErrorCode.JOB_FAILED
        case JobState.CANCELLED:
            return AuditOutcome.REJECTED, AuditErrorCode.JOB_CANCELLED
        case JobState.INTERRUPTED:
            return AuditOutcome.REJECTED, AuditErrorCode.JOB_INTERRUPTED
        case JobState.QUEUED | JobState.RUNNING:
            raise InvalidTerminalJobStateError(state)
        case unexpected:
            assert_never(unexpected)
