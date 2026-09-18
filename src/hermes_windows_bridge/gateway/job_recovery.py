"""Durable Job metadata의 reboot recovery와 retention receipt입니다."""

# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, assert_never

from hermes_windows_bridge.gateway import job_models
from hermes_windows_bridge.gateway.job_models import JobSnapshot, JobState

if TYPE_CHECKING:
    from collections.abc import Iterable
    from datetime import datetime
    from uuid import UUID


class JobSnapshotStore(Protocol):
    """Recovery가 필요한 durable snapshot I/O의 최소 경계입니다."""

    def load(self) -> tuple[JobSnapshot, ...]:
        """Retention을 적용한 durable snapshot을 반환합니다."""
        raise NotImplementedError

    def write_snapshot(self, snapshot: JobSnapshot) -> None:
        """복구한 snapshot을 durable metadata에 반영합니다."""
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class RecoveryResult:
    """Reboot 뒤 복구된 snapshot과 stale 실행 ID를 분리합니다."""

    snapshots: tuple[JobSnapshot, ...]
    interrupted_job_ids: tuple[UUID, ...]


@dataclass(frozen=True, slots=True)
class RetentionCleanupReceipt:
    """만료 disk artifact cleanup의 metadata-only receipt입니다."""

    removed_job_ids: tuple[UUID, ...]
    retained_job_ids: tuple[UUID, ...]


@dataclass(frozen=True, slots=True)
class RecoveredRegistryState:
    """Registry가 소유할 reboot-resume metadata와 idempotency index입니다."""

    records: dict[UUID, job_models.JobRecord]
    operation_jobs: dict[UUID, tuple[UUID, str]]


def recover_snapshots(snapshots: Iterable[JobSnapshot], now: datetime) -> RecoveryResult:
    """재시작 시 process handle이 없는 active snapshot만 interrupted로 고정합니다."""
    original = tuple(snapshots)
    recovered = tuple(_interrupt_stale_snapshot(snapshot, now) for snapshot in original)
    return RecoveryResult(
        snapshots=recovered,
        interrupted_job_ids=tuple(
            snapshot.job_id
            for snapshot in original
            if snapshot.state in {JobState.QUEUED, JobState.RUNNING}
        ),
    )


def retention_cleanup_receipt(
    previous_ids: Iterable[UUID], retained_ids: Iterable[UUID]
) -> RetentionCleanupReceipt:
    """Disk retention 이후 메모리에서 제거할 ID를 deterministic하게 계산합니다."""
    previous = frozenset(previous_ids)
    retained = tuple(sorted(frozenset(retained_ids), key=str))
    return RetentionCleanupReceipt(
        removed_job_ids=tuple(sorted(previous - frozenset(retained), key=str)),
        retained_job_ids=retained,
    )


def recover_store(store: JobSnapshotStore, now: datetime) -> RecoveredRegistryState:
    """Stale active snapshot을 durable interrupted 상태로 고정하고 index를 재구성합니다."""
    result = recover_snapshots(store.load(), now)
    for snapshot in result.snapshots:
        if snapshot.job_id in result.interrupted_job_ids:
            store.write_snapshot(snapshot)
    return RecoveredRegistryState(
        records={snapshot.job_id: job_models.JobRecord(snapshot) for snapshot in result.snapshots},
        operation_jobs={
            snapshot.operation_id: (snapshot.job_id, snapshot.request_digest)
            for snapshot in result.snapshots
        },
    )


def cleanup_retained_state(
    store: JobSnapshotStore, state: RecoveredRegistryState
) -> tuple[RetentionCleanupReceipt, RecoveredRegistryState]:
    """Disk retention이 지운 terminal ID만 in-memory catalog에서 제거합니다."""
    receipt = retention_cleanup_receipt(
        state.records,
        (snapshot.job_id for snapshot in store.load()),
    )
    retained = frozenset(receipt.retained_job_ids)
    return receipt, RecoveredRegistryState(
        records={job_id: record for job_id, record in state.records.items() if job_id in retained},
        operation_jobs={
            operation_id: value
            for operation_id, value in state.operation_jobs.items()
            if value[0] in retained
        },
    )


def _interrupt_stale_snapshot(snapshot: JobSnapshot, now: datetime) -> JobSnapshot:
    """Queued/running process reference는 reboot 뒤 신뢰할 수 없으므로 중단 처리합니다."""
    match snapshot.state:
        case JobState.QUEUED | JobState.RUNNING:
            return snapshot.model_copy(
                update={"state": JobState.INTERRUPTED, "pid": None, "updated_at": now}
            )
        case JobState.SUCCEEDED | JobState.FAILED | JobState.CANCELLED | JobState.INTERRUPTED:
            return snapshot
        case unreachable:
            assert_never(unreachable)
