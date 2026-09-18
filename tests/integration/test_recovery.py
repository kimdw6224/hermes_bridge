from __future__ import annotations

import sys
import time
from datetime import UTC, datetime, timedelta
from os import utime
from threading import Event
from typing import TYPE_CHECKING, Protocol, final
from uuid import UUID, uuid4

import pytest

from hermes_windows_bridge.gateway import audit
from hermes_windows_bridge.gateway.job_models import (
    JobKind,
    JobLimits,
    JobSnapshot,
    JobSpec,
    JobState,
)
from hermes_windows_bridge.gateway.job_store import JobStore
from hermes_windows_bridge.gateway.jobs import JobRegistry
from hermes_windows_bridge.worker.job_process import RunningJobProcess
from hermes_windows_bridge.worker.main import (
    WatchdogDependencies,
    WatchdogPolicy,
    WorkerWatchdog,
)

if TYPE_CHECKING:
    from pathlib import Path


class _Runtime(Protocol):
    def run(self, stop: Event) -> None:
        ...

    def close(self) -> None:
        ...


def _wait_for_job_state(registry: JobRegistry, job_id: UUID, state: JobState) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and registry.status(job_id).state is not state:
        time.sleep(0.01)
    assert registry.status(job_id).state is state


class _RecoveringRuntime:
    def __init__(self, stop: Event) -> None:
        self.stop: Event = stop
        self.closed: bool = False

    def run(self, stop: Event) -> None:
        assert stop is self.stop
        stop.set()

    def close(self) -> None:
        self.closed = True


class _FailingRuntime:
    def run(self, stop: Event) -> None:
        del stop
        raise OSError

    def close(self) -> None:
        return


@final
class _RuntimeFactory:
    def __init__(self, stop: Event) -> None:
        self._stop: Event = stop
        self.created: int = 0
        self.recovered: _RecoveringRuntime | None = None

    def __call__(self) -> _Runtime:
        self.created += 1
        if self.created == 1:
            return _FailingRuntime()
        self.recovered = _RecoveringRuntime(self._stop)
        return self.recovered


@pytest.mark.integration
def test_worker_watchdog_reconnects_after_typed_failure_and_closes_stale_runtime() -> None:
    # Given: 첫 Worker runtime의 typed pipe 실패와 즉시 성공하는 재연결 runtime입니다.
    stop = Event()
    delays: list[float] = []
    factory = _RuntimeFactory(stop)
    watchdog = WorkerWatchdog(
        policy=WatchdogPolicy(
            initial_backoff_seconds=0.01,
            max_backoff_seconds=0.02,
            jitter_cap_seconds=0.01,
        ),
        dependencies=WatchdogDependencies(
            runtime_factory=factory,
            wait=lambda delay: delays.append(delay) or stop.wait(0),
            jitter=lambda cap: cap,
        ),
    )

    # When: watchdog를 실행하면
    receipt = watchdog.run(stop)

    # Then: 실패 로그가 아닌 reconnect와 cleanup 관찰값으로만 성공을 판정합니다.
    assert factory.created == 2
    assert factory.recovered is not None
    assert factory.recovered.closed
    assert receipt.recoverable_failures == 1
    assert receipt.last_failure == "os_error"
    assert delays == [0.02]


@pytest.mark.integration
def test_reboot_resume_and_retention_cleanup_remove_stale_job_state(tmp_path: Path) -> None:
    # Given: reboot 직전 queued metadata가 durable store에 남아 있습니다.
    root = tmp_path / "jobs"
    job_id = uuid4()
    operation_id = uuid4()
    snapshot = JobSnapshot(
        job_id=job_id,
        operation_id=operation_id,
        request_digest="0" * 64,
        kind=JobKind.PROCESS,
        state=JobState.QUEUED,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    store = JobStore(root, retention=timedelta(hours=1))
    store.write_snapshot(snapshot)
    # When: 새 registry가 reboot-resume snapshot을 복구하면
    with JobRegistry(
        root,
        process_factory=RunningJobProcess,
        limits=JobLimits(retention=timedelta(hours=1)),
    ) as registry:
        recovered = registry.status(job_id)

    # Then: 재기동 전 실행 상태는 실제 read-back에서 interrupted로 고정됩니다.
    assert recovered.state is JobState.INTERRUPTED
    assert JobStore(root, retention=timedelta(hours=1)).load() == (recovered,)


@pytest.mark.integration
def test_public_retention_cleanup_removes_expired_job_body_and_preserves_audit_metadata(
    tmp_path: Path,
) -> None:
    # Given: 실제 registry output body와 redacted audit metadata가 서로 분리되어 있습니다.
    jobs_root = tmp_path / "jobs"
    audit_store = audit.AuditJsonlStore(tmp_path / "audit", retention=timedelta(hours=1))
    recorder = audit.AuditRecorder(store=audit_store)
    event = recorder.record(
        audit.AuditInput(
            event_id=uuid4(),
            occurred_at=datetime.now(UTC),
            tool_name="job_start",
            operation_id=uuid4(),
            payload={"secret": "retention-secret"},
            outcome=audit.AuditOutcome.SUCCEEDED,
            stdout="retention-sensitive-output",
        )
    )
    legacy_body = tmp_path / "audit" / "legacy.stdout.body"
    _ = legacy_body.write_text("retention-sensitive-output", encoding="utf-8")
    expired_timestamp = (datetime.now(UTC) - timedelta(hours=2)).timestamp()
    utime(legacy_body, (expired_timestamp, expired_timestamp))
    with JobRegistry(
        jobs_root,
        process_factory=RunningJobProcess,
        limits=JobLimits(retention=timedelta(milliseconds=1)),
    ) as registry:
        started = registry.start(
            JobSpec(
                operation_id=uuid4(),
                kind=JobKind.PROCESS,
                argv=(sys.executable, "-c", "print('retention-sensitive-output')"),
                cwd=tmp_path,
            )
        )
        _wait_for_job_state(registry, started.job_id, JobState.SUCCEEDED)
        output = registry.output(started.job_id, stream="stdout", offset=0, limit=128)
        assert output.data.strip() == "retention-sensitive-output"
        time.sleep(0.02)
        receipt = registry.cleanup_retention()
        with pytest.raises(LookupError):
            _ = registry.status(started.job_id)

    # Then: registry body는 삭제되고, audit의 redacted metadata만 read-back됩니다.
    audit_receipt = audit_store.cleanup_expired_sensitive_artifacts(datetime.now(UTC))
    persisted = audit_store.path_for(event.occurred_at).read_text(encoding="utf-8")
    assert receipt.removed_job_ids == (started.job_id,)
    assert not JobStore(jobs_root, retention=timedelta(hours=1)).output_path(
        started.job_id, "stdout"
    ).exists()
    assert audit_receipt.deleted_paths == (legacy_body,)
    assert str(event.event_id) in persisted
    assert "retention-secret" not in persisted
    assert "retention-sensitive-output" not in persisted


@pytest.mark.integration
def test_failed_job_audit_never_infers_success_from_output(tmp_path: Path) -> None:
    # Given: stdout에는 success라고 쓰지만 exit code는 실패인 실제 process입니다.
    recorder = audit.AuditRecorder()
    with JobRegistry(
        tmp_path / "jobs", process_factory=RunningJobProcess, audit=recorder
    ) as registry:
        started = registry.start(
            JobSpec(
                operation_id=uuid4(),
                kind=JobKind.PROCESS,
                argv=(sys.executable, "-c", "print('success');raise SystemExit(7)"),
                cwd=tmp_path,
            )
        )
        _wait_for_job_state(registry, started.job_id, JobState.FAILED)

    # Then: success-looking output가 아닌 terminal state가 audit outcome과 typed error를 결정합니다.
    completion = recorder.records[-1]
    assert completion.outcome is audit.AuditOutcome.FAILED
    assert completion.error_code is audit.AuditErrorCode.JOB_FAILED
    assert completion.stdout is not None
