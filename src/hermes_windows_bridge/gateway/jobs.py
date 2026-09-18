"""MCP 재연결과 독립적인 bounded background job registry입니다."""

# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractContextManager
from datetime import UTC, datetime, timedelta
from threading import RLock
from typing import TYPE_CHECKING, assert_never, final, override
from uuid import UUID, uuid4

from hermes_windows_bridge.gateway import audit as audit_api
from hermes_windows_bridge.gateway import job_audit, job_models, job_recovery, job_store
from hermes_windows_bridge.gateway.job_models import JobState
from hermes_windows_bridge.worker.job_process import JobProcessSpec

if TYPE_CHECKING:
    from pathlib import Path
    from types import TracebackType


@final
class JobRegistry(AbstractContextManager["JobRegistry"]):
    """Metadata persistence, bounded execution, cancellation을 직렬화합니다."""

    def __init__(
        self,
        root: Path,
        *,
        process_factory: job_models.JobProcessFactory,
        limits: job_models.JobLimits | None = None,
        audit: audit_api.AuditRecorder | None = None,
    ) -> None:
        """검증된 경로와 concurrency/output/retention 상한을 보관합니다."""
        limits = limits or job_models.JobLimits()
        if min(limits.max_concurrent, limits.max_output_bytes) < 1 or limits.retention <= timedelta(
            0
        ):
            raise job_models.InvalidJobConfigurationError
        self._limits = limits
        self._process_factory = process_factory
        self._store = job_store.JobStore(root, limits.retention)
        self._audit = audit
        self._lock = RLock()
        recovered = job_recovery.recover_store(self._store, datetime.now(UTC))
        self._records = recovered.records
        self._operation_jobs = recovered.operation_jobs
        self._executor = ThreadPoolExecutor(
            max_workers=limits.max_concurrent, thread_name_prefix="job"
        )
        self._closed = False

    @override
    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        """예외 여부와 관계없이 background process를 정리합니다."""
        self.close()

    def start(
        self, spec: job_models.JobSpec, *, job_id: UUID | None = None
    ) -> job_models.JobSnapshot:
        """Operation별 한 job ID를 즉시 반환하고 실행은 background에 맡깁니다."""
        if not spec.argv or any(not value or "\0" in value for value in spec.argv):
            raise job_models.InvalidJobSpecError
        with self._lock:
            if self._closed:
                raise job_models.JobRegistryClosedError
            request_digest = job_models.job_request_digest(spec, self._limits)
            existing = self._operation_jobs.get(spec.operation_id)
            if existing is not None:
                existing_id, existing_digest = existing
                if existing_digest != request_digest:
                    raise job_models.JobReplayConflictError(operation_id=spec.operation_id)
                return self._records[existing_id].snapshot
            selected_job_id = job_id or uuid4()
            if selected_job_id in self._records:
                raise job_models.JobReplayConflictError(operation_id=spec.operation_id)
            now = datetime.now(UTC)
            snapshot = job_models.JobSnapshot(
                job_id=selected_job_id,
                operation_id=spec.operation_id,
                request_digest=request_digest,
                kind=spec.kind,
                state=job_models.JobState.QUEUED,
                created_at=now,
                updated_at=now,
            )
            self._records[snapshot.job_id] = job_models.JobRecord(snapshot)
            self._operation_jobs[spec.operation_id] = (snapshot.job_id, request_digest)
            self._store.write_snapshot(snapshot)
            _ = self._executor.submit(self._run, snapshot.job_id, spec)
            return snapshot

    def status(self, job_id: UUID) -> job_models.JobSnapshot:
        """현재 job metadata의 immutable snapshot을 반환합니다."""
        with self._lock:
            return self._get(job_id).snapshot

    def output(
        self,
        job_id: UUID,
        *,
        stream: job_models.JobOutputStream,
        offset: int,
        limit: int,
    ) -> job_models.JobOutput:
        """보존 파일에서 요청한 UTF-8 byte window만 읽습니다."""
        if offset < 0 or limit < 1 or limit > job_models.MAX_JOB_OUTPUT_CHUNK_BYTES:
            raise job_models.InvalidOutputWindowError
        with self._lock:
            snapshot = self._get(job_id).snapshot
            data = self._store.read_output(job_id, stream)
        try:
            _ = data[:offset].decode("utf-8")
        except UnicodeDecodeError as error:
            raise job_models.InvalidOutputWindowError from error
        text = data[offset : offset + limit].decode("utf-8", errors="ignore")
        consumed = len(text.encode())
        match stream:
            case "stdout":
                total_bytes = snapshot.stdout_bytes
            case "stderr":
                total_bytes = snapshot.stderr_bytes
            case unreachable:
                assert_never(unreachable)
        return job_models.JobOutput(
            job_id=job_id,
            stream=stream,
            data=text,
            offset=offset,
            next_offset=offset + consumed,
            complete=offset + consumed >= len(data),
            total_bytes=total_bytes,
            retained_bytes=len(data),
            truncated=snapshot.truncated,
        )

    def cancel(self, job_id: UUID) -> job_models.JobSnapshot:
        """Queued/running 작업을 cancelled로 고정하고 Job Object에 전파합니다."""
        with self._lock:
            record = self._get(job_id)
            if record.snapshot.state in job_models.TERMINAL_JOB_STATES:
                return record.snapshot
            process = record.process
            cancelled = record.snapshot.model_copy(
                update={"state": job_models.JobState.CANCELLED, "updated_at": datetime.now(UTC)}
            )
            record.snapshot = cancelled
            self._store.write_snapshot(cancelled)
            if process is not None:
                _ = process.cancel()
            self._record_audit(cancelled)
            return cancelled

    def close(self) -> None:
        """Registry가 소유한 실행을 취소하고 background threads를 회수합니다."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            active = tuple(
                job_id
                for job_id, record in self._records.items()
                if record.snapshot.state not in job_models.TERMINAL_JOB_STATES
            )
        for job_id in active:
            _ = self.cancel(job_id)
        self._executor.shutdown(wait=True, cancel_futures=False)

    def cleanup_retention(self) -> job_recovery.RetentionCleanupReceipt:
        """Disk expiry 결과와 메모리 registry를 같은 retained ID 집합으로 축소합니다."""
        with self._lock:
            state = job_recovery.RecoveredRegistryState(self._records, self._operation_jobs)
            receipt, retained = job_recovery.cleanup_retained_state(self._store, state)
            self._records, self._operation_jobs = retained.records, retained.operation_jobs
        return receipt

    def _run(self, job_id: UUID, spec: job_models.JobSpec) -> None:
        with self._lock:
            record = self._get(job_id)
            if record.snapshot.state is job_models.JobState.CANCELLED:
                return
        try:
            process = self._process_factory(
                JobProcessSpec(spec.argv, spec.cwd), max_output_bytes=self._limits.max_output_bytes
            )
        except OSError:
            with self._lock:
                record = self._get(job_id)
                record.snapshot = record.snapshot.model_copy(
                    update={"state": job_models.JobState.FAILED, "updated_at": datetime.now(UTC)}
                )
                self._store.write_snapshot(record.snapshot)
                self._record_audit(record.snapshot)
            return
        with self._lock:
            record = self._get(job_id)
            record.process = process
            if record.snapshot.state is job_models.JobState.CANCELLED:
                _ = process.cancel()
            else:
                record.snapshot = record.snapshot.model_copy(
                    update={
                        "state": job_models.JobState.RUNNING,
                        "pid": process.pid,
                        "updated_at": datetime.now(UTC),
                    }
                )
                self._store.write_snapshot(record.snapshot)
        result = process.wait()
        with self._lock:
            record = self._get(job_id)
            state = record.snapshot.state
            if state is not job_models.JobState.CANCELLED:
                state = JobState.SUCCEEDED if result.exit_code == 0 else JobState.FAILED
            self._store.write_output(job_id, "stdout", result.stdout)
            self._store.write_output(job_id, "stderr", result.stderr)
            retained = len(result.stdout.encode()) + len(result.stderr.encode())
            record.snapshot = record.snapshot.model_copy(
                update={
                    "state": state,
                    "exit_code": result.exit_code,
                    "updated_at": datetime.now(UTC),
                    "stdout_bytes": result.stdout_bytes,
                    "stderr_bytes": result.stderr_bytes,
                    "retained_bytes": retained,
                    "truncated": result.truncated,
                }
            )
            self._store.write_snapshot(record.snapshot)
            self._record_audit(record.snapshot, result.stdout, result.stderr)
            record.process = None

    def _record_audit(
        self,
        snapshot: job_models.JobSnapshot,
        stdout: str | None = None,
        stderr: str | None = None,
    ) -> None:
        if self._audit is None:
            return
        outcome, error_code = job_audit.for_terminal_state(snapshot.state)
        _ = self._audit.record(
            audit_api.AuditInput(
                event_id=uuid4(),
                occurred_at=datetime.now(UTC),
                tool_name="job_cancel" if snapshot.state is JobState.CANCELLED else "job_start",
                operation_id=snapshot.operation_id,
                payload={"job_id": str(snapshot.job_id), "kind": snapshot.kind.value},
                outcome=outcome,
                error_code=error_code,
                stdout=stdout,
                stderr=stderr,
            )
        )

    def _get(self, job_id: UUID) -> job_models.JobRecord:
        record = self._records.get(job_id)
        if record is None:
            raise job_models.JobNotFoundError(job_id=job_id)
        return record
