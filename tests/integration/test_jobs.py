from __future__ import annotations

import sys
import time
from datetime import timedelta
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import psutil
import pytest

from hermes_windows_bridge.gateway.audit import AuditRecorder
from hermes_windows_bridge.gateway.job_models import (
    JobKind,
    JobLimits,
    JobSnapshot,
    JobSpec,
    JobState,
)
from hermes_windows_bridge.gateway.jobs import JobRegistry
from hermes_windows_bridge.worker.job_process import RunningJobProcess

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.integration


def _wait_for_state(
    registry: JobRegistry,
    job_id: UUID,
    expected: set[JobState],
    timeout_seconds: float = 10.0,
) -> JobSnapshot:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        snapshot = registry.status(job_id)
        if snapshot.state in expected:
            return snapshot
        time.sleep(0.02)
    pytest.fail(f"job did not reach {expected}")


class TestJobs:
    def test_start_poll_complete_bounded_output(self, tmp_path: Path) -> None:
        audit = AuditRecorder()
        with JobRegistry(
            tmp_path / "jobs",
            process_factory=RunningJobProcess,
            limits=JobLimits(max_output_bytes=64, retention=timedelta(hours=24)),
            audit=audit,
        ) as registry:
            before = time.monotonic()
            started = registry.start(
                JobSpec(
                    operation_id=uuid4(),
                    kind=JobKind.PROCESS,
                    argv=(sys.executable, "-c", "import time;print('x'*1000);time.sleep(.2)"),
                    cwd=tmp_path,
                )
            )
            elapsed = time.monotonic() - before
            finished = _wait_for_state(registry, started.job_id, {JobState.SUCCEEDED})
            output = registry.output(started.job_id, stream="stdout", offset=0, limit=64)

            assert elapsed < 0.5
            assert started.state in {JobState.QUEUED, JobState.RUNNING}
            assert finished.exit_code == 0
            assert len(output.data.encode("utf-8")) <= 64
            assert output.total_bytes >= 1_000
            assert output.truncated is True
            assert sum(path.stat().st_size for path in (tmp_path / "jobs").glob("*.output")) <= 64
            assert any(record.operation_id == started.operation_id for record in audit.records)

    def test_cancel_terminates_process_tree(self, tmp_path: Path) -> None:
        child_code = "import threading;threading.Event().wait(300)"
        parent_code = (
            "import subprocess,sys,threading;"
            "p=subprocess.Popen([sys.executable,'-c',sys.argv[1]]);"
            "print(p.pid,flush=True);threading.Event().wait(300)"
        )
        with JobRegistry(
            tmp_path / "jobs",
            process_factory=RunningJobProcess,
            limits=JobLimits(max_output_bytes=256),
        ) as registry:
            started = registry.start(
                JobSpec(
                    operation_id=uuid4(),
                    kind=JobKind.PROCESS,
                    argv=(sys.executable, "-c", parent_code, child_code),
                    cwd=tmp_path,
                )
            )
            running = _wait_for_state(registry, started.job_id, {JobState.RUNNING})
            assert running.pid is not None
            parent = psutil.Process(running.pid)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not parent.children():
                time.sleep(0.02)
            child = parent.children()[0]
            cancelled = registry.cancel(started.job_id)
            repeated = registry.cancel(started.job_id)
            finished = _wait_for_state(registry, started.job_id, {JobState.CANCELLED})

            _, alive = psutil.wait_procs((parent, child), timeout=5)
            assert cancelled.state is JobState.CANCELLED
            assert repeated.state is JobState.CANCELLED
            assert finished.state is JobState.CANCELLED
            assert alive == []

    def test_start_failure_is_a_typed_terminal_state(self, tmp_path: Path) -> None:
        with JobRegistry(tmp_path / "jobs", process_factory=RunningJobProcess) as registry:
            started = registry.start(
                JobSpec(
                    operation_id=uuid4(),
                    kind=JobKind.PROCESS,
                    argv=(f"missing-{uuid4()}.exe",),
                    cwd=tmp_path,
                )
            )
            failed = _wait_for_state(registry, started.job_id, {JobState.FAILED})

        assert failed.exit_code is None
        assert failed.pid is None

    def test_literal_argv_and_exit_code_defeat_misleading_output(self, tmp_path: Path) -> None:
        result_path = tmp_path / "literal.txt"
        injected_path = tmp_path / "injected.txt"
        untrusted = f"success & echo injected>{injected_path}"
        code = (
            "from pathlib import Path;import sys;"
            "Path(sys.argv[1]).write_text(sys.argv[2]);print('success');raise SystemExit(7)"
        )
        with JobRegistry(tmp_path / "jobs", process_factory=RunningJobProcess) as registry:
            started = registry.start(
                JobSpec(
                    operation_id=uuid4(),
                    kind=JobKind.PROCESS,
                    argv=(sys.executable, "-c", code, str(result_path), untrusted),
                    cwd=tmp_path,
                )
            )
            failed = _wait_for_state(registry, started.job_id, {JobState.FAILED})
            output = registry.output(started.job_id, stream="stdout", offset=0, limit=64)

        assert failed.exit_code == 7
        assert output.data.strip() == "success"
        assert result_path.read_text() == untrusted
        assert not injected_path.exists()
