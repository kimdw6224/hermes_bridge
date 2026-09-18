from __future__ import annotations

import sys
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import psutil
import pytest

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


def _wait_for_state(registry: JobRegistry, job_id: UUID, expected: JobState) -> JobSnapshot:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        snapshot = registry.status(job_id)
        if snapshot.state is expected:
            return snapshot
        time.sleep(0.02)
    pytest.fail(f"job did not reach {expected}")


def test_running_metadata_is_interrupted_after_registry_restart(tmp_path: Path) -> None:
    root = tmp_path / "jobs"
    root.mkdir()
    job_id = uuid4()
    stale = JobSnapshot(
        job_id=job_id,
        operation_id=uuid4(),
        request_digest="0" * 64,
        kind=JobKind.PROCESS,
        state=JobState.RUNNING,
        created_at=datetime(2026, 9, 5, tzinfo=UTC),
        updated_at=datetime.now(UTC),
        pid=123,
    )
    _ = (root / f"{job_id}.json").write_text(stale.model_dump_json(), encoding="utf-8")

    with JobRegistry(
        root,
        process_factory=RunningJobProcess,
        limits=JobLimits(max_output_bytes=64),
    ) as registry:
        recovered = registry.status(job_id)

    assert recovered.state is JobState.INTERRUPTED
    assert recovered.pid is None


def test_terminal_jobs_release_kernel_handles_before_registry_close(tmp_path: Path) -> None:
    process = psutil.Process()
    with JobRegistry(
        tmp_path / "jobs",
        process_factory=RunningJobProcess,
        limits=JobLimits(max_concurrent=4, max_output_bytes=64),
    ) as registry:
        warm = [
            registry.start(
                JobSpec(
                    operation_id=uuid4(),
                    kind=JobKind.PROCESS,
                    argv=(sys.executable, "-c", "raise SystemExit(0)"),
                    cwd=tmp_path,
                )
            )
            for _ in range(4)
        ]
        for snapshot in warm:
            _ = _wait_for_state(registry, snapshot.job_id, JobState.SUCCEEDED)
        before = process.num_handles()
        jobs = [
            registry.start(
                JobSpec(
                    operation_id=uuid4(),
                    kind=JobKind.PROCESS,
                    argv=(sys.executable, "-c", "raise SystemExit(0)"),
                    cwd=tmp_path,
                )
            )
            for _ in range(36)
        ]
        for snapshot in jobs:
            _ = _wait_for_state(registry, snapshot.job_id, JobState.SUCCEEDED)
        after = process.num_handles()

        assert after <= before + 2, {"before": before, "after": after}
