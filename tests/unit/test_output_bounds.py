from __future__ import annotations

import sys
import time
from typing import TYPE_CHECKING
from uuid import uuid4

import pytest

from hermes_windows_bridge.gateway.job_models import (
    InvalidJobSpecError,
    InvalidOutputWindowError,
    JobKind,
    JobLimits,
    JobSpec,
    JobState,
)
from hermes_windows_bridge.gateway.jobs import JobRegistry
from hermes_windows_bridge.worker.job_process import RunningJobProcess

if TYPE_CHECKING:
    from pathlib import Path


def test_stdout_and_stderr_share_one_persistent_byte_budget(tmp_path: Path) -> None:
    with JobRegistry(
        tmp_path / "jobs",
        process_factory=RunningJobProcess,
        limits=JobLimits(max_output_bytes=9),
    ) as registry:
        started = registry.start(
            JobSpec(
                operation_id=uuid4(),
                kind=JobKind.PROCESS,
                argv=(
                    sys.executable,
                    "-c",
                    "import sys;sys.stdout.write('한글');sys.stderr.write('abcdef')",
                ),
                cwd=tmp_path,
            )
        )
        deadline = time.monotonic() + 5
        while registry.status(started.job_id).state not in {
            JobState.SUCCEEDED,
            JobState.FAILED,
        }:
            if time.monotonic() >= deadline:
                pytest.fail("job did not finish")
            time.sleep(0.01)

        stdout = registry.output(started.job_id, stream="stdout", offset=0, limit=64)
        stderr = registry.output(started.job_id, stream="stderr", offset=0, limit=64)

    assert len(stdout.data.encode("utf-8")) + len(stderr.data.encode("utf-8")) <= 9
    assert stdout.truncated or stderr.truncated


def test_multibyte_output_window_never_returns_invalid_utf8(tmp_path: Path) -> None:
    with JobRegistry(
        tmp_path / "jobs",
        process_factory=RunningJobProcess,
        limits=JobLimits(max_output_bytes=64),
    ) as registry:
        started = registry.start(
            JobSpec(
                operation_id=uuid4(),
                kind=JobKind.PROCESS,
                argv=(sys.executable, "-c", "print('한글')"),
                cwd=tmp_path,
            )
        )
        deadline = time.monotonic() + 5
        while registry.status(started.job_id).state is not JobState.SUCCEEDED:
            if time.monotonic() >= deadline:
                pytest.fail("job did not finish")
            time.sleep(0.01)

        chunk = registry.output(started.job_id, stream="stdout", offset=0, limit=4)

    assert "�" not in chunk.data
    assert len(chunk.data.encode("utf-8")) <= 4
    assert chunk.data == "한"

    with (
        JobRegistry(
            tmp_path / "jobs",
            process_factory=RunningJobProcess,
            limits=JobLimits(max_output_bytes=64),
        ) as registry,
        pytest.raises(InvalidOutputWindowError),
    ):
        _ = registry.output(started.job_id, stream="stdout", offset=1, limit=4)


def test_output_offset_and_limit_are_rejected_before_disk_read(tmp_path: Path) -> None:
    with JobRegistry(
        tmp_path / "jobs",
        process_factory=RunningJobProcess,
        limits=JobLimits(max_output_bytes=64),
    ) as registry:
        with pytest.raises(InvalidOutputWindowError):
            _ = registry.output(uuid4(), stream="stdout", offset=-1, limit=64)
        with pytest.raises(InvalidOutputWindowError):
            _ = registry.output(uuid4(), stream="stdout", offset=0, limit=0)


def test_empty_and_nul_argv_are_rejected_before_process_start(tmp_path: Path) -> None:
    with JobRegistry(tmp_path / "jobs", process_factory=RunningJobProcess) as registry:
        for argv in ((), ("python", "bad\0arg")):
            with pytest.raises(InvalidJobSpecError):
                _ = registry.start(
                    JobSpec(
                        operation_id=uuid4(),
                        kind=JobKind.PROCESS,
                        argv=argv,
                        cwd=tmp_path,
                    )
                )
