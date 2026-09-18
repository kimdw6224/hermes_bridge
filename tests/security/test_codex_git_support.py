from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from shutil import which
from threading import Event
from typing import TYPE_CHECKING, ClassVar
from uuid import uuid4

import pytest
from pydantic import ValidationError

from hermes_windows_bridge.gateway.job_models import JobState
from hermes_windows_bridge.tools.codex import CodexRunInput, CommandResult, GitSnapshot
from hermes_windows_bridge.worker.codex_deadline import ThreadDeadlineScheduler
from hermes_windows_bridge.worker.codex_records import (
    CodexPreflightRecord,
    CodexRecordStore,
    InvalidCodexRecordError,
)
from hermes_windows_bridge.worker.job_object import JobCancelReceipt
from hermes_windows_bridge.worker.job_process import JobProcessResult

if TYPE_CHECKING:
    from pathlib import Path
    from uuid import UUID

    from hermes_windows_bridge.worker.codex_deadline import JobCanceller, JobStateReader
    from hermes_windows_bridge.worker.job_process import JobProcessSpec


class ManualDeadlineScheduler:
    """adapter test에 결정적인 deadline trigger를 제공합니다."""

    def __init__(self) -> None:
        self.job_id: UUID | None = None
        self.timeout_s: float | None = None
        self.canceller: JobCanceller | None = None

    def arm(
        self,
        job_id: UUID,
        timeout_s: float,
        _state_reader: JobStateReader,
        canceller: JobCanceller,
    ) -> None:
        """test가 trigger할 때까지 adapter deadline 요청을 저장합니다."""
        self.job_id = job_id
        self.timeout_s = timeout_s
        self.canceller = canceller

    def trigger(self) -> None:
        """armed job을 취소하고 deadline 요청이 없으면 실패합니다."""
        if self.job_id is None or self.canceller is None:
            message = "deadline was not armed"
            raise AssertionError(message)
        self.canceller(self.job_id)


def git(repo: Path, *args: str) -> str:
    """격리된 repository fixture에서 Git을 실행합니다."""
    return subprocess.run(
        (which("git") or "git", "-C", str(repo), *args),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.strip()


def repository(path: Path) -> Path:
    """하나의 tracked file을 가진 committed repository fixture를 만듭니다."""
    path.mkdir()
    _ = git(path, "init", "-b", "main")
    _ = git(path, "config", "user.email", "safety@example.invalid")
    _ = git(path, "config", "user.name", "Safety Test")
    _ = (path / "kept.txt").write_text("original\n", encoding="utf-8")
    _ = git(path, "add", "kept.txt")
    _ = git(path, "commit", "-m", "fixture")
    return path


def runner(argv: tuple[str, ...], _cwd: Path, _timeout_s: int) -> CommandResult:
    """보안 시나리오에 결정적인 fake Codex CLI 응답을 반환합니다."""
    if argv[1:] == ("--version",):
        return CommandResult(0, "codex-cli fake\n", "")
    if argv[1:] == ("--help",):
        return CommandResult(0, "Commands: exec login\nOptions: --strict-config\n", "")
    if argv[1:] == ("exec", "--help"):
        return CommandResult(0, "--model --config --color\n", "")
    if argv[1:] == ("login", "status"):
        return CommandResult(0, "credential-data\n", "")
    if argv[1:3] == ("--strict-config", "--config"):
        return CommandResult(0, "codex-cli fake\n", "")
    return CommandResult(2, "", "")


@dataclass(frozen=True, slots=True)
class BlockingProcess:
    """deadline·replay 경로를 관찰할 수 있도록 취소까지 block합니다."""

    spec: JobProcessSpec
    max_output_bytes: int
    cancelled: Event = field(default_factory=Event)
    pid: ClassVar[int] = 5252

    def wait(self) -> JobProcessResult:
        """취소를 기다린 뒤 synthetic process 실패를 보고합니다."""
        _ = self.cancelled.wait(5)
        return JobProcessResult(
            exit_code=1,
            stdout="",
            stderr="cancelled",
            stdout_bytes=0,
            stderr_bytes=9,
            truncated=False,
        )

    def cancel(self) -> JobCancelReceipt:
        """synthetic blocking process에 취소 신호를 보냅니다."""
        self.cancelled.set()
        return JobCancelReceipt(terminated=True, already_terminated=False)


def blocking_factory(spec: JobProcessSpec, *, max_output_bytes: int) -> BlockingProcess:
    """Codex 보안 test에서 사용하는 blocking process fake를 만듭니다."""
    return BlockingProcess(spec, max_output_bytes)


def never_start(spec: JobProcessSpec, *, max_output_bytes: int) -> BlockingProcess:
    """unsafe dirty-worktree 경로가 process 생성까지 오면 실패합니다."""
    del spec, max_output_bytes
    message = "dirty worktree must fail before process creation"
    raise AssertionError(message)


def run_deadline_scheduler_cancels_at_deadline_and_disarms_on_terminal() -> None:
    """deadline scheduler의 취소와 terminal disarm을 검증합니다."""
    cancelled = Event()
    terminal_checks = 0

    def running_status(_job_id: UUID) -> JobState:
        nonlocal terminal_checks
        terminal_checks += 1
        return JobState.RUNNING

    def cancel(_job_id: UUID) -> None:
        cancelled.set()

    scheduler = ThreadDeadlineScheduler(poll_interval_s=0.005)
    scheduler.arm(uuid4(), 0.01, running_status, cancel)

    assert cancelled.wait(1) is True
    assert terminal_checks >= 1

    terminal_cancelled = Event()
    scheduler.arm(
        uuid4(),
        0.01,
        lambda _job_id: JobState.SUCCEEDED,
        lambda _job_id: terminal_cancelled.set(),
    )
    assert terminal_cancelled.wait(0.05) is False


def run_record_store_is_atomic_strict_and_contains_no_prompt(tmp_path: Path) -> None:
    """record store atomicity와 prompt 미보관을 검증합니다."""
    records_root = tmp_path / "records"
    store = CodexRecordStore(records_root)
    job_id = uuid4()
    record = CodexPreflightRecord(
        job_id=job_id,
        cwd=tmp_path,
        preflight=GitSnapshot(is_repository=False),
    )

    store.write(record)
    serialized = store.path(job_id).read_text(encoding="utf-8")

    assert store.read(job_id) == record
    assert tuple(records_root.glob("*.tmp")) == ()
    assert "unique-prompt-secret" not in serialized

    corrupt = records_root / f"{uuid4()}.json"
    _ = corrupt.write_text('{"job_id":"broken"}', encoding="utf-8")
    with pytest.raises(InvalidCodexRecordError):
        _ = CodexRecordStore(records_root).load()


def run_malformed_codex_input_is_rejected(tmp_path: Path, field: str, value: str) -> None:
    """NUL을 포함한 Codex input이 boundary에서 거부되는지 검증합니다."""
    payload = {
        "operation_id": str(uuid4()),
        "prompt": "safe",
        "cwd": str(tmp_path),
        "model": None,
    }
    payload[field] = value

    with pytest.raises(ValidationError):
        _ = CodexRunInput.model_validate(payload)
