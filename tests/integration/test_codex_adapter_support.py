from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from shutil import which
from typing import TYPE_CHECKING, ClassVar

import pytest

from hermes_windows_bridge.gateway.job_models import JobState
from hermes_windows_bridge.tools.codex import CommandResult
from hermes_windows_bridge.worker.job_object import JobCancelReceipt
from hermes_windows_bridge.worker.job_process import JobProcessResult

if TYPE_CHECKING:
    from pathlib import Path
    from uuid import UUID

    from hermes_windows_bridge.gateway.jobs import JobRegistry
    from hermes_windows_bridge.worker.job_process import JobProcessSpec


def git(repo: Path, *args: str) -> str:
    """격리된 repository fixture에서 Git을 실행합니다."""
    completed = subprocess.run(
        (which("git") or "git", "-C", str(repo), *args),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def repository(path: Path) -> Path:
    """Codex adapter 시나리오용 committed repository fixture를 만듭니다."""
    path.mkdir()
    _ = git(path, "init", "-b", "main")
    _ = git(path, "config", "user.email", "codex-test@example.invalid")
    _ = git(path, "config", "user.name", "Codex Adapter Test")
    tracked = path / "tracked.txt"
    _ = tracked.write_text("before\n", encoding="utf-8")
    _ = git(path, "add", "tracked.txt")
    _ = git(path, "commit", "-m", "fixture")
    return path


def command_runner(argv: tuple[str, ...], _cwd: Path, _timeout_s: int) -> CommandResult:
    """shell을 실행하지 않고 결정적인 fake CLI 응답을 반환합니다."""
    if (
        len(argv) == 5
        and argv[1:3] == ("--strict-config", "--config")
        and argv[-1:] == ("--version",)
    ):
        return CommandResult(0, "codex-cli 99.1\n", "")
    responses: dict[tuple[str, ...], CommandResult] = {
        ("--version",): CommandResult(0, "codex-cli 99.1\n", ""),
        ("--help",): CommandResult(
            0, "Commands:\n  exec\n  login\nOptions:\n --strict-config\n", ""
        ),
        ("exec", "--help"): CommandResult(
            0,
            "Options:\n  -m, --model <MODEL>\n  -c, --config <key=value>\n  --color <COLOR>\n",
            "",
        ),
        ("login", "status"): CommandResult(0, "authenticated-secret-must-not-escape\n", ""),
    }
    return responses.get(argv[1:], CommandResult(2, "", "unsupported"))


@dataclass(frozen=True, slots=True)
class FakeProcess:
    """repository fixture에 synthetic Codex 완료를 기록합니다."""

    spec: JobProcessSpec
    max_output_bytes: int
    pid: ClassVar[int] = 4242

    def wait(self) -> JobProcessResult:
        """예상 tracked-file 변경을 쓰고 성공 결과를 반환합니다."""
        _ = (self.spec.cwd / "tracked.txt").write_text("after\n", encoding="utf-8")
        output = "fake codex completed"
        return JobProcessResult(
            exit_code=0,
            stdout=output,
            stderr="",
            stdout_bytes=len(output.encode()),
            stderr_bytes=0,
            truncated=False,
        )

    def cancel(self) -> JobCancelReceipt:
        """synthetic process의 성공적인 취소를 모델링합니다."""
        return JobCancelReceipt(terminated=True, already_terminated=False)


def process_factory(spec: JobProcessSpec, *, max_output_bytes: int) -> FakeProcess:
    """adapter integration 시나리오에 사용하는 process fake를 만듭니다."""
    return FakeProcess(spec, max_output_bytes)


def wait_for_terminal(registry: JobRegistry, job_id: UUID) -> JobState:
    """synthetic job이 terminal state에 도달할 때까지 기다립니다."""
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        state = registry.status(job_id).state
        if state in {JobState.SUCCEEDED, JobState.FAILED, JobState.CANCELLED}:
            return state
        time.sleep(0.01)
    pytest.fail("fake codex job did not finish")
