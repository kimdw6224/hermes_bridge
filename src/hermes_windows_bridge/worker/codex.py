"""Logged-in-user Codex CLI discovery와 Git-safe durable job adapter입니다."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from threading import RLock
from typing import TYPE_CHECKING, Final, final, override
from uuid import UUID, uuid4

from hermes_windows_bridge.gateway.job_models import (
    TERMINAL_JOB_STATES,
    JobKind,
    JobNotFoundError,
    JobSpec,
)
from hermes_windows_bridge.tools.codex import (
    CodexInvocation,
    CodexJobStart,
    CodexPostflight,
    CodexStatus,
    CommandRunner,
    run_bounded_command,
)
from hermes_windows_bridge.worker.codex_deadline import DeadlineScheduler, ThreadDeadlineScheduler
from hermes_windows_bridge.worker.codex_git import capture_git_snapshot
from hermes_windows_bridge.worker.codex_records import (
    CodexPreflightRecord,
    CodexRecordStore,
    StaleCodexRecordError,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from hermes_windows_bridge.gateway.jobs import JobRegistry

_DISCOVERY_TIMEOUT_S: Final = 10
_PRESERVE_INSTRUCTION: Final = (
    "\n\nPreserve every pre-existing user change in this working tree. Do not clean, reset, "
    "checkout, stash, discard, overwrite, or reformat unrelated files."
)


class DirtyWorktreePolicy(StrEnum):
    """Dirty repository에서 허용하는 유일한 비파괴 정책입니다."""

    PRESERVE = "preserve"


@dataclass(frozen=True, slots=True)
class DirtyWorktreePolicyRequiredError(RuntimeError):
    """Dirty files가 있는데 명시적 preserve 정책이 빠졌습니다."""

    dirty_files: tuple[str, ...]

    @override
    def __str__(self) -> str:
        return "dirty_worktree_requires_explicit_preserve_policy"


@dataclass(frozen=True, slots=True)
class CodexUnavailableError(RuntimeError):
    """CLI를 찾지 못했거나 현재 CLI가 non-interactive exec를 지원하지 않습니다."""

    reason: str

    @override
    def __str__(self) -> str:
        return f"codex_unavailable:{self.reason}"


@dataclass(frozen=True, slots=True)
class UnknownCodexJobError(LookupError):
    """이 adapter가 만든 Codex job이 아닙니다."""

    job_id: UUID

    @override
    def __str__(self) -> str:
        return f"unknown_codex_job:{self.job_id}"


@dataclass(frozen=True, slots=True)
class PostflightNotReadyError(RuntimeError):
    """Active job에는 최종 Git 상태가 아직 없습니다."""

    job_id: UUID

    @override
    def __str__(self) -> str:
        return f"codex_postflight_not_ready:{self.job_id}"


@final
class CodexAdapter:
    """현재 CLI help에서 지원 옵션을 고르고 durable registry에 제출합니다."""

    def __init__(  # noqa: PLR0913 - explicit injectable runtime boundaries입니다.
        self,
        executable: str,
        registry: JobRegistry,
        *,
        records_root: Path,
        command_runner: CommandRunner | None = None,
        deadline_scheduler: DeadlineScheduler | None = None,
        job_id_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        """실행 파일, durable registry, read-only probe seam을 보관합니다."""
        self._executable = executable
        self._registry = registry
        self._runner = command_runner or run_bounded_command
        self._deadlines = deadline_scheduler or ThreadDeadlineScheduler()
        self._job_id_factory = job_id_factory
        self._records = CodexRecordStore(records_root)
        self._tracked = {record.job_id: record for record in self._records.load()}
        self._lock = RLock()

    def status(self) -> CodexStatus:
        """Version/help/login-status의 성공 여부만 공개합니다."""
        resolved = shutil.which(self._executable)
        executable = Path(resolved) if resolved is not None else Path(self._executable)
        version = self._runner((self._executable, "--version"), Path.cwd(), _DISCOVERY_TIMEOUT_S)
        root_help = self._runner((self._executable, "--help"), Path.cwd(), _DISCOVERY_TIMEOUT_S)
        exec_help = self._runner(
            (self._executable, "exec", "--help"), Path.cwd(), _DISCOVERY_TIMEOUT_S
        )
        root_text = root_help.stdout + root_help.stderr
        exec_text = exec_help.stdout + exec_help.stderr
        exec_supported = root_help.exit_code == 0 and _has_token(root_text, "exec")
        config_supported = _has_option(exec_text, "--config") and _has_option(
            root_text, "--strict-config"
        )
        effort_supported = False
        if config_supported:
            effort_probe = self._runner(
                (
                    self._executable,
                    "--strict-config",
                    "--config",
                    'model_reasoning_effort="low"',
                    "--version",
                ),
                Path.cwd(),
                _DISCOVERY_TIMEOUT_S,
            )
            effort_supported = effort_probe.exit_code == 0
        version_text = _first_line(version.stdout) if version.exit_code == 0 else None
        login_available = False
        if root_help.exit_code == 0 and _has_token(root_text, "login"):
            login = self._runner(
                (self._executable, "login", "status"), Path.cwd(), _DISCOVERY_TIMEOUT_S
            )
            login_available = login.exit_code == 0
        return CodexStatus(
            executable=executable if version.exit_code == 0 else None,
            version=version_text,
            callable=version.exit_code == 0 and exec_help.exit_code == 0 and exec_supported,
            login_available=login_available,
            exec_supported=exec_supported,
            model_option_supported=_has_option(exec_text, "--model"),
            effort_option_supported=effort_supported,
        )

    def start(  # noqa: PLR0913 - 외부 typed request 필드를 그대로 받습니다.
        self,
        *,
        operation_id: UUID,
        prompt: str,
        cwd: Path,
        model: str | None,
        effort: str | None,
        dirty_policy: DirtyWorktreePolicy | str | None,
        timeout_s: int,
    ) -> CodexJobStart:
        """Git 상태를 고정한 뒤 capability-derived literal argv를 제출합니다."""
        status = self.status()
        if not status.callable:
            raise CodexUnavailableError(reason="exec_not_callable")
        preflight = capture_git_snapshot(cwd)
        dirty = bool(preflight.dirty_files)
        if dirty and dirty_policy not in {DirtyWorktreePolicy.PRESERVE, "preserve"}:
            raise DirtyWorktreePolicyRequiredError(preflight.dirty_files)
        final_prompt = prompt + _PRESERVE_INSTRUCTION if dirty else prompt
        prefix = [self._executable, "exec"]
        model_applied = model is not None and status.model_option_supported
        if model is not None and status.model_option_supported:
            prefix.extend(("--model", model))
        effort_applied = effort is not None and status.effort_option_supported
        if effort is not None and status.effort_option_supported:
            prefix.extend(("--config", f'model_reasoning_effort="{effort}"'))
        if _has_option(
            self._runner((self._executable, "exec", "--help"), cwd, _DISCOVERY_TIMEOUT_S).stdout,
            "--color",
        ):
            prefix.extend(("--color", "never"))
        argv = (*prefix, final_prompt)
        proposed_job_id = self._job_id_factory()
        proposed = CodexPreflightRecord(
            job_id=proposed_job_id, cwd=cwd.resolve(), preflight=preflight
        )
        with self._lock:
            self._records.write(proposed)
            started = False
            try:
                job = self._registry.start(
                    JobSpec(operation_id, JobKind.CODEX, argv, cwd), job_id=proposed_job_id
                )
                started = True
            finally:
                if not started:
                    self._records.delete(proposed_job_id)
            if job.job_id == proposed_job_id:
                record = proposed
            else:
                self._records.delete(proposed_job_id)
                record = self._records.read(job.job_id)
            self._tracked[job.job_id] = record
        if job.job_id == proposed_job_id:
            try:
                self._deadlines.arm(
                    job.job_id,
                    timeout_s,
                    lambda current: self._registry.status(current).state,
                    lambda current: _cancel(self._registry, current),
                )
            except RuntimeError:
                _ = self._registry.cancel(job.job_id)
                raise
        return CodexJobStart(
            job=job,
            preflight=record.preflight,
            invocation=CodexInvocation(
                command_prefix=tuple(prefix),
                argument_count=len(argv),
                model_applied=model_applied,
                effort_applied=effort_applied,
                preservation_instruction_applied=dirty,
                requested_timeout_s=timeout_s,
            ),
        )

    def postflight(self, job_id: UUID) -> CodexPostflight:
        """Terminal 상태일 때만 Git postflight를 한 번의 typed 결과로 반환합니다."""
        with self._lock:
            tracked = self._tracked.get(job_id)
        if tracked is None:
            raise UnknownCodexJobError(job_id)
        try:
            job = self._registry.status(job_id)
        except JobNotFoundError as error:
            raise StaleCodexRecordError(job_id) from error
        if job.state not in TERMINAL_JOB_STATES:
            raise PostflightNotReadyError(job_id)
        return CodexPostflight(
            job_id=job_id,
            job=job,
            preflight=tracked.preflight,
            postflight=capture_git_snapshot(tracked.cwd),
        )


def _first_line(text: str) -> str | None:
    lines = text.splitlines()
    return lines[0][:256] if lines else None


def _has_token(text: str, token: str) -> bool:
    return any(token == part.strip(" ,:[]<>()") for part in text.split())


def _has_option(text: str, option: str) -> bool:
    return option in text.split()


def _cancel(registry: JobRegistry, job_id: UUID) -> None:
    _ = registry.cancel(job_id)
