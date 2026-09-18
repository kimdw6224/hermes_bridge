# pyright: reportArgumentType=false

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar
from uuid import uuid4

import pytest

from hermes_windows_bridge.gateway.job_models import JobState
from hermes_windows_bridge.gateway.jobs import JobRegistry
from hermes_windows_bridge.tools.codex import CommandResult, GitSnapshot
from hermes_windows_bridge.worker import codex, codex_records
from hermes_windows_bridge.worker.job_object import JobCancelReceipt
from hermes_windows_bridge.worker.job_process import JobProcessResult
from tests.security.test_codex_git_support import (
    ManualDeadlineScheduler,
    blocking_factory,
    git,
    never_start,
    repository,
    run_deadline_scheduler_cancels_at_deadline_and_disarms_on_terminal,
    run_malformed_codex_input_is_rejected,
    run_record_store_is_atomic_strict_and_contains_no_prompt,
    runner,
)

if TYPE_CHECKING:
    from pathlib import Path

    from hermes_windows_bridge.worker.job_process import JobProcessSpec
pytestmark = pytest.mark.security


class TestCodexGitSafety:
    def test_adapter_arms_requested_timeout_and_cancels_durable_job(self, tmp_path: Path) -> None:
        repo = repository(tmp_path / "repo")
        scheduler = ManualDeadlineScheduler()
        with JobRegistry(tmp_path / "jobs", process_factory=blocking_factory) as registry:
            adapter = codex.CodexAdapter(
                "fake-codex",
                registry,
                records_root=tmp_path / "records",
                command_runner=runner,
                deadline_scheduler=scheduler,
            )
            started = adapter.start(
                operation_id=uuid4(),
                prompt="Stop at deadline.",
                cwd=repo,
                model=None,
                effort=None,
                dirty_policy=None,
                timeout_s=30,
            )
            scheduler.trigger()
            cancelled = registry.status(started.job.job_id)

        assert scheduler.job_id == started.job.job_id
        assert scheduler.timeout_s == 30
        assert cancelled.state is JobState.CANCELLED

    def test_deadline_scheduler_cancels_at_deadline_and_disarms_on_terminal(self) -> None:
        run_deadline_scheduler_cancels_at_deadline_and_disarms_on_terminal()

    def test_record_store_is_atomic_strict_and_contains_no_prompt(self, tmp_path: Path) -> None:
        run_record_store_is_atomic_strict_and_contains_no_prompt(tmp_path)

    def test_stale_persisted_record_fails_closed(self, tmp_path: Path) -> None:
        records_root = tmp_path / "records"
        stale_id = uuid4()
        codex_records.CodexRecordStore(records_root).write(
            codex_records.CodexPreflightRecord(
                job_id=stale_id, cwd=tmp_path, preflight=GitSnapshot(is_repository=False)
            )
        )
        with JobRegistry(tmp_path / "jobs", process_factory=blocking_factory) as registry:
            adapter = codex.CodexAdapter(
                "fake-codex",
                registry,
                records_root=records_root,
                command_runner=runner,
            )

            with pytest.raises(codex_records.StaleCodexRecordError):
                _ = adapter.postflight(stale_id)

    @pytest.mark.parametrize(
        ("field", "value"),
        [("prompt", "bad\0prompt"), ("model", "bad\0model")],
    )
    def test_malformed_codex_input_is_rejected(
        self, tmp_path: Path, field: str, value: str
    ) -> None:
        run_malformed_codex_input_is_rejected(tmp_path, field, value)

    def test_dirty_worktree_requires_explicit_policy(self, tmp_path: Path) -> None:
        repo = repository(tmp_path / "repo")
        dirty_file = repo / "kept.txt"
        _ = dirty_file.write_text("user change\n", encoding="utf-8")
        before = dirty_file.read_bytes()

        with JobRegistry(tmp_path / "jobs", process_factory=never_start) as registry:
            adapter = codex.CodexAdapter(
                "fake-codex",
                registry,
                records_root=tmp_path / "codex-records",
                command_runner=runner,
            )
            with pytest.raises(codex.DirtyWorktreePolicyRequiredError) as captured:
                _ = adapter.start(
                    operation_id=uuid4(),
                    prompt="Make a safe change.",
                    cwd=repo,
                    model=None,
                    effort=None,
                    dirty_policy=None,
                    timeout_s=30,
                )

        assert captured.value.dirty_files == ("kept.txt",)
        assert dirty_file.read_bytes() == before
        assert git(repo, "status", "--porcelain=v1") == "M kept.txt"

    def test_preserve_policy_records_dirty_files_without_git_mutation(self, tmp_path: Path) -> None:
        repo = repository(tmp_path / "repo")
        dirty_file = repo / "kept.txt"
        _ = dirty_file.write_text("user change\n", encoding="utf-8")

        with JobRegistry(tmp_path / "jobs", process_factory=blocking_factory) as registry:
            started = codex.CodexAdapter(
                "fake-codex",
                registry,
                records_root=tmp_path / "codex-records",
                command_runner=runner,
            ).start(
                operation_id=uuid4(),
                prompt="Preserve current work.",
                cwd=repo,
                model=None,
                effort=None,
                dirty_policy=codex.DirtyWorktreePolicy.PRESERVE,
                timeout_s=30,
            )
            _ = registry.cancel(started.job.job_id)

        assert started.preflight.dirty_files == ("kept.txt",)
        assert started.invocation.preservation_instruction_applied is True
        assert dirty_file.read_text(encoding="utf-8") == "user change\n"

    def test_postflight_rejects_unknown_and_active_jobs(self, tmp_path: Path) -> None:
        repo = repository(tmp_path / "repo")
        with JobRegistry(tmp_path / "jobs", process_factory=blocking_factory) as registry:
            adapter = codex.CodexAdapter(
                "fake-codex",
                registry,
                records_root=tmp_path / "codex-records",
                command_runner=runner,
            )
            with pytest.raises(codex.UnknownCodexJobError):
                _ = adapter.postflight(uuid4())

            started = adapter.start(
                operation_id=uuid4(),
                prompt="No existing changes.",
                cwd=repo,
                model=None,
                effort=None,
                dirty_policy=None,
                timeout_s=30,
            )
            with pytest.raises(codex.PostflightNotReadyError):
                _ = adapter.postflight(started.job.job_id)
            _ = registry.cancel(started.job.job_id)

    def test_cancel_replay_and_repeated_interruptions_are_idempotent(self, tmp_path: Path) -> None:
        repo = repository(tmp_path / "repo")
        operation_id = uuid4()
        with JobRegistry(tmp_path / "jobs", process_factory=blocking_factory) as registry:
            adapter = codex.CodexAdapter(
                "fake-codex",
                registry,
                records_root=tmp_path / "codex-records",
                command_runner=runner,
            )
            first = adapter.start(
                operation_id=operation_id,
                prompt="Stop safely.",
                cwd=repo,
                model=None,
                effort=None,
                dirty_policy=None,
                timeout_s=30,
            )
            replay = adapter.start(
                operation_id=operation_id,
                prompt="Stop safely.",
                cwd=repo,
                model=None,
                effort=None,
                dirty_policy=None,
                timeout_s=30,
            )
            cancelled = registry.cancel(first.job.job_id)
            repeated = registry.cancel(first.job.job_id)

        assert replay.job.job_id == first.job.job_id
        assert cancelled.state is JobState.CANCELLED
        assert repeated.state is JobState.CANCELLED
        assert len(tuple((tmp_path / "codex-records").glob("*.json"))) == 1

    def test_flaky_discovery_and_misleading_success_fail_closed(self, tmp_path: Path) -> None:
        repo = repository(tmp_path / "repo")
        attempts = 0

        def flaky_runner(argv: tuple[str, ...], cwd: Path, timeout_s: int) -> CommandResult:
            nonlocal attempts
            if argv[1:] == ("--version",):
                attempts += 1
                if attempts == 1:
                    return CommandResult(127, "success", "")
            return runner(argv, cwd, timeout_s)

        @dataclass(frozen=True, slots=True)
        class MisleadingProcess:
            spec: JobProcessSpec
            max_output_bytes: int
            pid: ClassVar[int] = 6262

            def wait(self) -> JobProcessResult:
                return JobProcessResult(
                    exit_code=7,
                    stdout="success",
                    stderr="",
                    stdout_bytes=7,
                    stderr_bytes=0,
                    truncated=False,
                )

            def cancel(self) -> JobCancelReceipt:
                return JobCancelReceipt(terminated=True, already_terminated=False)

        def misleading_factory(spec: JobProcessSpec, *, max_output_bytes: int) -> MisleadingProcess:
            return MisleadingProcess(spec, max_output_bytes)

        with JobRegistry(tmp_path / "jobs", process_factory=misleading_factory) as registry:
            adapter = codex.CodexAdapter(
                "fake-codex",
                registry,
                records_root=tmp_path / "codex-records",
                command_runner=flaky_runner,
            )
            assert adapter.status().callable is False
            assert adapter.status().callable is True
            started = adapter.start(
                operation_id=uuid4(),
                prompt="Report actual exit status.",
                cwd=repo,
                model=None,
                effort=None,
                dirty_policy=None,
                timeout_s=30,
            )
            deadline = time.monotonic() + 5
            while registry.status(started.job.job_id).state not in {
                JobState.SUCCEEDED,
                JobState.FAILED,
            }:
                if time.monotonic() >= deadline:
                    pytest.fail("misleading process did not finish")
                time.sleep(0.01)
            final = registry.status(started.job.job_id)

        assert final.state is JobState.FAILED
        assert final.exit_code == 7
