# pyright: reportArgumentType=false

from __future__ import annotations

from datetime import timedelta
from threading import Event
from typing import TYPE_CHECKING
from uuid import uuid4

import anyio
import pytest

from hermes_windows_bridge.gateway.audit import AuditRecorder
from hermes_windows_bridge.gateway.dispatcher import DispatcherServices, GatewayDispatcher
from hermes_windows_bridge.gateway.idempotency import IdempotencyStore
from hermes_windows_bridge.gateway.job_models import (
    JobKind,
    JobRegistryClosedError,
    JobReplayConflictError,
    JobSpec,
    JobState,
)
from hermes_windows_bridge.gateway.jobs import JobRegistry
from hermes_windows_bridge.gateway.mcp_server import create_gateway_server
from hermes_windows_bridge.gateway.policy import ApprovalManager
from hermes_windows_bridge.privileged.ipc_server import HelperRegistry
from hermes_windows_bridge.tools.codex import (
    CodexRunInput,
    CodexTools,
    CommandResult,
    register_codex_tools,
)
from hermes_windows_bridge.worker.codex import CodexAdapter
from hermes_windows_bridge.worker.codex_records import CodexRecordCollisionError
from hermes_windows_bridge.worker.ipc_client import WorkerRegistry
from tests.integration.test_codex_adapter_support import (
    FakeProcess,
    command_runner,
    process_factory,
    repository,
    wait_for_terminal,
)

if TYPE_CHECKING:
    from pathlib import Path

    from hermes_windows_bridge.worker.job_process import JobProcessSpec

pytestmark = pytest.mark.integration


class TestCodexAdapter:
    def test_supplied_job_id_collision_fails_closed(self, tmp_path: Path) -> None:
        supplied = uuid4()
        with JobRegistry(tmp_path / "jobs", process_factory=process_factory) as registry:
            first = registry.start(
                JobSpec(uuid4(), JobKind.CODEX, ("fake", "first"), tmp_path),
                job_id=supplied,
            )
            with pytest.raises(JobReplayConflictError):
                _ = registry.start(
                    JobSpec(uuid4(), JobKind.CODEX, ("fake", "second"), tmp_path),
                    job_id=supplied,
                )

        assert first.job_id == supplied

    def test_store_failure_prevents_process_creation(self, tmp_path: Path) -> None:
        repo = repository(tmp_path / "repo")
        process_started = Event()
        proposed_job_id = uuid4()

        def observed_factory(spec: JobProcessSpec, *, max_output_bytes: int) -> FakeProcess:
            process_started.set()
            return process_factory(spec, max_output_bytes=max_output_bytes)

        records_root = tmp_path / "records"
        with JobRegistry(tmp_path / "jobs", process_factory=observed_factory) as registry:
            adapter = CodexAdapter(
                "fake-codex",
                registry,
                records_root=records_root,
                command_runner=command_runner,
                job_id_factory=lambda: proposed_job_id,
            )
            store_collision = records_root / f"{proposed_job_id}.json"
            store_collision.mkdir()
            with pytest.raises(CodexRecordCollisionError):
                _ = adapter.start(
                    operation_id=uuid4(),
                    prompt="Do not start.",
                    cwd=repo,
                    model=None,
                    effort=None,
                    dirty_policy=None,
                    timeout_s=30,
                )

        assert process_started.is_set() is False

    def test_registry_start_failure_rolls_back_preflight(self, tmp_path: Path) -> None:
        repo = repository(tmp_path / "repo")
        records_root = tmp_path / "records"
        registry = JobRegistry(tmp_path / "jobs", process_factory=process_factory)
        registry.close()
        adapter = CodexAdapter(
            "fake-codex",
            registry,
            records_root=records_root,
            command_runner=command_runner,
        )

        with pytest.raises(JobRegistryClosedError):
            _ = adapter.start(
                operation_id=uuid4(),
                prompt="Do not leave stale state.",
                cwd=repo,
                model=None,
                effort=None,
                dirty_policy=None,
                timeout_s=30,
            )

        assert tuple(records_root.glob("*.json")) == ()

    def test_public_tools_have_closed_schemas_and_safe_hints(self) -> None:
        dispatcher = GatewayDispatcher(
            DispatcherServices(
                workers=WorkerRegistry(),
                helpers=HelperRegistry(),
                idempotency=IdempotencyStore(ttl=timedelta(minutes=30)),
                approvals=ApprovalManager(),
                audit=AuditRecorder(),
            )
        )
        server = create_gateway_server("x" * 32)
        register_codex_tools(server, dispatcher)

        tools = anyio.run(server.list_tools)

        assert {tool.name for tool in tools} == {"codex_status", "codex_run"}
        assert all(tool.input_schema.get("additionalProperties") is False for tool in tools)
        run = next(tool for tool in tools if tool.name == "codex_run")
        assert run.annotations is not None
        assert run.annotations.destructive_hint is True
        assert run.annotations.open_world_hint is True

    def test_fake_codex_job_records_pre_and_postflight(self, tmp_path: Path) -> None:
        repo = repository(tmp_path / "repo")
        with JobRegistry(tmp_path / "jobs", process_factory=process_factory) as registry:
            adapter = CodexAdapter(
                "fake-codex",
                registry,
                records_root=tmp_path / "codex-records",
                command_runner=command_runner,
            )
            tools = CodexTools(adapter)

            status = tools.codex_status()
            started = tools.codex_run(
                CodexRunInput(
                    operation_id=uuid4(),
                    prompt="Update the fixture safely.",
                    cwd=repo,
                    model="current-model",
                    effort="high",
                    timeout_s=30,
                )
            )
            final_state = wait_for_terminal(registry, started.job.job_id)
            restarted = CodexAdapter(
                "fake-codex",
                registry,
                records_root=tmp_path / "codex-records",
                command_runner=command_runner,
            )
            completed = restarted.postflight(started.job.job_id)

        assert status.callable is True
        assert status.login_available is True
        assert status.version == "codex-cli 99.1"
        assert "authenticated-secret" not in status.model_dump_json()
        assert started.preflight.repo_root == repo.resolve()
        assert started.preflight.branch == "main"
        assert started.preflight.dirty_files == ()
        assert started.invocation.command_prefix[0:2] == ("fake-codex", "exec")
        assert started.invocation.model_applied is True
        assert started.invocation.effort_applied is True
        assert final_state is JobState.SUCCEEDED
        assert completed.job_id == started.job.job_id
        assert completed.preflight.head == completed.postflight.head
        assert completed.postflight.dirty_files == ("tracked.txt",)
        assert "tracked.txt" in completed.postflight.diff_stat

    def test_unavailable_optional_flags_are_not_built(self, tmp_path: Path) -> None:
        repo = repository(tmp_path / "repo")

        def limited_runner(argv: tuple[str, ...], _cwd: Path, _timeout_s: int) -> CommandResult:
            if argv[1:] == ("--version",):
                return CommandResult(0, "codex-cli 1\n", "")
            if argv[1:] == ("--help",):
                return CommandResult(0, "Commands:\n exec\n", "")
            if argv[1:] == ("exec", "--help"):
                return CommandResult(0, "Usage: codex exec [PROMPT]\n", "")
            return CommandResult(2, "", "")

        with JobRegistry(tmp_path / "jobs", process_factory=process_factory) as registry:
            started = CodexAdapter(
                "fake-codex",
                registry,
                records_root=tmp_path / "codex-records",
                command_runner=limited_runner,
            ).start(
                operation_id=uuid4(),
                prompt="Keep changes.",
                cwd=repo,
                model="unsupported-model-option",
                effort="high",
                dirty_policy=None,
                timeout_s=30,
            )

        assert started.invocation.model_applied is False
        assert started.invocation.effort_applied is False
        assert "--model" not in started.invocation.command_prefix
        assert "--config" not in started.invocation.command_prefix

    def test_hostile_prompt_remains_one_literal_argument(self, tmp_path: Path) -> None:
        repo = repository(tmp_path / "repo")
        injected = tmp_path / "injected.txt"
        hostile_prompt = f"fix tests & echo owned>{injected}"
        with JobRegistry(tmp_path / "jobs", process_factory=process_factory) as registry:
            started = CodexAdapter(
                "fake-codex",
                registry,
                records_root=tmp_path / "codex-records",
                command_runner=command_runner,
            ).start(
                operation_id=uuid4(),
                prompt=hostile_prompt,
                cwd=repo,
                model=None,
                effort=None,
                dirty_policy=None,
                timeout_s=30,
            )
            _ = wait_for_terminal(registry, started.job.job_id)

        assert started.invocation.argument_count == 5
        assert injected.exists() is False
