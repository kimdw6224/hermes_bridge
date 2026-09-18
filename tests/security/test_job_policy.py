from __future__ import annotations

import sys
import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, cast
from uuid import UUID, uuid4

import anyio
import pytest
from mcp.types import CallToolResult, TextContent

from hermes_windows_bridge.gateway.audit import AuditRecorder
from hermes_windows_bridge.gateway.dispatcher import DispatcherServices, GatewayDispatcher
from hermes_windows_bridge.gateway.idempotency import IdempotencyStore
from hermes_windows_bridge.gateway.job_models import (
    JobKind,
    JobLimits,
    JobReplayConflictError,
    JobSnapshot,
    JobSpec,
    JobState,
)
from hermes_windows_bridge.gateway.jobs import JobRegistry
from hermes_windows_bridge.gateway.mcp_server import create_gateway_server
from hermes_windows_bridge.gateway.policy import (
    ApprovalDecision,
    ApprovalManager,
    ApprovalMethod,
    ApprovalSubmission,
)
from hermes_windows_bridge.privileged.ipc_server import HelperRegistry
from hermes_windows_bridge.tools.jobs import InvalidJobDispatcherError, JobTools, register_job_tools
from hermes_windows_bridge.worker.ipc_client import WorkerRegistry
from hermes_windows_bridge.worker.job_process import RunningJobProcess

if TYPE_CHECKING:
    from pathlib import Path

    from hermes_windows_bridge.ipc.protocol import JsonPayload


def _dispatcher(
    registry: JobRegistry, approvals: ApprovalManager | None = None
) -> GatewayDispatcher:
    return GatewayDispatcher(
        DispatcherServices(
            workers=WorkerRegistry(),
            helpers=HelperRegistry(),
            idempotency=IdempotencyStore(ttl=timedelta(minutes=30)),
            approvals=approvals or ApprovalManager(),
            audit=AuditRecorder(),
            jobs=registry,
        )
    )


def _approve(approvals: ApprovalManager, operation_id: UUID, payload: JsonPayload) -> str:
    submission = approvals.request(
        ApprovalSubmission(
            operation_id=operation_id,
            tool_name="job_start",
            payload=payload,
            requested_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(minutes=1),
        )
    )
    _ = approvals.decide(
        ApprovalDecision(
            approval_id=submission.approval_id,
            approved=True,
            method=ApprovalMethod.LOCAL,
            decided_at=datetime.now(UTC),
        )
    )
    return str(submission.approval_id)


def test_job_tools_publish_closed_destructive_mcp_schemas(tmp_path: Path) -> None:
    with JobRegistry(tmp_path / "jobs", process_factory=RunningJobProcess) as registry:
        server = create_gateway_server("x" * 32)
        register_job_tools(server, _dispatcher(registry))
        published = anyio.run(server.list_tools)

    assert {tool.name for tool in published} == {
        "job_start",
        "job_status",
        "job_output",
        "job_cancel",
    }
    assert all(tool.input_schema.get("additionalProperties") is False for tool in published)
    start = next(tool for tool in published if tool.name == "job_start")
    assert start.annotations is not None
    assert start.annotations.read_only_hint is False
    assert start.annotations.destructive_hint is True
    assert start.annotations.open_world_hint is True


def test_public_registration_fails_closed_without_dispatcher(tmp_path: Path) -> None:
    server = create_gateway_server("x" * 32)
    with JobRegistry(tmp_path / "jobs", process_factory=RunningJobProcess) as registry:
        wrong = cast("GatewayDispatcher", cast("object", JobTools(registry)))
        with pytest.raises(InvalidJobDispatcherError):
            register_job_tools(server, wrong)


def test_public_start_requires_approval_and_binds_full_payload(tmp_path: Path) -> None:
    marker = tmp_path / "executed.txt"
    changed_marker = tmp_path / "changed.txt"
    operation_id = uuid4()
    code = "from pathlib import Path;import sys;Path(sys.argv[1]).write_text('ran')"
    argv = (sys.executable, "-c", code, str(marker))
    payload: JsonPayload = {"kind": "process", "argv": list(argv), "cwd": str(tmp_path)}
    approvals = ApprovalManager()
    with JobRegistry(tmp_path / "jobs", process_factory=RunningJobProcess) as registry:
        server = create_gateway_server("x" * 32)
        register_job_tools(server, _dispatcher(registry, approvals))
        base = {"operation_id": str(operation_id), **payload}

        denied = anyio.run(server.call_tool, "job_start", base)
        time.sleep(0.1)
        assert isinstance(denied, CallToolResult)
        assert denied.is_error is True
        assert marker.exists() is False

        approved = anyio.run(
            server.call_tool,
            "job_start",
            {**base, "approval_id": _approve(approvals, operation_id, payload)},
        )
        assert isinstance(approved, CallToolResult)
        assert approved.is_error is False
        assert isinstance(approved.content[0], TextContent)
        started = JobSnapshot.model_validate_json(approved.content[0].text)
        while registry.status(started.job_id).state not in {JobState.SUCCEEDED, JobState.FAILED}:
            time.sleep(0.02)
        assert marker.read_text() == "ran"

        replay = anyio.run(
            server.call_tool,
            "job_start",
            {**base, "approval_id": _approve(approvals, operation_id, payload)},
        )
        assert isinstance(replay, CallToolResult)
        assert (replay.meta or {}).get("replayed") is True

        changed_argv = (*argv[:-1], str(changed_marker))
        changed_payload: JsonPayload = {
            "kind": "process",
            "argv": list(changed_argv),
            "cwd": str(tmp_path),
        }
        conflict = anyio.run(
            server.call_tool,
            "job_start",
            {
                "operation_id": str(operation_id),
                "approval_id": _approve(approvals, operation_id, changed_payload),
                **changed_payload,
            },
        )
        assert isinstance(conflict, CallToolResult)
        assert conflict.is_error is True
        assert isinstance(conflict.content[0], TextContent)
        assert "idempotency_conflict" in conflict.content[0].text
        assert changed_marker.exists() is False


def test_registry_identical_replay_returns_same_job(tmp_path: Path) -> None:
    operation_id = uuid4()
    spec = JobSpec(
        operation_id=operation_id,
        kind=JobKind.PROCESS,
        argv=(sys.executable, "-c", "raise SystemExit(0)"),
        cwd=tmp_path,
    )
    with JobRegistry(tmp_path / "jobs", process_factory=RunningJobProcess) as registry:
        first = registry.start(spec)
        assert registry.start(spec).job_id == first.job_id


def test_registry_replay_rejects_changed_argv_and_limits_after_restart(tmp_path: Path) -> None:
    operation_id = uuid4()
    spec = JobSpec(
        operation_id=operation_id,
        kind=JobKind.PROCESS,
        argv=(sys.executable, "-c", "raise SystemExit(0)"),
        cwd=tmp_path,
    )
    with JobRegistry(
        tmp_path / "jobs",
        process_factory=RunningJobProcess,
        limits=JobLimits(max_output_bytes=64),
    ) as registry:
        _ = registry.start(spec)
        with pytest.raises(JobReplayConflictError):
            _ = registry.start(
                JobSpec(
                    operation_id=operation_id,
                    kind=JobKind.PROCESS,
                    argv=(*spec.argv[:-1], "raise SystemExit(7)"),
                    cwd=tmp_path,
                )
            )

    with (
        JobRegistry(
            tmp_path / "jobs",
            process_factory=RunningJobProcess,
            limits=JobLimits(max_output_bytes=65),
        ) as registry,
        pytest.raises(JobReplayConflictError),
    ):
        _ = registry.start(spec)
