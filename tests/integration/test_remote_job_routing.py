from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import anyio
import pytest
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult, TextContent

from hermes_windows_bridge.gateway.audit import AuditRecorder
from hermes_windows_bridge.gateway.dispatcher import (
    DispatchCall,
    DispatcherServices,
    GatewayDispatcher,
)
from hermes_windows_bridge.gateway.idempotency import IdempotencyStore
from hermes_windows_bridge.gateway.jobs import JobRegistry
from hermes_windows_bridge.gateway.mcp_server import create_gateway_server
from hermes_windows_bridge.gateway.policy import (
    ApprovalDecision,
    ApprovalManager,
    ApprovalMethod,
    ApprovalSubmission,
)
from hermes_windows_bridge.ipc import protocol as ipc
from hermes_windows_bridge.privileged.ipc_server import HelperRegistry
from hermes_windows_bridge.tools.jobs import register_remote_job_tools
from hermes_windows_bridge.worker.ipc_client import WorkerRegistry
from hermes_windows_bridge.worker.job_process import RunningJobProcess

if TYPE_CHECKING:
    from pathlib import Path

    from hermes_windows_bridge.gateway.mcp_server import GatewayMCPServer
    from hermes_windows_bridge.ipc.protocol import JsonPayload, RequestMessage

pytestmark = pytest.mark.integration


class RecordingJobEndpoint:
    """실제 process 없이 Worker IPC 계약과 실행 횟수만 기록합니다."""

    def __init__(self) -> None:
        self.requests: list[RequestMessage] = []
        self.executions: int = 0

    def exchange(self, request: RequestMessage) -> ipc.IpcResponse:
        self.requests.append(request)
        self.executions += 1
        return ipc.IpcResponse(
            request_id=request.request_id,
            ok=True,
            payload={"accepted_operation": request.operation},
        )

    def cancel(self, request_id: UUID, reason: str) -> bool:
        del request_id, reason
        return False


def _dispatcher(
    endpoint: RecordingJobEndpoint | None = None,
    *,
    jobs: JobRegistry | None = None,
    approvals: ApprovalManager | None = None,
) -> GatewayDispatcher:
    workers = WorkerRegistry()
    if endpoint is not None:
        workers.register(
            ipc.WorkerRegistration(
                registration_id=uuid4(),
                generation=1,
                session_id=1,
                username="test-worker",
            ),
            endpoint,
        )
    return GatewayDispatcher(
        DispatcherServices(
            workers=workers,
            helpers=HelperRegistry(),
            idempotency=IdempotencyStore(ttl=timedelta(minutes=1)),
            approvals=approvals or ApprovalManager(),
            audit=AuditRecorder(),
            jobs=jobs,
        )
    )


def _server(dispatcher: GatewayDispatcher) -> GatewayMCPServer:
    server = create_gateway_server("x" * 32)
    register_remote_job_tools(server, dispatcher)
    return server


def _approve(
    approvals: ApprovalManager,
    operation_id: UUID,
    payload: JsonPayload,
) -> UUID:
    now = datetime.now(UTC)
    record = approvals.request(
        ApprovalSubmission(
            operation_id=operation_id,
            tool_name="job_start",
            payload=payload,
            requested_at=now,
            expires_at=now + timedelta(minutes=1),
        )
    )
    _ = approvals.decide(
        ApprovalDecision(
            approval_id=record.approval_id,
            approved=True,
            method=ApprovalMethod.LOCAL,
            decided_at=now,
        )
    )
    return record.approval_id


def _text(result: CallToolResult) -> str:
    return TextContent.model_validate(result.content[0]).text


def test_remote_job_start_requires_approval_before_worker_and_routes_exact_payload() -> None:
    # Given: 운영처럼 local registry가 없고 로그인 Worker만 등록된 Gateway입니다.
    endpoint = RecordingJobEndpoint()
    approvals = ApprovalManager()
    server = _server(_dispatcher(endpoint, approvals=approvals))
    operation_id = uuid4()
    payload: JsonPayload = {
        "kind": "process",
        "argv": ["cmd.exe", "/c", "exit 0"],
        "cwd": "C:\\safe",
    }

    # When: 같은 요청을 승인 없이 먼저 보내고, 독립 승인 후 다시 보냅니다.
    denied = anyio.run(
        server.call_tool,
        "job_start",
        {"operation_id": str(operation_id), **payload},
    )
    approved = anyio.run(
        server.call_tool,
        "job_start",
        {
            "operation_id": str(operation_id),
            "approval_id": str(_approve(approvals, operation_id, payload)),
            **payload,
        },
    )

    # Then: 미승인 호출은 peer 전에 막히고 승인 ID 없는 exact payload만 Worker에 도달합니다.
    assert isinstance(denied, CallToolResult)
    assert _text(denied) == '{"error":{"code":"approval_required"}}'
    assert isinstance(approved, CallToolResult)
    assert approved.is_error is False
    assert len(endpoint.requests) == 1
    request = endpoint.requests[0]
    assert isinstance(request, ipc.IpcRequest)
    assert request.request_id == operation_id
    assert request.operation == "job_start"
    assert request.payload == payload


@pytest.mark.parametrize(
    ("tool_name", "arguments", "expected_payload"),
    [
        (
            "job_status",
            {"job_id": "00000000-0000-4000-8000-000000000101"},
            {"job_id": "00000000-0000-4000-8000-000000000101"},
        ),
        (
            "job_output",
            {
                "job_id": "00000000-0000-4000-8000-000000000102",
                "stream": "stderr",
                "offset": 7,
                "limit": 65_536,
            },
            {
                "job_id": "00000000-0000-4000-8000-000000000102",
                "stream": "stderr",
                "offset": 7,
                "limit": 65_536,
            },
        ),
        (
            "job_cancel",
            {"job_id": "00000000-0000-4000-8000-000000000103"},
            {"job_id": "00000000-0000-4000-8000-000000000103"},
        ),
    ],
)
def test_remote_job_followups_route_exact_bounded_payloads(
    tool_name: str,
    arguments: JsonPayload,
    expected_payload: JsonPayload,
) -> None:
    # Given: local registry 없이 Worker endpoint만 등록된 공식 MCP surface입니다.
    endpoint = RecordingJobEndpoint()
    server = _server(_dispatcher(endpoint))

    # When: 상태, bounded output 또는 cancel을 호출합니다.
    result = anyio.run(server.call_tool, tool_name, arguments)

    # Then: 해당 typed operation과 닫힌 payload가 Worker IPC에 한 번 전달됩니다.
    assert isinstance(result, CallToolResult)
    assert result.is_error is False
    assert len(endpoint.requests) == 1
    request = endpoint.requests[0]
    assert isinstance(request, ipc.IpcRequest)
    assert request.operation == tool_name
    assert request.payload == expected_payload


def test_remote_job_output_rejects_oversized_window_before_worker() -> None:
    # Given: 호출 횟수를 기록하는 Worker와 closed job_output schema입니다.
    endpoint = RecordingJobEndpoint()
    server = _server(_dispatcher(endpoint))

    # When/Then: 64 KiB를 넘는 window는 IPC 전에 boundary 오류가 됩니다.
    with pytest.raises(ToolError, match="limit"):
        _ = anyio.run(
            server.call_tool,
            "job_output",
            {
                "job_id": str(uuid4()),
                "stream": "stdout",
                "offset": 0,
                "limit": 65_537,
            },
        )
    assert endpoint.requests == []


def test_remote_job_missing_worker_returns_typed_unavailable() -> None:
    # Given: local registry와 Worker가 모두 없는 운영 Gateway입니다.
    server = _server(_dispatcher())

    # When: read-only job status를 호출합니다.
    result = anyio.run(server.call_tool, "job_status", {"job_id": str(uuid4())})

    # Then: Gateway는 local process를 시작하지 않고 typed Worker 오류를 반환합니다.
    assert isinstance(result, CallToolResult)
    assert result.is_error is True
    assert _text(result) == '{"error":{"code":"worker_unavailable"}}'


def test_remote_job_start_replays_same_operation_without_second_peer_execution() -> None:
    # Given: 같은 operation ID에 쓸 별도 one-shot 승인을 두 번 발급할 수 있습니다.
    endpoint = RecordingJobEndpoint()
    approvals = ApprovalManager()
    server = _server(_dispatcher(endpoint, approvals=approvals))
    operation_id = uuid4()
    payload: JsonPayload = {
        "kind": "process",
        "argv": ["cmd.exe", "/c", "exit 0"],
        "cwd": "C:\\safe",
    }

    # When: 동일 payload와 operation ID를 각각 유효한 승인으로 두 번 호출합니다.
    results = [
        anyio.run(
            server.call_tool,
            "job_start",
            {
                "operation_id": str(operation_id),
                "approval_id": str(_approve(approvals, operation_id, payload)),
                **payload,
            },
        )
        for _ in range(2)
    ]

    # Then: Gateway idempotency가 Worker 실행을 한 번으로 제한하고 replay를 표시합니다.
    assert endpoint.executions == 1
    assert [(result.meta or {}).get("replayed") for result in results] == [False, True]


def test_explicit_local_registry_preserves_task17_interception(tmp_path: Path) -> None:
    # Given: Task 17 테스트처럼 명시적 local JobRegistry와 별도 Worker가 함께 있습니다.
    endpoint = RecordingJobEndpoint()
    with JobRegistry(tmp_path / "jobs", process_factory=RunningJobProcess) as registry:
        dispatcher = _dispatcher(endpoint, jobs=registry)
        call = DispatchCall(
            operation_id=uuid4(),
            tool_name="job_status",
            payload={"job_id": str(uuid4())},
            requested_at=datetime.now(UTC),
            timeout_ms=5_000,
        )

        # When: local test seam에서 job_status를 dispatch합니다.
        outcome = anyio.run(dispatcher.dispatch, call)

    # Then: Worker는 호출되지 않고 기존 local typed error 계약이 유지됩니다.
    assert endpoint.requests == []
    assert _text(outcome.result) == '{"error":{"code":"job_not_found"}}'
    assert (outcome.result.meta or {}).get("target") == ipc.PeerRole.GATEWAY.value
