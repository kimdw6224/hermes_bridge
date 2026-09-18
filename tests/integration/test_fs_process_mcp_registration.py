from __future__ import annotations

from datetime import timedelta
from uuid import UUID, uuid4

import anyio
import pytest
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult, TextContent

from hermes_windows_bridge.gateway import policy
from hermes_windows_bridge.gateway.audit import AuditRecorder
from hermes_windows_bridge.gateway.dispatcher import DispatcherServices, GatewayDispatcher
from hermes_windows_bridge.gateway.idempotency import IdempotencyStore
from hermes_windows_bridge.gateway.mcp_server import GatewayMCPServer, create_gateway_server
from hermes_windows_bridge.ipc import protocol as ipc
from hermes_windows_bridge.privileged.ipc_server import HelperRegistry
from hermes_windows_bridge.tools.fs_process_mcp import (
    register_filesystem_tools,
    register_process_tools,
)
from hermes_windows_bridge.worker.ipc_client import WorkerRegistry

pytestmark = pytest.mark.integration

_REGISTRATION_ID = UUID("3d1176f8-61a9-4d06-ad2e-3dd5ce0f67fd")
_READ_ONLY = frozenset({"fs_list", "fs_stat", "fs_read", "process_list"})
_DESTRUCTIVE = frozenset({"fs_delete", "process_kill"})
_IDEMPOTENT = _READ_ONLY | frozenset({"fs_write", "fs_mkdir", "fs_delete"})


class RecordingEndpoint:
    def __init__(self) -> None:
        self.requests: list[ipc.RequestMessage] = []

    def exchange(self, request: ipc.RequestMessage) -> ipc.IpcResponse:
        self.requests.append(request)
        return ipc.IpcResponse(
            request_id=request.request_id,
            ok=True,
            payload={"accepted_operation": request.operation},
        )

    def cancel(self, request_id: UUID, reason: str) -> bool:
        del request_id, reason
        return False


def _dispatcher(endpoint: RecordingEndpoint | None = None) -> GatewayDispatcher:
    workers = WorkerRegistry()
    if endpoint is not None:
        workers.register(
            ipc.WorkerRegistration(
                registration_id=_REGISTRATION_ID,
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
            approvals=policy.ApprovalManager(),
            audit=AuditRecorder(),
        )
    )


def _server(dispatcher: GatewayDispatcher) -> GatewayMCPServer:
    server = create_gateway_server("test-token")
    register_filesystem_tools(server, dispatcher)
    register_process_tools(server, dispatcher)
    return server


def _text(result: CallToolResult) -> str:
    return TextContent.model_validate(result.content[0]).text


@pytest.mark.parametrize(
    ("tool_name", "arguments", "expected_payload"),
    [
        ("fs_list", {"path": "C:\\safe"}, {"path": "C:\\safe"}),
        (
            "fs_stat",
            {"path": "C:\\safe\\item.txt"},
            {"path": "C:\\safe\\item.txt", "offset": 0, "length": None, "encoding": "utf-8"},
        ),
        (
            "fs_read",
            {"path": "C:\\safe\\item.txt", "offset": 2, "length": 4, "encoding": "base64"},
            {"path": "C:\\safe\\item.txt", "offset": 2, "length": 4, "encoding": "base64"},
        ),
        (
            "fs_write",
            {
                "operation_id": "00000000-0000-4000-8000-000000000001",
                "path": "C:\\safe\\item.txt",
                "text": "safe text",
            },
            {"path": "C:\\safe\\item.txt", "text": "safe text", "base64_data": None},
        ),
        (
            "fs_move",
            {
                "operation_id": "00000000-0000-4000-8000-000000000002",
                "source": "C:\\safe\\source.txt",
                "destination": "C:\\safe\\destination.txt",
            },
            {"source": "C:\\safe\\source.txt", "destination": "C:\\safe\\destination.txt"},
        ),
        (
            "fs_copy",
            {
                "operation_id": "00000000-0000-4000-8000-000000000003",
                "source": "C:\\safe\\source.txt",
                "destination": "C:\\safe\\destination.txt",
            },
            {"source": "C:\\safe\\source.txt", "destination": "C:\\safe\\destination.txt"},
        ),
        (
            "fs_delete",
            {
                "operation_id": "00000000-0000-4000-8000-000000000004",
                "path": "C:\\safe\\item.txt",
                "recursive": True,
            },
            {"path": "C:\\safe\\item.txt", "recursive": True},
        ),
        (
            "fs_mkdir",
            {
                "operation_id": "00000000-0000-4000-8000-000000000005",
                "path": "C:\\safe\\folder",
                "parents": True,
            },
            {"path": "C:\\safe\\folder", "parents": True},
        ),
        ("process_list", {}, {}),
        (
            "process_start",
            {
                "operation_id": "00000000-0000-4000-8000-000000000006",
                "argv": ["cmd.exe", "/c", "echo harmless"],
                "cwd": "C:\\safe",
                "lifecycle_managed": True,
            },
            {
                "argv": ["cmd.exe", "/c", "echo harmless"],
                "cwd": "C:\\safe",
                "lifecycle_managed": True,
            },
        ),
        (
            "process_kill",
            {"operation_id": "00000000-0000-4000-8000-000000000007", "pid": 1234},
            {"pid": 1234},
        ),
        (
            "app_open",
            {
                "operation_id": "00000000-0000-4000-8000-000000000008",
                "target": "notepad.exe",
                "arguments": ["C:\\safe\\read-only.txt"],
                "cwd": "C:\\safe",
            },
            {"target": "notepad.exe", "arguments": ["C:\\safe\\read-only.txt"], "cwd": "C:\\safe"},
        ),
    ],
)
def test_registered_tools_dispatch_exact_closed_payloads(
    tool_name: str,
    arguments: dict[str, str | bool | int | list[str]],
    expected_payload: ipc.JsonPayload,
) -> None:
    # Given: 실제 Worker 대신 기록만 하는 IPC endpoint와 공식 MCP 공개 표면입니다.
    endpoint = RecordingEndpoint()
    server = _server(_dispatcher(endpoint))

    # When: MCP SDK public call 경계에서 하나의 filesystem/process 요청을 호출합니다.
    result = anyio.run(server.call_tool, tool_name, arguments)

    # Then: Gateway policy/idempotency/audit 이후 IPC에 정확히 한 번 같은 payload만 전달됩니다.
    assert isinstance(result, CallToolResult)
    assert result.is_error is False
    assert _text(result) == f'{{"accepted_operation":"{tool_name}"}}'
    assert len(endpoint.requests) == 1
    request = endpoint.requests[0]
    assert isinstance(request, ipc.IpcRequest)
    assert request.operation == tool_name
    assert request.payload == expected_payload


def test_registered_tools_expose_exact_names_closed_schemas_and_truthful_hints() -> None:
    # Given: Worker가 없는 등록 전용 gateway입니다.
    server = _server(_dispatcher())

    # When: 공식 tools/list 결과를 조회합니다.
    tools = anyio.run(server.list_tools)

    # Then: 정확히 열두 도구가 closed input schema와 policy-aligned annotation을 제공합니다.
    exposed = {tool.name: tool for tool in tools}
    expected_names = {
        name
        for name in policy.registered_tool_names()
        if name.startswith(("fs_", "process_")) or name == "app_open"
    }
    assert set(exposed) == expected_names
    for name, tool in exposed.items():
        assert tool.input_schema.get("additionalProperties") is False
        assert tool.annotations is not None
        assert tool.annotations.read_only_hint is (name in _READ_ONLY)
        assert tool.annotations.destructive_hint is (name in _DESTRUCTIVE)
        assert tool.annotations.idempotent_hint is (name in _IDEMPOTENT)
        assert tool.annotations.open_world_hint is False


def test_closed_public_boundary_rejects_privilege_and_ambiguous_pid_surfaces() -> None:
    # Given: 공개 MCP registration과 dispatcher spy가 있습니다.
    endpoint = RecordingEndpoint()
    server = _server(_dispatcher(endpoint))

    # When/Then: unsupported elevation/all-process fields는 IPC 전에 schema에서 실패합니다.
    with pytest.raises(ToolError, match="elevated"):
        _ = anyio.run(
            server.call_tool,
            "fs_write",
            {
                "operation_id": str(uuid4()),
                "path": "C:\\safe\\item.txt",
                "text": "safe text",
                "elevated": True,
            },
        )
    with pytest.raises(ToolError, match="all"):
        _ = anyio.run(
            server.call_tool,
            "process_kill",
            {"operation_id": str(uuid4()), "pid": 1234, "all": True},
        )
    assert endpoint.requests == []


def test_destructive_request_obeys_dispatcher_approval_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: fs_delete를 approval-required로 분류한 dispatcher와 online Worker입니다.
    endpoint = RecordingEndpoint()
    server = _server(_dispatcher(endpoint))

    def require_approval(_tool_name: str) -> policy.PolicyDecision:
        return policy.PolicyDecision.REQUIRE_APPROVAL

    monkeypatch.setattr(policy, "evaluate_tool", require_approval)

    # When: approval receipt 없는 destructive 요청을 호출합니다.
    result = anyio.run(
        server.call_tool,
        "fs_delete",
        {
            "operation_id": "00000000-0000-4000-8000-000000000009",
            "path": "C:\\safe\\item.txt",
        },
    )

    # Then: Gateway가 worker IPC 전에 typed approval error로 fail-closed 합니다.
    assert isinstance(result, CallToolResult)
    assert result.is_error is True
    assert _text(result) == '{"error":{"code":"approval_required"}}'
    assert endpoint.requests == []


def test_missing_worker_returns_typed_unavailable_without_machine_mutation() -> None:
    # Given: Worker registry가 비어 있는 official MCP server입니다.
    server = _server(_dispatcher())

    # When: 직접 process 실행 대신 process_start 공개 surface를 호출합니다.
    result = anyio.run(
        server.call_tool,
        "process_start",
        {
            "operation_id": "00000000-0000-4000-8000-000000000010",
            "argv": ["cmd.exe", "/c", "echo must-not-run"],
            "cwd": "C:\\safe",
        },
    )

    # Then: Gateway는 local ProcessManager를 만들지 않고 typed Worker error를 반환합니다.
    assert isinstance(result, CallToolResult)
    assert result.is_error is True
    assert _text(result) == '{"error":{"code":"worker_unavailable"}}'
