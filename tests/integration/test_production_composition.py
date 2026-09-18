from __future__ import annotations

import multiprocessing
import sys
from threading import Event, Thread
from typing import cast
from uuid import UUID, uuid4

import anyio
import pytest
from mcp.types import CallToolResult, TextContent

from hermes_windows_bridge.gateway.main import (
    GatewayRegistries,
    build_gateway_server,
)
from hermes_windows_bridge.gateway.worker_runtime import GatewayWorkerWatcher
from hermes_windows_bridge.ipc.acl import current_process_sid
from hermes_windows_bridge.ipc.protocol import IpcRequest, JsonPayload, WorkerRegistration
from hermes_windows_bridge.privileged.ipc_server import HelperRegistry
from hermes_windows_bridge.tools.process import ProcessListResult
from hermes_windows_bridge.worker.ipc_client import WorkerRegistry
from hermes_windows_bridge.worker.operations import WorkerOperationDispatcher
from hermes_windows_bridge.worker.pipe_server import WorkerPipeConfig, serve_worker_pipe

EXPECTED_PUBLIC_TOOLS = frozenset(
    {
        "app_open",
        "browser_click",
        "browser_close",
        "browser_extract",
        "browser_navigate",
        "browser_open",
        "browser_snapshot",
        "browser_status",
        "browser_type",
        "codex_run",
        "codex_status",
        "computer_click",
        "computer_hotkey",
        "computer_key",
        "computer_move",
        "computer_observe",
        "computer_scroll",
        "computer_type",
        "fs_copy",
        "fs_delete",
        "fs_list",
        "fs_mkdir",
        "fs_move",
        "fs_read",
        "fs_stat",
        "fs_write",
        "job_cancel",
        "job_output",
        "job_start",
        "job_status",
        "process_kill",
        "process_list",
        "process_start",
        "shell_run",
        "status",
        "system_lock",
        "system_reboot",
        "system_shutdown",
        "system_sleep",
        "uia_action",
        "uia_find",
    }
)
FORBIDDEN_PUBLIC_TOOLS = frozenset(
    {
        "admin_shell",
        "approval_grant",
        "approve",
        "elevated_shell",
        "run_as_system",
        "system_shell",
    }
)


class _ProcessListHandler:
    def __call__(self, request: IpcRequest) -> JsonPayload:
        del request
        return {"processes": []}

    def cancel(self, request_id: UUID) -> bool:
        del request_id
        return False


def _serve_production_worker(pipe_name: str, sid: str, stop: Event) -> None:
    registration = WorkerRegistration(
        registration_id=uuid4(),
        generation=1,
        session_id=1,
        username="TEST\\worker",
    )
    dispatcher = WorkerOperationDispatcher({"process_list": _ProcessListHandler()})
    serve_worker_pipe(
        WorkerPipeConfig(
            pipe_name=pipe_name,
            target_user_sid=sid,
            registration=registration,
            expected_gateway_sid=sid,
            heartbeat_interval_seconds=0.05,
        ),
        dispatcher,
        stop,
    )


@pytest.mark.integration
def test_production_tools_list_matches_required_public_surface() -> None:
    # Given: 실제 production composition으로 만든 공식 MCP 서버입니다.
    server = build_gateway_server("test-token")

    # When: SDK의 tools/list 구현이 사용하는 공개 목록을 조회합니다.
    names = frozenset(tool.name for tool in anyio.run(server.list_tools))

    # Then: 명세의 전체 도구만 노출되고 승인/관리자 shell 표면은 없습니다.
    assert names == EXPECTED_PUBLIC_TOOLS
    assert names.isdisjoint(FORBIDDEN_PUBLIC_TOOLS)


@pytest.mark.integration
def test_production_tool_input_schemas_reject_unknown_fields() -> None:
    # Given: 실제 production composition의 전체 공식 MCP 도구 목록입니다.
    server = build_gateway_server("test-token")

    # When: SDK가 노출하는 입력 JSON Schema를 읽습니다.
    tools = anyio.run(server.list_tools)

    # Then: 모든 public boundary가 선언하지 않은 인자를 실패 폐쇄합니다.
    assert tools
    assert all(tool.input_schema.get("additionalProperties") is False for tool in tools)


@pytest.mark.integration
def test_production_worker_tool_stays_typed_when_worker_is_offline() -> None:
    # Given: 실제 production composition이지만 연결된 Worker가 없습니다.
    server = build_gateway_server("test-token")

    # When: Gateway에서 직접 실행해서는 안 되는 읽기 도구를 호출합니다.
    result = anyio.run(server.call_tool, "fs_list", {"path": "."})

    # Then: Gateway가 로컬 파일을 읽지 않고 typed Worker failure를 반환합니다.
    assert isinstance(result, CallToolResult)
    assert result.is_error is True
    assert TextContent.model_validate(result.content[0]).text == (
        '{"error":{"code":"worker_unavailable"}}'
    )


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "win32", reason="Windows named pipe required")
def test_production_process_tool_calls_worker_through_named_pipe() -> None:
    # Given: 별도 process의 실제 Worker pipe와 production registry watcher입니다.
    context = multiprocessing.get_context("spawn")
    stop = context.Event()
    pipe_name = rf"\\.\pipe\HermesWindowsBridgeComposition-{uuid4()}"
    sid = current_process_sid()
    process = context.Process(target=_serve_production_worker, args=(pipe_name, sid, stop))
    registries = GatewayRegistries(WorkerRegistry(), HelperRegistry())
    watcher = GatewayWorkerWatcher(pipe_name, registries.workers, connect_timeout_ms=200)
    watcher_thread = Thread(target=watcher.run, daemon=True)
    process.start()
    watcher_thread.start()
    try:
        assert watcher.wait_for_connections(1, timeout_seconds=3)
        server = build_gateway_server("test-token", registries=registries)

        # When: production MCP process_list를 호출합니다.
        arguments: JsonPayload = {}
        result = anyio.run(server.call_tool, "process_list", arguments)

        # Then: 요청은 authenticated pipe Worker를 왕복한 payload를 반환합니다.
        assert isinstance(result, CallToolResult)
        assert result.is_error is False
        structured_content = ProcessListResult.model_validate(
            cast("JsonPayload", result.structured_content)
        )
        assert structured_content.processes == ()
    finally:
        watcher.close()
        stop.set()
        process.join(3)
        if process.is_alive():
            process.terminate()
            process.join(2)
        watcher_thread.join(2)
    assert process.exitcode == 0
