"""Computer input MCP 등록의 schema와 실행 경로를 검증합니다."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, final

import pytest
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult, TextContent
from pydantic import JsonValue

from hermes_windows_bridge.gateway.mcp_server import create_gateway_server
from hermes_windows_bridge.tools.computer_input import register_computer_input_tools
from hermes_windows_bridge.tools.uia import register_uia_tools

if TYPE_CHECKING:
    from pydantic import JsonValue

    from hermes_windows_bridge.gateway.dispatcher import DispatchCall
    from hermes_windows_bridge.gateway.mcp_server import GatewayMCPServer


@dataclass(frozen=True, slots=True)
class _DispatchOutcome:
    result: CallToolResult


@final
class _RecordingDispatcher:
    """실제 MCP handler가 전달한 typed call과 Worker receipt만 기록합니다."""

    def __init__(self, result: CallToolResult) -> None:
        self.calls: list[DispatchCall] = []
        self._result: CallToolResult = result

    async def dispatch(self, call: DispatchCall) -> _DispatchOutcome:
        self.calls.append(call)
        return _DispatchOutcome(result=self._result)


def _server(dispatcher: _RecordingDispatcher) -> GatewayMCPServer:
    server = create_gateway_server("test-token")
    register_computer_input_tools(server, dispatcher)
    return server


def _uia_server(dispatcher: _RecordingDispatcher) -> GatewayMCPServer:
    server = create_gateway_server("test-token")
    register_uia_tools(server, dispatcher)
    return server


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("tool_name", "arguments"),
    [
        ("computer_click", {"x": 0, "y": 0}),
        ("computer_move", {"x": 0, "y": 0}),
        ("computer_scroll", {"delta_y": 120}),
        ("computer_type", {"text": "literal"}),
        ("computer_hotkey", {"keys": ["ctrl", "shift"]}),
        ("computer_key", {"key": "escape"}),
    ],
)
async def test_flat_input_schema_reaches_registered_computer_handler(
    tool_name: str,
    arguments: dict[str, JsonValue],
) -> None:
    # Given: 실제 Gateway MCP server에 mutating computer 도구가 등록되어 있습니다.
    receipt = CallToolResult(content=[TextContent(text='{"ok":true}')])
    dispatcher = _RecordingDispatcher(receipt)
    server = _server(dispatcher)

    # When: tools/list가 공개한 평탄 input을 그대로 tools/call에 전달합니다.
    tool = next(item for item in await server.list_tools() if item.name == tool_name)
    result = await server.call_tool(tool_name, arguments)

    # Then: 내부 handler가 가짜 arguments wrapper를 요구하지 않고 dispatcher에 도달합니다.
    assert "arguments" not in repr(tool.input_schema)
    assert result == receipt
    assert [call.tool_name for call in dispatcher.calls] == [tool_name]


@pytest.mark.anyio
async def test_invalid_flat_input_is_rejected_before_dispatch() -> None:
    # Given: extra-forbid computer_click schema가 등록되어 있습니다.
    dispatcher = _RecordingDispatcher(CallToolResult(content=[]))
    server = _server(dispatcher)

    # When / Then: 공개 schema 밖의 평탄 필드는 Worker dispatcher에 도달하지 못합니다.
    with pytest.raises(ToolError, match="extra_forbidden"):
        _ = await server.call_tool("computer_click", {"x": 0, "y": 0, "unexpected": True})
    assert dispatcher.calls == []


@pytest.mark.anyio
async def test_emergency_stop_receipt_is_returned_unchanged() -> None:
    # Given: Worker가 생성한 typed emergency-stop receipt입니다.
    receipt = CallToolResult(
        content=[TextContent(text='{"error":{"code":"emergency_stop"}}')],
        structured_content={"error": {"code": "emergency_stop"}},
        is_error=True,
    )
    dispatcher = _RecordingDispatcher(receipt)
    server = _server(dispatcher)

    # When: 실제 등록된 MCP handler로 안전한 좌표의 click을 호출합니다.
    result = await server.call_tool("computer_click", {"x": 0, "y": 0})

    # Then: local gate의 emergency-stop 결과가 변경 없이 caller에게 전달됩니다.
    assert result == receipt
    assert [call.tool_name for call in dispatcher.calls] == ["computer_click"]


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("tool_name", "arguments"),
    [
        ("uia_find", {"selector": {"title": "Fixture"}}),
        (
            "uia_action",
            {
                "selector": {"window_title_contains": "Fixture"},
                "action": "focus",
            },
        ),
    ],
)
async def test_flat_input_schema_reaches_registered_uia_handler(
    tool_name: str,
    arguments: dict[str, JsonValue],
) -> None:
    # Given: 실제 Gateway MCP server에 UIA 도구가 등록되어 있습니다.
    receipt = CallToolResult(content=[TextContent(text='{"ok":true}')])
    dispatcher = _RecordingDispatcher(receipt)
    server = _uia_server(dispatcher)

    # When: tools/list가 공개한 평탄 input을 그대로 tools/call에 전달합니다.
    tool = next(item for item in await server.list_tools() if item.name == tool_name)
    result = await server.call_tool(tool_name, arguments)

    # Then: UIA handler도 가짜 arguments wrapper 없이 dispatcher에 도달합니다.
    assert "arguments" not in repr(tool.input_schema)
    assert result == receipt
    assert [call.tool_name for call in dispatcher.calls] == [tool_name]
