"""Production system 도구의 실제 Streamable HTTP elicitation 연결을 검증합니다."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import TYPE_CHECKING, final
from uuid import UUID, uuid4

import anyio
import pytest
import uvicorn
from anyio.lowlevel import checkpoint
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client
from mcp.types import CallToolResult, ClientCapabilities, ElicitResult
from mcp.types.version import LATEST_HANDSHAKE_VERSION, LATEST_MODERN_VERSION
from pydantic import TypeAdapter

from hermes_windows_bridge.gateway.approval_elicitation import supports_form_elicitation
from hermes_windows_bridge.gateway.main import GatewayRegistries, build_gateway_server
from hermes_windows_bridge.ipc import protocol as ipc
from hermes_windows_bridge.privileged.ipc_server import HelperRegistry
from hermes_windows_bridge.worker.ipc_client import WorkerRegistry

if TYPE_CHECKING:
    from mcp.client.session import ClientRequestContext
    from mcp.types import ElicitRequestParams


@final
class _RecordingHelper:
    def __init__(self) -> None:
        self.requests: list[ipc.RequestMessage] = []

    def exchange(self, request: ipc.RequestMessage) -> ipc.IpcResponse:
        self.requests.append(request)
        return ipc.IpcResponse(
            request_id=request.request_id,
            ok=True,
            payload={"operation": "accepted"},
        )

    def cancel(self, request_id: UUID, reason: str) -> bool:
        del request_id, reason
        return False


@dataclass(slots=True)
class _ElicitationDecisions:
    responses: list[ElicitResult]
    calls: int = 0

    async def __call__(
        self,
        context: ClientRequestContext,
        params: ElicitRequestParams,
    ) -> ElicitResult:
        del context, params
        response = self.responses[self.calls]
        self.calls += 1
        return response


@pytest.mark.integration
def test_legacy_url_only_client_cannot_use_form_approval() -> None:
    # Given: legacy protocol에서 URL mode만 선언한 client입니다.
    capabilities = ClientCapabilities.model_validate({"elicitation": {"url": {}}})

    # When/Then: form elicitation을 시도하지 않고 unavailable로 거부합니다.
    assert supports_form_elicitation(capabilities, LATEST_HANDSHAKE_VERSION) is False


@pytest.mark.integration
def test_form_capability_variants_are_protocol_aware() -> None:
    legacy_empty = ClientCapabilities.model_validate({"elicitation": {}})
    modern_empty = ClientCapabilities.model_validate({"elicitation": {}})
    modern_form = ClientCapabilities.model_validate({"elicitation": {"form": {}}})

    assert supports_form_elicitation(legacy_empty, LATEST_HANDSHAKE_VERSION) is True
    assert supports_form_elicitation(modern_empty, LATEST_MODERN_VERSION) is False
    assert supports_form_elicitation(modern_form, LATEST_MODERN_VERSION) is True


async def _exercise_http_elicitation() -> tuple[int, int, list[CallToolResult]]:
    token = "x" * 32
    helper = _RecordingHelper()
    helpers = HelperRegistry()
    helpers.register(generation=1, client=helper)
    server = build_gateway_server(
        token,
        registries=GatewayRegistries(WorkerRegistry(), helpers),
    )
    app = server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=False,
        host="127.0.0.1",
    )
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    address = TypeAdapter(tuple[str, int]).validate_python(listener.getsockname())
    port = address[1]
    http_server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    )
    decisions = _ElicitationDecisions(
        [
            ElicitResult(action="accept", content={"approved": False}),
            ElicitResult(action="accept", content={}),
            ElicitResult(action="cancel"),
            ElicitResult(action="decline"),
        ]
    )
    results: list[CallToolResult] = []
    async with anyio.create_task_group() as task_group:
        _ = task_group.start_soon(http_server.serve, [listener])
        with anyio.fail_after(5):
            while not http_server.started:
                await checkpoint()
        http_client = create_mcp_http_client(
            headers={"Authorization": f"Bearer {token}"}
        )
        async with http_client:
            async with (
                streamable_http_client(
                    f"http://127.0.0.1:{port}/mcp",
                    http_client=http_client,
                ) as streams,
                ClientSession(*streams, elicitation_callback=decisions) as session,
            ):
                _ = await session.initialize()
                invalid = await session.call_tool(
                    "system_shutdown",
                    {
                        "operation_id": str(uuid4()),
                        "approval_id": str(uuid4()),
                        "reason": "invalid receipt",
                    },
                )
                rejected = await session.call_tool(
                    "system_shutdown",
                    {"operation_id": str(uuid4()), "reason": "declined"},
                )
                accepted = await session.call_tool(
                    "system_reboot",
                    {"operation_id": str(uuid4()), "reason": "accepted"},
                )
                cancelled = await session.call_tool(
                    "system_shutdown",
                    {"operation_id": str(uuid4()), "reason": "cancelled"},
                )
                declined = await session.call_tool(
                    "system_reboot",
                    {"operation_id": str(uuid4()), "reason": "declined"},
                )
                assert isinstance(invalid, CallToolResult)
                assert isinstance(rejected, CallToolResult)
                assert isinstance(accepted, CallToolResult)
                assert isinstance(cancelled, CallToolResult)
                assert isinstance(declined, CallToolResult)
                results.extend((invalid, rejected, accepted, cancelled, declined))
            async with (
                streamable_http_client(
                    f"http://127.0.0.1:{port}/mcp",
                    http_client=http_client,
                ) as streams,
                ClientSession(*streams) as unsupported_session,
            ):
                _ = await unsupported_session.initialize()
                unsupported = await unsupported_session.call_tool(
                    "system_reboot",
                    {"operation_id": str(uuid4()), "reason": "unsupported"},
                )
                assert isinstance(unsupported, CallToolResult)
                results.append(unsupported)
        http_server.should_exit = True
    listener.close()
    return decisions.calls, len(helper.requests), results


@pytest.mark.integration
def test_request_scoped_http_elicitation_gates_typed_helper_once() -> None:
    # Given/When: 실제 SDK HTTP/SSE client가 invalid ID, false, true 요청을 순서대로 보냅니다.
    elicitation_calls, helper_calls, results = anyio.run(_exercise_http_elicitation)

    # Then: invalid ID는 prompt 없이 거부되고 명시적 true만 Helper에 한 번 도달합니다.
    assert elicitation_calls == 4
    assert helper_calls == 1
    assert [result.is_error for result in results] == [True, True, False, True, True, True]
