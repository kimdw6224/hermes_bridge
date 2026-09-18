"""Official MCP SDK application assembly for the gateway."""

# pyright: reportExplicitAny=false

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, override

from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import AnyHttpUrl, BaseModel, ValidationError

from hermes_windows_bridge.gateway.auth import StaticBearerTokenVerifier
from hermes_windows_bridge.gateway.tailscale_identity import (
    AppCapabilityMiddleware,
    AppCapabilityPolicy,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from mcp.server.auth.provider import TokenVerifier
    from mcp.server.streamable_http import EventStore
    from mcp.server.transport_security import TransportSecuritySettings
    from mcp.types import CallToolResult, InputRequiredResult, Tool, ToolAnnotations
    from starlette.applications import Starlette

    from hermes_windows_bridge.gateway.origin_host import GatewayTransportPolicy


class ToolRegistrar(Protocol):
    """공식 MCPServer API에 도구를 합성하는 주입 seam입니다."""

    def __call__(self, server: GatewayMCPServer) -> None:
        """도구를 server에 등록합니다."""
        ...


class GatewayMCPServer(MCPServer[None]):
    """SDK tool registration에 closed external input models를 결합합니다."""

    def __init__(
        self,
        *,
        name: str,
        version: str,
        auth: AuthSettings,
        token_verifier: TokenVerifier,
        app_capability_policy: AppCapabilityPolicy | None = None,
    ) -> None:
        """Gateway가 사용하는 SDK 생성 인자와 closed schema 저장소를 초기화합니다."""
        super().__init__(name=name, version=version, auth=auth, token_verifier=token_verifier)
        self._closed_inputs: dict[str, type[BaseModel]] = {}
        self._app_capability_policy: AppCapabilityPolicy | None = app_capability_policy

    @override
    def streamable_http_app(
        self,
        *,
        streamable_http_path: str = "/mcp",
        json_response: bool = False,
        stateless_http: bool = False,
        event_store: EventStore | None = None,
        retry_interval: int | None = None,
        max_request_body_size: int = 4_194_304,
        transport_security: TransportSecuritySettings | None = None,
        host: str = "127.0.0.1",
    ) -> Starlette:
        """Apply the optional Serve capability boundary to every SDK HTTP path."""
        app = super().streamable_http_app(
            streamable_http_path=streamable_http_path,
            json_response=json_response,
            stateless_http=stateless_http,
            event_store=event_store,
            retry_interval=retry_interval,
            max_request_body_size=max_request_body_size,
            transport_security=transport_security,
            host=host,
        )
        if self._app_capability_policy is not None:
            app.add_middleware(
                AppCapabilityMiddleware,
                policy=self._app_capability_policy,
            )
        return app

    def add_closed_tool(  # noqa: PLR0913 - SDK registration fields를 그대로 전달합니다.
        self,
        fn: Callable[..., Awaitable[CallToolResult]],
        *,
        input_model: type[BaseModel],
        name: str,
        description: str,
        annotations: ToolAnnotations,
        structured_output: bool,
    ) -> None:
        """공식 add_tool로 등록하고 동일 모델을 공개 경계에 적용합니다."""
        super().add_tool(
            fn,
            name=name,
            description=description,
            annotations=annotations,
            structured_output=structured_output,
        )
        inputs = dict(getattr(self, "_closed_inputs", {}))
        inputs[name] = input_model
        self._closed_inputs = inputs

    @override
    async def list_tools(self) -> list[Tool]:
        tools = await super().list_tools()
        inputs = self._closed_inputs
        return [
            tool.model_copy(update={"input_schema": inputs[tool.name].model_json_schema()})
            if tool.name in inputs
            else tool
            for tool in tools
        ]

    @override
    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        context: Context[None, Any] | None = None,
    ) -> CallToolResult | InputRequiredResult:
        model = self._closed_inputs.get(name)
        if model is not None:
            try:
                arguments = model.model_validate(arguments).model_dump(mode="python")
            except ValidationError as exc:
                message = f"Error executing tool {name}: {exc}"
                raise ToolError(message) from exc
        return await super().call_tool(name, arguments, context)


def create_gateway_server(
    token: str,
    *,
    register_tools: ToolRegistrar | None = None,
    app_capability_policy: AppCapabilityPolicy | None = None,
) -> GatewayMCPServer:
    """Create the SDK server with mandatory opaque bearer authentication."""
    server = GatewayMCPServer(
        name="hermes-windows-bridge",
        version="0.1.0",
        auth=AuthSettings(
            issuer_url=AnyHttpUrl("https://hermes-windows-bridge.invalid"),
            resource_server_url=None,
        ),
        token_verifier=StaticBearerTokenVerifier(token),
        app_capability_policy=app_capability_policy,
    )
    if register_tools is not None:
        register_tools(server)
    return server


def create_gateway_app(
    *,
    token: str,
    policy: GatewayTransportPolicy,
    register_tools: ToolRegistrar | None = None,
    app_capability_policy: AppCapabilityPolicy | None = None,
) -> Starlette:
    """Create the authenticated `/mcp` ASGI application.

    The SDK owns the fail-closed order: bearer authentication and the protected route run
    before Content-Type/Host/Origin checks, then JSON and protocol routing-header checks.
    """
    server = create_gateway_server(
        token,
        register_tools=register_tools,
        app_capability_policy=app_capability_policy,
    )
    return server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        transport_security=policy.sdk_settings(),
        host="127.0.0.1",
    )
