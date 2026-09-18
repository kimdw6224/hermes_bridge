"""요청 범위 MCP elicitation을 독립 전원 승인 surface로 변환합니다."""

# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Protocol, assert_never, final

from anyio import BrokenResourceError, ClosedResourceError, EndOfStream
from mcp.server.elicitation import (
    AcceptedElicitation,
    CancelledElicitation,
    DeclinedElicitation,
)
from mcp.shared.exceptions import MCPError
from mcp.types import ClientCapabilities
from mcp.types.version import MODERN_PROTOCOL_VERSIONS
from pydantic import BaseModel, ConfigDict

from hermes_windows_bridge.gateway.policy import ApprovalSurfaceUnavailableError

if TYPE_CHECKING:
    from mcp.server.context import ServerRequestContext
    from mcp.types import ClientCapabilities

    from hermes_windows_bridge.models.policy import ApprovalRecord

__all__ = ("McpElicitationApprovalSurface", "supports_form_elicitation")


class _ApprovalResponse(BaseModel):
    """Hermes의 빈 accept content와 일치하는 closed 확인 응답입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)


class _ElicitationContext(Protocol):
    @property
    def client_capabilities(self) -> ClientCapabilities | None: ...

    @property
    def protocol_version(self) -> str | None: ...

    @property
    def request_context(self) -> ServerRequestContext[None, None]: ...

    async def elicit(
        self, message: str, schema: type[_ApprovalResponse]
    ) -> AcceptedElicitation[_ApprovalResponse] | DeclinedElicitation | CancelledElicitation: ...


def supports_form_elicitation(
    capabilities: ClientCapabilities | None, protocol_version: str | None
) -> bool:
    """Legacy empty capability와 explicit form을 허용하되 URL-only는 거부합니다."""
    elicitation = capabilities.elicitation if capabilities is not None else None
    if elicitation is None:
        return False
    if elicitation.form is not None:
        return True
    return elicitation.url is None and protocol_version not in MODERN_PROTOCOL_VERSIONS

@final
class McpElicitationApprovalSurface:
    """활성 MCP 요청의 back-channel에서만 elicitation을 수행합니다."""

    def __init__(self, context: _ElicitationContext) -> None:
        """현재 MCP 요청 context를 보관합니다."""
        self._context = context

    async def resolve(self, record: ApprovalRecord) -> bool:
        """클라이언트 capability와 양방향 transport가 없으면 fail closed합니다."""
        capabilities = self._context.client_capabilities
        if not supports_form_elicitation(
            capabilities, self._context.protocol_version
        ) or not self._context.request_context.session.can_send_request:
            raise ApprovalSurfaceUnavailableError
        message = (
            f"Approve this frozen request exactly once? Tool: {record.tool_name}; "
            f"payload: {record.canonical_payload.decode('utf-8')}; "
            f"digest: {record.payload_digest}"
        )
        try:
            result = await self._context.elicit(message, _ApprovalResponse)
        except (BrokenResourceError, ClosedResourceError, EndOfStream, MCPError, ValueError):
            raise ApprovalSurfaceUnavailableError from None
        match result:
            case AcceptedElicitation(data=data):
                del data
                return True
            case DeclinedElicitation() | CancelledElicitation():
                return False
            case unreachable:
                assert_never(unreachable)
