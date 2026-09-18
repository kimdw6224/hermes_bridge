"""Tailscale Serve identity checks and Hermes configuration generation."""

from __future__ import annotations

import ipaddress
from contextvars import ContextVar, Token
from typing import TYPE_CHECKING, ClassVar, Final, Literal, final, override

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    RootModel,
    ValidationError,
    field_validator,
)
from pydantic_core import PydanticCustomError
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import PlainTextResponse, Response

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.types import ASGIApp

APP_CAPABILITIES_HEADER: Final = "Tailscale-App-Capabilities"
DEFAULT_APP_CAPABILITY: Final = "hermes.local/windows-control"
MAX_APP_CAPABILITIES_HEADER_BYTES: Final = 8_192
_CAPABILITY_VERIFIED: ContextVar[bool] = ContextVar(
    "tailscale_app_capability_verified", default=False
)
_EMPTY_SOURCE_CODE: Final = "empty_capability_source"
_EMPTY_SOURCE_MESSAGE: Final = "capability grant sources must be non-empty"
_INVALID_CAPABILITY_CODE: Final = "invalid_capability"
_INVALID_CAPABILITY_MESSAGE: Final = "capability must be a namespaced non-whitespace value"
_INVALID_HOST_CODE: Final = "invalid_serve_host"
_INVALID_HOST_MESSAGE: Final = "serve_host must be one exact hostname"


class _StrictFrozenModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)


class AppCapabilityGrant(_StrictFrozenModel):
    """One capability grant forwarded by Tailscale Serve."""

    src: tuple[str, ...]

    @field_validator("src")
    @classmethod
    def require_nonempty_sources(cls, sources: tuple[str, ...]) -> tuple[str, ...]:
        """Reject grants that do not identify a source scope."""
        if not sources or any(not source.strip() for source in sources):
            raise PydanticCustomError(_EMPTY_SOURCE_CODE, _EMPTY_SOURCE_MESSAGE)
        return sources


class AppCapabilityHeader(RootModel[dict[str, tuple[AppCapabilityGrant, ...]]]):
    """Typed JSON representation of the forwarded capability header."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)


class AppCapabilityPolicy(_StrictFrozenModel):
    """Conditions under which a forwarded App Capability is trusted."""

    capability: str = DEFAULT_APP_CAPABILITY
    serve_host: str

    @field_validator("capability")
    @classmethod
    def require_namespaced_capability(cls, capability: str) -> str:
        """Require a namespaced capability identifier."""
        if "/" not in capability or not capability.strip() or any(
            character.isspace() for character in capability
        ):
            raise PydanticCustomError(_INVALID_CAPABILITY_CODE, _INVALID_CAPABILITY_MESSAGE)
        return capability

    @field_validator("serve_host")
    @classmethod
    def require_exact_serve_host(cls, serve_host: str) -> str:
        """Normalize one exact Serve hostname without wildcard semantics."""
        normalized = serve_host.strip().lower().rstrip(".")
        if not normalized or "://" in normalized or "*" in normalized or "/" in normalized:
            raise PydanticCustomError(_INVALID_HOST_CODE, _INVALID_HOST_MESSAGE)
        return normalized

    def has_trusted_serve_context(self, request: Request) -> bool:
        """Require the configured Serve Host and a loopback proxy peer."""
        client = request.client
        if client is None:
            return False
        try:
            peer = ipaddress.ip_address(client.host)
        except ValueError:
            return False
        host = request.headers.get("host", "").lower().rstrip(".")
        return peer.is_loopback and host in {self.serve_host, f"{self.serve_host}:443"}

    def verifies_header(self, value: str) -> bool:
        """Parse the untrusted JSON header and require a non-empty exact grant."""
        if len(value.encode("utf-8")) > MAX_APP_CAPABILITIES_HEADER_BYTES:
            return False
        try:
            capabilities = AppCapabilityHeader.model_validate_json(value)
        except ValidationError:
            return False
        grants = capabilities.root.get(self.capability, ())
        return bool(grants)


@final
class AppCapabilityMiddleware(BaseHTTPMiddleware):
    """Fail closed unless a request carries a capability from trusted Serve context."""

    def __init__(self, app: ASGIApp, policy: AppCapabilityPolicy) -> None:
        """Store the immutable trust policy for each request."""
        super().__init__(app)
        self._policy = policy

    @override
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if not self._policy.has_trusted_serve_context(request):
            return PlainTextResponse("Untrusted Tailscale Serve context", status_code=403)
        header = request.headers.get(APP_CAPABILITIES_HEADER, "")
        if not self._policy.verifies_header(header):
            return PlainTextResponse(
                "Required Tailscale App Capability was not verified", status_code=403
            )
        token: Token[bool] = _CAPABILITY_VERIFIED.set(True)
        try:
            return await call_next(request)
        finally:
            _CAPABILITY_VERIFIED.reset(token)


def app_capability_verified() -> bool:
    """Report whether the current request passed App Capability validation."""
    return _CAPABILITY_VERIFIED.get()


class _HermesHeaders(_StrictFrozenModel):
    authorization: str = Field(
        default="Bearer ${HERMES_WINDOWS_BRIDGE_TOKEN}", alias="Authorization"
    )


class _HermesElicitation(_StrictFrozenModel):
    enabled: bool = True
    timeout: int = 300


class _HermesTools(_StrictFrozenModel):
    resources: bool = False
    prompts: bool = False


class _HermesWindowsServer(_StrictFrozenModel):
    url: str
    headers: _HermesHeaders = Field(default_factory=_HermesHeaders)
    timeout: int = 120
    connect_timeout: int = 20
    supports_parallel_tool_calls: bool = False
    trust: Literal["untrusted"] = "untrusted"
    elicitation: _HermesElicitation = Field(default_factory=_HermesElicitation)
    tools: _HermesTools = Field(default_factory=_HermesTools)


class _HermesConfig(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow")

    mcp_servers: dict[str, JsonValue] = Field(default_factory=dict)


def merge_hermes_config(existing_yaml: str, *, serve_host: str) -> str:
    """Add a separate Windows MCP entry while preserving all existing Hermes keys."""
    policy = AppCapabilityPolicy(serve_host=serve_host)
    existing = _HermesConfig.model_validate(
        yaml.safe_load(existing_yaml) if existing_yaml.strip() else {}
    )
    servers = dict(existing.mcp_servers)
    windows_server = _HermesWindowsServer(url=f"https://{policy.serve_host}/mcp")
    servers["windows_pc"] = windows_server.model_dump(mode="json", by_alias=True)
    document = existing.model_dump(mode="json")
    document["mcp_servers"] = servers
    return yaml.safe_dump(document, sort_keys=False, allow_unicode=True)
