"""MCP SDK bearer-token verification adapter."""

from __future__ import annotations

from dataclasses import dataclass
from hmac import compare_digest
from typing import Final, override

from mcp.server.auth.provider import AccessToken

_CLIENT_ID: Final = "hermes-windows-bridge"


@dataclass(frozen=True, slots=True)
class InvalidBearerTokenConfigurationError(Exception):
    """Raised when the gateway is configured without a usable bearer token."""

    reason: str

    @override
    def __str__(self) -> str:
        """Return the configuration failure without including token data."""
        return self.reason


@dataclass(frozen=True, slots=True)
class StaticBearerTokenVerifier:
    """Verify one externally loaded opaque bearer token in constant time."""

    expected_token: str

    def __post_init__(self) -> None:
        """Reject an authentication configuration that would accept no token."""
        if not self.expected_token:
            raise InvalidBearerTokenConfigurationError(reason="bearer token must not be empty")

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return SDK access metadata only for an exact constant-time match."""
        if not compare_digest(token, self.expected_token):
            return None
        return AccessToken(token=token, client_id=_CLIENT_ID, scopes=[])
