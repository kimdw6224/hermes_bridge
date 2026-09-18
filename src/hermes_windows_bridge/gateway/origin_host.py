"""Typed configuration for the MCP SDK's DNS-rebinding protection."""

from __future__ import annotations

from typing import ClassVar, Self

from mcp.server.transport_security import TransportSecuritySettings
from pydantic import BaseModel, ConfigDict, field_validator
from pydantic_core import PydanticCustomError

_EMPTY_ALLOWLIST_CODE = "empty_allowlist"
_EMPTY_ALLOWLIST_MESSAGE = "allowlist must not be empty"
_UNSAFE_ENTRY_CODE = "unsafe_allowlist_entry"
_UNSAFE_ENTRY_MESSAGE = "allowlist entries must be non-empty exact values"


class GatewayTransportPolicy(BaseModel):
    """Exact host and origin allowlists for the loopback MCP gateway."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    allowed_hosts: tuple[str, ...]
    allowed_origins: tuple[str, ...]

    @field_validator("allowed_hosts", "allowed_origins")
    @classmethod
    def reject_empty_or_wildcard_entries(cls, entries: tuple[str, ...]) -> tuple[str, ...]:
        """Reject configurations that disable exact allowlist matching."""
        if not entries:
            raise PydanticCustomError(_EMPTY_ALLOWLIST_CODE, _EMPTY_ALLOWLIST_MESSAGE)
        if any(not entry.strip() or "*" in entry for entry in entries):
            raise PydanticCustomError(
                _UNSAFE_ENTRY_CODE,
                _UNSAFE_ENTRY_MESSAGE,
            )
        return entries

    def sdk_settings(self) -> TransportSecuritySettings:
        """Build a fresh SDK policy so updated application config cannot reuse stale state."""
        return TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(self.allowed_hosts),
            allowed_origins=list(self.allowed_origins),
        )

    @classmethod
    def from_csv(cls, *, hosts: str, origins: str) -> Self:
        """Parse comma-separated environment values at the process boundary."""
        return cls(
            allowed_hosts=tuple(value.strip() for value in hosts.split(",") if value.strip()),
            allowed_origins=tuple(value.strip() for value in origins.split(",") if value.strip()),
        )
