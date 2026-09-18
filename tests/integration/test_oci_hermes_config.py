from __future__ import annotations

from typing import ClassVar

import pytest
import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from hermes_windows_bridge.gateway.tailscale_identity import merge_hermes_config

SERVE_HOST = "main-pc.example.ts.net"


class _SshBackend(BaseModel):
    host: str
    user: str


class _Elicitation(BaseModel):
    enabled: bool
    timeout: int


class _Headers(BaseModel):
    authorization: str = Field(alias="Authorization")


class _WindowsServer(BaseModel):
    url: str
    headers: _Headers
    trust: str
    elicitation: _Elicitation
    supports_parallel_tool_calls: bool


class _McpServers(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow")

    windows_pc: _WindowsServer


class _MergedConfig(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow")

    ssh_backend: _SshBackend
    mcp_servers: _McpServers


class TestHermesConfigSnippet:
    def test_windows_pc_mcp_config_preserves_existing_backend(self) -> None:
        existing = """
ssh_backend:
  host: 150.230.255.165
  user: ubuntu
mcp_servers:
  existing_docs:
    command: docs-mcp
"""

        merged = merge_hermes_config(existing, serve_host=SERVE_HOST)
        parsed = _MergedConfig.model_validate(yaml.safe_load(merged))

        assert parsed.ssh_backend == _SshBackend(host="150.230.255.165", user="ubuntu")
        assert parsed.mcp_servers.model_extra == {"existing_docs": {"command": "docs-mcp"}}
        windows_pc = parsed.mcp_servers.windows_pc
        assert windows_pc.url == f"https://{SERVE_HOST}/mcp"
        assert windows_pc.headers.authorization == (
            "Bearer ${HERMES_WINDOWS_BRIDGE_TOKEN}"
        )
        assert windows_pc.trust == "untrusted"
        assert windows_pc.elicitation == _Elicitation(enabled=True, timeout=300)
        assert windows_pc.supports_parallel_tool_calls is False

    def test_merge_is_idempotent_and_preserves_unrelated_keys(self) -> None:
        existing = "profile: default\ncustom: keep-me\n"

        first = merge_hermes_config(existing, serve_host=SERVE_HOST)
        second = merge_hermes_config(first, serve_host=SERVE_HOST)

        assert first == second
        assert "custom: keep-me" in second

    def test_non_mapping_hermes_config_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _ = merge_hermes_config("- unexpected\n- list\n", serve_host=SERVE_HOST)
