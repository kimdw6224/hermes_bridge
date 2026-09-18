"""Operator-document contract checks without pinning Korean prose."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).parents[2]
README: Final = ROOT / "README.md"
STATUS: Final = ROOT / "IMPLEMENTATION_STATUS.md"
ENV_EXAMPLE: Final = ROOT / ".env.example"

_REQUIRED_SECTIONS: Final = frozenset(
    {
        "승인 후 Windows 설치",
        "Tailscale Serve와 App Capability",
        "Oracle Cloud Hermes 연결",
        "Token 회전",
        "비상 정지와 로컬 재활성화",
        "제거",
        "PC 상태별 동작",
        "문제 해결",
    }
)
_REQUIRED_SCRIPTS: Final = frozenset(
    {
        "scripts\\install.ps1",
        "scripts\\uninstall.ps1",
        "scripts\\rotate-token.ps1",
        "scripts\\doctor.ps1",
        "scripts\\configure-tailscale.ps1",
        "scripts\\enable-remote-input.ps1",
    }
)
_REQUIRED_HERMES_KEYS: Final = frozenset(
    {
        "mcp_servers:",
        "windows_pc:",
        "supports_parallel_tool_calls: false",
        "trust: untrusted",
        "elicitation:",
        "enabled: true",
        "/reload-mcp",
    }
)
_REQUIRED_ENV_KEYS: Final = frozenset(
    {
        "HERMES_BRIDGE_TOKEN",
        "HERMES_BRIDGE_ALLOWED_HOSTS",
        "HERMES_BRIDGE_ALLOWED_ORIGINS",
        "HERMES_BRIDGE_TAILSCALE_SERVE_HOST",
        "HERMES_BRIDGE_TAILSCALE_APP_CAPABILITY",
        "HERMES_WINDOWS_BRIDGE_TOKEN",
    }
)
_HEADING_PATTERN: Final = re.compile(r"^##\s+(.+?)\s*$", flags=re.MULTILINE)
_SCRIPT_PATTERN: Final = re.compile(r"scripts\\[a-z-]+\.ps1")
_FENCED_BLOCK_PATTERN: Final = re.compile(r"```(?:powershell|text|yaml)\n(.*?)```", flags=re.DOTALL)
_POWERSHELL_BLOCK_PATTERN: Final = re.compile(r"```powershell\n(.*?)```", flags=re.DOTALL)


def _read(path: Path) -> str:
    """Read a repository-controlled documentation artifact as UTF-8."""
    return path.read_text(encoding="utf-8")


def _headings(markdown: str) -> frozenset[str]:
    """Extract level-two headings as stable operator-document structure."""
    return frozenset(match.group(1) for match in _HEADING_PATTERN.finditer(markdown))


def _blocks(markdown: str, pattern: re.Pattern[str]) -> tuple[str, ...]:
    """Return fenced code blocks with their language already selected by the caller."""
    return tuple(match.group(1) for match in pattern.finditer(markdown))


class TestDocsCoverage:
    def test_required_workflows_documented(self) -> None:
        """Given operator artifacts, required workflows expose structured entrypoints."""
        # Given
        readme = _read(README)

        # When
        headings = _headings(readme)
        scripts = frozenset(match.group(0) for match in _SCRIPT_PATTERN.finditer(readme))

        # Then
        assert headings >= _REQUIRED_SECTIONS
        assert scripts >= _REQUIRED_SCRIPTS

    def test_hermes_config_contract_documented(self) -> None:
        """Given the remote configuration example, all safety-bearing keys are present."""
        # Given
        readme = _read(README)

        # When
        present_keys = frozenset(key for key in _REQUIRED_HERMES_KEYS if key in readme)

        # Then
        assert present_keys == _REQUIRED_HERMES_KEYS

    def test_status_declares_live_validation_boundary(self) -> None:
        """Given implementation status, live OCI work is not represented as completed."""
        # Given
        status = _read(STATUS)

        # When
        live_boundary = "실제 운영 증거" in status
        approval_boundary = "승인 필요" in status
        remote_smoke = "remote smoke" in status

        # Then
        assert live_boundary
        assert approval_boundary
        assert remote_smoke


class TestDocsSafety:
    def test_private_transport_instructions_only(self) -> None:
        """Given shell blocks, no executable instruction opens an internet/public listener."""
        # Given
        readme = _read(README)
        shell_blocks = _blocks(readme, _FENCED_BLOCK_PATTERN)

        # When
        executable_lines = {
            line.strip().casefold()
            for block in shell_blocks
            for line in block.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }

        # Then
        assert not any("tailscale funnel" in line for line in executable_lines)
        all_interface_address = f"{0}.{0}.{0}.{0}"
        assert not any(all_interface_address in line for line in executable_lines)
        assert "127.0.0.1" in readme

    def test_template_has_no_secret_value(self) -> None:
        """Given the environment template, token-bearing variables remain empty."""
        # Given
        lines = _read(ENV_EXAMPLE).splitlines()

        # When
        assignments = {
            key: value
            for line in lines
            if "=" in line and not line.lstrip().startswith("#")
            for key, value in [line.split("=", maxsplit=1)]
        }

        # Then
        assert assignments.keys() >= _REQUIRED_ENV_KEYS
        assert assignments["HERMES_BRIDGE_TOKEN"] == ""
        assert assignments["HERMES_WINDOWS_BRIDGE_TOKEN"] == ""

    def test_rotation_json_leak_is_not_recommended(self) -> None:
        """Given token guidance, Apply and JSON are not combined in one executable command."""
        # Given
        readme = _read(README)
        powershell_blocks = _blocks(readme, _POWERSHELL_BLOCK_PATTERN)

        # When
        commands = tuple(
            line.strip()
            for block in powershell_blocks
            for line in block.splitlines()
            if "rotate-token.ps1" in line
        )

        # Then
        assert commands
        assert all(not ("-Apply" in line and "-Json" in line) for line in commands)
