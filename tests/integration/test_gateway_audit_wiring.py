"""Gateway production 조립의 redacted audit persistence를 검증합니다."""

from __future__ import annotations

from typing import TYPE_CHECKING

import anyio
import pytest
from mcp.types import CallToolResult

from hermes_windows_bridge.config import load_bridge_settings
from hermes_windows_bridge.gateway.main import build_gateway_server

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.integration
def test_production_gateway_build_persists_only_redacted_audit_jsonl(tmp_path: Path) -> None:
    # Given: 운영 paths와 분리된 임시 Gateway 구성입니다.
    runtime_root = tmp_path / "runtime"
    config_file = tmp_path / "config.yaml"
    _ = config_file.write_text(
        f"paths:\n  program_data: '{runtime_root.as_posix()}'\n",
        encoding="utf-8",
    )
    settings = load_bridge_settings(config_file)
    marker = "sensitive-payload-marker"
    server = build_gateway_server("test-token", audit_root=settings.paths.gateway_logs)

    # When: 실제 production MCP 조립체가 offline Worker 요청을 처리합니다.
    result = anyio.run(server.call_tool, "fs_list", {"path": marker})

    # Then: caller failure와 별개로 파일에는 redacted 감사 metadata만 남습니다.
    records = tuple(settings.paths.gateway_logs.glob("audit-*.jsonl"))
    assert isinstance(result, CallToolResult)
    assert result.is_error is True
    assert len(records) == 1
    serialized = records[0].read_text(encoding="utf-8")
    assert '"tool_name":"fs_list"' in serialized
    assert marker not in serialized
    assert '\\"type\\":\\"string\\"' in serialized


@pytest.mark.integration
def test_production_gateway_build_surfaces_audit_store_root_failure(tmp_path: Path) -> None:
    # Given: audit root로 쓸 수 없는 일반 파일입니다.
    blocked_root = tmp_path / "not-a-directory"
    _ = blocked_root.write_text("fixture", encoding="utf-8")

    # When/Then: 저장소 초기화 오류를 in-memory audit로 조용히 대체하지 않습니다.
    with pytest.raises(FileExistsError):
        _ = build_gateway_server("test-token", audit_root=blocked_root)
