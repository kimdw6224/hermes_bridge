from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

import anyio
from mcp.types import CallToolResult, TextContent
from pydantic import ValidationError

from hermes_windows_bridge.models.tool_results import (
    ResourceStatus,
    StatusWarning,
    TailscaleStatus,
)
from hermes_windows_bridge.privileged.ipc_server import HelperRegistry
from hermes_windows_bridge.tools.status import StatusCollector, StatusSystemInfo
from hermes_windows_bridge.tools.tailscale_probe import (
    TailscaleConnectionSnapshot,
    worker_tailscale_connection,
)

if TYPE_CHECKING:
    from hermes_windows_bridge.gateway.dispatcher import DispatchCall

import pytest


@dataclass(frozen=True, slots=True)
class _Outcome:
    result: CallToolResult


class _Dispatcher:
    def __init__(self, payload: str = "{}") -> None:
        self._payload: str = payload

    async def dispatch(self, call: DispatchCall) -> _Outcome:
        del call
        return _Outcome(result=CallToolResult(content=[TextContent(text=self._payload)]))


def test_status_uses_worker_tailscale_when_gateway_cli_is_unavailable() -> None:
    # Given: Gateway CLI는 권한 오류지만 authenticated Worker는 연결 snapshot을 반환합니다.
    worker_payload = json.dumps(
        {
            "username": "DOMAIN\\worker",
            "session_id": 2,
            "desktop_unlocked": True,
            "remote_input_enabled": True,
            "active_window": {"title": "Terminal", "process": "WindowsTerminal.exe"},
            "tailscale": {"connected": True, "ip": "100.64.0.1"},
        }
    )
    # When: Tailscale 센서를 수집합니다.
    result = anyio.run(
        StatusCollector(
            dispatcher=_Dispatcher(worker_payload),
            helpers=HelperRegistry(),
            app_capability_verified=lambda: True,
            system_probe=lambda: StatusSystemInfo(hostname="MAIN-PC", windows_version="Windows"),
            resource_probe=ResourceStatus.unavailable,
        ).collect
    )

    # Then: Gateway CLI 실패와 무관하게 Worker snapshot과 Gateway capability가 결합됩니다.
    assert result.tailscale == TailscaleStatus(
        connected=True,
        ip="100.64.0.1",
        app_capability_verified=True,
    )


def test_worker_tailscale_failure_keeps_worker_online() -> None:
    # Given: CLI 실패로 tailscale field가 없는 이전/실패 Worker payload입니다.
    def unavailable_resources() -> ResourceStatus:
        return ResourceStatus.unavailable()

    collector = StatusCollector(
        dispatcher=_Dispatcher(
            json.dumps(
                {
                    "username": "DOMAIN\\worker",
                    "session_id": 2,
                    "desktop_unlocked": True,
                    "remote_input_enabled": True,
                    "active_window": {"title": "Terminal", "process": "WindowsTerminal.exe"},
                }
            )
        ),
        helpers=HelperRegistry(),
        app_capability_verified=lambda: True,
        system_probe=lambda: StatusSystemInfo(hostname="MAIN-PC", windows_version="Windows"),
        resource_probe=unavailable_resources,
    )

    # When: status를 수집합니다.
    result = anyio.run(collector.collect)

    # Then: CLI 실패는 연결만 offline으로 만들며 Worker health와 요청 권한 사실은 유지합니다.
    assert result.interactive_worker.online is True
    assert result.tailscale == TailscaleStatus.disconnected(app_capability_verified=True)
    assert StatusWarning(sensor="tailscale", code="sensor_failed") in result.warnings


def test_malformed_worker_tailscale_snapshot_fails_closed() -> None:
    # Given: Worker가 schema와 다른 tailscale field를 보냅니다.
    payload = json.dumps(
        {
            "username": "DOMAIN\\worker",
            "session_id": 2,
            "desktop_unlocked": True,
            "remote_input_enabled": True,
            "active_window": {"title": "Terminal", "process": "WindowsTerminal.exe"},
            "tailscale": {"connected": "yes", "ip": "100.64.0.1"},
        }
    )
    collector = StatusCollector(
        dispatcher=_Dispatcher(payload),
        helpers=HelperRegistry(),
        app_capability_verified=lambda: True,
        system_probe=lambda: StatusSystemInfo(hostname="MAIN-PC", windows_version="Windows"),
        resource_probe=ResourceStatus.unavailable,
    )

    # When: status를 수집합니다.
    result = anyio.run(collector.collect)

    # Then: untrusted Worker snapshot은 Worker online으로 승격되지 않습니다.
    assert result.interactive_worker.online is False


def test_worker_tailscale_snapshot_rejects_invalid_ip_and_auth_field() -> None:
    # Given: Worker IPC 경계를 통과하려는 잘못된 주소와 권한 필드입니다.
    # When/Then: public status 모델로 승격되기 전에 모두 거부됩니다.
    with pytest.raises(ValidationError):
        _ = TailscaleConnectionSnapshot(connected=True, ip="not-an-ip")
    with pytest.raises(ValidationError):
        _ = TailscaleConnectionSnapshot.model_validate(
            {"connected": True, "ip": "100.64.0.1", "app_capability_verified": True}
        )


def test_worker_tailscale_cli_failure_returns_no_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given: interactive Worker의 native CLI가 권한 오류로 실패합니다.
    def denied() -> TailscaleConnectionSnapshot:
        raise PermissionError

    monkeypatch.setattr(
        "hermes_windows_bridge.tools.tailscale_probe.probe_tailscale_connection", denied
    )

    # When: Worker가 optional connection snapshot을 읽습니다.
    snapshot = worker_tailscale_connection()

    # Then: Worker operation 자체는 예외 없이 health payload를 계속 만들 수 있습니다.
    assert snapshot is None
