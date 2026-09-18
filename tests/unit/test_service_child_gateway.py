"""Gateway readiness callback contract for the service child."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, ClassVar, final

import anyio
import uvicorn
from anyio import to_thread

from hermes_windows_bridge.gateway import main as gateway_main
from hermes_windows_bridge.gateway.origin_host import GatewayTransportPolicy

if TYPE_CHECKING:
    import pytest


@final
class _StartedUvicornServer:
    """Listener started flag와 callback 순서만 재현합니다."""

    release: ClassVar[threading.Event] = threading.Event()
    trace: ClassVar[list[str]] = []

    def __init__(self, config: uvicorn.Config) -> None:
        del config
        self.started = False

    async def serve(self) -> None:
        self.trace.append("serve")
        self.started = True
        _ = await to_thread.run_sync(self.release.wait)
        self.trace.append("return")


@final
class _FailedUvicornServer:
    """Listener bind 전 종료되어 ready가 되지 않는 startup failure를 재현합니다."""

    def __init__(self, config: uvicorn.Config) -> None:
        del config
        self.started = False

    async def serve(self) -> None:
        return


@final
class _GracefulStopUvicornServer:
    """should_exit가 설정될 때만 shutdown을 끝내는 Uvicorn seam입니다."""

    trace: ClassVar[list[str]] = []

    def __init__(self, config: uvicorn.Config) -> None:
        del config
        self.started = False
        self.should_exit = False

    async def serve(self) -> None:
        self.started = True
        _ = await to_thread.run_sync(_wait_for_should_exit, self)
        self.trace.append("shutdown")


def _wait_for_should_exit(server: _GracefulStopUvicornServer) -> None:
    while not server.should_exit:
        time.sleep(0.01)


def _gateway_policy() -> GatewayTransportPolicy:
    return GatewayTransportPolicy.from_csv(
        hosts="localhost",
        origins="https://localhost",
    )


def test_gateway_announces_ready_only_after_uvicorn_listener_started(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _StartedUvicornServer.release.clear()
    _StartedUvicornServer.trace.clear()
    monkeypatch.setattr(uvicorn, "Server", _StartedUvicornServer)

    def announce_ready() -> None:
        _StartedUvicornServer.trace.append("ready")
        _StartedUvicornServer.release.set()

    anyio.run(
        gateway_main._serve,
        gateway_main.build_gateway_server("test-token"),
        _gateway_policy(),
        8765,
        announce_ready,
    )

    assert _StartedUvicornServer.trace == ["serve", "ready", "return"]


def test_gateway_startup_failure_never_announces_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(uvicorn, "Server", _FailedUvicornServer)
    ready: list[str] = []

    anyio.run(
        gateway_main._serve,
        gateway_main.build_gateway_server("test-token"),
        _gateway_policy(),
        8765,
        lambda: ready.append("ready"),
    )

    assert ready == []


def test_gateway_parent_stop_requests_uvicorn_graceful_shutdown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _GracefulStopUvicornServer.trace.clear()
    parent_stop = threading.Event()
    monkeypatch.setattr(uvicorn, "Server", _GracefulStopUvicornServer)

    anyio.run(
        gateway_main._serve,
        gateway_main.build_gateway_server("test-token"),
        _gateway_policy(),
        8765,
        parent_stop.set,
        parent_stop.is_set,
    )

    assert _GracefulStopUvicornServer.trace == ["shutdown"]


def test_http_access_logs_do_not_corrupt_service_stdout(
    capsys: pytest.CaptureFixture[str],
    free_tcp_port: int,
) -> None:
    ready = threading.Event()
    stopped = threading.Event()
    async def exercise() -> None:
        with anyio.fail_after(10):
            async with anyio.create_task_group() as tasks:
                _ = tasks.start_soon(
                    gateway_main._serve,
                    gateway_main.build_gateway_server("test-token"),
                    _gateway_policy(),
                    free_tcp_port,
                    ready.set,
                    stopped.is_set,
                )
                try:
                    _ = await to_thread.run_sync(ready.wait, abandon_on_cancel=True)
                    async with await anyio.connect_tcp("127.0.0.1", free_tcp_port) as stream:
                        await stream.send(
                            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                        )
                        response = await stream.receive(4096)
                        assert b"401" in response.split(b"\r\n", 1)[0]
                finally:
                    stopped.set()

    anyio.run(exercise)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "GET /mcp HTTP/1.1" in captured.err
