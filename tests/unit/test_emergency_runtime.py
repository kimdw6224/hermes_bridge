from __future__ import annotations

from threading import Event
from typing import final
from uuid import UUID

import pytest

from hermes_windows_bridge.ipc.protocol import WorkerRegistration
from hermes_windows_bridge.worker.operations import WorkerOperationDispatcher
from hermes_windows_bridge.worker.pipe_server import (
    StopSignal,
    WorkerPipeConfig,
    WorkerRequestHandler,
)
from hermes_windows_bridge.worker.runtime_lifecycle import WorkerRuntime

_REQUEST_ID = UUID("018f0000-0000-7000-8000-000000000201")


def _config() -> WorkerPipeConfig:
    return WorkerPipeConfig(
        pipe_name=r"\\.\pipe\HermesWindowsBridgeHotkeyTest",
        target_user_sid="S-1-5-21-1",
        registration=WorkerRegistration(
            registration_id=_REQUEST_ID,
            generation=21,
            session_id=2,
            username="DOMAIN\\alice",
        ),
    )


def test_runtime_starts_hotkey_before_transport_and_closes_it_after_stop() -> None:
    # Given: lifecycle 순서를 기록하는 local emergency hotkey와 transport입니다.
    lifecycle: list[str] = []

    @final
    class RecordingHotkey:
        def start(self) -> None:
            lifecycle.append("hotkey-start")

        def close(self) -> None:
            lifecycle.append("hotkey-close")

        def failed(self) -> bool:
            return False

    def server(
        config: WorkerPipeConfig,
        handler: WorkerRequestHandler,
        stop: StopSignal,
    ) -> None:
        del config, handler, stop
        lifecycle.append("server")

    runtime = WorkerRuntime(
        _config(),
        WorkerOperationDispatcher({}),
        server=server,
        emergency_hotkey=RecordingHotkey(),
    )

    # When: Worker transport를 실행합니다.
    runtime.run(Event())

    # Then: transport는 registered hotkey가 준비된 뒤에만 실행되고 정리됩니다.
    assert lifecycle == ["hotkey-start", "server", "hotkey-close"]


def test_runtime_fails_closed_before_transport_when_hotkey_registration_fails() -> None:
    # Given: global key 충돌을 보고하는 local hotkey입니다.
    server_called = Event()

    @final
    class FailedHotkey:
        def start(self) -> None:
            raise OSError(1409, "hotkey already registered")

        def close(self) -> None:
            return None

        def failed(self) -> bool:
            return False

    def server(
        config: WorkerPipeConfig,
        handler: WorkerRequestHandler,
        stop: StopSignal,
    ) -> None:
        del config, handler, stop
        server_called.set()

    runtime = WorkerRuntime(
        _config(),
        WorkerOperationDispatcher({}),
        server=server,
        emergency_hotkey=FailedHotkey(),
    )

    # When/Then: transport open 전에 오류를 전파합니다.
    with pytest.raises(OSError, match="1409"):
        runtime.run(Event())
    assert server_called.is_set() is False
