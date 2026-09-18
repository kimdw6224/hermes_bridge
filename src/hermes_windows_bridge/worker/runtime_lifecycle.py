"""Worker transport와 local emergency hotkey의 결합 수명입니다."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, final

from hermes_windows_bridge.worker.pipe_server import (
    StopSignal,
    WorkerPipeConfig,
    WorkerRequestHandler,
    serve_worker_pipe,
)

if TYPE_CHECKING:
    from hermes_windows_bridge.worker.operations import WorkerOperationDispatcher

type WorkerPipeServer = Callable[[WorkerPipeConfig, WorkerRequestHandler, StopSignal], None]


class EmergencyHotkeyLifecycle(Protocol):
    """Worker transport보다 먼저 준비되고 함께 종료되는 local stop owner입니다."""

    def start(self) -> None:
        """등록 실패를 caller에게 전파해 transport 시작을 차단합니다."""
        ...

    def close(self) -> None:
        """Bounded cleanup을 완료하거나 오류를 전파합니다."""
        ...

    def failed(self) -> bool:
        """등록 뒤 local stop owner가 fail-closed 상태인지 반환합니다."""
        ...


@dataclass(frozen=True, slots=True)
class _WorkerStopSignal:
    """외부 stop과 local emergency hotkey failure를 하나의 pipe stop 조건으로 합칩니다."""

    stop: StopSignal
    hotkey: EmergencyHotkeyLifecycle

    def is_set(self) -> bool:
        """어느 한쪽이라도 중단을 요구하면 transport를 종료합니다."""
        return self.stop.is_set() or self.hotkey.failed()

    def wait(self, timeout: float | None = None) -> bool:
        """기존 bounded wait 뒤 local hotkey failure 상태도 다시 확인합니다."""
        return self.stop.wait(timeout) or self.hotkey.failed()


@final
class WorkerRuntime:
    """Registration, transport loop와 adapter cleanup의 단일 owner입니다."""

    def __init__(
        self,
        config: WorkerPipeConfig,
        dispatcher: WorkerOperationDispatcher,
        server: WorkerPipeServer = serve_worker_pipe,
        emergency_hotkey: EmergencyHotkeyLifecycle | None = None,
    ) -> None:
        """검증된 transport 설정과 adapter dispatcher를 보관합니다."""
        self.config = config
        self._dispatcher = dispatcher
        self._server = server
        self._emergency_hotkey = emergency_hotkey

    def run(self, stop: StopSignal) -> None:
        """Stop 또는 session 종료까지 reconnecting pipe server를 실행합니다."""
        if self._emergency_hotkey is not None:
            try:
                self._emergency_hotkey.start()
            except OSError:
                self._emergency_hotkey.close()
                raise
        try:
            server_stop: StopSignal = (
                stop
                if self._emergency_hotkey is None
                else _WorkerStopSignal(stop, self._emergency_hotkey)
            )
            self._server(self.config, self._dispatcher, server_stop)
        finally:
            if self._emergency_hotkey is not None:
                self._emergency_hotkey.close()

    def close(self) -> None:
        """Transport 종료 뒤 모든 adapter resource를 회수합니다."""
        self._dispatcher.close()
