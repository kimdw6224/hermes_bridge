"""Privileged named-pipe의 registration, heartbeat, typed request session입니다."""

# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, Self, assert_never, final, override

from hermes_windows_bridge.ipc.protocol import (
    CancelRequest,
    GatewayHello,
    Heartbeat,
    HelperHeartbeat,
    HelperRegistration,
    IpcMessage,
    IpcRequest,
    IpcResponse,
    JobOutputChunkRequest,
    JobOutputChunkResponse,
    RebootIpcRequest,
    ShutdownIpcRequest,
    WorkerRegistration,
)
from hermes_windows_bridge.privileged.ipc_server import parse_ipc_request

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType

    from hermes_windows_bridge.ipc.named_pipe import PeerIdentity
    from hermes_windows_bridge.privileged.operations import PowerActionService


@dataclass(frozen=True, slots=True)
class HelperRuntimeConfig:
    """Gateway watcher에 제공할 Helper registration과 heartbeat 간격입니다."""

    registration: HelperRegistration
    heartbeat_interval_seconds: float = 5.0


class PrivilegedHelperPipe(Protocol):
    """Privileged Helper가 소유하는 한 named-pipe 연결입니다."""

    @property
    def handle(self) -> int:
        """현재 kernel handle을 반환합니다."""
        ...

    def __enter__(self) -> Self:
        """연결 수명 내부의 pipe를 반환합니다."""
        ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """연결 종료 여부와 관계없이 handle을 정리합니다."""
        ...

    def wait_for_client(self, timeout_ms: int) -> None:
        """제한 시간 동안 Gateway 연결을 기다립니다."""
        ...

    def verify_peer(self) -> PeerIdentity:
        """연결한 Windows peer identity를 확인합니다."""
        ...

    def read_message(self) -> IpcMessage:
        """한 framed IPC message를 읽습니다."""
        ...

    def write_message(self, message: IpcMessage) -> None:
        """한 framed IPC message를 씁니다."""
        ...


@dataclass(frozen=True, slots=True)
class UnexpectedHelperMessageError(Exception):
    """Handshake 또는 session에 허용되지 않은 IPC variant입니다."""

    @override
    def __str__(self) -> str:
        """안전한 고정 boundary error를 반환합니다."""
        return "privileged helper received an unexpected IPC message"


@final
class HelperSession:
    """등록 후 heartbeat와 closed request response를 직렬화합니다."""

    def __init__(
        self,
        pipe: PrivilegedHelperPipe,
        actions: PowerActionService,
        config: HelperRuntimeConfig,
        outer_stop: threading.Event,
    ) -> None:
        """하나의 verified Gateway connection과 shutdown state를 보관합니다."""
        self._pipe = pipe
        self._actions = actions
        self._config = config
        self._outer_stop = outer_stop
        self._stop = threading.Event()
        self._write_lock = threading.Lock()

    def run(self, stop_requested: Callable[[], bool]) -> None:
        """즉시 heartbeat를 알리고 disconnect 또는 stop까지 typed request만 처리합니다."""
        self._write(self._heartbeat(0))
        heartbeat = threading.Thread(target=self._heartbeats, args=(1,))
        heartbeat.start()
        try:
            while (
                not self._outer_stop.is_set()
                and not self._stop.is_set()
                and not stop_requested()
            ):
                response = self._dispatch(self._pipe.read_message())
                if response is not None:
                    self._write(response)
        finally:
            self._stop.set()
            heartbeat.join()

    def _heartbeats(self, sequence: int) -> None:
        try:
            while not self._stop.is_set() and not self._outer_stop.is_set():
                _ = self._stop.wait(self._config.heartbeat_interval_seconds)
                if self._stop.is_set() or self._outer_stop.is_set():
                    return
                self._write(self._heartbeat(sequence))
                sequence += 1
        except OSError:
            self._stop.set()

    def _heartbeat(self, sequence: int) -> HelperHeartbeat:
        return HelperHeartbeat(
            registration_id=self._config.registration.registration_id,
            sequence=sequence,
        )

    def _write(self, message: IpcMessage) -> None:
        with self._write_lock:
            self._pipe.write_message(message)

    def _dispatch(self, message: IpcMessage) -> IpcResponse | None:
        match message:
            case RebootIpcRequest() | ShutdownIpcRequest():
                result = self._actions.execute(parse_ipc_request(message))
                return IpcResponse(
                    request_id=message.request_id,
                    ok=True,
                    payload={"operation": result.operation},
                )
            case IpcRequest(request_id=request_id):
                return IpcResponse(
                    request_id=request_id,
                    ok=False,
                    error_code="invalid_privileged_request",
                )
            case CancelRequest():
                raise UnexpectedHelperMessageError
            case (
                GatewayHello()
                | WorkerRegistration()
                | Heartbeat()
                | HelperRegistration()
                | HelperHeartbeat()
                | IpcResponse()
                | JobOutputChunkRequest()
                | JobOutputChunkResponse()
            ):
                raise UnexpectedHelperMessageError
            case unreachable:
                assert_never(unreachable)
