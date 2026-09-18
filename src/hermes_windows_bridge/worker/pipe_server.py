"""Worker가 소유하는 authenticated Named Pipe server입니다."""

from __future__ import annotations

from dataclasses import dataclass
from threading import Event, Lock, Thread
from typing import TYPE_CHECKING, Protocol, final

from hermes_windows_bridge.ipc.acl import LOCAL_SERVICE_SID, PipeAclError
from hermes_windows_bridge.ipc.framing import FrameTooLargeError, TruncatedFrameError
from hermes_windows_bridge.ipc.named_pipe import (
    NamedPipeServer,
    PipeEndpoint,
    PipeTimeoutError,
    create_server_pipe,
)
from hermes_windows_bridge.ipc.protocol import (
    CancelRequest,
    GatewayHello,
    Heartbeat,
    IpcRequest,
    IpcResponse,
    PeerRole,
    ProtocolMessageError,
    ProtocolVersionError,
    WorkerRegistration,
)

if TYPE_CHECKING:
    from uuid import UUID


class StopSignal(Protocol):
    """thread 또는 process stop event의 공통 계약입니다."""

    def is_set(self) -> bool:
        """중단 요청 여부를 반환합니다."""
        ...

    def wait(self, timeout: float | None = None) -> bool:
        """중단 요청을 bounded wait합니다."""
        ...


class WorkerRequestHandler(Protocol):
    """Worker operation dispatcher가 제공할 최소 계약입니다."""

    def exchange(self, request: IpcRequest) -> IpcResponse:
        """Worker operation 하나를 실행합니다."""
        ...

    def cancel(self, request_id: UUID) -> bool:
        """Request ID와 일치하는 operation을 취소합니다."""
        ...


@dataclass(frozen=True, slots=True)
class WorkerPipeConfig:
    """Worker pipe의 identity와 bounded lifecycle 설정입니다."""

    pipe_name: str
    target_user_sid: str
    registration: WorkerRegistration
    expected_gateway_sid: str = LOCAL_SERVICE_SID
    heartbeat_interval_seconds: float = 5.0
    accept_timeout_ms: int = 250


def serve_worker_pipe(
    config: WorkerPipeConfig,
    handler: WorkerRequestHandler,
    stop: StopSignal,
) -> None:
    """Worker-owned pipe를 disconnect 뒤에도 bounded wait로 다시 생성합니다."""
    import pywintypes  # noqa: PLC0415 - portable import를 유지합니다.

    while not stop.is_set():
        try:
            with create_server_pipe(
                PipeEndpoint.WORKER,
                pipe_name=config.pipe_name,
                target_user_sid=config.target_user_sid,
                expected_peer_sid=config.expected_gateway_sid,
            ) as server:
                server.wait_for_client(config.accept_timeout_ms)
                hello = server.read_message()
                if not isinstance(hello, GatewayHello) or hello.target is not PeerRole.WORKER:
                    continue
                _ = server.verify_peer()
                server.write_message(config.registration)
                _WorkerSession(server, config, handler, stop).run()
        except (
            FrameTooLargeError,
            OSError,
            PipeAclError,
            PipeTimeoutError,
            ProtocolMessageError,
            ProtocolVersionError,
            TruncatedFrameError,
            pywintypes.error,
        ):
            continue


@final
class _WorkerSession:
    """한 Gateway connection의 heartbeat와 active request를 조정합니다."""

    def __init__(
        self,
        server: NamedPipeServer,
        config: WorkerPipeConfig,
        handler: WorkerRequestHandler,
        stop: StopSignal,
    ) -> None:
        self._server = server
        self._config = config
        self._handler = handler
        self._outer_stop = stop
        self._stop = Event()
        self._write_lock = Lock()
        self._state_lock = Lock()
        self._active_id: UUID | None = None
        self._active_thread: Thread | None = None

    def run(self) -> None:
        heartbeat = Thread(target=self._heartbeats, daemon=True)
        heartbeat.start()
        try:
            while not self._outer_stop.is_set() and not self._stop.is_set():
                try:
                    message = self._server.read_message(self._config.accept_timeout_ms)
                except TimeoutError:
                    continue
                match message:  # noqa: MATCH_OK - Worker 외 variant는 연결을 종료합니다.
                    case IpcRequest():
                        self._start_request(message)
                    case CancelRequest(request_id=request_id):
                        _ = self._handler.cancel(request_id)
                    case _:
                        return
        finally:
            self._stop.set()
            with self._state_lock:
                active_id = self._active_id
            if active_id is not None:
                _ = self._handler.cancel(active_id)
            with self._state_lock:
                active_thread = self._active_thread
            if active_thread is not None:
                active_thread.join(1)
            heartbeat.join(1)

    def _start_request(self, request: IpcRequest) -> None:
        with self._state_lock:
            if self._active_id is not None:
                self._write(
                    IpcResponse(request_id=request.request_id, ok=False, error_code="busy")
                )
                return
            self._active_id = request.request_id
            thread = Thread(target=self._exchange, args=(request,), daemon=True)
            self._active_thread = thread
        thread.start()

    def _exchange(self, request: IpcRequest) -> None:
        try:
            self._write(self._handler.exchange(request))
        finally:
            with self._state_lock:
                if self._active_id == request.request_id:
                    self._active_id = None
                    self._active_thread = None

    def _heartbeats(self) -> None:
        sequence = 0
        while not self._stop.is_set() and not self._outer_stop.is_set():
            self._write(
                Heartbeat(
                    registration_id=self._config.registration.registration_id,
                    sequence=sequence,
                    session_id=self._config.registration.session_id,
                    username=self._config.registration.username,
                )
            )
            sequence += 1
            _ = self._stop.wait(self._config.heartbeat_interval_seconds)

    def _write(self, message: Heartbeat | IpcResponse) -> None:
        import pywintypes  # noqa: PLC0415 - Windows 오류를 connection 종료로 처리합니다.

        with self._write_lock:
            try:
                self._server.write_message(message)
            except (OSError, pywintypes.error):
                self._stop.set()
