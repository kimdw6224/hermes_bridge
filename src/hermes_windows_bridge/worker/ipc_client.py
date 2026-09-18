"""Gateway가 bounded named-pipe request/response를 수행하는 typed client 계약입니다."""

# pyright: reportAny=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false

from __future__ import annotations

import time
from dataclasses import dataclass
from threading import Event, Lock, get_native_id
from typing import TYPE_CHECKING, Final, Never, Protocol, final, override, runtime_checkable

from anyio import sleep

from hermes_windows_bridge.ipc.named_pipe import NamedPipeClient, connect_named_pipe_client
from hermes_windows_bridge.ipc.protocol import (
    HEARTBEAT_INTERVAL_SECONDS,
    HEARTBEAT_OFFLINE_SECONDS,
    Heartbeat,
    IpcResponse,
    RequestMessage,
    WorkerRegistration,
    correlate_response,
    serialize_message,
)
from hermes_windows_bridge.ipc.registration import accept_registration

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from uuid import UUID


class IpcExchangeClient(Protocol):
    """Dispatcher registry에 저장할 동기 IPC endpoint입니다."""

    def exchange(self, request: RequestMessage) -> IpcResponse:
        """연관된 응답 하나를 반환합니다."""
        ...

    def cancel(self, request_id: UUID, reason: str) -> bool:
        """일치하는 진행 중 request를 중단했는지 반환합니다."""
        ...


@runtime_checkable
class AbandonableIpcExchangeClient(Protocol):
    """lock 대기 중 취소를 write 직전까지 전달할 수 있는 endpoint입니다."""

    def exchange_with_abandon(self, request: RequestMessage, abandoned: Event) -> IpcResponse:
        """이미 abandon된 request는 peer I/O 전에 중단합니다."""
        ...


class Clock(Protocol):
    """Heartbeat 만료 판단에 필요한 monotonic clock입니다."""

    def monotonic(self) -> float:
        """단조 증가 초를 반환합니다."""
        ...


class SystemClock:
    """운영 환경의 monotonic clock adapter입니다."""

    def monotonic(self) -> float:
        """시스템 monotonic clock을 읽습니다."""
        return time.monotonic()


class EndpointDisconnectedError(ConnectionError):
    """등록된 IPC endpoint가 요청 중 끊겼습니다."""

    @override
    def __str__(self) -> str:
        """신뢰하지 않는 OS 오류 상세를 노출하지 않습니다."""
        return "IPC endpoint disconnected"


class EndpointTimeoutError(TimeoutError):
    """Named Pipe 연결 자체가 bounded timeout에 도달했습니다."""


class EndpointCancelledError(ConnectionError):
    """소유한 Named Pipe handle의 I/O가 취소되었습니다."""


class EndpointIoError(OSError):
    """분류되지 않은 Win32 오류를 cause와 함께 보존합니다."""

    def __init__(self, code: int | None) -> None:
        """Win32 error code를 보존합니다."""
        super().__init__(code)
        self.code: int | None = code


class AbandonedExchangeError(RuntimeError):
    """Timeout/cancel 뒤 도착한 응답은 완료 결과가 아닙니다."""


@dataclass(frozen=True, slots=True)
class ExchangeAttempt:
    """단일 peer exchange와 caller cancellation 상태를 결합합니다."""

    client: IpcExchangeClient
    request: RequestMessage
    abandoned: Event

    def run(self) -> bytes:
        """Late response가 idempotency cache에 기록되기 전에 거부합니다."""
        if self.abandoned.is_set():
            raise AbandonedExchangeError
        if isinstance(self.client, AbandonableIpcExchangeClient):
            response = self.client.exchange_with_abandon(self.request, self.abandoned)
        else:
            response = self.client.exchange(self.request)
        response = correlate_response(self.request, response)
        if self.abandoned.is_set():
            raise AbandonedExchangeError
        return serialize_message(response)


@dataclass(frozen=True, slots=True)
class StaleHeartbeatError(RuntimeError):
    """현재 Worker 등록과 맞지 않는 heartbeat입니다."""

    reason: str

    @override
    def __str__(self) -> str:
        """원문 identity 없이 mismatch 종류만 반환합니다."""
        return f"stale worker heartbeat: {self.reason}"


class WorkerUnavailableError(ConnectionError):
    """현재 online Worker가 없습니다."""


class InvalidHeartbeatIntervalError(ValueError):
    """Heartbeat cadence는 양수여야 합니다."""


async def run_heartbeat_loop(
    registration: WorkerRegistration,
    send: Callable[[Heartbeat], Awaitable[None]],
    *,
    interval_seconds: float = HEARTBEAT_INTERVAL_SECONDS,
) -> None:
    """Worker 수명 동안 순차 heartbeat를 즉시, 이후 약 5초마다 보냅니다."""
    if interval_seconds <= 0:
        raise InvalidHeartbeatIntervalError
    sequence = 0
    while True:
        await send(
            Heartbeat(
                registration_id=registration.registration_id,
                sequence=sequence,
                session_id=registration.session_id,
                username=registration.username,
            )
        )
        sequence += 1
        await sleep(interval_seconds)


@dataclass(frozen=True, slots=True)
class _WorkerConnection:
    connection_epoch: int
    registration: WorkerRegistration
    client: IpcExchangeClient
    heartbeat_at: float
    heartbeat_sequence: int
    pipe_acl_probe: Callable[[], str] | None


class WorkerRegistry:
    """Worker generation과 heartbeat 상태를 교체 가능하게 소유합니다."""

    def __init__(
        self,
        *,
        clock: Clock | None = None,
        offline_after: float = HEARTBEAT_OFFLINE_SECONDS,
    ) -> None:
        """빈 registry와 heartbeat 만료 기한을 초기화합니다."""
        self._clock: Clock = clock or SystemClock()
        self._offline_after: float = offline_after
        self._connection: _WorkerConnection | None = None
        self._lock: Lock = Lock()
        self._next_connection_epoch: int = 1

    def register(
        self,
        registration: WorkerRegistration,
        client: IpcExchangeClient,
        *,
        pipe_acl_probe: Callable[[], str] | None = None,
    ) -> None:
        """현재보다 새 generation만 online 상태로 등록합니다."""
        with self._lock:
            current = self._connection.registration if self._connection is not None else None
            accepted = accept_registration(current, registration)
            self._connection = _WorkerConnection(
                self._next_connection_epoch,
                accepted,
                client,
                self._clock.monotonic(),
                -1,
                pipe_acl_probe,
            )
            self._next_connection_epoch += 1

    def heartbeat(self, heartbeat: Heartbeat) -> None:
        """현재 registration의 순서가 증가한 heartbeat만 반영합니다."""
        with self._lock:
            connection = self._connection
            if connection is None:
                raise StaleHeartbeatError(reason="worker_not_registered")
            matches_registration = (
                heartbeat.registration_id == connection.registration.registration_id
                and heartbeat.session_id == connection.registration.session_id
                and heartbeat.username == connection.registration.username
            )
            if not matches_registration or heartbeat.sequence <= connection.heartbeat_sequence:
                raise StaleHeartbeatError(reason="registration_or_sequence_mismatch")
            self._connection = _WorkerConnection(
                connection.connection_epoch,
                connection.registration,
                connection.client,
                self._clock.monotonic(),
                heartbeat.sequence,
                connection.pipe_acl_probe,
            )

    def current(self) -> IpcExchangeClient:
        """15초 heartbeat 기한 안의 client만 반환합니다."""
        with self._lock:
            connection = self._current_connection_locked()
            if connection is None:
                raise WorkerUnavailableError
            return connection.client

    def disconnect(self, client: IpcExchangeClient) -> None:
        """실패한 client가 여전히 current일 때만 offline 처리합니다."""
        with self._lock:
            if self._connection is not None and self._connection.client is client:
                self._connection = None

    def pipe_acl_state(self) -> str:
        """현재 live connection의 DACL을 매 status read마다 같은 handle에서 재검증합니다."""
        with self._lock:
            connection = self._current_connection_locked()
        if connection is None:
            return "offline"
        probe = connection.pipe_acl_probe
        if probe is None:
            return "unverified"
        state = probe()
        with self._lock:
            current = self._current_connection_locked()
            if (
                current is None
                or current.connection_epoch != connection.connection_epoch
                or current.client is not connection.client
            ):
                return "offline"
        return state

    def _current_connection_locked(self) -> _WorkerConnection | None:
        connection = self._connection
        if connection is None:
            return None
        if self._clock.monotonic() - connection.heartbeat_at >= self._offline_after:
            self._connection = None
            return None
        return connection


_DISCONNECTED_ERRORS: Final = frozenset({2, 109, 231, 232})
_CANCELLED_ERRORS: Final = frozenset({6, 995})
_TIMEOUT_ERRORS: Final = frozenset({121})
_ERROR_NOT_FOUND: Final = 1168


@dataclass(frozen=True, slots=True)
class _ActiveExchange:
    request_id: UUID
    client: NamedPipeClient
    thread_id: int


@final
class NamedPipeIpcClient:
    """각 교환의 단일 handle을 소유하고 같은 handle로 취소합니다."""

    def __init__(self, pipe_name: str, connect_timeout_ms: int) -> None:
        """고정 endpoint 설정과 교환별 handle 상태를 초기화합니다."""
        self.pipe_name = pipe_name
        self.connect_timeout_ms = connect_timeout_ms
        self._exchange_lock = Lock()
        self._state_lock = Lock()
        self._active: _ActiveExchange | None = None

    def exchange(self, request: RequestMessage) -> IpcResponse:
        """요청을 framed pipe로 왕복하고 correlation을 검증합니다."""
        return self.exchange_with_abandon(request, Event())

    def exchange_with_abandon(self, request: RequestMessage, abandoned: Event) -> IpcResponse:
        """Lock 대기 중 abandon된 request는 pipe handle을 열지 않습니다."""
        import pywintypes  # noqa: PLC0415 - Windows 전용 오류를 경계에서 분류합니다.

        try:
            with self._exchange_lock:
                if abandoned.is_set():
                    raise AbandonedExchangeError
                client = connect_named_pipe_client(
                    self.pipe_name,
                    timeout_ms=min(self.connect_timeout_ms, request.timeout_ms),
                )
                if abandoned.is_set():
                    client.__exit__(None, None, None)
                    raise AbandonedExchangeError
                active = _ActiveExchange(request.request_id, client, get_native_id())
                with self._state_lock:
                    self._active = active
                try:
                    if abandoned.is_set():
                        raise AbandonedExchangeError
                    client.write_message(request)
                    response = client.read_message()
                    return correlate_response(request, response)
                finally:
                    self._release(active)
        except pywintypes.error as error:
            self._raise_endpoint_error(error.winerror, error)
        except OSError as error:
            self._raise_endpoint_error(error.winerror, error)

    def cancel(self, request_id: UUID, reason: str) -> bool:
        """별도 pipe instance 없이 현재 exchange handle을 닫아 I/O를 중단합니다."""
        del reason
        import pywintypes  # noqa: PLC0415 - Windows 전용 오류를 경계에서 분류합니다.

        with self._state_lock:
            active = self._active
            if active is None or active.request_id != request_id:
                return False
            self._active = None
        try:
            self._cancel_synchronous_io(active.thread_id)
            active.client.__exit__(None, None, None)
        except pywintypes.error as error:
            self._raise_endpoint_error(error.winerror, error)
        except OSError as error:
            self._raise_endpoint_error(error.winerror, error)
        return True

    @staticmethod
    def _cancel_synchronous_io(thread_id: int) -> None:
        """ReadFile을 발행한 thread의 synchronous I/O만 취소합니다."""
        import ctypes  # noqa: PLC0415 - Windows 전용 FFI를 경계에 격리합니다.

        import win32api  # noqa: PLC0415 - Windows thread handle 경계입니다.
        import win32con  # noqa: PLC0415 - Windows access mask 경계입니다.

        thread_handle = win32api.OpenThread(
            win32con.THREAD_TERMINATE,
            False,  # noqa: FBT003 - Win32 positional API입니다.
            thread_id,
        )
        try:
            cancelled = ctypes.windll.kernel32.CancelSynchronousIo(int(thread_handle))
            if cancelled == 0 and ctypes.GetLastError() != _ERROR_NOT_FOUND:
                raise ctypes.WinError()
        finally:
            win32api.CloseHandle(thread_handle)

    def _release(self, active: _ActiveExchange) -> None:
        with self._state_lock:
            if self._active is not active:
                return
            self._active = None
        active.client.__exit__(None, None, None)

    @staticmethod
    def _raise_endpoint_error(code: int | None, error: BaseException) -> Never:
        if code in _DISCONNECTED_ERRORS:
            raise EndpointDisconnectedError from error
        if code in _TIMEOUT_ERRORS:
            raise EndpointTimeoutError from error
        if code in _CANCELLED_ERRORS:
            raise EndpointCancelledError from error
        raise EndpointIoError(code=code) from error
