"""Worker-owned pipe의 등록, heartbeat, request transport입니다."""

from __future__ import annotations

import time
from dataclasses import dataclass
from threading import Condition, Event, Lock
from typing import TYPE_CHECKING, Final, final, override

from hermes_windows_bridge.ipc.acl import (
    PipeAcl,
    PipeAclError,
    PipeAclProbeState,
    build_worker_pipe_acl,
)
from hermes_windows_bridge.ipc.named_pipe import (
    NamedPipeClient,
    connect_named_pipe_client,
    observe_gateway_client_pipe_acl,
)
from hermes_windows_bridge.ipc.protocol import (
    CancelRequest,
    GatewayHello,
    Heartbeat,
    IpcResponse,
    PeerRole,
    ProtocolMessageError,
    ProtocolVersionError,
    RequestMessage,
    WorkerRegistration,
)
from hermes_windows_bridge.ipc.protocol_errors import CorrelationError
from hermes_windows_bridge.ipc.registration import RegistrationConflictError
from hermes_windows_bridge.worker.ipc_client import (
    AbandonedExchangeError,
    EndpointDisconnectedError,
    EndpointTimeoutError,
    StaleHeartbeatError,
    WorkerRegistry,
)
from hermes_windows_bridge.worker.pipe_server import WorkerPipeConfig, serve_worker_pipe

if TYPE_CHECKING:
    from collections.abc import Callable
    from uuid import UUID

__all__ = ["GatewayWorkerWatcher", "WorkerPipeConfig", "serve_worker_pipe"]

_DEFAULT_CONNECT_TIMEOUT_MS: Final = 500
_INITIAL_RETRY_SECONDS: Final = 0.05
_MAX_RETRY_SECONDS: Final = 1.0


@dataclass(frozen=True, slots=True)
class UnexpectedWorkerMessageError(RuntimeError):
    """현재 transport phase에서 허용되지 않은 메시지입니다."""

    kind: str

    @override
    def __str__(self) -> str:
        return f"unexpected worker transport message: {self.kind}"


@final
class _GatewayConnection:
    """단일 persistent pipe의 response correlation 상태입니다."""

    def __init__(self, pipe: NamedPipeClient, expected_acl: PipeAcl | None) -> None:
        self._pipe = pipe
        self._expected_acl = expected_acl
        self._write_lock = Lock()
        self._exchange_lock = Lock()
        self._acl_lock = Lock()
        self._condition = Condition()
        self._active_id: UUID | None = None
        self._response: IpcResponse | None = None
        self._closed = False

    def exchange(self, request: RequestMessage) -> IpcResponse:
        """기존 synchronous endpoint 계약으로 exchange를 수행합니다."""
        return self.exchange_with_abandon(request, Event())

    def exchange_with_abandon(self, request: RequestMessage, abandoned: Event) -> IpcResponse:
        """Lock 대기 중 abandon된 request가 persistent pipe에 쓰이지 않게 합니다."""
        with self._exchange_lock:
            with self._condition:
                if self._closed:
                    raise EndpointDisconnectedError
                self._active_id = request.request_id
                self._response = None
                self._condition.notify_all()
            if abandoned.is_set():
                with self._condition:
                    if self._active_id == request.request_id:
                        self._active_id = None
                        self._condition.notify_all()
                raise AbandonedExchangeError
            try:
                self._write(request, abandoned)
            except AbandonedExchangeError:
                with self._condition:
                    if self._active_id == request.request_id:
                        self._active_id = None
                        self._condition.notify_all()
                raise
            deadline = time.monotonic() + request.timeout_ms / 1_000
            with self._condition:
                while self._response is None and not self._closed:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not self._condition.wait(remaining):
                        self._active_id = None
                        raise EndpointTimeoutError
                if self._closed:
                    raise EndpointDisconnectedError
                response = self._response
                self._active_id = None
                self._response = None
            if response is None:
                raise EndpointDisconnectedError
            return response

    def cancel(self, request_id: UUID, reason: str) -> bool:
        with self._condition:
            if self._closed or self._active_id != request_id:
                return False
        self._write(CancelRequest(request_id=request_id, reason=reason))
        return True

    def deliver(self, response: IpcResponse) -> None:
        with self._condition:
            active_id = self._active_id
            if active_id is None:
                raise UnexpectedWorkerMessageError(type(response).__name__)
            if active_id != response.request_id:
                raise CorrelationError(expected=active_id, received=response.request_id)
            self._response = response
            self._condition.notify_all()

    def wait_until_active(self, request_id: UUID, timeout_seconds: float) -> bool:
        deadline = time.monotonic() + timeout_seconds
        with self._condition:
            while self._active_id != request_id and not self._closed:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not self._condition.wait(remaining):
                    return False
            return self._active_id == request_id

    def close(self) -> None:
        import pywintypes  # noqa: PLC0415 - Windows 오류를 transport 경계에서 정규화합니다.

        with self._condition:
            if self._closed:
                return
            self._closed = True
            self._condition.notify_all()
        with self._acl_lock:
            try:
                self._pipe.__exit__(None, None, None)
            except (OSError, pywintypes.error):
                return

    def pipe_acl_state(self) -> PipeAclProbeState:
        """Legacy 연결은 unverified이며 bound 연결은 같은 owned handle을 재검증합니다."""
        expected_acl = self._expected_acl
        if expected_acl is None:
            return PipeAclProbeState.UNVERIFIED
        if not self._acl_lock.acquire(blocking=False):
            return PipeAclProbeState.UNVERIFIED
        try:
            with self._condition:
                if self._closed:
                    return PipeAclProbeState.UNVERIFIED
                return observe_gateway_client_pipe_acl(self._pipe.handle, expected_acl)
        finally:
            self._acl_lock.release()

    def _write(
        self,
        message: RequestMessage | CancelRequest,
        abandoned: Event | None = None,
    ) -> None:
        with self._write_lock:
            if abandoned is not None and abandoned.is_set():
                raise AbandonedExchangeError
            try:
                self._pipe.write_message(message)
            except OSError as error:
                self.close()
                raise EndpointDisconnectedError from error


@final
class GatewayWorkerWatcher:
    """Gateway의 persistent Worker 연결과 bounded reconnect를 소유합니다."""

    def __init__(
        self,
        pipe_name: str,
        registry: WorkerRegistry,
        connect_timeout_ms: int = _DEFAULT_CONNECT_TIMEOUT_MS,
        *,
        expected_worker_sid: str | None = None,
        resolve_username_sid: Callable[[str], str] | None = None,
    ) -> None:
        """연결할 pipe와 registry를 고정하고 watcher 상태를 초기화합니다."""
        self._pipe_name = pipe_name
        self._registry = registry
        self._connect_timeout_ms = connect_timeout_ms
        self._expected_worker_sid = expected_worker_sid
        self._resolve_username_sid = resolve_username_sid or _resolve_username_sid
        self._stop = Event()
        self._retry = Event()
        self._condition = Condition()
        self._connection: _GatewayConnection | None = None
        self._connection_count = 0
        self._heartbeat_count = 0

    def run(self) -> None:
        """종료될 때까지 bounded backoff로 Worker 연결을 유지합니다."""
        delay = _INITIAL_RETRY_SECONDS
        while not self._stop.is_set():
            try:
                self._serve_connection()
            except (
                CorrelationError,
                EndpointDisconnectedError,
                OSError,
                ProtocolMessageError,
                ProtocolVersionError,
                RegistrationConflictError,
                StaleHeartbeatError,
                UnexpectedWorkerMessageError,
            ):
                delay = min(delay * 2, _MAX_RETRY_SECONDS)
            else:
                delay = _INITIAL_RETRY_SECONDS
            finally:
                with self._condition:
                    connection = self._connection
                if connection is not None:
                    self._registry.disconnect(connection)
                    connection.close()
                    with self._condition:
                        if self._connection is connection:
                            self._connection = None
            if self._retry.wait(delay):
                self._retry.clear()

    def close(self) -> None:
        """현재 I/O와 이후 reconnect를 중단합니다."""
        self._stop.set()
        self.disconnect()

    def disconnect(self) -> None:
        """현재 연결만 offline 처리해 reconnect 경로를 실행합니다."""
        with self._condition:
            connection = self._connection
            self._connection = None
        if connection is not None:
            self._registry.disconnect(connection)
            connection.close()
        self._retry.set()

    def wait_for_connections(self, count: int, timeout_seconds: float) -> bool:
        """테스트/시작 동기화를 위해 연결 횟수를 bounded wait합니다."""
        deadline = time.monotonic() + timeout_seconds
        with self._condition:
            while self._connection_count < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not self._condition.wait(remaining):
                    return False
            return True

    def wait_for_request(self, request_id: UUID, timeout_seconds: float) -> bool:
        """현재 connection이 request를 송신한 시점을 bounded wait합니다."""
        with self._condition:
            connection = self._connection
        return connection is not None and connection.wait_until_active(
            request_id,
            timeout_seconds,
        )

    def wait_for_heartbeats(self, count: int, timeout_seconds: float) -> bool:
        """지정 횟수 heartbeat 수신을 bounded wait합니다."""
        deadline = time.monotonic() + timeout_seconds
        with self._condition:
            while self._heartbeat_count < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not self._condition.wait(remaining):
                    return False
            return True

    def _serve_connection(self) -> None:
        import pywintypes  # noqa: PLC0415 - portable import를 유지합니다.

        try:
            self._serve_connection_unchecked()
        except pywintypes.error as error:
            raise EndpointDisconnectedError from error

    def _serve_connection_unchecked(self) -> None:
        pipe: NamedPipeClient | None = None
        ownership_transferred = False
        try:
            pipe = connect_named_pipe_client(
                self._pipe_name,
                timeout_ms=self._connect_timeout_ms,
            )
            pipe.write_message(GatewayHello(target=PeerRole.WORKER))
            registration = pipe.read_message(timeout_ms=self._connect_timeout_ms)
            if not isinstance(registration, WorkerRegistration):
                raise UnexpectedWorkerMessageError(type(registration).__name__)
            expected_acl = self._expected_acl_for_registration(registration, pipe.handle)
            connection = _GatewayConnection(pipe, expected_acl)
            self._registry.register(
                registration,
                connection,
                pipe_acl_probe=connection.pipe_acl_state,
            )
            with self._condition:
                self._connection = connection
                self._connection_count += 1
                self._condition.notify_all()
            ownership_transferred = True
            while not self._stop.is_set():
                message = pipe.read_message(timeout_ms=15_000)
                match message:
                    case Heartbeat():
                        self._registry.heartbeat(message)
                        with self._condition:
                            self._heartbeat_count += 1
                            self._condition.notify_all()
                    case IpcResponse():
                        connection.deliver(message)
                    case _:
                        raise UnexpectedWorkerMessageError(type(message).__name__)
        finally:
            if pipe is not None and not ownership_transferred:
                pipe.__exit__(None, None, None)

    def _expected_acl_for_registration(
        self,
        registration: WorkerRegistration,
        handle: int,
    ) -> PipeAcl | None:
        """Binding SID와 local account lookup이 모두 일치할 때만 Worker template을 신뢰합니다."""
        expected_worker_sid = self._expected_worker_sid
        if expected_worker_sid is None:
            return None
        try:
            registered_sid = self._resolve_username_sid(registration.username)
            expected_acl = build_worker_pipe_acl(expected_worker_sid)
        except OSError, PipeAclError:
            raise EndpointDisconnectedError from None
        if registered_sid != expected_acl.allowed_sids[1]:
            raise EndpointDisconnectedError
        if observe_gateway_client_pipe_acl(handle, expected_acl) is not PipeAclProbeState.VERIFIED:
            raise EndpointDisconnectedError
        return expected_acl


def _resolve_username_sid(username: str) -> str:
    """등록 username을 Gateway-local Win32 account lookup으로만 SID화합니다."""
    import win32security  # noqa: PLC0415 - Windows identity 경계를 이 함수에 한정합니다.

    account_sid, _, _ = win32security.LookupAccountName(None, username)
    return win32security.ConvertSidToStringSid(account_sid)
