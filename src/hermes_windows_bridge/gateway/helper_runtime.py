"""Privileged Helper-owned pipe의 Gateway watcher와 persistent client입니다."""

# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

import time
from dataclasses import dataclass
from threading import Condition, Event, Lock
from typing import TYPE_CHECKING, Final, assert_never, final, override

from pydantic import ValidationError

from hermes_windows_bridge.ipc.acl import (
    PipeAcl,
    PipeAclProbeState,
    build_privileged_pipe_acl,
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
    HelperHeartbeat,
    HelperRegistration,
    IpcRequest,
    IpcResponse,
    JobOutputChunkRequest,
    JobOutputChunkResponse,
    PeerRole,
    RebootIpcRequest,
    RequestMessage,
    ShutdownIpcRequest,
    WorkerRegistration,
)
from hermes_windows_bridge.ipc.protocol_errors import CorrelationError
from hermes_windows_bridge.ipc.registration import RegistrationConflictError
from hermes_windows_bridge.privileged.ipc_server import (
    HelperRegistry,
    StaleHelperHeartbeatError,
)
from hermes_windows_bridge.worker.ipc_client import (
    AbandonedExchangeError,
    EndpointDisconnectedError,
    EndpointTimeoutError,
)

_DEFAULT_CONNECT_TIMEOUT_MS: Final = 500
_INITIAL_RETRY_SECONDS: Final = 0.05
_MAX_RETRY_SECONDS: Final = 1.0

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class UnexpectedHelperMessageError(RuntimeError):
    """현재 Helper transport phase에서 허용되지 않은 메시지입니다."""

    kind: str

    @override
    def __str__(self) -> str:
        return f"unexpected helper transport message: {self.kind}"


@final
class _HelperConnection:
    """한 persistent Helper pipe의 request/response correlation을 소유합니다."""

    def __init__(self, pipe: NamedPipeClient, expected_acl: PipeAcl) -> None:
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
        """Lock 대기 중 abandon된 request가 persistent Helper pipe에 쓰이지 않게 합니다."""
        with self._exchange_lock:
            with self._condition:
                if self._closed:
                    raise EndpointDisconnectedError
                self._active_id = request.request_id
                self._response = None
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
        # OS power action이 시작되었을 수 있으므로 성공 취소 응답을 가장하지 않습니다.
        self.close()
        return True

    def deliver(self, response: IpcResponse) -> None:
        with self._condition:
            active_id = self._active_id
            if active_id is None:
                raise UnexpectedHelperMessageError(type(response).__name__)
            if active_id != response.request_id:
                raise CorrelationError(expected=active_id, received=response.request_id)
            self._response = response
            self._condition.notify_all()

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
        """close와 같은 lock으로 current client handle의 DACL을 다시 읽습니다."""
        if not self._acl_lock.acquire(blocking=False):
            return PipeAclProbeState.UNVERIFIED
        try:
            with self._condition:
                if self._closed:
                    return PipeAclProbeState.UNVERIFIED
                return observe_gateway_client_pipe_acl(self._pipe.handle, self._expected_acl)
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
class GatewayHelperWatcher:
    """Gateway의 Helper registration, heartbeat, bounded reconnect를 소유합니다."""

    def __init__(
        self,
        pipe_name: str,
        registry: HelperRegistry,
        connect_timeout_ms: int = _DEFAULT_CONNECT_TIMEOUT_MS,
    ) -> None:
        """연결 설정과 관찰 가능한 lifecycle counters를 초기화합니다."""
        self._pipe_name = pipe_name
        self._registry = registry
        self._connect_timeout_ms = connect_timeout_ms
        self._stop = Event()
        self._retry = Event()
        self._condition = Condition()
        self._connection: _HelperConnection | None = None
        self._connection_count = 0
        self._disconnection_count = 0
        self._heartbeat_count = 0

    def run(self) -> None:
        """중단될 때까지 Helper 연결을 bounded exponential backoff로 복구합니다."""
        delay = _INITIAL_RETRY_SECONDS
        while not self._stop.is_set():
            try:
                self._serve_connection()
                delay = _INITIAL_RETRY_SECONDS
            except (
                CorrelationError,
                EndpointDisconnectedError,
                OSError,
                RegistrationConflictError,
                StaleHelperHeartbeatError,
                UnexpectedHelperMessageError,
            ):
                delay = min(delay * 2, _MAX_RETRY_SECONDS)
            finally:
                with self._condition:
                    connection = self._connection
                if connection is not None:
                    self._registry.disconnect(connection)
                    connection.close()
                    with self._condition:
                        if self._connection is connection:
                            self._connection = None
                            self._disconnection_count += 1
                            self._condition.notify_all()
            if self._retry.wait(delay):
                self._retry.clear()

    def close(self) -> None:
        """Watcher를 중단하고 pending pipe read를 해제합니다."""
        self._stop.set()
        self.disconnect()

    def disconnect(self) -> None:
        """현재 연결만 끊고 reconnect wait를 깨웁니다."""
        with self._condition:
            connection = self._connection
        if connection is not None:
            connection.close()
        self._retry.set()

    def wait_for_connections(self, count: int, timeout_seconds: float) -> bool:
        """지정 횟수의 registration까지 bounded wait합니다."""
        deadline = time.monotonic() + timeout_seconds
        with self._condition:
            while self._connection_count < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not self._condition.wait(remaining):
                    return False
            return True

    def wait_for_disconnections(self, count: int, timeout_seconds: float) -> bool:
        """지정 횟수의 offline 전환까지 bounded wait합니다."""
        deadline = time.monotonic() + timeout_seconds
        with self._condition:
            while self._disconnection_count < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not self._condition.wait(remaining):
                    return False
            return True

    def wait_for_heartbeats(self, count: int, timeout_seconds: float) -> bool:
        """지정 횟수의 heartbeat 반영까지 bounded wait합니다."""
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
            expected_acl = build_privileged_pipe_acl()
            if (
                observe_gateway_client_pipe_acl(pipe.handle, expected_acl)
                is not PipeAclProbeState.VERIFIED
            ):
                raise EndpointDisconnectedError
            pipe.write_message(GatewayHello(target=PeerRole.PRIVILEGED_HELPER))
            message = pipe.read_message(timeout_ms=self._connect_timeout_ms)
            try:
                registration = HelperRegistration.model_validate(message.model_dump())
            except ValidationError as error:
                raise UnexpectedHelperMessageError(type(message).__name__) from error
            connection = _HelperConnection(pipe, expected_acl)
            self._registry.register_transport(
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
                message = pipe.read_message()
                match message:
                    case HelperHeartbeat():
                        self._registry.heartbeat(message)
                        with self._condition:
                            self._heartbeat_count += 1
                            self._condition.notify_all()
                    case IpcResponse():
                        connection.deliver(message)
                    case (
                        GatewayHello()
                        | WorkerRegistration()
                        | Heartbeat()
                        | HelperRegistration()
                        | IpcRequest()
                        | RebootIpcRequest()
                        | ShutdownIpcRequest()
                        | JobOutputChunkRequest()
                        | JobOutputChunkResponse()
                        | CancelRequest()
                    ):
                        raise UnexpectedHelperMessageError(type(message).__name__)
                    case unreachable:
                        assert_never(unreachable)
        finally:
            if pipe is not None and not ownership_transferred:
                pipe.__exit__(None, None, None)
