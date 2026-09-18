"""권한 named-pipe 요청을 typed allowlist로 제한하는 경계입니다."""

# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import TYPE_CHECKING, Protocol, assert_never, override
from uuid import uuid4

from pydantic import ValidationError

from hermes_windows_bridge.ipc.operation_policy import (
    PrivilegedOperation,
    RebootPayload,
    ShutdownPayload,
)
from hermes_windows_bridge.ipc.protocol import (
    HEARTBEAT_OFFLINE_SECONDS,
    HelperHeartbeat,
    HelperRegistration,
    RebootIpcRequest,
    ShutdownIpcRequest,
)
from hermes_windows_bridge.ipc.registration import accept_registration
from hermes_windows_bridge.privileged.operations import (
    PrivilegedRequest,
    RebootRequest,
    ShutdownRequest,
    parse_privileged_operation,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from uuid import UUID

    from hermes_windows_bridge.ipc.protocol import JsonPayload
    from hermes_windows_bridge.worker.ipc_client import Clock, IpcExchangeClient

from hermes_windows_bridge.worker.ipc_client import SystemClock

__all__ = (
    "HelperRegistry",
    "HelperUnavailableError",
    "InvalidPrivilegedRequestError",
    "StaleHelperHeartbeatError",
    "build_privileged_request",
    "parse_ipc_request",
    "parse_request",
)


class PrivilegedCall(Protocol):
    """Helper request 생성에 필요한 dispatch 입력의 최소 shape입니다."""

    operation_id: UUID
    tool_name: str
    payload: JsonPayload
    timeout_ms: int


class InvalidPrivilegedRequestError(ValueError):
    """Tool 이름 또는 payload가 Helper contract와 맞지 않습니다."""


def build_privileged_request(
    call: PrivilegedCall,
) -> RebootIpcRequest | ShutdownIpcRequest:
    """MCP tool을 Helper의 closed request variant로 변환합니다."""
    try:
        if call.tool_name == "system_reboot":
            return RebootIpcRequest(
                request_id=call.operation_id,
                operation=PrivilegedOperation.REBOOT,
                payload=RebootPayload.model_validate(call.payload),
                timeout_ms=call.timeout_ms,
            )
        if call.tool_name == "system_shutdown":
            return ShutdownIpcRequest(
                request_id=call.operation_id,
                operation=PrivilegedOperation.SHUTDOWN,
                payload=ShutdownPayload.model_validate(call.payload),
                timeout_ms=call.timeout_ms,
            )
        raise InvalidPrivilegedRequestError
    except ValidationError as error:
        raise InvalidPrivilegedRequestError from error


@dataclass(frozen=True, slots=True)
class _HelperConnection:
    connection_epoch: int
    registration: HelperRegistration
    client: IpcExchangeClient
    heartbeat_at: float
    heartbeat_sequence: int
    pipe_acl_probe: Callable[[], str] | None


class HelperUnavailableError(ConnectionError):
    """현재 online Privileged Helper가 없습니다."""


@dataclass(frozen=True, slots=True)
class StaleHelperHeartbeatError(RuntimeError):
    """현재 Helper 등록과 일치하지 않는 heartbeat입니다."""

    reason: str

    @override
    def __str__(self) -> str:
        return f"stale helper heartbeat: {self.reason}"


class HelperRegistry:
    """Privileged Helper의 generation과 연결 상태를 소유합니다."""

    def __init__(
        self,
        *,
        clock: Clock | None = None,
        offline_after: float = HEARTBEAT_OFFLINE_SECONDS,
    ) -> None:
        """연결되지 않은 Helper registry를 초기화합니다."""
        self._clock: Clock = clock or SystemClock()
        self._offline_after: float = offline_after
        self._connection: _HelperConnection | None = None
        self._lock: Lock = Lock()
        self._next_connection_epoch: int = 1

    def register(self, *, generation: int, client: IpcExchangeClient) -> None:
        """현재보다 새 generation의 Helper만 등록합니다."""
        self.register_transport(
            HelperRegistration(registration_id=uuid4(), generation=generation), client
        )

    def register_transport(
        self,
        registration: HelperRegistration,
        client: IpcExchangeClient,
        *,
        pipe_acl_probe: Callable[[], str] | None = None,
    ) -> None:
        """실제 Helper registration identity와 client를 함께 등록합니다."""
        with self._lock:
            current = self._connection.registration if self._connection is not None else None
            accepted = accept_registration(current, registration)
            self._connection = _HelperConnection(
                self._next_connection_epoch,
                accepted, client, self._clock.monotonic(), -1, pipe_acl_probe
            )
            self._next_connection_epoch += 1

    def heartbeat(self, heartbeat: HelperHeartbeat) -> None:
        """현재 registration의 증가하는 heartbeat만 반영합니다."""
        with self._lock:
            connection = self._connection
            if connection is None:
                raise StaleHelperHeartbeatError(reason="helper_not_registered")
            if (
                heartbeat.registration_id != connection.registration.registration_id
                or heartbeat.sequence <= connection.heartbeat_sequence
            ):
                raise StaleHelperHeartbeatError(reason="registration_or_sequence_mismatch")
            self._connection = _HelperConnection(
                connection.connection_epoch,
                connection.registration,
                connection.client,
                self._clock.monotonic(),
                heartbeat.sequence,
                connection.pipe_acl_probe,
            )

    def current(self) -> IpcExchangeClient:
        """현재 online Helper client를 반환합니다."""
        with self._lock:
            connection = self._current_connection_locked()
            if connection is None:
                raise HelperUnavailableError
            return connection.client

    def disconnect(self, client: IpcExchangeClient) -> None:
        """실패한 client가 여전히 current일 때만 offline 처리합니다."""
        with self._lock:
            if self._connection is not None and self._connection.client is client:
                self._connection = None

    def pipe_acl_state(self) -> str:
        """현재 Helper handle을 status read마다 재검증해 stale pass를 허용하지 않습니다."""
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

    def _current_connection_locked(self) -> _HelperConnection | None:
        connection = self._connection
        if connection is None:
            return None
        if self._clock.monotonic() - connection.heartbeat_at >= self._offline_after:
            self._connection = None
            return None
        return connection


def parse_request(payload: str) -> PrivilegedRequest:
    """실행이나 성공 응답 없이 helper 요청 형식만 검사합니다."""
    return parse_privileged_operation(payload)


def parse_ipc_request(request: RebootIpcRequest | ShutdownIpcRequest) -> PrivilegedRequest:
    """Protocol의 closed request variant를 Helper의 독립 allowlist로 재검증합니다."""
    match request:
        case RebootIpcRequest(payload=payload):
            return RebootRequest(
                operation="reboot",
                delay_seconds=payload.delay_seconds,
                reason=payload.reason,
            )
        case ShutdownIpcRequest(payload=payload):
            return ShutdownRequest(
                operation="shutdown",
                delay_seconds=payload.delay_seconds,
                reason=payload.reason,
            )
        case unreachable:
            assert_never(unreachable)
