"""Lock 대기 중 취소된 IPC 교환이 peer에 전송되지 않는지 검증합니다."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from threading import Event, Lock, Thread
from typing import TYPE_CHECKING, Self, final
from uuid import UUID

import pytest

from hermes_windows_bridge.gateway.helper_runtime import _HelperConnection
from hermes_windows_bridge.gateway.worker_runtime import _GatewayConnection
from hermes_windows_bridge.ipc.acl import build_privileged_pipe_acl
from hermes_windows_bridge.ipc.named_pipe import NamedPipeClient
from hermes_windows_bridge.ipc.protocol import CancelRequest, IpcRequest, PeerRole
from hermes_windows_bridge.worker.ipc_client import (
    AbandonedExchangeError,
    ExchangeAttempt,
    NamedPipeIpcClient,
)

if TYPE_CHECKING:
    from collections.abc import Callable

_FIRST_ID = UUID("11111111-1111-1111-1111-111111111111")
_SECOND_ID = UUID("22222222-2222-2222-2222-222222222222")


def _worker_connection(pipe: NamedPipeClient) -> _GatewayConnection:
    return _GatewayConnection(pipe, None)


def _helper_connection(pipe: NamedPipeClient) -> _HelperConnection:
    return _HelperConnection(pipe, build_privileged_pipe_acl())


@final
class _HeldLock:
    """진입을 알린 뒤 명시적으로 해제될 때까지 교환을 대기시킵니다."""

    def __init__(self) -> None:
        self.entered: Event = Event()
        self._lock: Lock = Lock()

    def hold(self) -> None:
        _ = self._lock.acquire()

    def release(self) -> None:
        self._lock.release()

    def __enter__(self) -> Self:
        self.entered.set()
        _ = self._lock.acquire()
        return self

    def __exit__(self, *_: object) -> None:
        self._lock.release()


def _request(request_id: UUID) -> IpcRequest:
    return IpcRequest(
        request_id=request_id,
        target=PeerRole.WORKER,
        operation="status",
        payload={},
        timeout_ms=1_000,
    )


@pytest.mark.parametrize("connection_factory", [_worker_connection, _helper_connection])
def test_exchange_waiting_for_serialization_lock_is_not_written_after_abandon(
    connection_factory: Callable[[NamedPipeClient], _GatewayConnection | _HelperConnection],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: transport lock을 이미 보유해 exchange 사전 검사 뒤 실제 lock 대기를 고정합니다.
    pipe = NamedPipeClient(handle=0)
    messages: list[IpcRequest | CancelRequest] = []
    serialization_lock = _HeldLock()
    serialization_lock.hold()

    def record_write(_pipe: NamedPipeClient, message: IpcRequest | CancelRequest) -> None:
        messages.append(message)

    monkeypatch.setattr(NamedPipeClient, "write_message", record_write)
    connection = connection_factory(pipe)
    second_errors: list[type[AbandonedExchangeError]] = []
    abandoned = Event()
    monkeypatch.setattr(connection, "_exchange_lock", serialization_lock)

    def exchange_second() -> None:
        try:
            _ = ExchangeAttempt(connection, _request(_SECOND_ID), abandoned).run()
        except AbandonedExchangeError as error:
            second_errors.append(type(error))

    second = Thread(target=exchange_second)
    second.start()
    try:
        assert serialization_lock.entered.wait(1)

        # When: lock 대기 상태의 caller가 timeout/cancel됩니다.
        abandoned.set()
        assert connection.cancel(_SECOND_ID, "caller_cancelled") is False
    finally:
        serialization_lock.release()
    second.join(1)

    # Then: request는 peer에 전혀 쓰이지 않습니다.
    assert not second.is_alive()
    assert second_errors == [AbandonedExchangeError]
    assert messages == []


@pytest.mark.parametrize("connection_factory", [_worker_connection, _helper_connection])
def test_exchange_waiting_for_write_lock_is_not_written_after_abandon(
    connection_factory: Callable[[NamedPipeClient], _GatewayConnection | _HelperConnection],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: request가 active가 된 뒤 write lock에서 대기합니다.
    pipe = NamedPipeClient(handle=0)
    messages: list[IpcRequest | CancelRequest] = []
    write_lock = _HeldLock()
    write_lock.hold()

    def record_write(_pipe: NamedPipeClient, message: IpcRequest | CancelRequest) -> None:
        messages.append(message)

    monkeypatch.setattr(NamedPipeClient, "write_message", record_write)
    connection = connection_factory(pipe)
    monkeypatch.setattr(connection, "_write_lock", write_lock)
    abandoned = Event()
    errors: list[type[AbandonedExchangeError]] = []

    def exchange() -> None:
        try:
            _ = connection.exchange_with_abandon(_request(_SECOND_ID), abandoned)
        except AbandonedExchangeError as error:
            errors.append(type(error))

    waiting = Thread(target=exchange)
    waiting.start()
    try:
        assert write_lock.entered.wait(1)

        # When: write lock 대기 중 caller가 취소됩니다.
        abandoned.set()
    finally:
        write_lock.release()
    waiting.join(1)

    # Then: active ID를 정리하고 request write를 생략합니다.
    assert not waiting.is_alive()
    assert errors == [AbandonedExchangeError]
    assert messages == []
    assert connection.cancel(_SECOND_ID, "late") is False


def test_named_pipe_client_does_not_connect_for_queued_abandoned_exchange(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: 다른 exchange가 lock을 보유해 이 요청은 lock 대기 상태입니다.
    client = NamedPipeIpcClient(r"\\.\pipe\HermesWindowsBridgeTest", 100)
    serialization_lock = _HeldLock()
    serialization_lock.hold()
    abandoned = Event()
    connection_attempted = Event()
    errors: list[type[AbandonedExchangeError]] = []

    def unexpected_connect(*_: object, **_kwargs: object) -> NamedPipeClient:
        connection_attempted.set()
        pytest.fail("abandoned request must not connect")

    monkeypatch.setattr(
        "hermes_windows_bridge.worker.ipc_client.connect_named_pipe_client",
        unexpected_connect,
    )
    monkeypatch.setattr(client, "_exchange_lock", serialization_lock)

    def exchange() -> None:
        try:
            _ = client.exchange_with_abandon(_request(_SECOND_ID), abandoned)
        except AbandonedExchangeError as error:
            errors.append(type(error))

    queued = Thread(target=exchange)
    queued.start()
    try:
        assert serialization_lock.entered.wait(1)
        abandoned.set()
    finally:
        serialization_lock.release()
    queued.join(1)

    # Then: timeout/cancel 후에는 handle 연결조차 시작하지 않습니다.
    assert not queued.is_alive()
    assert not connection_attempted.is_set()
    assert errors == [AbandonedExchangeError]
