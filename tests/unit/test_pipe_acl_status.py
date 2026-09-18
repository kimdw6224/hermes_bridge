"""Pipe ACL 관찰의 연결 수명과 status fail-closed 동작을 검증합니다."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, final
from uuid import UUID

import pytest

from hermes_windows_bridge.gateway import helper_runtime, worker_runtime
from hermes_windows_bridge.gateway.helper_runtime import GatewayHelperWatcher
from hermes_windows_bridge.gateway.worker_runtime import GatewayWorkerWatcher
from hermes_windows_bridge.ipc.acl import PipeAcl, PipeAclProbeState
from hermes_windows_bridge.ipc.protocol import (
    GatewayHello,
    HelperHeartbeat,
    HelperRegistration,
    IpcResponse,
    RequestMessage,
    WorkerRegistration,
)
from hermes_windows_bridge.privileged.ipc_server import (
    HelperRegistry,
    StaleHelperHeartbeatError,
)
from hermes_windows_bridge.worker.ipc_client import EndpointDisconnectedError, WorkerRegistry

if TYPE_CHECKING:
    from types import TracebackType


@final
class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now


@final
class _Client:
    def exchange(self, request: RequestMessage) -> IpcResponse:
        del request
        raise AssertionError

    def cancel(self, request_id: UUID, reason: str) -> bool:
        del request_id, reason
        return False


@dataclass(slots=True)
class _Probe:
    state: PipeAclProbeState
    calls: int = 0

    def __call__(self) -> PipeAclProbeState:
        self.calls += 1
        return self.state


@final
class _Pipe:
    def __init__(
        self,
        *,
        read_result: WorkerRegistration | None = None,
        failure: OSError | None = None,
    ) -> None:
        self.handle = 123
        self._read_result = read_result
        self._failure = failure
        self.close_count = 0

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self.close_count += 1

    def write_message(self, message: GatewayHello) -> None:
        del message
        if self._failure is not None:
            raise self._failure

    def read_message(self, timeout_ms: int | None = None) -> WorkerRegistration:
        del timeout_ms
        if self._failure is not None:
            raise self._failure
        if self._read_result is None:
            raise AssertionError
        return self._read_result


def test_worker_pipe_acl_refreshes_current_handle_and_rejects_descriptor_change() -> None:
    # Given: locally registered current client handle의 첫 DACL 관찰이 exact입니다.
    registry = WorkerRegistry()
    probe = _Probe(PipeAclProbeState.VERIFIED)
    registration = WorkerRegistration(
        registration_id=UUID("11111111-1111-1111-1111-111111111111"),
        generation=1,
        session_id=1,
        username="TEST\\worker",
    )
    registry.register(registration, _Client(), pipe_acl_probe=probe)

    # When: status read 사이에 같은 handle의 descriptor 결과가 mismatch로 바뀝니다.
    initially = registry.pipe_acl_state()
    probe.state = PipeAclProbeState.MISMATCH
    after_change = registry.pipe_acl_state()

    # Then: cached pass를 재사용하지 않고 양쪽 read를 수행합니다.
    assert initially == "verified"
    assert after_change == "mismatch"
    assert probe.calls == 2


def test_worker_pipe_acl_is_offline_after_heartbeat_expiry_and_old_probe_cannot_revive_it() -> None:
    # Given: heartbeat가 아직 없는 registered client와 controllable local clock입니다.
    clock = _Clock()
    registry = WorkerRegistry(clock=clock, offline_after=1.0)
    old_probe = _Probe(PipeAclProbeState.VERIFIED)
    registration = WorkerRegistration(
        registration_id=UUID("22222222-2222-2222-2222-222222222222"),
        generation=1,
        session_id=1,
        username="TEST\\worker",
    )
    registry.register(registration, _Client(), pipe_acl_probe=old_probe)

    # When: active registration의 heartbeat lifetime이 끝납니다.
    clock.now = 1.0
    state = registry.pipe_acl_state()

    # Then: endpoint는 offline이고, stale probe는 상태 read에 쓰이지 않습니다.
    assert state == "offline"
    assert old_probe.calls == 0


def test_worker_pipe_acl_disconnect_uses_only_new_connection_epoch_probe() -> None:
    # Given: 첫 connection이 verified이며 이후 close/disconnect 됩니다.
    registry = WorkerRegistry()
    first = _Probe(PipeAclProbeState.VERIFIED)
    first_client = _Client()
    first_registration = WorkerRegistration(
        registration_id=UUID("33333333-3333-3333-3333-333333333333"),
        generation=1,
        session_id=1,
        username="TEST\\worker",
    )
    registry.register(first_registration, first_client, pipe_acl_probe=first)
    registry.disconnect(first_client)
    second = _Probe(PipeAclProbeState.UNVERIFIED)
    registry.register(
        first_registration.model_copy(
            update={
                "registration_id": UUID("44444444-4444-4444-4444-444444444444"),
                "generation": 2,
            }
        ),
        _Client(),
        pipe_acl_probe=second,
    )

    # When: reconnect 뒤 status를 읽습니다.
    state = registry.pipe_acl_state()

    # Then: old epoch probe는 호출되지 않고 새 handle 결과만 반영합니다.
    assert state == "unverified"
    assert first.calls == 0
    assert second.calls == 1


def test_helper_pipe_acl_heartbeat_mismatch_keeps_current_observation_fail_closed() -> None:
    # Given: Helper registry에 locally owned probe가 연결되어 있습니다.
    registry = HelperRegistry()
    probe = _Probe(PipeAclProbeState.VERIFIED)
    registration = HelperRegistration(
        registration_id=UUID("55555555-5555-5555-5555-555555555555"), generation=1
    )
    client = _Client()
    registry.register_transport(registration, client, pipe_acl_probe=probe)

    # When: 다른 registration identity를 가진 heartbeat가 도착합니다.
    with suppress(StaleHelperHeartbeatError):
        registry.heartbeat(
            HelperHeartbeat(
                registration_id=UUID("66666666-6666-6666-6666-666666666666"),
                sequence=0,
            )
        )

    # Then: forged peer field는 관찰을 verified로 만들지 못하며 현재 handle만 recheck됩니다.
    assert registry.pipe_acl_state() == "verified"
    assert probe.calls == 1


def test_worker_pipe_acl_becomes_offline_when_probe_outlasts_heartbeat_lifetime() -> None:
    # Given: probe 시작 후 heartbeat lifetime이 끝나는 current connection입니다.
    clock = _Clock()
    registry = WorkerRegistry(clock=clock, offline_after=1.0)

    def expires_during_probe() -> PipeAclProbeState:
        clock.now = 1.0
        return PipeAclProbeState.VERIFIED

    registry.register(
        WorkerRegistration(
            registration_id=UUID("77777777-7777-7777-7777-777777777777"),
            generation=1,
            session_id=1,
            username="TEST\\worker",
        ),
        _Client(),
        pipe_acl_probe=expires_during_probe,
    )

    # When: status read가 probe를 호출합니다.
    state = registry.pipe_acl_state()

    # Then: probe 전 pass가 heartbeat expiry 뒤 cached pass로 반환되지 않습니다.
    assert state == "offline"


def test_worker_handshake_write_failure_closes_untransferred_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: GatewayHello write가 실패하는 newly opened client handle입니다.
    pipe = _Pipe(failure=OSError())

    def connect_worker(pipe_name: str, *, timeout_ms: int) -> _Pipe:
        del pipe_name, timeout_ms
        return pipe

    monkeypatch.setattr(worker_runtime, "connect_named_pipe_client", connect_worker)
    watcher = GatewayWorkerWatcher(r"\\.\pipe\HermesWindowsBridgeTest-write", WorkerRegistry())

    # When: registration ownership transfer 전 handshake가 실패합니다.
    with pytest.raises(OSError, match=r"^$"):
        watcher._serve_connection_unchecked()

    # Then: watcher가 소유한 untransferred handle을 정확히 닫습니다.
    assert pipe.close_count == 1


def test_helper_handshake_read_failure_closes_untransferred_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: exact initial ACL을 통과했지만 Helper registration read가 실패합니다.
    pipe = _Pipe(failure=OSError())

    def connect_helper(pipe_name: str, *, timeout_ms: int) -> _Pipe:
        del pipe_name, timeout_ms
        return pipe

    def verified_observation(handle: int, expected: PipeAcl) -> PipeAclProbeState:
        del handle, expected
        return PipeAclProbeState.VERIFIED

    monkeypatch.setattr(helper_runtime, "connect_named_pipe_client", connect_helper)
    monkeypatch.setattr(
        helper_runtime,
        "observe_gateway_client_pipe_acl",
        verified_observation,
    )
    watcher = GatewayHelperWatcher(r"\\.\pipe\HermesWindowsBridgeTest-read", HelperRegistry())

    # When: bounded registration read가 실패합니다.
    with pytest.raises(OSError, match=r"^$"):
        watcher._serve_connection_unchecked()

    # Then: registry에 전달되지 않은 handle을 watcher가 닫습니다.
    assert pipe.close_count == 1


def test_worker_identity_lookup_failure_closes_untransferred_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: Worker registration 후 protected SID correlation lookup이 OS 오류를 냅니다.
    registration = WorkerRegistration(
        registration_id=UUID("88888888-8888-8888-8888-888888888888"),
        generation=1,
        session_id=1,
        username="TEST\\worker",
    )
    pipe = _Pipe(read_result=registration)
    def connect_worker(pipe_name: str, *, timeout_ms: int) -> _Pipe:
        del pipe_name, timeout_ms
        return pipe

    monkeypatch.setattr(worker_runtime, "connect_named_pipe_client", connect_worker)
    def failed_lookup(username: str) -> str:
        del username
        raise OSError

    watcher = GatewayWorkerWatcher(
        r"\\.\pipe\HermesWindowsBridgeTest-identity",
        WorkerRegistry(),
        expected_worker_sid="S-1-5-21-1-2-3-1001",
        resolve_username_sid=failed_lookup,
    )

    # When: trusted expected identity를 준비하지 못합니다.
    with pytest.raises(EndpointDisconnectedError):
        watcher._serve_connection_unchecked()

    # Then: registration/registry 전 handle은 fail-closed로 닫힙니다.
    assert pipe.close_count == 1
