"""Gateway와 Privileged Helper 사이 실제 Named Pipe transport 검증입니다."""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Event, Thread
from uuid import UUID, uuid4

import pytest

from hermes_windows_bridge.gateway import helper_runtime
from hermes_windows_bridge.gateway.helper_runtime import GatewayHelperWatcher
from hermes_windows_bridge.ipc.acl import PipeAcl, build_privileged_pipe_acl, current_process_sid
from hermes_windows_bridge.ipc.named_pipe import PipeEndpoint, create_server_pipe
from hermes_windows_bridge.ipc.operation_policy import RebootPayload, ShutdownPayload
from hermes_windows_bridge.ipc.protocol import (
    CancelRequest,
    GatewayHello,
    HelperHeartbeat,
    HelperRegistration,
    IpcResponse,
    PeerRole,
    RebootIpcRequest,
    RequestMessage,
    ShutdownIpcRequest,
)
from hermes_windows_bridge.ipc.registration import RegistrationConflictError
from hermes_windows_bridge.privileged.ipc_server import (
    HelperRegistry,
    HelperUnavailableError,
    StaleHelperHeartbeatError,
)
from hermes_windows_bridge.worker.ipc_client import EndpointDisconnectedError


class _Endpoint:
    def exchange(self, request: RequestMessage) -> IpcResponse:
        return IpcResponse(request_id=request.request_id, ok=True, payload={})

    def cancel(self, request_id: UUID, reason: str) -> bool:
        del request_id, reason
        return False


def test_registry_rejects_stale_generation_and_heartbeat_sequence() -> None:
    # Given: generation 2 Helper와 sequence 3 heartbeat가 등록되어 있습니다.
    registry = HelperRegistry()
    endpoint = _Endpoint()
    registration = HelperRegistration(registration_id=uuid4(), generation=2)
    registry.register_transport(registration, endpoint)
    heartbeat = HelperHeartbeat(registration_id=registration.registration_id, sequence=3)
    registry.heartbeat(heartbeat)

    # When/Then: 이전 generation과 반복 sequence는 현재 연결을 덮지 못합니다.
    with pytest.raises(RegistrationConflictError):
        registry.register_transport(
            HelperRegistration(registration_id=uuid4(), generation=1), endpoint
        )
    with pytest.raises(StaleHelperHeartbeatError):
        registry.heartbeat(heartbeat)


def _serve_helper(
    pipe_name: str,
    sid: str,
    request_received: Event,
    allow_reconnect: Event,
) -> None:
    for generation in (1, 2):
        with create_server_pipe(
            PipeEndpoint.PRIVILEGED_HELPER,
            pipe_name=pipe_name,
            expected_peer_sid=sid,
        ) as server:
            server.wait_for_client(2_000)
            hello = server.read_message()
            assert isinstance(hello, GatewayHello)
            assert hello.target is PeerRole.PRIVILEGED_HELPER
            assert server.verify_peer().sid == sid
            registration = HelperRegistration(registration_id=uuid4(), generation=generation)
            server.write_message(registration)
            server.write_message(
                HelperHeartbeat(registration_id=registration.registration_id, sequence=0)
            )
            reboot = server.read_message()
            assert isinstance(reboot, RebootIpcRequest)
            server.write_message(
                IpcResponse(
                    request_id=reboot.request_id,
                    ok=True,
                    payload={"operation": "reboot"},
                )
            )
            if generation == 1:
                shutdown = server.read_message()
                assert isinstance(shutdown, ShutdownIpcRequest)
                request_received.set()
                cancel = server.read_message()
                assert isinstance(cancel, CancelRequest)
                assert cancel.request_id == shutdown.request_id
                assert allow_reconnect.wait(3)


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "win32", reason="Windows named pipe required")
def test_handshake_heartbeat_typed_exchange_disconnect_and_reconnect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: transport fixture의 current-user ACE는 test-only expanded template입니다.
    # fixed production Helper ACL 검증은 독립 exact ACL/LocalService acceptance로 남깁니다.
    pipe_name = rf"\\.\pipe\HermesWindowsBridgeHelper-{uuid4()}"
    fixture_acl = PipeAcl((*build_privileged_pipe_acl().allowed_sids, current_process_sid()))
    monkeypatch.setattr(helper_runtime, "build_privileged_pipe_acl", lambda: fixture_acl)
    request_received, allow_reconnect = Event(), Event()
    registry = HelperRegistry(offline_after=1.0)
    watcher = GatewayHelperWatcher(pipe_name, registry, connect_timeout_ms=100)
    watcher_thread = Thread(target=watcher.run, daemon=True)

    with ThreadPoolExecutor(max_workers=1) as executor:
        server = executor.submit(
            _serve_helper,
            pipe_name,
            current_process_sid(),
            request_received,
            allow_reconnect,
        )
        watcher_thread.start()
        try:
            assert watcher.wait_for_connections(1, timeout_seconds=3)
            assert watcher.wait_for_heartbeats(1, timeout_seconds=1)
            client = registry.current()
            reboot = RebootIpcRequest(
                request_id=uuid4(),
                payload=RebootPayload(delay_seconds=0, reason="test"),
                timeout_ms=1_000,
            )
            assert client.exchange(reboot).payload == {"operation": "reboot"}

            # When: 진행 중 typed shutdown을 request ID로 취소하고 연결을 끊습니다.
            shutdown = ShutdownIpcRequest(
                request_id=uuid4(),
                payload=ShutdownPayload(delay_seconds=0, reason="test"),
                timeout_ms=1_000,
            )
            disconnected = Event()

            def exchange_shutdown() -> None:
                try:
                    _ = client.exchange(shutdown)
                except EndpointDisconnectedError:
                    disconnected.set()

            exchange = Thread(target=exchange_shutdown)
            exchange.start()
            assert request_received.wait(1)
            assert client.cancel(shutdown.request_id, "test_cancel")
            exchange.join(2)
            assert disconnected.is_set()
            assert watcher.wait_for_disconnections(1, timeout_seconds=1)
            with pytest.raises(HelperUnavailableError):
                _ = registry.current()
            allow_reconnect.set()

            # Then: bounded backoff 뒤 새 generation으로 재등록되어 다시 응답합니다.
            assert watcher.wait_for_connections(2, timeout_seconds=3)
            assert watcher.wait_for_heartbeats(2, timeout_seconds=1)
            reconnected = registry.current()
            assert reconnected is not client
            assert reconnected.exchange(reboot.model_copy(update={"request_id": uuid4()})).ok
        finally:
            allow_reconnect.set()
            watcher.close()
            watcher_thread.join(2)
        server.result(timeout=4)
    assert not watcher_thread.is_alive()
