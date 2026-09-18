"""Gateway-owned client handle의 live Worker pipe ACL status를 검증합니다."""

# pyright: reportMissingModuleSource=false
# pyright: reportUnknownMemberType=false
# pyright: reportArgumentType=false

from __future__ import annotations

import sys
from threading import Event, Thread
from uuid import uuid4

import pytest
import win32security

from hermes_windows_bridge.gateway.worker_runtime import GatewayWorkerWatcher
from hermes_windows_bridge.ipc.acl import (
    EVERYONE_SID,
    PIPE_CLIENT_ACCESS,
    PipeAcl,
    PipeAclError,
    build_security_attributes,
    build_worker_pipe_acl,
    current_process_sid,
)
from hermes_windows_bridge.ipc.framing import TruncatedFrameError
from hermes_windows_bridge.ipc.named_pipe import (
    NamedPipeServer,
    PipeEndpoint,
    PipeTimeoutError,
    verify_server_pipe_acl,
)
from hermes_windows_bridge.ipc.protocol import (
    GatewayHello,
    Heartbeat,
    PeerRole,
    ProtocolMessageError,
    ProtocolVersionError,
    WorkerRegistration,
)
from hermes_windows_bridge.ipc.win32_pipe_io import close_pipe_handle
from hermes_windows_bridge.worker.ipc_client import WorkerRegistry

_PIPE_BUFFER_SIZE = 1_048_580
_IO_TIMEOUT_MS = 1_000


class FixtureStageTimeoutError(AssertionError):
    """정해진 fixture synchronization 단계가 끝나지 않았습니다."""


class UnexpectedGatewayHelloError(AssertionError):
    """Gateway watcher가 Worker handshake가 아닌 frame을 보냈습니다."""


def _create_mutable_worker_pipe(pipe_name: str, sid: str) -> NamedPipeServer:
    """Fixture server에만 WRITE_DAC을 요청하고 production wrapper로 handle 수명을 관리합니다."""
    import win32con  # noqa: PLC0415 - test fixture Win32 access mask 경계입니다.
    import win32file  # noqa: PLC0415 - test fixture Win32 file flag 경계입니다.
    import win32pipe  # noqa: PLC0415 - test fixture pipe 생성 경계입니다.

    acl = build_worker_pipe_acl(sid)
    handle: int = win32pipe.CreateNamedPipe(
        pipe_name,
        win32pipe.PIPE_ACCESS_DUPLEX
        | win32con.WRITE_DAC
        | win32pipe.FILE_FLAG_FIRST_PIPE_INSTANCE
        | win32file.FILE_FLAG_OVERLAPPED,
        win32pipe.PIPE_TYPE_BYTE
        | win32pipe.PIPE_READMODE_BYTE
        | win32pipe.PIPE_WAIT
        | win32pipe.PIPE_REJECT_REMOTE_CLIENTS,
        1,
        _PIPE_BUFFER_SIZE,
        _PIPE_BUFFER_SIZE,
        5_000,
        build_security_attributes(acl),
    )
    verified = False
    try:
        verify_server_pipe_acl(handle, acl)
        verified = True
    finally:
        if not verified:
            close_pipe_handle(handle)
    return NamedPipeServer(
        endpoint=PipeEndpoint.WORKER,
        name=pipe_name,
        handle=handle,
        acl=acl,
        expected_peer_sid=sid,
    )


def _replace_server_dacl(handle: int, acl: PipeAcl) -> None:
    """Fixture server가 소유한 handle에만 ordered DACL을 원자적으로 교체합니다."""
    discretionary_acl = win32security.ACL()
    for sid in acl.allowed_sids:
        discretionary_acl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            PIPE_CLIENT_ACCESS,
            win32security.ConvertStringSidToSid(sid),
        )
    win32security.SetSecurityInfo(
        handle,
        win32security.SE_KERNEL_OBJECT,
        win32security.DACL_SECURITY_INFORMATION,
        None,
        None,
        discretionary_acl,
        None,
    )


def _send_heartbeat(server: NamedPipeServer, registration: WorkerRegistration) -> None:
    """각 fixture instance는 one-shot heartbeat로 새 epoch 수신을 구분합니다."""
    server.write_message(
        Heartbeat(
            registration_id=registration.registration_id,
            sequence=0,
            session_id=registration.session_id,
            username=registration.username,
        ),
        timeout_ms=_IO_TIMEOUT_MS,
    )


def _wait_for_stage(event: Event, timeout_seconds: float, errors: list[Exception]) -> None:
    """서버 thread 오류를 단순 event timeout보다 먼저 보존합니다."""
    if event.wait(timeout_seconds):
        return
    if errors:
        raise errors[0]
    raise FixtureStageTimeoutError


def _serve_worker_status_fixture(  # noqa: PLR0913, PLR0917 - thread events가 fixture lifecycle입니다.
    pipe_name: str,
    sid: str,
    stop: Event,
    first_ready: Event,
    extra_requested: Event,
    extra_applied: Event,
    missing_requested: Event,
    missing_applied: Event,
    restore_requested: Event,
    restore_applied: Event,
    close_first: Event,
    first_closed: Event,
    allow_second: Event,
    errors: list[Exception],
) -> None:
    """두 nonce Worker instance에서 DACL mutation과 exact reconnect를 순차 수행합니다."""
    exact_acl = build_worker_pipe_acl(sid)
    extra_acl = PipeAcl((*exact_acl.allowed_sids, EVERYONE_SID))
    missing_acl = PipeAcl(exact_acl.allowed_sids[:-1])
    try:
        with _create_mutable_worker_pipe(pipe_name, sid) as server:
            first_ready.set()
            server.wait_for_client(_IO_TIMEOUT_MS)
            hello = server.read_message(_IO_TIMEOUT_MS)
            if not isinstance(hello, GatewayHello) or hello.target is not PeerRole.WORKER:
                raise UnexpectedGatewayHelloError
            _ = server.verify_peer()
            registration = WorkerRegistration(
                registration_id=uuid4(),
                generation=1,
                session_id=1,
                username="FIXTURE\\worker",
            )
            server.write_message(registration, timeout_ms=_IO_TIMEOUT_MS)
            _send_heartbeat(server, registration)

            _wait_for_stage(extra_requested, 3, errors)
            _replace_server_dacl(server.handle, extra_acl)
            extra_applied.set()
            _wait_for_stage(missing_requested, 3, errors)
            _replace_server_dacl(server.handle, missing_acl)
            missing_applied.set()
            _wait_for_stage(restore_requested, 3, errors)
            _replace_server_dacl(server.handle, exact_acl)
            restore_applied.set()
            _wait_for_stage(close_first, 3, errors)

        # NamedPipeServer.__exit__가 first server handle을 닫은 뒤에만 disconnect를 허용합니다.
        first_closed.set()
        _wait_for_stage(allow_second, 3, errors)
        with _create_mutable_worker_pipe(pipe_name, sid) as server:
            server.wait_for_client(_IO_TIMEOUT_MS)
            hello = server.read_message(_IO_TIMEOUT_MS)
            if not isinstance(hello, GatewayHello) or hello.target is not PeerRole.WORKER:
                raise UnexpectedGatewayHelloError
            _ = server.verify_peer()
            registration = WorkerRegistration(
                registration_id=uuid4(),
                generation=2,
                session_id=1,
                username="FIXTURE\\worker",
            )
            server.write_message(registration, timeout_ms=_IO_TIMEOUT_MS)
            _send_heartbeat(server, registration)
            _ = stop.wait(3)
    except (
        AssertionError,
        OSError,
        PipeAclError,
        PipeTimeoutError,
        ProtocolMessageError,
        ProtocolVersionError,
        TruncatedFrameError,
    ) as error:
        errors.append(error)


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "win32", reason="Windows named pipe required")
def test_gateway_owned_worker_handle_rechecks_live_dacl_and_reconnects_exact_epoch(  # noqa: PLR0915 - acceptance sequence 자체가 observable contract입니다.
) -> None:
    """현재 Gateway handle은 live DACL mutation을 cache하지 않고 새 epoch만 신뢰합니다."""
    sid = current_process_sid()
    pipe_name = rf"\\.\pipe\HermesWindowsBridgePipeAclLive-{uuid4()}"
    stop = Event()
    first_ready = Event()
    extra_requested = Event()
    extra_applied = Event()
    missing_requested = Event()
    missing_applied = Event()
    restore_requested = Event()
    restore_applied = Event()
    close_first = Event()
    first_closed = Event()
    allow_second = Event()
    server_errors: list[Exception] = []
    registry = WorkerRegistry(offline_after=5.0)

    def resolve_fixture_username(username: str) -> str:
        del username
        return sid

    watcher = GatewayWorkerWatcher(
        pipe_name,
        registry,
        connect_timeout_ms=200,
        expected_worker_sid=sid,
        resolve_username_sid=resolve_fixture_username,
    )
    server_thread = Thread(
        target=_serve_worker_status_fixture,
        args=(
            pipe_name,
            sid,
            stop,
            first_ready,
            extra_requested,
            extra_applied,
            missing_requested,
            missing_applied,
            restore_requested,
            restore_applied,
            close_first,
            first_closed,
            allow_second,
            server_errors,
        ),
        daemon=True,
    )
    watcher_thread = Thread(target=watcher.run, daemon=True)
    server_thread.start()
    watcher_thread.start()
    try:
        # Given: bound registration의 exact server DACL과 first one-shot heartbeat가 수신됩니다.
        _wait_for_stage(first_ready, 2, server_errors)
        assert watcher.wait_for_connections(1, timeout_seconds=3)
        assert watcher.wait_for_heartbeats(1, timeout_seconds=1)
        first_client = registry.current()
        assert registry.pipe_acl_state() == "verified"

        # When: live server DACL에 broad extra ACE를 추가합니다.
        extra_requested.set()
        _wait_for_stage(extra_applied, 1, server_errors)

        # Then: same connected client handle의 fresh native read가 mismatch입니다.
        assert registry.pipe_acl_state() == "mismatch"

        # When: 연결을 유지한 채 하나의 required ACE를 제거합니다.
        missing_requested.set()
        _wait_for_stage(missing_applied, 1, server_errors)

        # Then: missing ACE도 cached pass 없이 mismatch입니다.
        assert registry.pipe_acl_state() == "mismatch"

        # When: exact descriptor를 복원합니다.
        restore_requested.set()
        _wait_for_stage(restore_applied, 1, server_errors)

        # Then: 같은 handle의 subsequent read만 verified로 회복합니다.
        assert registry.pipe_acl_state() == "verified"

        # When: first server instance가 닫힌 뒤 locally owned connection을 끝냅니다.
        close_first.set()
        _wait_for_stage(first_closed, 1, server_errors)
        watcher.disconnect()

        # Then: disconnect된 epoch은 pass를 반환할 수 없습니다.
        assert registry.pipe_acl_state() == "offline"

        # When: fresh exact-DACL Worker instance가 같은 nonce pipe name으로 연결됩니다.
        allow_second.set()
        assert watcher.wait_for_connections(2, timeout_seconds=3)
        assert watcher.wait_for_heartbeats(2, timeout_seconds=1)

        # Then: generation 2의 heartbeat와 새 Gateway client handle만 verified를 반환합니다.
        assert registry.current() is not first_client
        assert registry.pipe_acl_state() == "verified"
    finally:
        stop.set()
        extra_requested.set()
        missing_requested.set()
        restore_requested.set()
        close_first.set()
        allow_second.set()
        watcher.close()
        server_thread.join(3)
        watcher_thread.join(3)
        assert not server_thread.is_alive()
        assert not watcher_thread.is_alive()
        assert not server_errors
