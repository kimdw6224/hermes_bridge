"""Privileged Helper Windows service runtime의 좁은 경계를 검증합니다."""

# pyright: reportUnnecessaryComparison=false
# pyright: reportPrivateUsage=false

from __future__ import annotations

from typing import TYPE_CHECKING, Self, assert_never, final
from uuid import UUID, uuid4

from hermes_windows_bridge.ipc.named_pipe import PeerIdentity, PipeEndpoint, create_server_pipe
from hermes_windows_bridge.ipc.operation_policy import PrivilegedOperation, RebootPayload
from hermes_windows_bridge.ipc.protocol import (
    CancelRequest,
    GatewayHello,
    HelperHeartbeat,
    HelperRegistration,
    IpcMessage,
    IpcRequest,
    IpcResponse,
    PeerRole,
    ProtocolMessageError,
    RebootIpcRequest,
)
from hermes_windows_bridge.ipc.win32_pipe_io import close_pipe_handle
from hermes_windows_bridge.privileged.pipe_session import HelperRuntimeConfig, PrivilegedHelperPipe
from hermes_windows_bridge.privileged.runtime import PrivilegedHelperRuntime, _cancel_pending_io

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType

    from hermes_windows_bridge.privileged.operations import RebootRequest, ShutdownRequest

REQUEST_ID = UUID("018f0000-0000-7000-8000-000000000021")
REGISTRATION_ID = UUID("018f0000-0000-7000-8000-000000000022")
DEFAULT_GATEWAY_PEER = PeerIdentity(sid="S-1-5-19", process_id=41)
RUNTIME_CONFIG = HelperRuntimeConfig(
    HelperRegistration(registration_id=REGISTRATION_ID, generation=2)
)


@final
class _RecordingExecutor:
    """전원 API 대신 typed 호출 횟수만 기록합니다."""

    def __init__(self) -> None:
        self.reboots = 0
        self.shutdowns = 0

    def reboot(self, request: RebootRequest) -> None:
        del request
        self.reboots += 1

    def shutdown(self, request: ShutdownRequest) -> None:
        del request
        self.shutdowns += 1


@final
class _FakePipe:
    """한 연결의 peer 검증, 수신, 정리를 관찰하는 in-memory pipe입니다."""

    def __init__(
        self,
        messages: list[
            GatewayHello | RebootIpcRequest | IpcRequest | CancelRequest | ProtocolMessageError
        ],
        *,
        peer: PeerIdentity = DEFAULT_GATEWAY_PEER,
        on_wait: Callable[[], None] | None = None,
    ) -> None:
        self._messages = messages
        self._peer = peer
        self._on_wait = on_wait
        self.handle = 0
        self.exited = False
        self.waited = False
        self.written: list[IpcMessage] = []

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self.exited = True

    def wait_for_client(self, timeout_ms: int) -> None:
        assert timeout_ms > 0
        self.waited = True
        if self._on_wait is not None:
            self._on_wait()

    def verify_peer(self) -> PeerIdentity:
        return self._peer

    def set_on_wait(self, callback: Callable[[], None]) -> None:
        self._on_wait = callback

    def read_message(self) -> IpcMessage:
        message = self._messages.pop(0)
        match message:
            case ProtocolMessageError() as error:
                raise error
            case GatewayHello() | IpcRequest() | RebootIpcRequest() | CancelRequest():
                return message
            case unreachable:
                assert_never(unreachable)

    def write_message(self, message: IpcMessage) -> None:
        self.written.append(message)


@final
class _PipeFactory:
    """연결 종료 뒤 다음 pipe instance를 제공하는 runtime fake입니다."""

    def __init__(self, pipes: list[_FakePipe]) -> None:
        self._pipes = pipes

    def __call__(self, endpoint: PipeEndpoint) -> _FakePipe:
        del endpoint
        return self._pipes.pop(0)


def _reboot_request() -> RebootIpcRequest:
    return RebootIpcRequest(
        request_id=REQUEST_ID,
        operation=PrivilegedOperation.REBOOT,
        payload=RebootPayload(delay_seconds=0, reason="maintenance"),
        timeout_ms=1_000,
    )


def _privileged_hello() -> GatewayHello:
    return GatewayHello(target=PeerRole.PRIVILEGED_HELPER)


class TestPrivilegedHelperRuntime:
    def test_cancel_pending_io_accepts_concrete_pywin32_handle(self) -> None:
        # Given: CreateNamedPipe가 반환한 builtins.PyHANDLE입니다.
        pipe = create_server_pipe(
            PipeEndpoint.PRIVILEGED_HELPER,
            pipe_name=rf"\\.\pipe\HermesWindowsBridgeCancelIoEx-{uuid4().hex}",
        )
        try:
            # When: SCM stop adapter가 pending I/O cancellation을 요청합니다.
            _cancel_pending_io(pipe)

            # Then: ctypes가 PyHANDLE을 거부하지 않고 no-pending-I/O도 허용합니다.
            assert type(pipe.handle).__name__ == "PyHANDLE"
        finally:
            close_pipe_handle(pipe.handle)

    def test_executes_only_typed_reboot_from_localsystem_gateway_peer(self) -> None:
        # Given: Session 0 LocalService peer와 injected harmless executor입니다.
        executor = _RecordingExecutor()
        pipe = _FakePipe([_privileged_hello(), _reboot_request()])
        runtime = PrivilegedHelperRuntime(
            executor=executor,
            config=RUNTIME_CONFIG,
            pipe_factory=_PipeFactory([pipe]),
            peer_session_id=lambda process_id: 0,
        )

        # When: 하나의 verified typed request를 service loop가 처리합니다.
        runtime.run_pipe_loop(lambda: executor.reboots == 1)

        # Then: reboot allowlist만 실행하고 correlated response와 cleanup을 남깁니다.
        assert (executor.reboots, executor.shutdowns) == (1, 0)
        assert pipe.written == [
            RUNTIME_CONFIG.registration,
            HelperHeartbeat(registration_id=REGISTRATION_ID, sequence=0),
            IpcResponse(request_id=REQUEST_ID, ok=True, payload={"operation": "reboot"})
        ]
        assert pipe.exited is True

    def test_rejects_wrong_peer_session_without_executing_request(self) -> None:
        # Given: LocalService SID이지만 Session 0 밖에서 연결한 peer입니다.
        executor = _RecordingExecutor()
        pipe = _FakePipe([_privileged_hello(), _reboot_request()])
        runtime = PrivilegedHelperRuntime(
            executor=executor,
            config=RUNTIME_CONFIG,
            pipe_factory=_PipeFactory([pipe]),
            peer_session_id=lambda process_id: 3,
        )

        # When: Helper가 peer session을 검증합니다.
        runtime.run_pipe_loop(lambda: pipe.exited)

        # Then: 잘못된 peer는 executor 호출 전에 연결만 정리하고 fail-closed 합니다.
        assert (executor.reboots, executor.shutdowns) == (0, 0)
        assert pipe.written == []
        assert pipe.exited is True

    def test_rejects_wrong_peer_sid_without_executing_request(self) -> None:
        # Given: LocalSystem이 Helper endpoint에 접속하려는 peer입니다.
        executor = _RecordingExecutor()
        pipe = _FakePipe(
            [_privileged_hello(), _reboot_request()],
            peer=PeerIdentity(sid="S-1-5-18", process_id=41),
        )
        runtime = PrivilegedHelperRuntime(
            executor=executor,
            config=RUNTIME_CONFIG,
            pipe_factory=_PipeFactory([pipe]),
            peer_session_id=lambda process_id: 0,
        )

        # When: Helper가 authenticated pipe peer SID를 검증합니다.
        runtime.run_pipe_loop(lambda: pipe.exited)

        # Then: LocalService 외 SID는 allowlisted action 전에 fail-closed 됩니다.
        assert (executor.reboots, executor.shutdowns) == (0, 0)
        assert pipe.written == []
        assert pipe.exited is True

    def test_rejects_hello_for_another_endpoint(self) -> None:
        # Given: Worker endpoint용 hello가 Helper pipe에 도착합니다.
        executor = _RecordingExecutor()
        pipe = _FakePipe([GatewayHello(target=PeerRole.WORKER)])
        runtime = PrivilegedHelperRuntime(
            executor=executor,
            config=RUNTIME_CONFIG,
            pipe_factory=_PipeFactory([pipe]),
            peer_session_id=lambda process_id: 0,
        )

        # When: Helper가 first-frame target을 검사합니다.
        runtime.run_pipe_loop(lambda: pipe.exited)

        # Then: registration/action/write 없이 연결을 재활용 대상으로 폐기합니다.
        assert (executor.reboots, executor.shutdowns) == (0, 0)
        assert pipe.written == []
        assert pipe.exited is True

    def test_rejects_wrong_target_role_and_preserves_connection_cleanup(self) -> None:
        # Given: Gateway source지만 Worker target으로 향한 request입니다.
        executor = _RecordingExecutor()
        request = IpcRequest(
            request_id=REQUEST_ID,
            target=PeerRole.WORKER,
            operation="shell_run",
            payload={"command": "whoami"},
            timeout_ms=1_000,
        )
        pipe = _FakePipe([_privileged_hello(), request])
        runtime = PrivilegedHelperRuntime(
            executor=executor,
            config=RUNTIME_CONFIG,
            pipe_factory=_PipeFactory([pipe]),
            peer_session_id=lambda process_id: 0,
        )

        # When: Helper pipe에서 role이 맞지 않은 frame을 수신합니다.
        runtime.run_pipe_loop(lambda: len(pipe.written) == 3)

        # Then: raw operation은 실행되지 않고 typed rejection만 응답합니다.
        assert (executor.reboots, executor.shutdowns) == (0, 0)
        assert pipe.written == [
            RUNTIME_CONFIG.registration,
            HelperHeartbeat(registration_id=REGISTRATION_ID, sequence=0),
            IpcResponse(request_id=REQUEST_ID, ok=False, error_code="invalid_privileged_request"),
        ]
        assert pipe.exited is True

    def test_discards_malformed_connection_then_accepts_reconnected_typed_request(self) -> None:
        # Given: protocol parser가 거부한 연결 뒤 정상 Gateway 재연결입니다.
        executor = _RecordingExecutor()
        malformed = _FakePipe([_privileged_hello(), ProtocolMessageError(detail="invalid frame")])
        reconnected = _FakePipe([_privileged_hello(), _reboot_request()])
        runtime = PrivilegedHelperRuntime(
            executor=executor,
            config=RUNTIME_CONFIG,
            pipe_factory=_PipeFactory([malformed, reconnected]),
            peer_session_id=lambda process_id: 0,
        )

        # When: 첫 연결을 정리하고 다음 연결에서 typed request를 처리합니다.
        runtime.run_pipe_loop(lambda: executor.reboots == 1)

        # Then: malformed request는 action 없이 폐기되고 재연결은 정상 실행됩니다.
        assert (executor.reboots, executor.shutdowns) == (1, 0)
        assert malformed.exited is True
        assert reconnected.exited is True
        assert reconnected.written == [
            RUNTIME_CONFIG.registration,
            HelperHeartbeat(registration_id=REGISTRATION_ID, sequence=0),
            IpcResponse(request_id=REQUEST_ID, ok=True, payload={"operation": "reboot"})
        ]

    def test_stop_cancels_active_pipe_and_exits_its_context(self) -> None:
        # Given: SCM stop control을 pipe wait 도중 전달하는 연결입니다.
        executor = _RecordingExecutor()
        pipe = _FakePipe([_privileged_hello(), _reboot_request()])
        cancelled_handles: list[int] = []

        def cancel_active_io(active_pipe: PrivilegedHelperPipe) -> None:
            cancelled_handles.append(active_pipe.handle)

        runtime = PrivilegedHelperRuntime(
            executor=executor,
            config=RUNTIME_CONFIG,
            pipe_factory=_PipeFactory([pipe]),
            peer_session_id=lambda process_id: 0,
            cancel_pending_io=cancel_active_io,
        )
        pipe.set_on_wait(runtime.request_stop)

        # When: wait 도중 runtime cancellation을 요청합니다.
        runtime.run_pipe_loop(lambda: False)

        # Then: pending I/O는 취소되고 pipe context는 정확히 정리됩니다.
        assert cancelled_handles == [0]
        assert (executor.reboots, executor.shutdowns) == (0, 0)
        assert pipe.exited is True
