"""시작된 privileged action의 취소 진실성과 cleanup을 검증합니다."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Self, final
from uuid import UUID

from hermes_windows_bridge.ipc.named_pipe import PeerIdentity, PipeEndpoint
from hermes_windows_bridge.ipc.operation_policy import PrivilegedOperation, RebootPayload
from hermes_windows_bridge.ipc.protocol import (
    CancelRequest,
    GatewayHello,
    HelperRegistration,
    IpcMessage,
    IpcResponse,
    PeerRole,
    RebootIpcRequest,
)
from hermes_windows_bridge.privileged.pipe_session import HelperRuntimeConfig
from hermes_windows_bridge.privileged.runtime import PrivilegedHelperRuntime

if TYPE_CHECKING:
    from types import TracebackType

    from hermes_windows_bridge.privileged.operations import RebootRequest, ShutdownRequest

REQUEST_ID = UUID("018f0000-0000-7000-8000-000000000021")
RUNTIME_CONFIG = HelperRuntimeConfig(
    HelperRegistration(
        registration_id=UUID("018f0000-0000-7000-8000-000000000022"),
        generation=2,
    )
)


@final
class _BlockingExecutor:
    """취소 frame 도착 전 이미 시작된 action을 재현합니다."""

    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()

    def reboot(self, request: RebootRequest) -> None:
        del request
        self.started.set()
        assert self.release.wait(1)

    def shutdown(self, request: ShutdownRequest) -> None:
        del request
        message = "shutdown must not execute"
        raise AssertionError(message)


@final
class _CancellationPipe:
    """Started-action cancel 순서만 재현하는 한 연결입니다."""

    def __init__(self) -> None:
        self.handle = 0
        self.exited = False
        self.written: list[IpcMessage] = []
        self._messages: list[IpcMessage] = [
            GatewayHello(target=PeerRole.PRIVILEGED_HELPER),
            RebootIpcRequest(
                request_id=REQUEST_ID,
                operation=PrivilegedOperation.REBOOT,
                payload=RebootPayload(delay_seconds=0, reason="maintenance"),
                timeout_ms=1_000,
            ),
            CancelRequest(request_id=REQUEST_ID, reason="gateway disconnect"),
        ]

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

    def verify_peer(self) -> PeerIdentity:
        return PeerIdentity(sid="S-1-5-19", process_id=41)

    def read_message(self) -> IpcMessage:
        return self._messages.pop(0)

    def write_message(self, message: IpcMessage) -> None:
        self.written.append(message)


@final
class _ReadyPipe:
    """ACL 검증을 끝낸 factory 결과와 첫 readiness callback 순서만 재현합니다."""

    def __init__(self, stop: threading.Event) -> None:
        self.handle = 0
        self._stop = stop

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback

    def wait_for_client(self, timeout_ms: int) -> None:
        assert timeout_ms > 0
        self._stop.set()

    def verify_peer(self) -> PeerIdentity:
        message = "stop before peer verification"
        raise AssertionError(message)

    def read_message(self) -> IpcMessage:
        message = "stop before IPC reads"
        raise AssertionError(message)

    def write_message(self, message: IpcMessage) -> None:
        del message
        message_text = "stop before IPC writes"
        raise AssertionError(message_text)


def test_cancel_after_started_power_action_never_claims_operation_cancelled() -> None:
    # Given: action이 시작된 뒤 Gateway가 cancel frame과 연결 종료를 준비합니다.
    executor = _BlockingExecutor()
    pipe = _CancellationPipe()

    def create_pipe(endpoint: PipeEndpoint) -> _CancellationPipe:
        assert endpoint is PipeEndpoint.PRIVILEGED_HELPER
        return pipe

    runtime = PrivilegedHelperRuntime(
        executor=executor,
        config=RUNTIME_CONFIG,
        pipe_factory=create_pipe,
        peer_session_id=lambda process_id: 0,
    )
    runner = threading.Thread(target=runtime.run_pipe_loop, args=(lambda: pipe.exited,))

    # When: executor가 non-preemptible action을 시작한 상태를 명시적으로 만듭니다.
    runner.start()
    assert executor.started.wait(1)
    executor.release.set()
    runner.join(1)

    # Then: cancel success를 위조하지 않고 connection을 cleanup합니다.
    assert runner.is_alive() is False
    assert pipe.exited is True
    assert all(
        not (
            isinstance(message, IpcResponse)
            and message.error_code == "operation_cancelled"
        )
        for message in pipe.written
    )


def test_ready_callback_follows_first_acl_verified_pipe_creation_once() -> None:
    # Given: production factory 경계가 ACL 검증을 마친 뒤에만 pipe를 반환합니다.
    stop = threading.Event()
    factory_completed = threading.Event()
    pipe = _ReadyPipe(stop)
    ready_after_factory: list[bool] = []

    def create_pipe(endpoint: PipeEndpoint) -> _ReadyPipe:
        assert endpoint is PipeEndpoint.PRIVILEGED_HELPER
        factory_completed.set()
        return pipe

    runtime = PrivilegedHelperRuntime(
        executor=_BlockingExecutor(),
        config=RUNTIME_CONFIG,
        pipe_factory=create_pipe,
        peer_session_id=lambda process_id: 0,
    )

    # When: 첫 server pipe가 만들어진 직후 service child readiness를 전달합니다.
    runtime.run_pipe_loop(
        stop.is_set,
        on_ready=lambda: ready_after_factory.append(factory_completed.is_set()),
    )

    # Then: pipe 재수용 횟수와 무관하게 callback은 검증된 최초 생성 뒤 한 번뿐입니다.
    assert ready_after_factory == [True]
