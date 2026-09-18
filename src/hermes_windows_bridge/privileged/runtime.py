"""Privileged Helper의 authenticated named-pipe session runtime입니다."""

# pyright: reportMissingModuleSource=false
# pyright: reportArgumentType=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, assert_never, final, override
from uuid import uuid4

from hermes_windows_bridge.ipc.acl import LOCAL_SERVICE_SID, PipeAclError, require_expected_sid
from hermes_windows_bridge.ipc.framing import TruncatedFrameError
from hermes_windows_bridge.ipc.named_pipe import (
    PeerIdentity,
    PipeEndpoint,
    PipeTimeoutError,
    create_server_pipe,
)
from hermes_windows_bridge.ipc.protocol import (
    CancelRequest,
    GatewayHello,
    Heartbeat,
    HelperHeartbeat,
    HelperRegistration,
    IpcMessage,
    IpcRequest,
    IpcResponse,
    JobOutputChunkRequest,
    JobOutputChunkResponse,
    PeerRole,
    ProtocolMessageError,
    ProtocolVersionError,
    RebootIpcRequest,
    ShutdownIpcRequest,
    WorkerRegistration,
)
from hermes_windows_bridge.ipc.win32_pipe_io import cancel_pending_io as cancel_named_pipe_io
from hermes_windows_bridge.privileged.operations import (
    PowerActionExecutor,
    PowerActionService,
    RebootRequest,
    ShutdownRequest,
)
from hermes_windows_bridge.privileged.pipe_session import (
    HelperRuntimeConfig,
    HelperSession,
    PrivilegedHelperPipe,
    UnexpectedHelperMessageError,
)

_PIPE_WAIT_TIMEOUT_MS: Final = 250
_GATEWAY_SESSION_ID: Final = 0
type PipeFactory = Callable[[PipeEndpoint], PrivilegedHelperPipe]
type PeerSessionId = Callable[[int], int]
type PendingIoCanceller = Callable[[PrivilegedHelperPipe], None]


@dataclass(frozen=True, slots=True)
class PeerSessionError(Exception):
    """LocalService Gateway가 아닌 Windows session의 peer입니다."""

    process_id: int
    session_id: int

    @override
    def __str__(self) -> str:
        return "privileged helper peer is outside the Gateway service session"


@final
class WindowsPowerActionExecutor:
    """LocalSystem Helper의 allowlisted Windows power API adapter입니다."""

    def reboot(self, request: RebootRequest) -> None:
        """검증된 reboot request를 Windows API로 전달합니다."""
        self._initiate(request.reason, request.delay_seconds, reboot=True)

    def shutdown(self, request: ShutdownRequest) -> None:
        """검증된 shutdown request를 Windows API로 전달합니다."""
        self._initiate(request.reason, request.delay_seconds, reboot=False)

    @staticmethod
    def _initiate(reason: str, delay_seconds: int, *, reboot: bool) -> None:
        from ctypes import WinError  # noqa: PLC0415 - 권한 미할당을 Win32 오류로 전달합니다.

        import win32api  # noqa: PLC0415 - power API를 좁은 LocalSystem adapter에 격리합니다.
        import win32con  # noqa: PLC0415 - 권한 상수는 Windows adapter에서만 사용합니다.
        import win32security  # noqa: PLC0415 - 전원 호출 동안만 기존 권한을 활성화합니다.

        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY
        )
        try:
            privilege = win32security.LookupPrivilegeValue(None, win32security.SE_SHUTDOWN_NAME)
            previous = win32security.AdjustTokenPrivileges(
                token, False, [(privilege, win32con.SE_PRIVILEGE_ENABLED)]  # noqa: FBT003
            )
            error_code = win32api.GetLastError()
            try:
                if error_code:
                    raise WinError(error_code)
                win32api.InitiateSystemShutdown(
                    None,
                    reason,
                    delay_seconds,
                    False,  # noqa: FBT003 - 사용자 앱을 강제로 종료하지 않습니다.
                    reboot,
                )
            finally:
                # 성공·실패 모두 요청 이전 권한 상태로 복원합니다.
                _ = win32security.AdjustTokenPrivileges(token, False, previous)  # noqa: FBT003
        finally:
            win32api.CloseHandle(token)


@final
class PrivilegedHelperRuntime:
    """Gateway handshake를 검증하고 Helper session을 재수용합니다."""

    def __init__(  # noqa: PLR0913 - 독립 Win32 seam을 명시적으로 주입합니다.
        self,
        *,
        executor: PowerActionExecutor,
        pipe_name: str | None = None,
        config: HelperRuntimeConfig | None = None,
        pipe_factory: PipeFactory | None = None,
        peer_session_id: PeerSessionId | None = None,
        cancel_pending_io: PendingIoCanceller | None = None,
    ) -> None:
        """실제 executor와 named-pipe seams를 명시적으로 보관합니다."""
        self._actions = PowerActionService(executor)
        self._pipe_name = pipe_name
        self._config = config or _default_config()
        self._pipe_factory = pipe_factory or create_server_pipe
        self._peer_session_id = peer_session_id or _peer_session_id
        self._cancel_pending_io = cancel_pending_io or _cancel_pending_io
        self._stop_event = threading.Event()
        self._active_lock = threading.Lock()
        self._active_pipe: PrivilegedHelperPipe | None = None

    def request_stop(self) -> None:
        """SCM stop signal에서 active I/O를 취소합니다."""
        self._stop_event.set()
        with self._active_lock:
            active_pipe = self._active_pipe
        if active_pipe is not None:
            self._cancel_pending_io(active_pipe)

    def run_pipe_loop(
        self,
        stop_requested: Callable[[], bool],
        on_ready: Callable[[], None] | None = None,
    ) -> None:
        """끊긴 client마다 새 privileged pipe instance로 안전하게 재수용합니다."""
        import pywintypes  # noqa: PLC0415 - overlapped named-pipe disconnect를 transport boundary에서 재수용합니다.

        ready_announced = False
        while not self._stop_event.is_set() and not stop_requested():
            try:
                with self._create_pipe() as pipe:
                    self._set_active_pipe(pipe)
                    try:
                        if not ready_announced and on_ready is not None:
                            on_ready()
                            ready_announced = True
                        pipe.wait_for_client(_PIPE_WAIT_TIMEOUT_MS)
                        if self._stop_event.is_set() or stop_requested():
                            continue
                        self._require_gateway_hello(pipe.read_message())
                        self._validate_gateway_peer(pipe.verify_peer())
                        pipe.write_message(self._config.registration)
                        HelperSession(pipe, self._actions, self._config, self._stop_event).run(
                            stop_requested
                        )
                    finally:
                        self._clear_active_pipe(pipe)
            except (
                OSError,
                PipeAclError,
                PipeTimeoutError,
                PeerSessionError,
                UnexpectedHelperMessageError,
                ProtocolMessageError,
                ProtocolVersionError,
                TruncatedFrameError,
                pywintypes.error,
            ):
                continue

    def _create_pipe(self) -> PrivilegedHelperPipe:
        """Use the legacy fixed endpoint or the binding-selected unique endpoint."""
        if self._pipe_name is None:
            return self._pipe_factory(PipeEndpoint.PRIVILEGED_HELPER)
        return create_server_pipe(PipeEndpoint.PRIVILEGED_HELPER, pipe_name=self._pipe_name)

    @staticmethod
    def _require_gateway_hello(message: IpcMessage) -> None:
        match message:
            case GatewayHello(target=PeerRole.PRIVILEGED_HELPER):
                return
            case (
                GatewayHello()
                | WorkerRegistration()
                | Heartbeat()
                | HelperRegistration()
                | HelperHeartbeat()
                | IpcRequest()
                | RebootIpcRequest()
                | ShutdownIpcRequest()
                | IpcResponse()
                | JobOutputChunkRequest()
                | JobOutputChunkResponse()
                | CancelRequest()
            ):
                raise UnexpectedHelperMessageError
            case unreachable:
                assert_never(unreachable)

    def _set_active_pipe(self, pipe: PrivilegedHelperPipe) -> None:
        with self._active_lock:
            self._active_pipe = pipe

    def _clear_active_pipe(self, pipe: PrivilegedHelperPipe) -> None:
        with self._active_lock:
            if self._active_pipe is pipe:
                self._active_pipe = None

    def _validate_gateway_peer(self, peer: PeerIdentity) -> None:
        _ = require_expected_sid(LOCAL_SERVICE_SID, peer.sid)
        session_id = self._peer_session_id(peer.process_id)
        if session_id != _GATEWAY_SESSION_ID:
            raise PeerSessionError(process_id=peer.process_id, session_id=session_id)


def _default_config() -> HelperRuntimeConfig:
    return HelperRuntimeConfig(HelperRegistration(registration_id=uuid4(), generation=0))


def _peer_session_id(process_id: int) -> int:
    import win32ts  # noqa: PLC0415 - peer session query를 Windows adapter에 격리합니다.

    return int(win32ts.ProcessIdToSessionId(process_id))


def _cancel_pending_io(pipe: PrivilegedHelperPipe) -> None:
    """공유 Win32 FFI boundary에서 PyHANDLE을 pointer-size HANDLE로 변환합니다."""
    cancel_named_pipe_io(pipe.handle)
