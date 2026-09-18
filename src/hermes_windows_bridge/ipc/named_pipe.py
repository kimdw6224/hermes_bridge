"""pywin32 Named Pipe 생성, bounded wait, peer identity 경계입니다."""

# pyright: reportUnnecessaryComparison=false
# pyright: reportMissingModuleSource=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Self, assert_never, override

from hermes_windows_bridge.ipc.acl import (
    LOCAL_SERVICE_SID,
    PipeAcl,
    PipeAclProbeState,
    build_privileged_pipe_acl,
    build_security_attributes,
    build_worker_pipe_acl,
    descriptor_acl_sids,
    observe_client_pipe_acl,
    read_server_pipe_security_descriptor,
    require_expected_sid,
    verify_pipe_security_descriptor,
)
from hermes_windows_bridge.ipc.win32_pipe_io import (
    cancel_pending_io,
    close_pipe_handle,
    open_client_handle,
    read_pipe_message,
    wait_for_client,
    write_pipe_message,
)

if TYPE_CHECKING:
    from types import TracebackType

    import _win32typing

    from hermes_windows_bridge.ipc.protocol import IpcMessage

WORKER_PIPE_NAME: Final = r"\\.\pipe\HermesWindowsBridgeWorker"
PRIVILEGED_PIPE_NAME: Final = r"\\.\pipe\HermesWindowsBridgePrivileged"
_PIPE_NAME_PATTERN: Final = re.compile(r"^\\\\\.\\pipe\\HermesWindowsBridge[A-Za-z0-9-]{1,128}$")


class PipeEndpoint(StrEnum):
    """Gateway가 연결할 수 있는 두 로컬 IPC endpoint입니다."""

    WORKER = "worker"
    PRIVILEGED_HELPER = "privileged_helper"


@dataclass(frozen=True, slots=True)
class PipeConfigurationError(Exception):
    """pipe 이름 또는 endpoint 설정이 보안 정책과 맞지 않습니다."""

    detail: str

    @override
    def __str__(self) -> str:
        """잘못된 pipe 설정 상세를 표시합니다."""
        return f"invalid named-pipe configuration: {self.detail}"


@dataclass(frozen=True, slots=True)
class PipeTimeoutError(TimeoutError):
    """peer 연결이 지정 시간 안에 완료되지 않았습니다."""

    timeout_ms: int

    @override
    def __str__(self) -> str:
        """초과한 연결 대기 시간을 표시합니다."""
        return f"named-pipe connection timed out after {self.timeout_ms} ms"


@dataclass(frozen=True, slots=True)
class PeerIdentity:
    """ACL 외에 Windows token에서 확인한 실제 client identity입니다."""

    sid: str
    process_id: int


@dataclass(frozen=True, slots=True)
class PeerProcessError(Exception):
    """client PID가 호출자가 기대한 process와 다릅니다."""

    expected: int
    received: int

    @override
    def __str__(self) -> str:
        """기대한 PID와 실제 PID를 표시합니다."""
        return f"named-pipe peer PID mismatch: expected {self.expected}, received {self.received}"


@dataclass(frozen=True, slots=True)
class NamedPipeServer:
    """실제 Windows pipe handle을 context manager 수명으로 소유합니다."""

    endpoint: PipeEndpoint
    name: str
    handle: int
    acl: PipeAcl
    expected_peer_sid: str

    def __enter__(self) -> Self:
        """관리 중인 server를 반환합니다."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """경로와 무관하게 kernel handle을 닫습니다."""
        cancel_pending_io(self.handle)
        close_pipe_handle(self.handle)

    def wait_for_client(self, timeout_ms: int) -> None:
        """Overlapped connect를 bounded wait하고 timeout이면 pending I/O를 취소합니다."""
        if timeout_ms <= 0:
            raise PipeConfigurationError(detail="timeout_ms must be positive")
        try:
            wait_for_client(self.handle, timeout_ms)
        except TimeoutError as exc:
            raise PipeTimeoutError(timeout_ms=timeout_ms) from exc

    def read_message(self, timeout_ms: int = 300_000) -> IpcMessage:
        """연결된 client에서 framed message 하나를 읽습니다."""
        return read_pipe_message(self.handle, timeout_ms)

    def write_message(self, message: IpcMessage, timeout_ms: int = 300_000) -> None:
        """연결된 client에 framed message 하나를 씁니다."""
        write_pipe_message(self.handle, message, timeout_ms)

    def verify_peer(self, expected_process_id: int | None = None) -> PeerIdentity:
        """연결된 client의 token SID와 선택적 PID를 확인합니다."""
        return verify_named_pipe_peer(
            self.handle,
            self.expected_peer_sid,
            expected_process_id,
        )


def create_server_pipe(
    endpoint: PipeEndpoint,
    *,
    pipe_name: str | None = None,
    target_user_sid: str | None = None,
    expected_peer_sid: str | None = None,
) -> NamedPipeServer:
    """Remote client와 pipe squatting을 막는 단일 local server instance를 만듭니다."""
    import win32file  # noqa: PLC0415 - portable module import를 유지합니다.
    import win32pipe  # noqa: PLC0415 - Windows API 경계를 이 함수로 격리합니다.

    name = pipe_name or _default_pipe_name(endpoint)
    if _PIPE_NAME_PATTERN.fullmatch(name) is None:
        raise PipeConfigurationError(detail=f"local Hermes pipe name required: {name!r}")
    acl = _endpoint_acl(endpoint, target_user_sid, expected_peer_sid)
    attributes = build_security_attributes(acl)
    handle: int = win32pipe.CreateNamedPipe(
        name,
        win32pipe.PIPE_ACCESS_DUPLEX
        | win32pipe.FILE_FLAG_FIRST_PIPE_INSTANCE
        | win32file.FILE_FLAG_OVERLAPPED,
        win32pipe.PIPE_TYPE_BYTE
        | win32pipe.PIPE_READMODE_BYTE
        | win32pipe.PIPE_WAIT
        | win32pipe.PIPE_REJECT_REMOTE_CLIENTS,
        1,
        1_048_580,
        1_048_580,
        5_000,
        attributes,
    )
    verified = False
    try:
        verify_server_pipe_acl(handle, acl)
        verified = True
    finally:
        if not verified:
            close_pipe_handle(handle)
    peer_sid = expected_peer_sid or target_user_sid or LOCAL_SERVICE_SID
    return NamedPipeServer(
        endpoint=endpoint,
        name=name,
        handle=handle,
        acl=acl,
        expected_peer_sid=peer_sid,
    )


@dataclass(frozen=True, slots=True)
class NamedPipeClient:
    """bounded connect로 연 local Named Pipe client handle입니다."""

    handle: int

    def __enter__(self) -> Self:
        """관리 중인 client를 반환합니다."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """경로와 무관하게 client handle을 닫습니다."""
        cancel_pending_io(self.handle)
        close_pipe_handle(self.handle)

    def read_message(self, timeout_ms: int = 300_000) -> IpcMessage:
        """server에서 framed message 하나를 읽습니다."""
        return read_pipe_message(self.handle, timeout_ms)

    def write_message(self, message: IpcMessage, timeout_ms: int = 300_000) -> None:
        """server에 framed message 하나를 씁니다."""
        write_pipe_message(self.handle, message, timeout_ms)


def connect_named_pipe_client(pipe_name: str, *, timeout_ms: int) -> NamedPipeClient:
    """Hermes local pipe에 bounded client connection을 엽니다."""
    if _PIPE_NAME_PATTERN.fullmatch(pipe_name) is None:
        raise PipeConfigurationError(detail=f"local Hermes pipe name required: {pipe_name!r}")
    if timeout_ms <= 0:
        raise PipeConfigurationError(detail="timeout_ms must be positive")
    return NamedPipeClient(handle=open_client_handle(pipe_name, timeout_ms))


def verify_named_pipe_peer(
    handle: int,
    expected_sid: str,
    expected_process_id: int | None = None,
) -> PeerIdentity:
    """Named Pipe client를 impersonate해 SID를 읽고 PID도 독립 확인합니다."""
    import win32api  # noqa: PLC0415 - Windows API 경계를 이 함수로 격리합니다.
    import win32pipe  # noqa: PLC0415 - Windows API 경계를 이 함수로 격리합니다.
    import win32security  # noqa: PLC0415 - Windows API 경계를 이 함수로 격리합니다.

    win32security.ImpersonateNamedPipeClient(handle)
    try:
        token: int = win32security.OpenThreadToken(
            win32api.GetCurrentThread(),
            win32security.TOKEN_QUERY,
            True,  # noqa: FBT003 - Win32 positional API입니다.
        )
        try:
            token_user: tuple[_win32typing.PySID, int] = win32security.GetTokenInformation(
                token,
                win32security.TokenUser,
            )
            sid = require_expected_sid(
                expected_sid,
                win32security.ConvertSidToStringSid(token_user[0]),
            )
        finally:
            win32api.CloseHandle(token)
    finally:
        win32security.RevertToSelf()
    process_id: int = win32pipe.GetNamedPipeClientProcessId(handle)
    if expected_process_id is not None and process_id != expected_process_id:
        raise PeerProcessError(expected=expected_process_id, received=process_id)
    return PeerIdentity(sid=sid, process_id=process_id)


def server_security_sids(server: NamedPipeServer) -> frozenset[str]:
    """실제 생성된 pipe kernel object의 DACL SID를 반환합니다."""
    return descriptor_acl_sids(read_server_pipe_security_descriptor(server.handle))


def verify_server_pipe_acl(handle: int, expected: PipeAcl) -> None:
    """소유한 server handle의 실제 DACL이 구성 template과 정확히 일치하는지 확인합니다."""
    verify_pipe_security_descriptor(expected, read_server_pipe_security_descriptor(handle))


def observe_gateway_client_pipe_acl(handle: int, expected: PipeAcl) -> PipeAclProbeState:
    """Gateway가 이미 연결한 client handle에서만 opaque ACL 결과를 반환합니다."""
    return observe_client_pipe_acl(handle, expected)


def _default_pipe_name(endpoint: PipeEndpoint) -> str:
    match endpoint:
        case PipeEndpoint.WORKER:
            return WORKER_PIPE_NAME
        case PipeEndpoint.PRIVILEGED_HELPER:
            return PRIVILEGED_PIPE_NAME
        case _ as unreachable:
            assert_never(unreachable)


def _endpoint_acl(
    endpoint: PipeEndpoint,
    target_user_sid: str | None,
    expected_peer_sid: str | None,
) -> PipeAcl:
    match endpoint:
        case PipeEndpoint.WORKER:
            if target_user_sid is None:
                raise PipeConfigurationError(detail="worker pipe requires target_user_sid")
            return build_worker_pipe_acl(target_user_sid)
        case PipeEndpoint.PRIVILEGED_HELPER:
            if target_user_sid is not None:
                raise PipeConfigurationError(
                    detail="privileged pipe does not accept a target user SID"
                )
            acl = build_privileged_pipe_acl()
            if expected_peer_sid is None or expected_peer_sid == LOCAL_SERVICE_SID:
                return acl
            validated_sid = build_worker_pipe_acl(expected_peer_sid).allowed_sids[1]
            return PipeAcl((*acl.allowed_sids, validated_sid))
        case _ as unreachable:
            assert_never(unreachable)
