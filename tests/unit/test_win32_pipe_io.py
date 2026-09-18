"""Win32 named-pipe overlapped I/O completion 계약을 검증합니다."""

# pyright: reportGeneralTypeIssues=false
# pyright: reportPrivateUsage=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownLambdaType=false
# pyright: reportUnknownParameterType=false

from __future__ import annotations

import pytest
import pywintypes
import win32event
import win32file
import win32pipe
import win32security

from hermes_windows_bridge.ipc import named_pipe, win32_pipe_io
from hermes_windows_bridge.ipc.acl import (
    PipeAclError,
    PipeAclVerificationError,
    current_process_sid,
)


def test_connect_pipe_connected_fast_path_skips_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: client가 ConnectNamedPipe 직전 연결된 race입니다.
    waits: list[int] = []

    def already_connected(handle: int, overlapped: pywintypes.OVERLAPPED) -> int:
        del handle, overlapped
        raise pywintypes.error(535, "ConnectNamedPipe", "connected")

    monkeypatch.setattr(win32pipe, "ConnectNamedPipe", already_connected)
    monkeypatch.setattr(
        win32event,
        "WaitForSingleObject",
        lambda event, timeout: waits.append(timeout),
    )

    # When: overlapped server connect를 시작합니다.
    win32_pipe_io.wait_for_client(41, 100)

    # Then: ERROR_PIPE_CONNECTED는 유효 연결이며 event wait를 하지 않습니다.
    assert waits == []


def test_connect_pending_waits_on_event_then_reads_overlapped_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: ConnectNamedPipe가 ERROR_IO_PENDING으로 시작됩니다.
    calls: list[tuple[str, int | bool]] = []
    monkeypatch.setattr(win32pipe, "ConnectNamedPipe", lambda handle, overlapped: 997)
    monkeypatch.setattr(
        win32event,
        "WaitForSingleObject",
        lambda event, timeout: calls.append(("wait", timeout)) or win32event.WAIT_OBJECT_0,
    )
    monkeypatch.setattr(
        win32file,
        "GetOverlappedResult",
        lambda handle, overlapped, wait: calls.append(("result", wait)) or 0,
    )

    # When: pending connect event가 signal됩니다.
    win32_pipe_io.wait_for_client(42, 120)

    # Then: pipe handle이 아닌 event를 기다린 뒤 nonblocking completion을 회수합니다.
    assert calls == [("wait", 120), ("result", False)]


def test_connect_timeout_uses_cancel_io_ex_and_drains_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: connect가 timeout된 뒤 cancel completion event가 signal됩니다.
    calls: list[tuple[str, int | bool]] = []
    wait_results = iter((win32event.WAIT_TIMEOUT, win32event.WAIT_OBJECT_0))
    monkeypatch.setattr(win32pipe, "ConnectNamedPipe", lambda handle, overlapped: 997)
    monkeypatch.setattr(
        win32event,
        "WaitForSingleObject",
        lambda event, timeout: calls.append(("wait", timeout)) or next(wait_results),
    )
    monkeypatch.setattr(
        win32_pipe_io,
        "cancel_pending_io",
        lambda handle: calls.append(("cancel_io_ex", handle)),
    )
    monkeypatch.setattr(
        win32file,
        "CancelIo",
        lambda handle: pytest.fail("thread-local CancelIo must not be used"),
    )
    monkeypatch.setattr(
        win32file,
        "GetOverlappedResult",
        lambda handle, overlapped, wait: calls.append(("result", wait)) or 0,
    )

    # When: bounded wait가 만료됩니다.
    with pytest.raises(TimeoutError):
        win32_pipe_io.wait_for_client(43, 5)

    # Then: cross-thread CancelIoEx 요청 뒤 event와 completion을 모두 drain합니다.
    assert calls == [
        ("wait", 5),
        ("cancel_io_ex", 43),
        ("wait", win32event.INFINITE),
        ("result", False),
    ]


def test_client_handle_requests_file_flag_overlapped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: CreateFile 인자를 기록하는 실제 pywin32 module seam입니다.
    flags: list[int] = []
    monkeypatch.setattr(win32pipe, "WaitNamedPipe", lambda name, timeout: None)

    def create_file(*arguments: int | str | None) -> int:
        attributes = arguments[5]
        assert isinstance(attributes, int)
        flags.append(attributes)
        return 44

    monkeypatch.setattr(win32file, "CreateFile", create_file)

    # When: named-pipe client handle을 엽니다.
    handle = win32_pipe_io.open_client_handle(r"\\.\pipe\HermesWindowsBridgeTest", 50)

    # Then: client도 비동기 I/O handle로 열립니다.
    assert handle == 44
    assert flags == [win32file.FILE_FLAG_OVERLAPPED]


def test_server_handle_requests_file_flag_overlapped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: CreateNamedPipe open mode를 기록하는 pywin32 module seam입니다.
    open_modes: list[int] = []
    monkeypatch.setattr(named_pipe, "build_security_attributes", lambda acl: None)

    def create_named_pipe(*arguments: int | str | None) -> int:
        open_mode = arguments[1]
        assert isinstance(open_mode, int)
        open_modes.append(open_mode)
        return 45

    monkeypatch.setattr(win32pipe, "CreateNamedPipe", create_named_pipe)
    monkeypatch.setattr(named_pipe, "verify_server_pipe_acl", lambda handle, acl: None)

    # When: Worker-owned server handle을 생성합니다.
    server = named_pipe.create_server_pipe(
        named_pipe.PipeEndpoint.WORKER,
        pipe_name=r"\\.\pipe\HermesWindowsBridgeTest",
        target_user_sid=current_process_sid(),
    )

    # Then: server도 비동기 I/O handle이며 단일 instance 보호를 유지합니다.
    assert server.handle == 45
    assert open_modes == [
        win32pipe.PIPE_ACCESS_DUPLEX
        | win32pipe.FILE_FLAG_FIRST_PIPE_INSTANCE
        | win32file.FILE_FLAG_OVERLAPPED
    ]


def test_server_acl_verification_failure_closes_handle_before_accept(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: CreateNamedPipe 뒤 owned-handle DACL이 빈 template으로 바뀝니다.
    closed: list[int] = []
    descriptor = win32security.SECURITY_DESCRIPTOR()
    descriptor.SetSecurityDescriptorDacl(
        True,  # noqa: FBT003 - Win32 positional API입니다.
        win32security.ACL(),
        False,  # noqa: FBT003 - Win32 positional API입니다.
    )
    monkeypatch.setattr(named_pipe, "build_security_attributes", lambda acl: None)
    monkeypatch.setattr(win32pipe, "CreateNamedPipe", lambda *arguments: 46)
    monkeypatch.setattr(
        win32security,
        "GetSecurityInfo",
        lambda *arguments: descriptor,
    )
    monkeypatch.setattr(named_pipe, "close_pipe_handle", closed.append)

    # When/Then: 실제 DACL mismatch에서 handle을 반환하지 않고 즉시 닫습니다.
    with pytest.raises(PipeAclVerificationError, match="DACL ACE template mismatch"):
        _ = named_pipe.create_server_pipe(
            named_pipe.PipeEndpoint.WORKER,
            pipe_name=r"\\.\pipe\HermesWindowsBridgeTest",
            target_user_sid=current_process_sid(),
        )
    assert closed == [46]


def test_acl_verification_error_is_outside_retryable_pipe_error_types() -> None:
    # Given: Worker와 Helper의 기존 retry 대상 error type입니다.

    # When/Then: ACL 검증 실패는 그 대상이 아닌 별도 fail-closed signal입니다.
    assert not issubclass(PipeAclVerificationError, OSError)
    assert not issubclass(PipeAclVerificationError, PipeAclError)
    assert not issubclass(PipeAclVerificationError, pywintypes.error)


def test_server_acl_query_os_error_closes_handle_and_raises_typed_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: owned server handle의 DACL 조회가 OS 오류로 실패합니다.
    closed: list[int] = []
    monkeypatch.setattr(named_pipe, "build_security_attributes", lambda acl: None)
    monkeypatch.setattr(win32pipe, "CreateNamedPipe", lambda *arguments: 47)

    def unavailable_security_info(*arguments: int) -> None:
        del arguments
        raise OSError

    monkeypatch.setattr(win32security, "GetSecurityInfo", unavailable_security_info)
    monkeypatch.setattr(named_pipe, "close_pipe_handle", closed.append)

    # When/Then: raw OS 오류를 retryable OSError로 남기지 않고 handle을 닫아 fail closed합니다.
    with pytest.raises(PipeAclVerificationError, match="GetSecurityInfo failed"):
        _ = named_pipe.create_server_pipe(
            named_pipe.PipeEndpoint.WORKER,
            pipe_name=r"\\.\pipe\HermesWindowsBridgeTest",
            target_user_sid=current_process_sid(),
        )
    assert closed == [47]


def test_read_write_timeout_drains_cancelled_overlapped_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: pending read/write completion이 deadline 뒤 cancel event로 깨어납니다.
    calls: list[tuple[str, int | bool]] = []
    wait_results = iter((win32event.WAIT_TIMEOUT, win32event.WAIT_OBJECT_0))
    overlapped = pywintypes.OVERLAPPED()
    monkeypatch.setattr(
        win32event,
        "WaitForSingleObject",
        lambda event, timeout: calls.append(("wait", timeout)) or next(wait_results),
    )
    monkeypatch.setattr(
        win32_pipe_io,
        "cancel_pending_io",
        lambda handle: calls.append(("cancel_io_ex", handle)),
    )
    monkeypatch.setattr(
        win32file,
        "GetOverlappedResult",
        lambda handle, pending, wait: calls.append(("result", wait)) or 0,
    )

    # When: 공통 read/write overlapped completion helper가 timeout됩니다.
    with pytest.raises(TimeoutError):
        _ = win32_pipe_io._complete_overlapped(45, overlapped, 46, 997, 5)

    # Then: CancelIoEx 뒤 event와 GetOverlappedResult를 모두 drain합니다.
    assert calls == [
        ("wait", 5),
        ("cancel_io_ex", 45),
        ("wait", win32event.INFINITE),
        ("result", False),
    ]
