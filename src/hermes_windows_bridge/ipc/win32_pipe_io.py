"""Named Pipe의 blocking/overlapped Win32 I/O 경계입니다."""

# pyright: reportMissingModuleSource=false
# pyright: reportArgumentType=false
# pyright: reportReturnType=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false
# pyright: reportAny=false

from __future__ import annotations

from typing import TYPE_CHECKING, Final, final

from hermes_windows_bridge.ipc.framing import encode_frame, read_frame

if TYPE_CHECKING:
    import _win32typing

    from hermes_windows_bridge.ipc.protocol import IpcMessage

_ERROR_PIPE_CONNECTED: Final = 535
_ERROR_OPERATION_ABORTED: Final = 995
_ERROR_IO_PENDING: Final = 997
_ERROR_NOT_FOUND: Final = 1168
_DEFAULT_IO_TIMEOUT_MS: Final = 300_000


class PipeWriteError(OSError):
    """Named Pipe write가 진행되지 않았습니다."""


@final
class PipeByteReader:
    """Win32 handle을 framing의 최소 reader 계약에 맞춥니다."""

    __slots__: tuple[str, str] = ("_handle", "_timeout_ms")

    def __init__(self, handle: int, timeout_ms: int) -> None:
        """읽을 Win32 handle을 보관합니다."""
        self._handle = handle
        self._timeout_ms = timeout_ms

    def read(self, size: int, /) -> bytes:
        """Win32가 반환한 현재 read 조각을 bytes로 변환합니다."""
        import pywintypes  # noqa: PLC0415 - Windows OVERLAPPED 경계입니다.
        import win32api  # noqa: PLC0415 - event handle 수명 경계입니다.
        import win32event  # noqa: PLC0415 - bounded wait 경계입니다.
        import win32file  # noqa: PLC0415 - Windows 전용 경계를 격리합니다.

        event: int = win32event.CreateEvent(
            None,
            True,  # noqa: FBT003 - Win32 positional API입니다.
            False,  # noqa: FBT003 - Win32 positional API입니다.
            None,
        )
        overlapped = pywintypes.OVERLAPPED()
        overlapped.hEvent = event
        try:
            result, data = win32file.ReadFile(self._handle, size, overlapped)
            count = _complete_overlapped(
                self._handle,
                overlapped,
                event,
                result,
                self._timeout_ms,
            )
        finally:
            win32api.CloseHandle(event)
        return bytes(data)[:count]


def read_pipe_message(
    handle: int,
    timeout_ms: int = _DEFAULT_IO_TIMEOUT_MS,
) -> IpcMessage:
    """한 개의 bounded framed message를 읽습니다."""
    return read_frame(PipeByteReader(handle, timeout_ms))


def write_pipe_message(
    handle: int,
    message: IpcMessage,
    timeout_ms: int = _DEFAULT_IO_TIMEOUT_MS,
) -> None:
    """한 개의 framed message를 끝까지 씁니다."""
    import pywintypes  # noqa: PLC0415 - Windows OVERLAPPED 경계입니다.
    import win32api  # noqa: PLC0415 - event handle 수명 경계입니다.
    import win32event  # noqa: PLC0415 - bounded wait 경계입니다.
    import win32file  # noqa: PLC0415 - Windows 전용 경계를 격리합니다.

    frame = encode_frame(message)
    written = 0
    while written < len(frame):
        event: int = win32event.CreateEvent(
            None,
            True,  # noqa: FBT003 - Win32 positional API입니다.
            False,  # noqa: FBT003 - Win32 positional API입니다.
            None,
        )
        overlapped = pywintypes.OVERLAPPED()
        overlapped.hEvent = event
        try:
            result, _ = win32file.WriteFile(handle, frame[written:], overlapped)
            count = _complete_overlapped(handle, overlapped, event, result, timeout_ms)
        finally:
            win32api.CloseHandle(event)
        if count <= 0:
            raise PipeWriteError
        written += count


def open_client_handle(pipe_name: str, timeout_ms: int) -> int:
    """기존 local pipe instance를 bounded wait 후 duplex로 엽니다."""
    import win32con  # noqa: PLC0415 - Windows 전용 경계를 격리합니다.
    import win32file  # noqa: PLC0415 - Windows 전용 경계를 격리합니다.
    import win32pipe  # noqa: PLC0415 - Windows 전용 경계를 격리합니다.

    win32pipe.WaitNamedPipe(pipe_name, timeout_ms)
    return win32file.CreateFile(
        pipe_name,
        win32con.GENERIC_READ | win32con.GENERIC_WRITE,
        0,
        None,
        win32con.OPEN_EXISTING,
        win32file.FILE_FLAG_OVERLAPPED,
        None,
    )


def close_pipe_handle(handle: int) -> None:
    """소유한 Win32 handle을 닫습니다."""
    import win32api  # noqa: PLC0415 - Windows 전용 경계를 격리합니다.

    win32api.CloseHandle(handle)


def wait_for_client(handle: int, timeout_ms: int) -> None:
    """Overlapped connect를 bounded wait하고 pending I/O를 정리합니다."""
    import pywintypes  # noqa: PLC0415 - Windows 전용 경계를 격리합니다.
    import win32api  # noqa: PLC0415 - Windows 전용 경계를 격리합니다.
    import win32event  # noqa: PLC0415 - Windows 전용 경계를 격리합니다.
    import win32file  # noqa: PLC0415 - Windows 전용 경계를 격리합니다.
    import win32pipe  # noqa: PLC0415 - Windows 전용 경계를 격리합니다.

    event: int = win32event.CreateEvent(
        None,
        True,  # noqa: FBT003 - Win32 positional API입니다.
        False,  # noqa: FBT003 - Win32 positional API입니다.
        None,
    )
    overlapped = pywintypes.OVERLAPPED()
    overlapped.hEvent = event
    try:
        try:
            result = win32pipe.ConnectNamedPipe(handle, overlapped)
        except pywintypes.error as exc:
            if exc.winerror == _ERROR_PIPE_CONNECTED:
                return
            if exc.winerror != _ERROR_IO_PENDING:
                raise
        else:
            if result == _ERROR_PIPE_CONNECTED:
                return
            if result not in (0, _ERROR_IO_PENDING):
                raise OSError(result, "ConnectNamedPipe failed")
        wait_result = win32event.WaitForSingleObject(event, timeout_ms)
        if wait_result == win32event.WAIT_TIMEOUT:
            _cancel_and_drain(handle, overlapped, event)
            raise TimeoutError
        _ = win32file.GetOverlappedResult(
            handle,
            overlapped,
            False,  # noqa: FBT003 - Win32 positional API입니다.
        )
    finally:
        win32api.CloseHandle(event)


def _complete_overlapped(
    handle: int,
    overlapped: _win32typing.PyOVERLAPPED,
    event: int,
    initial_result: int,
    timeout_ms: int,
) -> int:
    import win32event  # noqa: PLC0415 - Windows bounded wait 경계입니다.
    import win32file  # noqa: PLC0415 - Windows OVERLAPPED 경계입니다.

    if initial_result == 0:
        return win32file.GetOverlappedResult(
            handle,
            overlapped,
            True,  # noqa: FBT003 - Win32 positional API입니다.
        )
    if initial_result != _ERROR_IO_PENDING:
        raise OSError(initial_result, "overlapped named-pipe I/O failed")
    if win32event.WaitForSingleObject(event, timeout_ms) == win32event.WAIT_TIMEOUT:
        _cancel_and_drain(handle, overlapped, event)
        raise TimeoutError
    return win32file.GetOverlappedResult(
        handle,
        overlapped,
        False,  # noqa: FBT003 - Win32 positional API입니다.
    )


def _cancel_and_drain(
    handle: int,
    overlapped: _win32typing.PyOVERLAPPED,
    event: int,
) -> None:
    """OVERLAPPED 수명을 취소 완료까지 유지한 뒤 결과를 회수합니다."""
    import pywintypes  # noqa: PLC0415 - Windows completion error 경계입니다.
    import win32event  # noqa: PLC0415 - 취소 completion wait 경계입니다.
    import win32file  # noqa: PLC0415 - Windows OVERLAPPED 경계입니다.

    cancel_pending_io(handle)
    _ = win32event.WaitForSingleObject(event, win32event.INFINITE)
    try:
        _ = win32file.GetOverlappedResult(handle, overlapped, False)  # noqa: FBT003
    except pywintypes.error as error:
        if error.winerror != _ERROR_OPERATION_ABORTED:
            raise


def cancel_pending_io(handle: int) -> None:
    """Handle의 pending OVERLAPPED I/O를 cross-thread에서도 취소합니다."""
    import ctypes  # noqa: PLC0415 - CancelIoEx FFI를 이 경계로 격리합니다.

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    cancel_io_ex = kernel32.CancelIoEx
    cancel_io_ex.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    cancel_io_ex.restype = ctypes.c_int
    cancelled = cancel_io_ex(ctypes.c_void_p(int(handle)), None)
    if cancelled == 0 and ctypes.get_last_error() != _ERROR_NOT_FOUND:
        raise ctypes.WinError()
