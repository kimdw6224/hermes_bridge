"""로컬 비상 정지 hotkey의 Win32 message-loop owner입니다."""

# pyright: reportUnknownArgumentType=false
# pyright: reportAny=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from threading import Event, Lock, Thread
from typing import TYPE_CHECKING, Final, Protocol, final, override

if TYPE_CHECKING:
    from collections.abc import Callable

    from hermes_windows_bridge.worker.desktop_lock import DesktopMutationGate

_HOTKEY_ID: Final = 0x4842
_MOD_ALT: Final = 0x0001
_MOD_CONTROL: Final = 0x0002
_MOD_SHIFT: Final = 0x0004
_MOD_NOREPEAT: Final = 0x4000
_VK_F11: Final = 0x7A
_VK_F24: Final = 0x87
_WM_HOTKEY: Final = 0x0312
_WM_QUIT: Final = 0x0012
_PM_NOREMOVE: Final = 0
_START_TIMEOUT_SECONDS: Final = 1.0
_STOP_TIMEOUT_SECONDS: Final = 1.0


@dataclass(frozen=True, slots=True)
class EmergencyHotkeyStartupTimeoutError(OSError):
    """등록 thread가 제한 시간 안에 준비 상태를 알리지 못했습니다."""

    @override
    def __str__(self) -> str:
        """비민감 stable 오류 문구를 반환합니다."""
        return "local emergency hotkey startup timed out"


@dataclass(frozen=True, slots=True)
class EmergencyHotkeyShutdownTimeoutError(OSError):
    """종료 요청 뒤 message thread가 제한 시간 안에 끝나지 않았습니다."""

    @override
    def __str__(self) -> str:
        """비민감 stable 오류 문구를 반환합니다."""
        return "local emergency hotkey shutdown timed out"


class EmergencyHotkeyBackend(Protocol):
    """Worker thread에 소유권을 고정하는 최소 Win32 API 경계입니다."""

    def register(self) -> None:
        """현재 thread에 global hotkey를 등록합니다."""
        ...

    def next_message(self) -> HotkeyMessage:
        """다음 Windows message ID를 반환하거나 Win32 오류를 전파합니다."""
        ...

    def request_quit(self) -> None:
        """소유 thread의 message loop에 WM_QUIT를 게시합니다."""
        ...

    def unregister(self) -> None:
        """현재 thread에 등록한 hotkey를 해제합니다."""
        ...


@dataclass(frozen=True, slots=True)
class HotkeyMessage:
    """message loop가 식별하는 Win32 message와 hotkey registration ID입니다."""

    message_id: int
    hotkey_id: int | None


def win32_error_from_saved_last_error() -> OSError:
    """use_last_error가 보관한 ctypes thread-local error를 OSError로 변환합니다."""
    return ctypes.WinError(ctypes.get_last_error())


@final
class Win32EmergencyHotkey:
    """User32 호출을 한 message-loop thread에서만 수행합니다."""

    def __init__(self, *, virtual_key: int = _VK_F11) -> None:
        """아직 등록되지 않은 thread-bound backend를 만듭니다."""
        self._thread_id: int | None = None
        self._virtual_key = virtual_key
        self._user32 = ctypes.WinDLL("user32", use_last_error=True)
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._register_hotkey = self._user32.RegisterHotKey
        self._register_hotkey.argtypes = (
            wintypes.HWND,
            ctypes.c_int,
            wintypes.UINT,
            wintypes.UINT,
        )
        self._register_hotkey.restype = wintypes.BOOL
        self._unregister_hotkey = self._user32.UnregisterHotKey
        self._unregister_hotkey.argtypes = (wintypes.HWND, ctypes.c_int)
        self._unregister_hotkey.restype = wintypes.BOOL
        self._get_message = self._user32.GetMessageW
        self._get_message.argtypes = (
            ctypes.POINTER(wintypes.MSG),
            wintypes.HWND,
            wintypes.UINT,
            wintypes.UINT,
        )
        self._get_message.restype = ctypes.c_int
        self._peek_message = self._user32.PeekMessageW
        self._peek_message.argtypes = (
            ctypes.POINTER(wintypes.MSG),
            wintypes.HWND,
            wintypes.UINT,
            wintypes.UINT,
            wintypes.UINT,
        )
        self._peek_message.restype = wintypes.BOOL
        self._post_thread_message = self._user32.PostThreadMessageW
        self._post_thread_message.argtypes = (
            wintypes.DWORD,
            wintypes.UINT,
            wintypes.WPARAM,
            wintypes.LPARAM,
        )
        self._post_thread_message.restype = wintypes.BOOL
        self._get_current_thread_id = self._kernel32.GetCurrentThreadId
        self._get_current_thread_id.argtypes = ()
        self._get_current_thread_id.restype = wintypes.DWORD

    def register(self) -> None:
        """NULL window message queue에 Ctrl+Alt+Shift+F11을 등록합니다."""
        message = wintypes.MSG()
        _ = self._peek_message(ctypes.byref(message), None, 0, 0, _PM_NOREMOVE)
        self._thread_id = int(self._get_current_thread_id())
        modifiers = _MOD_ALT | _MOD_CONTROL | _MOD_SHIFT | _MOD_NOREPEAT
        if self._register_hotkey(None, _HOTKEY_ID, modifiers, self._virtual_key) == 0:
            raise win32_error_from_saved_last_error()

    def next_message(self) -> HotkeyMessage:
        """현재 thread queue에서 다음 message를 block하며 읽습니다."""
        message = wintypes.MSG()
        result = self._get_message(ctypes.byref(message), None, 0, 0)
        if result == -1:
            raise win32_error_from_saved_last_error()
        hotkey_id = int(message.wParam) if message.message == _WM_HOTKEY else None
        return HotkeyMessage(message_id=int(message.message), hotkey_id=hotkey_id)

    def request_quit(self) -> None:
        """등록 thread에만 종료 message를 보냅니다."""
        if self._thread_id is None:
            raise EmergencyHotkeyStartupTimeoutError
        if self._post_thread_message(self._thread_id, _WM_QUIT, 0, 0) == 0:
            raise win32_error_from_saved_last_error()

    def unregister(self) -> None:
        """등록과 동일한 thread에서 hotkey를 제거합니다."""
        if self._unregister_hotkey(None, _HOTKEY_ID) == 0:
            raise win32_error_from_saved_last_error()


@final
class LocalEmergencyHotkey:
    """비상 정지 hotkey의 등록·message loop·bounded cleanup을 소유합니다."""

    def __init__(
        self,
        gate: DesktopMutationGate,
        *,
        backend_factory: Callable[[], EmergencyHotkeyBackend] = Win32EmergencyHotkey,
        activation: Callable[[], None] | None = None,
    ) -> None:
        """공유 mutation gate와 thread-local Win32 backend factory를 고정합니다."""
        self._gate = gate
        self._backend_factory = backend_factory
        self._activation = activation or gate.activate_emergency_stop
        self._ready = Event()
        self._finished = Event()
        self._state_lock = Lock()
        self._backend: EmergencyHotkeyBackend | None = None
        self._thread: Thread | None = None
        self._error: OSError | ValueError | None = None
        self._failed = Event()
        self._started = False

    def failed(self) -> bool:
        """등록 뒤 message loop 또는 local audit 오류가 발생했는지 반환합니다."""
        return self._failed.is_set()

    def start(self) -> None:
        """등록 성공을 확인한 뒤에만 Worker transport 시작을 허용합니다."""
        with self._state_lock:
            if self._thread is not None:
                raise EmergencyHotkeyStartupTimeoutError
            thread = Thread(target=self._run, name="HermesEmergencyHotkey", daemon=True)
            self._thread = thread
            thread.start()
        if not self._ready.wait(_START_TIMEOUT_SECONDS):
            self.close()
            raise EmergencyHotkeyStartupTimeoutError
        if self._error is not None:
            self.close()
            raise self._error
        self._started = True

    def close(self) -> None:
        """WM_QUIT와 unregister를 사용해 thread를 제한 시간 안에 회수합니다."""
        with self._state_lock:
            backend, thread = self._backend, self._thread
        stop_error: OSError | None = None
        if backend is not None and thread is not None and thread.is_alive():
            try:
                backend.request_quit()
            except OSError as error:
                stop_error = error
        if thread is not None:
            thread.join(_STOP_TIMEOUT_SECONDS)
            if thread.is_alive():
                raise EmergencyHotkeyShutdownTimeoutError
        if stop_error is not None:
            raise stop_error
        if self._started and self._error is not None:
            raise self._error

    def _run(self) -> None:
        """Win32 API가 요구하는 단일 thread에서 hotkey lifecycle을 실행합니다."""
        backend: EmergencyHotkeyBackend | None = None
        registered = False
        try:
            backend = self._backend_factory()
            with self._state_lock:
                self._backend = backend
            backend.register()
            registered = True
            self._ready.set()
            while True:
                message = backend.next_message()
                if message.message_id == _WM_QUIT:
                    return
                if message.message_id == _WM_HOTKEY and message.hotkey_id == _HOTKEY_ID:
                    self._activation()
        except (OSError, ValueError) as error:
            with self._state_lock:
                self._error = error
            try:
                if registered:
                    self._gate.activate_emergency_stop()
            finally:
                self._failed.set()
                self._ready.set()
        finally:
            if registered and backend is not None:
                try:
                    backend.unregister()
                except OSError as error:
                    with self._state_lock:
                        self._error = error
            self._finished.set()
