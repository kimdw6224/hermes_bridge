"""Worker 전용 User32 SendInput 플랫폼 adapter입니다."""

# pyright: reportAny=false
# pyright: reportUnannotatedClassAttribute=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

import ctypes
import time
from ctypes import wintypes
from typing import TYPE_CHECKING, Final, Never, assert_never, final

from hermes_windows_bridge.worker.desktop_input import (
    KEY_CODES,
    ClickPointer,
    DesktopMutation,
    Hotkey,
    InputPoint,
    MovePointer,
    PressKey,
    ScrollWheel,
    TypeText,
)
from hermes_windows_bridge.worker.desktop_lock import (
    DesktopLimitationError,
    DesktopMutationError,
    DesktopStateUncertainError,
)

if TYPE_CHECKING:
    from collections.abc import Callable

_KEYUP: Final = 0x0002
_UNICODE: Final = 0x0004
_MOVE: Final = 0x0001
_BUTTON_FLAGS: Final = {
    "left": (0x0002, 0x0004),
    "right": (0x0008, 0x0010),
    "middle": (0x0020, 0x0040),
}


class _MOUSEINPUT(ctypes.Structure):
    _fields_ = (
        ("dx", wintypes.LONG),
        ("dy", wintypes.LONG),
        ("data", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("extra", wintypes.WPARAM),
    )


class _KEYBDINPUT(ctypes.Structure):
    _fields_ = (
        ("key", wintypes.WORD),
        ("scan", wintypes.WORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("extra", wintypes.WPARAM),
    )


class _INPUTUNION(ctypes.Union):
    _fields_ = (("mi", _MOUSEINPUT), ("ki", _KEYBDINPUT))


class _INPUT(ctypes.Structure):
    _anonymous_ = ("data",)
    _fields_ = (("type", wintypes.DWORD), ("data", _INPUTUNION))


@final
class Win32InputBackend:
    """Worker 내부에서만 User32 SendInput을 호출합니다."""

    def send(self, mutation: DesktopMutation, boundary_check: Callable[[], None]) -> None:
        """Pointer postcondition을 보장하고 나머지는 하나의 batch로 전송합니다."""
        match mutation:
            case MovePointer(point=point):
                _ = self._move_verified(point, boundary_check)
            case ClickPointer(point=point, button=button, clicks=clicks):
                before = self._move_verified(point, boundary_check)
                down, up = _BUTTON_FLAGS[button]
                events = [
                    event
                    for _ in range(clicks)
                    for event in (self._mouse(down), self._mouse(up))
                ]
                try:
                    inserted = self._insert(events, boundary_check)
                except DesktopMutationError:
                    self._repair_failed_click(before, point, up, 0, boundary_check)
                if inserted != len(events):
                    self._repair_failed_click(before, point, up, inserted, boundary_check)
                try:
                    observed = self._wait_for_cursor(point)
                except DesktopMutationError:
                    self._compensate(before, None, point, boundary_check)
                if observed != point:
                    self._compensate(before, observed, point, boundary_check)
            case ScrollWheel() | TypeText() | Hotkey() | PressKey() as non_pointer:
                events = self._events(non_pointer)
                inserted = self._insert(events, boundary_check)
                if inserted == 0:
                    raise DesktopLimitationError
                if inserted != len(events):
                    raise DesktopStateUncertainError(before=None, observed=None, target=None)
            case unreachable:
                assert_never(unreachable)

    @staticmethod
    def _insert(events: list[_INPUT], boundary_check: Callable[[], None]) -> int:
        values = (_INPUT * len(events))(*events)
        send_input = ctypes.windll.user32.SendInput
        send_input.argtypes = (wintypes.UINT, ctypes.POINTER(_INPUT), ctypes.c_int)
        send_input.restype = wintypes.UINT
        boundary_check()
        return int(send_input(len(values), values, ctypes.sizeof(_INPUT)))

    def _events(self, mutation: ScrollWheel | TypeText | Hotkey | PressKey) -> list[_INPUT]:
        match mutation:
            case ScrollWheel(delta_x=x, delta_y=y):
                return ([self._mouse(0x1000, x)] if x else []) + (
                    [self._mouse(0x0800, y)] if y else []
                )
            case TypeText(text=text):
                return self._text_events(text)
            case Hotkey(keys=keys):
                return [self._key(KEY_CODES[key]) for key in keys] + [
                    self._key(KEY_CODES[key], flags=_KEYUP) for key in reversed(keys)
                ]
            case PressKey(key=key, presses=presses):
                return [
                    event
                    for _ in range(presses)
                    for event in (
                        self._key(KEY_CODES[key]),
                        self._key(KEY_CODES[key], flags=_KEYUP),
                    )
                ]
            case unreachable:
                assert_never(unreachable)

    def _text_events(self, text: str) -> list[_INPUT]:
        encoded = text.encode("utf-16-le", errors="surrogatepass")
        return [
            event
            for index in range(0, len(encoded), 2)
            for event in (
                self._key(
                    scan=int.from_bytes(encoded[index : index + 2], "little"),
                    flags=_UNICODE,
                ),
                self._key(
                    scan=int.from_bytes(encoded[index : index + 2], "little"),
                    flags=_UNICODE | _KEYUP,
                ),
            )
        ]

    @staticmethod
    def _mouse(flags: int, data: int = 0, x: int = 0, y: int = 0) -> _INPUT:
        return _INPUT(type=0, mi=_MOUSEINPUT(x, y, data, flags, 0, 0))

    def _move(self, point: InputPoint) -> _INPUT:
        user32 = ctypes.windll.user32
        left, top = int(user32.GetSystemMetrics(76)), int(user32.GetSystemMetrics(77))
        width, height = int(user32.GetSystemMetrics(78)), int(user32.GetSystemMetrics(79))
        x = self._absolute_coordinate(point.x, left, width)
        y = self._absolute_coordinate(point.y, top, height)
        return self._mouse(_MOVE | 0x4000 | 0x8000, x=x, y=y)

    @staticmethod
    def _absolute_coordinate(pixel: int, origin: int, span: int) -> int:
        """0..65535 endpoint mapping의 목표 pixel 하한을 올림으로 선택합니다."""
        offset = max(0, min(span - 1, pixel - origin))
        denominator = max(span - 1, 1)
        return min((offset * 65_535 + denominator - 1) // denominator, 65_535)

    def _move_verified(self, target: InputPoint, boundary_check: Callable[[], None]) -> InputPoint:
        """부정확한 pointer move를 원래 좌표로 보상한 뒤 typed failure로 만듭니다."""
        before = self._cursor_position()
        inserted = self._insert([self._move(target)], boundary_check)
        if inserted == 0:
            raise DesktopLimitationError
        if inserted != 1:
            raise DesktopStateUncertainError(
                (before.x, before.y), None, (target.x, target.y)
            )
        try:
            observed = self._wait_for_cursor(target)
        except DesktopMutationError:
            return self._compensate(before, None, target, boundary_check)
        if observed == target:
            return before
        return self._compensate(before, observed, target, boundary_check)

    def _repair_failed_click(
        self,
        before: InputPoint,
        target: InputPoint,
        button_up: int,
        inserted: int,
        boundary_check: Callable[[], None],
    ) -> Never:
        """실패한 click의 눌린 버튼과 pointer를 복구합니다."""
        try:
            observed = self._cursor_position()
        except DesktopMutationError:
            observed = None
        repair = [self._mouse(button_up)] if inserted % 2 else []
        repair.append(self._move(before))
        try:
            repaired = self._insert(repair, boundary_check)
            restored = self._wait_for_cursor(before)
        except DesktopMutationError as error:
            raise DesktopStateUncertainError(
                before=(before.x, before.y),
                observed=(observed.x, observed.y) if observed is not None else None,
                target=(target.x, target.y),
            ) from error
        if repaired == len(repair) and restored == before:
            raise DesktopLimitationError(
                before=(before.x, before.y), observed=(restored.x, restored.y),
                target=(target.x, target.y)
            )
        raise DesktopStateUncertainError(
            (before.x, before.y), (restored.x, restored.y), (target.x, target.y)
        )

    def _compensate(
        self,
        before: InputPoint,
        observed: InputPoint | None,
        target: InputPoint,
        boundary_check: Callable[[], None],
    ) -> Never:
        """원래 pointer 좌표를 복구하거나 uncertain metadata를 반환합니다."""
        try:
            repaired = self._insert([self._move(before)], boundary_check)
            restored = self._wait_for_cursor(before)
        except DesktopMutationError as error:
            raise DesktopStateUncertainError(
                before=(before.x, before.y),
                observed=(observed.x, observed.y) if observed is not None else None,
                target=(target.x, target.y),
            ) from error
        if repaired == 1 and restored == before:
            raise DesktopLimitationError(
                before=(before.x, before.y), observed=(restored.x, restored.y),
                target=(target.x, target.y)
            )
        raise DesktopStateUncertainError(
            (before.x, before.y), (restored.x, restored.y), (target.x, target.y)
        )

    def _wait_for_cursor(self, target: InputPoint) -> InputPoint:
        """SendInput queue가 pointer move를 적용할 때까지 bounded하게 기다립니다."""
        deadline = time.monotonic() + 0.1
        while time.monotonic() < deadline:
            current = self._cursor_position()
            if current == target:
                return current
            time.sleep(0.001)
        return self._cursor_position()

    @staticmethod
    def _cursor_position() -> InputPoint:
        """현재 physical cursor 좌표를 읽거나 limitation을 반환합니다."""
        user32 = ctypes.windll.user32
        user32.GetCursorPos.argtypes = (ctypes.POINTER(wintypes.POINT),)
        user32.GetCursorPos.restype = wintypes.BOOL
        current = wintypes.POINT()
        if not user32.GetCursorPos(ctypes.byref(current)):
            raise DesktopLimitationError
        return InputPoint(current.x, current.y)

    @staticmethod
    def _key(key: int = 0, *, scan: int = 0, flags: int = 0) -> _INPUT:
        return _INPUT(type=1, ki=_KEYBDINPUT(key, scan, flags, 0, 0))
