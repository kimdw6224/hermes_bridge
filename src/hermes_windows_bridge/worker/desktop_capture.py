"""Task 13 read-only desktop capture data와 Windows adapters입니다."""

# pyright: reportAny=false
# pyright: reportMissingModuleSource=false
# pyright: reportUnknownMemberType=false

from __future__ import annotations

import base64
import io
import math
from dataclasses import dataclass
from typing import Final

import mss.tools
import psutil
from PIL import Image

MAX_SCREENSHOT_BASE64_BYTES: Final = 900_000
_PER_MONITOR_AWARE_V2: Final = -4
_DEFAULT_DPI: Final = 96


@dataclass(frozen=True, slots=True)
class Bounds:
    """화면 좌표계의 직사각형입니다."""

    left: int
    top: int
    width: int
    height: int


@dataclass(frozen=True, slots=True)
class MonitorInfo:
    """물리/논리 좌표를 함께 보존하는 모니터 정보입니다."""

    index: int
    is_primary: bool
    physical_bounds: Bounds
    logical_bounds: Bounds
    dpi_scale: float


@dataclass(frozen=True, slots=True)
class MousePosition:
    """가상 데스크톱의 물리 마우스 좌표입니다."""

    x: int
    y: int


@dataclass(frozen=True, slots=True)
class ActiveWindow:
    """현재 foreground 창의 최소 컨텍스트입니다."""

    title: str
    pid: int
    process_name: str | None
    bounds: Bounds
    handle: int | None = None


@dataclass(frozen=True, slots=True)
class ScreenshotCapture:
    """응답 수명 동안만 보관하는 PNG와 역좌표 변환 정보입니다."""

    png: bytes
    width: int
    height: int
    physical_bounds: Bounds
    scale_x: float
    scale_y: float
    sha256: str


class MonitorUnavailableError(IndexError):
    """요청한 실제 모니터 번호가 존재하지 않습니다."""


class ScreenshotEncodingError(RuntimeError):
    """mss가 메모리 PNG를 반환하지 않았습니다."""


def enable_per_monitor_v2_awareness() -> bool:
    """Worker 수명 동안 호출 thread를 PMv2로 유지하고 실제 context를 확인합니다."""
    import ctypes  # noqa: PLC0415 - Windows FFI를 Worker 경계에 격리합니다.

    user32 = ctypes.windll.user32
    context = ctypes.c_void_p(_PER_MONITOR_AWARE_V2)
    user32.SetProcessDpiAwarenessContext.argtypes = [ctypes.c_void_p]
    user32.SetProcessDpiAwarenessContext.restype = ctypes.c_bool
    user32.SetThreadDpiAwarenessContext.argtypes = [ctypes.c_void_p]
    user32.SetThreadDpiAwarenessContext.restype = ctypes.c_void_p
    user32.GetThreadDpiAwarenessContext.restype = ctypes.c_void_p
    user32.AreDpiAwarenessContextsEqual.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    user32.AreDpiAwarenessContextsEqual.restype = ctypes.c_bool
    _ = user32.SetProcessDpiAwarenessContext(context)
    current = user32.GetThreadDpiAwarenessContext()
    if user32.AreDpiAwarenessContextsEqual(current, context):
        return True
    _ = user32.SetThreadDpiAwarenessContext(context)
    effective = user32.GetThreadDpiAwarenessContext()
    return bool(user32.AreDpiAwarenessContextsEqual(effective, context))


def is_primary_monitor(bounds: Bounds) -> bool:
    """Windows primary monitor의 물리 원점 포함 여부로 MSS monitor를 식별합니다."""
    return (
        bounds.left <= 0 < bounds.left + bounds.width
        and bounds.top <= 0 < bounds.top + bounds.height
    )


def dpi_scale(bounds: Bounds) -> float:
    """Physical monitor의 effective DPI scale을 조회합니다."""
    import ctypes  # noqa: PLC0415 - Windows FFI를 Worker 경계에 격리합니다.

    import win32api  # noqa: PLC0415 - Windows 모니터 handle은 Worker만 조회합니다.

    for handle, _, rectangle in win32api.EnumDisplayMonitors():
        left, top, right, bottom = rectangle
        if (left, top, right - left, bottom - top) != (
            bounds.left,
            bounds.top,
            bounds.width,
            bounds.height,
        ):
            continue
        dpi_x = ctypes.c_uint(_DEFAULT_DPI)
        dpi_y = ctypes.c_uint(_DEFAULT_DPI)
        result = ctypes.windll.shcore.GetDpiForMonitor(
            int(handle), 0, ctypes.byref(dpi_x), ctypes.byref(dpi_y)
        )
        if result == 0:
            return max(dpi_x.value / _DEFAULT_DPI, 1.0)
    return 1.0


def logical_bounds(bounds: Bounds, scale: float) -> Bounds:
    """Physical bounds를 effective logical bounds로 변환합니다."""
    return Bounds(
        left=round(bounds.left / scale),
        top=round(bounds.top / scale),
        width=round(bounds.width / scale),
        height=round(bounds.height / scale),
    )


def active_window() -> ActiveWindow | None:
    """Foreground window의 bounded metadata만 조회합니다."""
    import win32gui  # noqa: PLC0415 - foreground 조회는 Worker 전용입니다.
    import win32process  # noqa: PLC0415 - foreground PID 조회는 Worker 전용입니다.

    handle = win32gui.GetForegroundWindow()
    if handle == 0:
        return None
    _, pid = win32process.GetWindowThreadProcessId(handle)
    left, top, right, bottom = win32gui.GetWindowRect(handle)
    try:
        process_name = psutil.Process(pid).name()
    except psutil.AccessDenied, psutil.NoSuchProcess:
        process_name = None
    return ActiveWindow(
        title=win32gui.GetWindowText(handle),
        pid=pid,
        process_name=process_name,
        bounds=Bounds(left=left, top=top, width=right - left, height=bottom - top),
        handle=handle,
    )


def bounded_png(rgb: bytes, size: tuple[int, int]) -> tuple[bytes, tuple[int, int]]:
    """PNG를 base64 응답 상한까지 메모리에서 반복 축소합니다."""
    encoded = mss.tools.to_png(rgb, size)
    if encoded is None:
        raise ScreenshotEncodingError
    width, height = size
    if len(base64.b64encode(encoded)) <= MAX_SCREENSHOT_BASE64_BYTES:
        return encoded, size
    with Image.frombytes("RGB", size, rgb) as source:
        current = source
        while True:
            ratio = math.sqrt(MAX_SCREENSHOT_BASE64_BYTES / len(base64.b64encode(encoded))) * 0.9
            width = max(1, round(width * min(ratio, 0.9)))
            height = max(1, round(height * min(ratio, 0.9)))
            resized = current.resize((width, height), Image.Resampling.LANCZOS)
            output = io.BytesIO()
            resized.save(output, format="PNG", compress_level=9)
            if current is not source:
                current.close()
            current = resized
            encoded = output.getvalue()
            if len(base64.b64encode(encoded)) <= MAX_SCREENSHOT_BASE64_BYTES:
                current.close()
                return encoded, (width, height)
