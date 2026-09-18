"""로그인 사용자 Worker의 메모리 전용 데스크톱 관찰입니다."""

# pyright: reportAny=false
# pyright: reportMissingModuleSource=false
# pyright: reportUnnecessaryComparison=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, final

import mss
from pydantic import BaseModel, ConfigDict

from hermes_windows_bridge.worker.desktop_capture import (
    ActiveWindow,
    Bounds,
    MonitorInfo,
    MonitorUnavailableError,
    MousePosition,
    ScreenshotCapture,
    active_window,
    bounded_png,
    dpi_scale,
    enable_per_monitor_v2_awareness,
    is_primary_monitor,
    logical_bounds,
)
from hermes_windows_bridge.worker.desktop_input import (
    DesktopInputBackend,
    DesktopInputController,
    DesktopMutation,
    DesktopMutationResult,
    DesktopRuntimeState,
    ForegroundState,
    InputGuard,
    ObservationTransform,
)
from hermes_windows_bridge.worker.desktop_input import (
    desktop_state_token as input_state_token,
)
from hermes_windows_bridge.worker.desktop_lock import (
    DesktopMutationGate,
    RemoteInputState,
)
from hermes_windows_bridge.worker.win32_input import Win32InputBackend

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = (
    "ActiveWindow",
    "Bounds",
    "MonitorInfo",
    "MonitorUnavailableError",
    "MousePosition",
    "ScreenshotCapture",
    "enable_per_monitor_v2_awareness",
    "is_primary_monitor",
)


@dataclass(frozen=True, slots=True)
class DesktopObservation:
    """한 시점의 데스크톱 메타데이터와 선택적 이미지입니다."""

    monitors: tuple[MonitorInfo, ...]
    mouse: MousePosition
    active_window: ActiveWindow | None
    screenshot: ScreenshotCapture | None
    state_token: str | None = None


@dataclass(frozen=True, slots=True)
class DesktopObserveRequest:
    """Worker가 실행할 검증된 관찰 요청입니다."""

    screenshot: bool = True
    monitor: int | None = None


class _MonitorSpec(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore", frozen=True)

    left: int
    top: int
    width: int
    height: int

    def bounds(self) -> Bounds:
        return Bounds(left=self.left, top=self.top, width=self.width, height=self.height)


def _foreground(active_window: ActiveWindow | None) -> ForegroundState | None:
    if active_window is None:
        return None
    bounds = active_window.bounds
    return ForegroundState(
        title=active_window.title,
        process_name=active_window.process_name,
        pid=active_window.pid,
        bounds=(bounds.left, bounds.top, bounds.width, bounds.height),
        handle=active_window.handle,
    )


def desktop_state_token(active_window: ActiveWindow | None) -> str:
    """Foreground identity를 원문 없는 짧은 재검증 token으로 만듭니다."""
    return input_state_token(_foreground(active_window))


def _runtime_state() -> DesktopRuntimeState:
    import ctypes  # noqa: PLC0415 - interactive desktop 검사는 Worker 내부에서만 수행합니다.
    from ctypes import wintypes  # noqa: PLC0415 - Windows FFI type입니다.

    user32 = ctypes.windll.user32
    user32.OpenInputDesktop.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    user32.OpenInputDesktop.restype = wintypes.HANDLE
    user32.SwitchDesktop.argtypes = (wintypes.HANDLE,)
    user32.SwitchDesktop.restype = wintypes.BOOL
    user32.CloseDesktop.argtypes = (wintypes.HANDLE,)
    user32.CloseDesktop.restype = wintypes.BOOL
    desktop = user32.OpenInputDesktop(0, False, 0x0100)  # noqa: FBT003 - Win32 positional API
    if not desktop:
        return DesktopRuntimeState(available=False, unlocked=False, foreground=None)
    try:
        unlocked = bool(user32.SwitchDesktop(desktop))
    finally:
        _ = user32.CloseDesktop(desktop)
    return DesktopRuntimeState(
        available=True,
        unlocked=unlocked,
        foreground=_foreground(active_window()),
    )


def _default_remote_input_state() -> RemoteInputState:
    local_app_data = os.environ.get("LOCALAPPDATA")
    root = Path(local_app_data) if local_app_data else Path.home() / "AppData" / "Local"
    return RemoteInputState(root / "HermesWindowsBridge" / "remote-input.disabled")


@final
class DesktopWorker:
    """현재 interactive desktop을 관찰하고 mutation을 직렬화하는 Worker adapter입니다."""

    def __init__(
        self,
        *,
        input_backend: DesktopInputBackend | None = None,
        runtime_probe: Callable[[], DesktopRuntimeState] = _runtime_state,
        mutation_gate: DesktopMutationGate | None = None,
        initialize_desktop: bool = True,
    ) -> None:
        """캡처보다 먼저 DPI awareness를 적용하고 세션 전용 mutation gate를 만듭니다."""
        self.dpi_awareness_enabled = (
            enable_per_monitor_v2_awareness() if initialize_desktop else False
        )
        self._input = DesktopInputController(
            input_backend or Win32InputBackend(),
            runtime_probe,
            mutation_gate or DesktopMutationGate(_default_remote_input_state()),
        )

    def observe(self, request: DesktopObserveRequest) -> DesktopObservation:
        """파일을 만들지 않고 가상 데스크톱 또는 단일 모니터를 관찰합니다."""
        import win32api  # noqa: PLC0415 - 마우스 좌표는 Worker만 읽습니다.

        with mss.MSS() as capture:
            specs = tuple(_MonitorSpec.model_validate(item) for item in capture.monitors[1:])
            monitors_list: list[MonitorInfo] = []
            for index, spec in enumerate(specs, start=1):
                bounds = spec.bounds()
                scale = dpi_scale(bounds)
                monitors_list.append(
                    MonitorInfo(
                        index=index,
                        is_primary=is_primary_monitor(bounds),
                        physical_bounds=bounds,
                        logical_bounds=logical_bounds(bounds, scale),
                        dpi_scale=scale,
                    )
                )
            screenshot: ScreenshotCapture | None = None
            if request.screenshot:
                selected = 0 if request.monitor is None else request.monitor
                if selected >= len(capture.monitors):
                    raise MonitorUnavailableError
                target = _MonitorSpec.model_validate(capture.monitors[selected])
                grabbed = capture.grab(capture.monitors[selected])
                png, rendered_size = bounded_png(grabbed.rgb, grabbed.size)
                screenshot = ScreenshotCapture(
                    png=png,
                    width=rendered_size[0],
                    height=rendered_size[1],
                    physical_bounds=target.bounds(),
                    scale_x=target.width / rendered_size[0],
                    scale_y=target.height / rendered_size[1],
                    sha256=hashlib.sha256(png).hexdigest(),
                )
        mouse_x, mouse_y = win32api.GetCursorPos()
        active_window_value = active_window()
        observation = DesktopObservation(
            monitors=tuple(monitors_list),
            mouse=MousePosition(x=mouse_x, y=mouse_y),
            active_window=active_window_value,
            screenshot=screenshot,
            state_token=desktop_state_token(active_window_value),
        )
        self.remember_observation(observation)
        return observation

    def remember_observation(self, observation: DesktopObservation) -> None:
        """가장 최근 observation만 좌표 역변환에 사용합니다."""
        screenshot = observation.screenshot
        transform = (
            ObservationTransform(
                token=observation.state_token,
                left=screenshot.physical_bounds.left,
                top=screenshot.physical_bounds.top,
                width=screenshot.width,
                height=screenshot.height,
                scale_x=screenshot.scale_x,
                scale_y=screenshot.scale_y,
            )
            if screenshot is not None and observation.state_token is not None
            else None
        )
        self._input.remember(transform)

    @property
    def remote_input_enabled(self) -> bool:
        """현재 persistent emergency marker 기준 입력 허용 상태입니다."""
        return self._input.remote_input_enabled

    def activate_emergency_stop(self) -> None:
        """로컬 hotkey/tray adapter가 호출할 단방향 비상정지 경계입니다."""
        self._input.activate_emergency_stop()

    def mutate(
        self,
        mutation: DesktopMutation,
        guard: InputGuard,
    ) -> DesktopMutationResult:
        """Lock 내부의 상태 검증과 좌표 변환을 input controller에 위임합니다."""
        return self._input.mutate(mutation, guard)
