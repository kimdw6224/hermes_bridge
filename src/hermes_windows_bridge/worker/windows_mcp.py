"""Pinned Windows-MCP stdio input backend."""

# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

import os
from contextlib import AbstractContextManager, asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Literal, assert_never, final

import anyio
from anyio.from_thread import BlockingPortal, start_blocking_portal
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import DEFAULT_INHERITED_ENV_VARS, stdio_client
from mcp.types import CallToolResult, TextContent

from hermes_windows_bridge.models.config import WindowsMcpSettings
from hermes_windows_bridge.worker.desktop_input import (
    ClickPointer,
    DesktopMutation,
    Hotkey,
    MovePointer,
    PressKey,
    ScrollWheel,
    TypeText,
)
from hermes_windows_bridge.worker.desktop_lock import (
    DesktopLimitationError,
    DesktopStateUncertainError,
)
from hermes_windows_bridge.worker.win32_input import Win32InputBackend

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Callable
    from pathlib import Path
    from types import TracebackType

type ToolName = Literal["Click", "Move", "Scroll", "Type", "Shortcut"]

_CALL_TIMEOUT_SECONDS: Final = 10.0
_KEY_NAMES: Final = {
    "alt": "Alt", "backspace": "Back", "ctrl": "Ctrl", "delete": "Delete",
    "down": "Down", "end": "End", "enter": "Enter", "escape": "Esc",
    "home": "Home", "left": "Left", "pagedown": "PgDn", "pageup": "PgUp",
    "right": "Right", "shift": "Shift", "space": "Space", "tab": "Tab",
    "up": "Up", "win": "Win",
}


@dataclass(frozen=True, slots=True)
class _ToolRequest:
    name: ToolName
    arguments: dict[str, bool | int | str | list[int]]
    expected_response: str


def _child_environment() -> dict[str, str]:
    environment = {
        name: value for name in DEFAULT_INHERITED_ENV_VARS if (value := os.environ.get(name))
    }
    environment.update(
        {
            "ANONYMIZED_TELEMETRY": "false",
            "PYTHONUTF8": "1",
            "WINDOWS_MCP_DISABLE_FLASH": "1",
        }
    )
    return environment


@asynccontextmanager
async def _opened_session(parameters: StdioServerParameters) -> AsyncGenerator[ClientSession]:
    async with stdio_client(parameters) as streams, ClientSession(*streams) as session:
        with anyio.fail_after(_CALL_TIMEOUT_SECONDS):
            _ = await session.initialize()
        yield session


def load_windows_mcp_executable(user_data: Path) -> Path | None:
    """Worker 사용자 설정만 읽어 공유 서비스 설정과 실행 경로를 분리합니다."""
    try:
        payload = (user_data / "windows-mcp.json").read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    return WindowsMcpSettings.model_validate_json(payload).python_executable


@final
class WindowsMcpInputBackend:
    """Allowlisted Windows-MCP calls만 persistent stdio child에 전달합니다."""

    def __init__(self, executable: Path) -> None:
        """고정 Python executable로만 Windows-MCP를 시작할 준비를 합니다."""
        self._parameters = StdioServerParameters(
            command=str(executable),
            args=[
                "-m",
                "windows_mcp",
                "serve",
                "--transport",
                "stdio",
                "--tools",
                "Click,Move,Scroll,Shortcut",
            ],
            env=_child_environment(),
            encoding="utf-8",
        )
        self._portal_context: AbstractContextManager[BlockingPortal] | None = None
        self._portal: BlockingPortal | None = None
        self._session_context: AbstractContextManager[ClientSession] | None = None
        self._session: ClientSession | None = None
        self._usable = True

    def __enter__(self) -> WindowsMcpInputBackend:
        """Persistent stdio child와 initialized MCP session을 엽니다."""
        self._portal_context = start_blocking_portal(name="hermes-windows-mcp")
        self._portal = self._portal_context.__enter__()
        self._session_context = self._portal.wrap_async_context_manager(
            _opened_session(self._parameters)
        )
        try:
            self._session = self._session_context.__enter__()
        except OSError, RuntimeError, TimeoutError, BaseExceptionGroup:
            _ = self._close_contexts(None, None, None)
            raise
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Session 종료가 실패해도 portal thread를 반드시 정리합니다."""
        _ = self._close_contexts(exception_type, exception, traceback)

    def send(self, mutation: DesktopMutation, boundary_check: Callable[[], None]) -> None:
        """각 실제 dispatch 직전에 gate 검사를 실행하고 실패를 fail-closed 처리합니다."""
        if not self._usable:
            raise DesktopLimitationError
        match mutation:
            case PressKey(key=key, presses=presses):
                for _ in range(presses):
                    self._send_request(self._press_request(key), boundary_check)
                return
            case ScrollWheel() as scroll:
                request = self._request_for(scroll)
                if request is None:
                    self._native_input.send(scroll, boundary_check)
                    return
            case TypeText() as text:
                self._native_input.send(text, boundary_check)
                return
            case ClickPointer() | MovePointer() | Hotkey():
                request = self._request_for(mutation)
            case unreachable:
                assert_never(unreachable)
        if request is None:
            raise DesktopLimitationError
        self._send_request(request, boundary_check)

    def _send_request(self, request: _ToolRequest, boundary_check: Callable[[], None]) -> None:
        boundary_check()
        try:
            result = self._call(request)
        except OSError, RuntimeError, TimeoutError:
            self._invalidate()
            raise DesktopLimitationError from None
        if not self._is_expected_success(result, request.expected_response):
            self._invalidate()
            raise DesktopLimitationError

    @property
    def _native_input(self) -> Win32InputBackend:
        return Win32InputBackend()

    def _request_for(self, mutation: DesktopMutation) -> _ToolRequest | None:
        match mutation:
            case ClickPointer(point=point, button=button, clicks=clicks):
                expected = (
                    f"{self._click_description(clicks)} {button} clicked at ({point.x},{point.y})."
                )
                return _ToolRequest(
                    "Click",
                    {"loc": [point.x, point.y], "button": button, "clicks": clicks},
                    expected,
                )
            case MovePointer(point=point):
                return _ToolRequest(
                    "Move",
                    {"loc": [point.x, point.y], "drag": False},
                    f"Moved the mouse pointer to ({point.x},{point.y}).",
                )
            case ScrollWheel(delta_x=delta_x, delta_y=delta_y):
                return self._scroll_request(delta_x, delta_y)
            case Hotkey(keys=keys):
                shortcut = self._shortcut(keys)
                return _ToolRequest("Shortcut", {"shortcut": shortcut}, f"Pressed {shortcut}.")
            case PressKey(key=key):
                return self._press_request(key)
            case TypeText():
                raise DesktopLimitationError
            case unreachable:
                assert_never(unreachable)

    @staticmethod
    def _press_request(key: str) -> _ToolRequest:
        shortcut = WindowsMcpInputBackend._named_key(key)
        return _ToolRequest("Shortcut", {"shortcut": shortcut}, f"Pressed {shortcut}.")

    @staticmethod
    def _click_description(clicks: int) -> str:
        descriptions = ("", "Single", "Double", "None")
        if 1 <= clicks < len(descriptions):
            return descriptions[clicks]
        raise DesktopLimitationError

    @staticmethod
    def _scroll_request(delta_x: int, delta_y: int) -> _ToolRequest | None:
        if delta_x != 0 or delta_y % 120 != 0:
            return None
        if delta_y == 0:
            raise DesktopLimitationError
        direction: Literal["up", "down"] = "up" if delta_y > 0 else "down"
        wheel_times = abs(delta_y) // 120
        return _ToolRequest(
            "Scroll",
            {"type": "vertical", "direction": direction, "wheel_times": wheel_times},
            "",
        )

    @staticmethod
    def _shortcut(keys: tuple[str, ...]) -> str:
        return "+".join(WindowsMcpInputBackend._named_key(key) for key in keys)

    @staticmethod
    def _named_key(key: str) -> str:
        if len(key) == 1 and key.isascii() and key.isalnum():
            return key
        name = _KEY_NAMES.get(key)
        if name is None:
            raise DesktopLimitationError
        return name

    def _call(self, request: _ToolRequest) -> CallToolResult:
        if not self._usable or self._portal is None or self._session is None:
            raise RuntimeError
        return self._portal.call(self._call_async, request)

    async def _call_async(self, request: _ToolRequest) -> CallToolResult:
        session = self._session
        if session is None:
            raise RuntimeError
        with anyio.fail_after(_CALL_TIMEOUT_SECONDS):
            return await session.call_tool(
                request.name,
                request.arguments,
                read_timeout_seconds=_CALL_TIMEOUT_SECONDS,
            )

    @staticmethod
    def _is_expected_success(result: CallToolResult, expected: str) -> bool:
        if result.is_error or len(result.content) != 1:
            return False
        content = result.content[0]
        return isinstance(content, TextContent) and content.text == expected

    def _invalidate(self) -> None:
        self._usable = False
        try:
            _ = self._close_contexts(None, None, None)
        except OSError, RuntimeError, TimeoutError, BaseExceptionGroup:
            raise DesktopStateUncertainError(before=None, observed=None, target=None) from None

    def _close_contexts(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        session_context, self._session_context = self._session_context, None
        portal_context, self._portal_context = self._portal_context, None
        self._session, self._portal, self._usable = None, None, False
        try:
            return (
                session_context.__exit__(exception_type, exception, traceback)
                if session_context is not None
                else None
            )
        finally:
            if portal_context is not None:
                _ = portal_context.__exit__(exception_type, exception, traceback)
