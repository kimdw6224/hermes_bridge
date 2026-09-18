# pyright: reportPrivateUsage=false

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from mcp.types import CallToolResult, TextContent
from pydantic import ValidationError

from hermes_windows_bridge.worker.desktop_input import (
    ClickPointer,
    Hotkey,
    InputPoint,
    MovePointer,
    PressKey,
    ScrollWheel,
    TypeText,
)
from hermes_windows_bridge.worker.desktop_lock import DesktopLimitationError
from hermes_windows_bridge.worker.windows_mcp import (
    WindowsMcpInputBackend,
    _ToolRequest,
    load_windows_mcp_executable,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


def test_user_settings_are_optional_and_invalid_settings_do_not_fall_back(tmp_path: Path) -> None:
    assert load_windows_mcp_executable(tmp_path) is None
    config = tmp_path / "windows-mcp.json"
    executable = tmp_path / "python.exe"
    _ = config.write_text(json.dumps({"python_executable": str(executable)}), encoding="utf-8")
    assert load_windows_mcp_executable(tmp_path) == executable
    _ = config.write_text('{"python_executable":"relative.exe"}', encoding="utf-8")
    with pytest.raises(ValidationError):
        _ = load_windows_mcp_executable(tmp_path)


def test_request_mapper_uses_only_the_pinned_input_tool_contract() -> None:
    backend = WindowsMcpInputBackend.__new__(WindowsMcpInputBackend)
    click = backend._request_for(ClickPointer(InputPoint(10, 20), "right", 2))
    move = backend._request_for(MovePointer(InputPoint(-4, 7)))
    scroll = backend._request_for(ScrollWheel(delta_y=-240))
    hotkey = backend._request_for(Hotkey(("ctrl", "a")))
    press = backend._request_for(PressKey("backspace"))

    assert click is not None
    assert move is not None
    assert scroll is not None
    assert hotkey is not None
    assert press is not None
    assert (click.name, click.arguments) == (
        "Click",
        {"loc": [10, 20], "button": "right", "clicks": 2},
    )
    assert (move.name, move.arguments) == ("Move", {"loc": [-4, 7], "drag": False})
    assert (scroll.name, scroll.arguments) == (
        "Scroll",
        {"type": "vertical", "direction": "down", "wheel_times": 2},
    )
    assert (hotkey.name, hotkey.arguments) == ("Shortcut", {"shortcut": "Ctrl+a"})
    assert (press.name, press.arguments) == ("Shortcut", {"shortcut": "Back"})


def test_type_uses_native_input_to_preserve_current_focus(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = WindowsMcpInputBackend.__new__(WindowsMcpInputBackend)
    backend._usable = True
    calls: list[str] = []

    class Native:
        def send(self, mutation: TypeText, check: Callable[[], None]) -> None:
            check()
            calls.append(mutation.text)

    def native_input(_backend: WindowsMcpInputBackend) -> Native:
        return Native()

    monkeypatch.setattr(WindowsMcpInputBackend, "_native_input", property(native_input))
    backend.send(TypeText("literal"), lambda: None)

    assert calls == ["literal"]


@pytest.mark.parametrize("mutation", [ScrollWheel(delta_x=120), ScrollWheel(delta_y=60)])
def test_inexact_scroll_routes_to_native_before_any_mcp_call(
    mutation: ScrollWheel, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = WindowsMcpInputBackend.__new__(WindowsMcpInputBackend)
    backend._usable = True
    calls: list[DesktopLimitationError] = []

    class Native:
        def send(self, _mutation: ScrollWheel, check: Callable[[], None]) -> None:
            check()
            calls.append(DesktopLimitationError())

    def native_input(_backend: WindowsMcpInputBackend) -> Native:
        return Native()

    monkeypatch.setattr(WindowsMcpInputBackend, "_native_input", property(native_input))
    backend.send(mutation, lambda: None)

    assert len(calls) == 1


def test_gate_runs_before_the_upstream_call() -> None:
    backend = WindowsMcpInputBackend.__new__(WindowsMcpInputBackend)
    backend._usable = True
    backend._portal = None
    backend._session = None
    def boundary_check() -> None:
        raise DesktopLimitationError

    with pytest.raises(DesktopLimitationError):
        backend.send(MovePointer(InputPoint(1, 2)), boundary_check)


def test_repeated_key_checks_the_gate_before_each_fake_upstream_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = WindowsMcpInputBackend.__new__(WindowsMcpInputBackend)
    backend._usable = True
    boundaries: list[int] = []
    requests: list[_ToolRequest] = []

    def fake_call(request: _ToolRequest) -> CallToolResult:
        requests.append(request)
        return CallToolResult(content=[TextContent(text=request.expected_response)])

    monkeypatch.setattr(backend, "_call", fake_call)
    backend.send(PressKey("enter", 3), lambda: boundaries.append(1))

    assert boundaries == [1, 1, 1]
    assert [request.arguments for request in requests] == [
        {"shortcut": "Enter"},
        {"shortcut": "Enter"},
        {"shortcut": "Enter"},
    ]


def test_plain_error_text_never_counts_as_success() -> None:
    result = CallToolResult(content=[TextContent(text="Error: input failed")])

    expected = "Moved the mouse pointer to (1,2)."
    assert WindowsMcpInputBackend._is_expected_success(result, expected) is False
