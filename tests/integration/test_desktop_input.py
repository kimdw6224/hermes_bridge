# pyright: reportAny=false

from __future__ import annotations

import sys
from threading import Event, Lock, Thread
from typing import TYPE_CHECKING, final, override
from uuid import UUID

import pytest
from pydantic import BaseModel, ValidationError

from hermes_windows_bridge.tools.computer import ComputerTools
from hermes_windows_bridge.tools.computer_input import (
    ComputerClickInput,
    ComputerHotkeyInput,
    ComputerKeyInput,
    ComputerMoveInput,
    ComputerMutationInput,
    ComputerScrollInput,
    ComputerTypeInput,
)
from hermes_windows_bridge.worker.desktop import (
    ActiveWindow,
    Bounds,
    DesktopObservation,
    DesktopWorker,
    MousePosition,
    ScreenshotCapture,
    desktop_state_token,
    enable_per_monitor_v2_awareness,
)
from hermes_windows_bridge.worker.desktop_input import (
    DesktopInputBackend,
    DesktopMutation,
    DesktopRuntimeState,
    ForegroundState,
    Hotkey,
    InputGuard,
    InputPoint,
    MovePointer,
)
from hermes_windows_bridge.worker.desktop_lock import (
    DesktopMutationGate,
    RemoteInputState,
)
from hermes_windows_bridge.worker.win32_input import Win32InputBackend

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


OPERATION_ID = UUID("00000000-0000-4000-8000-000000000014")


@final
class RecordingBackend(DesktopInputBackend):
    """동시 실행 구간을 기록하기 위해 의도적으로 mutable한 test backend입니다."""

    def __init__(
        self, entered: Event, release_first: Event, records: list[tuple[str, str]],
        records_lock: Lock,
    ) -> None:
        self.entered: Event = entered
        self.release_first: Event = release_first
        self.records: list[tuple[str, str]] = records
        self.records_lock: Lock = records_lock

    @override
    def send(self, mutation: DesktopMutation, boundary_check: Callable[[], None]) -> None:
        boundary_check()
        name = type(mutation).__name__
        with self.records_lock:
            self.records.append(("start", name))
            position = len(self.records)
        self.entered.set()
        if position == 1:
            assert self.release_first.wait(2)
        with self.records_lock:
            self.records.append(("end", name))


def _runtime_state() -> DesktopRuntimeState:
    return DesktopRuntimeState(
        available=True,
        unlocked=True,
        foreground=ForegroundState(
            title="Fixture Window",
            pid=42,
            process_name="fixture.exe",
            bounds=(10, 20, 300, 200),
        ),
    )


def _active_window() -> ActiveWindow:
    return ActiveWindow(
        title="Fixture Window",
        pid=42,
        process_name="fixture.exe",
        bounds=Bounds(left=10, top=20, width=300, height=200),
    )


def _worker(tmp_path: Path, backend: DesktopInputBackend) -> DesktopWorker:
    return DesktopWorker(
        input_backend=backend,
        runtime_probe=_runtime_state,
        mutation_gate=DesktopMutationGate(RemoteInputState(tmp_path / "remote-input.disabled")),
        initialize_desktop=False,
    )


@pytest.mark.integration
class TestDesktopInputBoundary:
    def test_window_closed_after_input_is_uncertain_without_resending(self, tmp_path: Path) -> None:
        released = Event()
        released.set()
        backend = RecordingBackend(Event(), released, [], Lock())

        def probe() -> DesktopRuntimeState:
            if backend.records and backend.records[-1][0] == "end":
                return DesktopRuntimeState(available=True, unlocked=True, foreground=None)
            return _runtime_state()

        worker = DesktopWorker(
            input_backend=backend,
            runtime_probe=probe,
            mutation_gate=DesktopMutationGate(RemoteInputState(tmp_path / "disabled")),
            initialize_desktop=False,
        )
        result = worker.mutate(
            Hotkey(("ctrl", "enter")),
            InputGuard(expected_window_title_contains="Fixture Window"),
        )
        assert result.ok is False
        assert result.error_code == "state_uncertain"
        assert backend.records == [("start", "Hotkey"), ("end", "Hotkey")]

    @pytest.mark.parametrize(
        ("model", "payload"),
        [
            (ComputerClickInput, {"x": 1, "y": 2, "unexpected": True}),
            (ComputerMoveInput, {"x": -100_001, "y": 2}),
            (ComputerScrollInput, {"delta_y": 0}),
            (ComputerTypeInput, {"text": ""}),
            (ComputerHotkeyInput, {"keys": ["ctrl", "not-a-key"]}),
            (ComputerKeyInput, {"key": "not-a-key"}),
        ],
    )
    def test_malformed_input_is_rejected_at_frozen_boundary(
        self,
        model: type[BaseModel],
        payload: dict[str, int | str | bool | list[str]],
    ) -> None:
        # Given: 범위 밖 값 또는 알 수 없는 필드를 가진 remote payload입니다.
        # When/Then: 도구 경계에서 내부 Worker 호출 전에 거부합니다.
        with pytest.raises(ValidationError):
            _ = model.model_validate(payload)

    def test_literal_text_is_forwarded_without_shell_or_format_interpretation(
        self, tmp_path: Path
    ) -> None:
        # Given: shell metacharacter와 pywinauto escape 문법처럼 보이는 문자열입니다.
        backend = RecordingBackend(Event(), Event(), [], Lock())
        backend.release_first.set()
        tools = ComputerTools(_worker(tmp_path, backend))
        text = "$(whoami); {ENTER} && %PATH%"

        # When: computer_type을 실행합니다.
        result = tools.computer_type(ComputerTypeInput(operation_id=OPERATION_ID, text=text))

        # Then: 성공하며 backend에는 하나의 literal text mutation만 전달됩니다.
        assert result.ok is True
        assert backend.records == [("start", "TypeText"), ("end", "TypeText")]

    @pytest.mark.parametrize(
        ("method", "input_model", "expected_mutation"),
        [
            ("computer_click", ComputerClickInput(x=1, y=2), "ClickPointer"),
            ("computer_move", ComputerMoveInput(x=1, y=2), "MovePointer"),
            ("computer_scroll", ComputerScrollInput(delta_y=120), "ScrollWheel"),
            ("computer_type", ComputerTypeInput(text="literal"), "TypeText"),
            ("computer_hotkey", ComputerHotkeyInput(keys=("ctrl", "a")), "Hotkey"),
            ("computer_key", ComputerKeyInput(key="escape"), "PressKey"),
        ],
    )
    def test_every_input_tool_uses_the_single_worker_mutation_path(
        self,
        tmp_path: Path,
        method: str,
        input_model: ComputerMutationInput,
        expected_mutation: str,
    ) -> None:
        # Given: 모든 mutation을 기록하는 동일 Worker backend입니다.
        backend = RecordingBackend(Event(), Event(), [], Lock())
        backend.release_first.set()
        tools = ComputerTools(_worker(tmp_path, backend))

        # When: 각 공개 input method를 한 번 호출합니다.
        result = getattr(tools, method)(input_model)

        # Then: 정확히 하나의 typed mutation batch만 전달됩니다.
        assert result.ok is True
        assert backend.records == [("start", expected_mutation), ("end", expected_mutation)]


@pytest.mark.integration
class TestDesktopMutex:
    def test_concurrent_input_requests_do_not_interleave(self, tmp_path: Path) -> None:
        # Given: 첫 mutation을 명시적으로 멈추는 실제 thread 경쟁입니다.
        backend = RecordingBackend(Event(), Event(), [], Lock())
        tools = ComputerTools(_worker(tmp_path, backend))
        first = ComputerMoveInput(operation_id=OPERATION_ID, x=20, y=30)
        second = ComputerClickInput(operation_id=OPERATION_ID, x=20, y=30)
        results: list[bool] = []
        first_thread = Thread(target=lambda: results.append(tools.computer_move(first).ok))
        second_thread = Thread(target=lambda: results.append(tools.computer_click(second).ok))

        # When: 두 요청이 같은 세션 mutex를 경쟁합니다.
        first_thread.start()
        assert backend.entered.wait(1)
        second_thread.start()
        assert backend.records == [("start", "MovePointer")]
        backend.release_first.set()
        first_thread.join(2)
        second_thread.join(2)

        # Then: 두 mutation의 start/end 구간이 겹치지 않습니다.
        assert results == [True, True]
        assert backend.records == [
            ("start", "MovePointer"),
            ("end", "MovePointer"),
            ("start", "ClickPointer"),
            ("end", "ClickPointer"),
        ]

    def test_observation_coordinates_map_back_to_physical_desktop(self, tmp_path: Path) -> None:
        # Given: 2배 축소된 음수 원점 모니터 observation이 있습니다.
        backend = RecordingBackend(Event(), Event(), [], Lock())
        backend.release_first.set()
        worker = _worker(tmp_path, backend)
        active_window = _active_window()
        token = desktop_state_token(active_window)
        worker.remember_observation(
            DesktopObservation(
                monitors=(),
                mouse=MousePosition(x=0, y=0),
                active_window=active_window,
                screenshot=ScreenshotCapture(
                    png=b"png",
                    width=960,
                    height=540,
                    physical_bounds=Bounds(left=-1920, top=0, width=1920, height=1080),
                    scale_x=2.0,
                    scale_y=2.0,
                    sha256="0" * 64,
                ),
                state_token=token,
            )
        )

        # When: observation 좌표로 포인터를 이동합니다.
        result = worker.mutate(
            MovePointer(InputPoint(x=100, y=50, coordinate_space="observation")),
            InputGuard(state_token=token),
        )

        # Then: Task 13 transform을 적용한 물리 좌표가 backend에 전달됩니다.
        assert result.ok is True
        assert result.physical_point == InputPoint(x=-1720, y=100, coordinate_space="physical")

    def test_stale_foreground_is_state_conflict(self, tmp_path: Path) -> None:
        # Given: 현재 foreground와 다른 expected process입니다.
        backend = RecordingBackend(Event(), Event(), [], Lock())
        tools = ComputerTools(_worker(tmp_path, backend))

        # When: stale expectation을 가진 click을 요청합니다.
        result = tools.computer_click(
            ComputerClickInput(
                operation_id=OPERATION_ID,
                x=10,
                y=20,
                expected_process="other.exe",
            )
        )

        # Then: 입력은 보내지 않고 typed state_conflict를 반환합니다.
        assert result.ok is False
        assert result.error_code == "state_conflict"
        assert backend.records == []

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows SendInput")
    def test_real_cursor_input_is_reversible_and_stop_blocks_followup(self, tmp_path: Path) -> None:
        import win32api  # noqa: PLC0415 - 실제 Windows fixture에서만 사용합니다.

        # Given: 현재 cursor와 화면 안의 1px 이동 target을 기억합니다.
        assert enable_per_monitor_v2_awareness() is True
        before_x, before_y = win32api.GetCursorPos()
        width, left = win32api.GetSystemMetrics(78), win32api.GetSystemMetrics(76)
        target_x = before_x + 1 if before_x < left + width - 1 else before_x - 1
        target = InputPoint(target_x, before_y)
        state = RemoteInputState(tmp_path / "remote-input.disabled")
        backend = Win32InputBackend()
        worker = DesktopWorker(
            input_backend=backend,
            runtime_probe=_runtime_state,
            mutation_gate=DesktopMutationGate(state),
            initialize_desktop=False,
        )
        try:
            # When: 실제 SendInput 이동 후 비상정지 상태에서 두 번째 이동을 요청합니다.
            moved = worker.mutate(MovePointer(target), InputGuard())
            after_move = win32api.GetCursorPos()
            worker.activate_emergency_stop()
            blocked = worker.mutate(MovePointer(InputPoint(before_x, before_y)), InputGuard())
            after_block = win32api.GetCursorPos()

            # Then: 허용된 desktop은 정확히 이동하고, 제한된 host는 unchanged limitation입니다.
            if moved.ok:
                assert after_move == (target_x, before_y)
            else:
                assert moved.error_code in {"limitation", "state_uncertain"}
                receipt = moved.before_point, moved.observed_point, moved.target_point
                assert receipt == (InputPoint(before_x, before_y), InputPoint(*after_move), target)
                if moved.error_code == "limitation":
                    assert after_move == (before_x, before_y)
            assert blocked.error_code == "emergency_stop"
            assert after_block == after_move
        finally:
            backend.send(MovePointer(InputPoint(before_x, before_y)), lambda: None)
        after_restore = win32api.GetCursorPos()
        assert after_restore == (before_x, before_y), ((before_x, before_y), after_restore)
