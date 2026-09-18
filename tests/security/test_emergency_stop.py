# pyright: reportAny=false
# pyright: reportPrivateUsage=false

from __future__ import annotations

import json
import subprocess as sp
from threading import Event, Thread
from time import monotonic
from typing import TYPE_CHECKING, Never, final, override

import anyio
import pytest
from pydantic import ValidationError

from hermes_windows_bridge.gateway.mcp_server import create_gateway_server
from hermes_windows_bridge.tools.computer import ComputerTools, register_computer_tool
from hermes_windows_bridge.tools.computer_input import ComputerClickInput
from hermes_windows_bridge.worker.desktop import DesktopWorker
from hermes_windows_bridge.worker.desktop_input import (
    ClickPointer,
    DesktopInputBackend,
    DesktopMutation,
    DesktopRuntimeState,
    ForegroundState,
    InputGuard,
    InputPoint,
    MovePointer,
)
from hermes_windows_bridge.worker.desktop_lock import (
    DesktopBusyError,
    DesktopLimitationError,
    DesktopMutationGate,
    DesktopStateUncertainError,
    EmergencyStopActiveError,
    RemoteInputState,
)
from hermes_windows_bridge.worker.win32_input import _INPUT, Win32InputBackend

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from hermes_windows_bridge.gateway.dispatcher import DispatchCall


@final
class CountingBackend(DesktopInputBackend):
    """실제 injection 시도 횟수만 기록하는 mutable test backend입니다."""

    def __init__(self) -> None:
        self.calls = 0

    @override
    def send(self, mutation: DesktopMutation, boundary_check: Callable[[], None]) -> None:
        boundary_check()
        self.calls += 1


def _worker(tmp_path: Path, backend: DesktopInputBackend,
            runtime_probe: Callable[[], DesktopRuntimeState]) -> DesktopWorker:
    gate = DesktopMutationGate(RemoteInputState(tmp_path / "disabled"))
    return DesktopWorker(
        input_backend=backend, runtime_probe=runtime_probe,
        mutation_gate=gate, initialize_desktop=False,
    )


def _state(foreground: ForegroundState | None) -> DesktopRuntimeState:
    return DesktopRuntimeState(available=True, unlocked=True, foreground=foreground)


@pytest.mark.security
class TestEmergencyStop:
    def test_foreground_is_revalidated_at_action_boundary(self, tmp_path: Path) -> None:
        # Given: gate 검증 직후 foreground가 바뀌는 runtime probe입니다.
        expected = ForegroundState("Expected", "expected.exe", 1, (0, 0, 100, 100), 100)
        stale = ForegroundState("Expected", "expected.exe", 1, (0, 0, 100, 100), 101)
        states = iter((expected, stale))
        backend = CountingBackend()
        worker = _worker(tmp_path, backend, lambda: _state(next(states)))

        # When: 첫 검증 뒤 stale foreground로 바뀝니다.
        result = worker.mutate(
            MovePointer(InputPoint(10, 10)), InputGuard(expected_process="expected.exe")
        )

        # Then: action boundary가 충돌을 감지하여 injection은 0회입니다.
        assert result.error_code == "state_conflict"
        assert backend.calls == 0

    def test_partial_click_batch_restores_cursor_and_reports_receipt(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # Given: pointer 이동 뒤 button batch가 한 건만 삽입하고 실패합니다.
        backend = Win32InputBackend()
        before, target = InputPoint(10, 10), InputPoint(11, 10)
        cursor = [before]
        batches: list[int] = []

        def insert(events: list[_INPUT], boundary_check: Callable[[], None]) -> int:
            boundary_check()
            batches.append(len(events))
            cursor[0] = target if len(batches) < 3 else before
            return 1 if len(batches) == 2 else len(events)

        def cursor_after_input(_target: InputPoint) -> InputPoint:
            return cursor[0]

        monkeypatch.setattr(backend, "_cursor_position", lambda: cursor[0])
        monkeypatch.setattr(backend, "_insert", insert)
        monkeypatch.setattr(backend, "_wait_for_cursor", cursor_after_input)
        worker = _worker(tmp_path, backend, lambda: _state(None))

        # When: native button batch가 down event 하나만 삽입합니다.
        result = ComputerTools(worker).computer_click(ComputerClickInput(x=11, y=10))

        # Then: cursor는 복구되고 limitation receipt가 최종 상태를 증명합니다.
        assert (result.error_code, cursor[0], batches) == ("limitation", before, [1, 2, 2])
        assert (result.before, result.observed, result.target) == ((10, 10), (10, 10), (11, 10))

    def test_failed_pointer_compensation_reports_uncertain_coordinates(
        self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Given: 목표를 지나치고 복구 입력 뒤에도 원래 좌표가 아닌 상태입니다.
        backend = Win32InputBackend()
        observed = iter((InputPoint(12, 10), InputPoint(9, 10)))

        def discard(events: list[_INPUT], boundary_check: Callable[[], None]) -> int:
            boundary_check()
            return len(events)

        def wait_for_cursor(target: InputPoint) -> InputPoint:
            del target
            return next(observed)

        monkeypatch.setattr(backend, "_cursor_position", lambda: InputPoint(10, 10))
        monkeypatch.setattr(backend, "_insert", discard)
        monkeypatch.setattr(backend, "_wait_for_cursor", wait_for_cursor)

        # When/Then: limitation이 아니라 최종 좌표를 포함한 state_uncertain입니다.
        with pytest.raises(DesktopStateUncertainError) as captured:
            backend.send(MovePointer(InputPoint(11, 10)), lambda: None)
        assert captured.value.before == (10, 10)
        assert captured.value.observed == (9, 10)
        assert captured.value.target == (11, 10)

    def test_wrong_click_coordinate_never_sends_button_events(
        self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Given: click target을 지나친 뒤 원래 좌표로 복구되는 Win32 관찰입니다.
        backend = Win32InputBackend()
        inserted: list[int] = []
        observed = iter((InputPoint(12, 10), InputPoint(10, 10)))

        def insert(events: list[_INPUT], boundary_check: Callable[[], None]) -> int:
            boundary_check()
            inserted.append(len(events))
            return len(events)

        def wait_for_cursor(target: InputPoint) -> InputPoint:
            del target
            return next(observed)

        monkeypatch.setattr(backend, "_cursor_position", lambda: InputPoint(10, 10))
        monkeypatch.setattr(backend, "_insert", insert)
        monkeypatch.setattr(backend, "_wait_for_cursor", wait_for_cursor)

        # When/Then: move와 보상만 전송되고 button down/up batch는 전송되지 않습니다.
        with pytest.raises(DesktopLimitationError):
            backend.send(ClickPointer(InputPoint(11, 10)), lambda: None)
        assert inserted == [1, 1]

    def test_worker_returns_uncertain_coordinate_metadata(self, tmp_path: Path) -> None:
        # Given: 플랫폼 adapter가 복구 실패와 세 좌표를 보고합니다.
        class UncertainBackend(DesktopInputBackend):
            @override
            def send(self, mutation: DesktopMutation,
                     boundary_check: Callable[[], None]) -> None:
                boundary_check()
                raise DesktopStateUncertainError(before=(10, 10), observed=(9, 10), target=(11, 10))

        worker = _worker(tmp_path, UncertainBackend(), lambda: _state(None))

        # When: Worker mutation boundary가 typed platform error를 처리합니다.
        result = worker.mutate(MovePointer(InputPoint(11, 10)), InputGuard())

        # Then: 원격 결과에 before/observed/target이 손실 없이 남습니다.
        assert result.error_code == "state_uncertain"
        assert result.before_point == InputPoint(10, 10)
        assert result.observed_point == InputPoint(9, 10)
        assert result.target_point == InputPoint(11, 10)

    def test_foreground_change_before_button_batch_reports_pointer_and_sends_no_button(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # Given: verified pointer move 직후 HWND가 바뀌는 runtime입니다.
        expected = ForegroundState("Expected", "expected.exe", 1, (0, 0, 100, 100), 100)
        stale = ForegroundState("Expected", "expected.exe", 1, (0, 0, 100, 100), 101)
        current = [expected]
        before, target = InputPoint(10, 10), InputPoint(11, 10)
        cursor = [before]
        inserted_events: list[int] = []
        backend = Win32InputBackend()

        def interposed_insert(
            events: list[_INPUT], boundary_check: Callable[[], None]
        ) -> int:
            boundary_check()
            inserted_events.append(len(events))
            cursor[0] = target
            current[0] = stale
            return len(events)

        def cursor_after_input(_target: InputPoint) -> InputPoint:
            return cursor[0]

        monkeypatch.setattr(backend, "_insert", interposed_insert)
        monkeypatch.setattr(backend, "_cursor_position", lambda: cursor[0])
        monkeypatch.setattr(backend, "_wait_for_cursor", cursor_after_input)
        worker = _worker(tmp_path, backend, lambda: _state(current[0]))

        # When: click이 button insertion 경계에 도달합니다.
        result = worker.mutate(
            ClickPointer(target), InputGuard(expected_process="expected.exe")
        )

        # Then: button은 삽입되지 않고 이미 이동한 pointer는 receipt로 드러납니다.
        assert (result.error_code, inserted_events) == ("state_uncertain", [1])
        points = result.before_point, result.observed_point, result.target_point
        assert points == (InputPoint(10, 10), InputPoint(11, 10), InputPoint(11, 10))

    @pytest.mark.parametrize("offset", [0, 1, 1919, 3838, 3839])
    def test_absolute_coordinate_quantization_never_crosses_pixel_edge(self, offset: int) -> None:
        # Given/When: 3840px desktop의 경계와 내부 점을 absolute 좌표로 변환합니다.
        normalized = Win32InputBackend._absolute_coordinate(offset, 0, 3840)

        # Then: Windows endpoint 역양자화가 정확한 요청 pixel을 복원합니다.
        assert normalized * 3839 // 65_535 == offset

    def test_remote_reset_tool_is_absent(self) -> None:
        # Given: computer 도구가 등록된 MCP server입니다.
        class UnusedDispatcher:
            async def dispatch(self, call: DispatchCall) -> Never:
                raise AssertionError(call)

        server = create_gateway_server("test-token")
        register_computer_tool(server, UnusedDispatcher())

        # When: 공개 tool 목록을 조회합니다.
        names = {tool.name for tool in anyio.run(server.list_tools)}

        # Then: reset/re-enable operation은 공개되지 않습니다.
        assert "enable_remote_input" not in names
        assert "reset_emergency_stop" not in names
        assert "computer_click" in names

    def test_remote_payload_cannot_flip_disabled_state(self) -> None:
        # Given: 입력 payload에 로컬 상태 변경 필드를 위조합니다.
        payload = {"x": 1, "y": 2, "remote_input_enabled": True}

        # When/Then: frozen extra-forbid schema가 필드를 거부합니다.
        with pytest.raises(ValidationError):
            _ = ComputerClickInput.model_validate(payload)

    def test_emergency_stop_persists_and_cancels_queued_input(self, tmp_path: Path) -> None:
        # Given: 첫 transaction이 lock을 점유하고 두 번째가 대기합니다.
        state = RemoteInputState(tmp_path / "remote-input.disabled")
        gate = DesktopMutationGate(state, acquire_timeout_seconds=1.0)
        first_entered, release_first, second_done = Event(), Event(), Event()
        second_error: list[type[BaseException]] = []

        def first() -> None:
            def hold_lock() -> None:
                first_entered.set()
                assert release_first.wait(2)

            gate.run(lambda: None, hold_lock)

        def second() -> None:
            try:
                gate.run(lambda: None, lambda: None)
            except EmergencyStopActiveError as exc:
                second_error.append(type(exc))
            finally:
                second_done.set()

        first_thread, second_thread = Thread(target=first), Thread(target=second)
        first_thread.start()
        assert first_entered.wait(1)
        second_thread.start()

        # When: 로컬 비상정지를 활성화합니다.
        gate.activate_emergency_stop()

        # Then: marker가 지속되고 queued mutation이 실행되지 않습니다.
        assert state.enabled is False
        assert second_done.wait(1)
        assert second_error == [EmergencyStopActiveError]
        release_first.set()
        first_thread.join(2)
        second_thread.join(2)
        assert RemoteInputState(state.path).enabled is False

    def test_observation_remains_available_while_input_is_stopped(self, tmp_path: Path) -> None:
        # Given: persistent emergency marker가 존재합니다.
        state = RemoteInputState(tmp_path / "remote-input.disabled")
        state.disable()

        # When: read-only state를 조회합니다.
        enabled = state.enabled

        # Then: 조회 자체는 가능하고 false를 반환합니다.
        assert enabled is False

    def test_lock_wait_is_bounded_when_an_input_hangs(self, tmp_path: Path) -> None:
        # Given: 첫 transaction이 끝나지 않은 동안 짧은 timeout의 두 번째 요청입니다.
        gate = DesktopMutationGate(
            RemoteInputState(tmp_path / "remote-input.disabled"),
            acquire_timeout_seconds=0.05,
        )
        entered, release = Event(), Event()

        def hold() -> None:
            _ = release.wait(2)

        first = Thread(target=lambda: gate.run(entered.set, hold))
        first.start()
        assert entered.wait(1)

        # When: 두 번째 요청이 같은 gate를 획득하려 합니다.
        started = monotonic()
        with pytest.raises(DesktopBusyError):
            gate.run(lambda: None, lambda: None)
        elapsed = monotonic() - started

        # Then: 정해진 시간 안에 typed busy로 종료됩니다.
        assert elapsed < 0.5
        release.set()
        first.join(2)

    def test_repeated_mutations_remain_blocked_after_stop(self, tmp_path: Path) -> None:
        # Given: 비상정지 marker가 활성화된 gate입니다.
        gate = DesktopMutationGate(RemoteInputState(tmp_path / "remote-input.disabled"))
        gate.activate_emergency_stop()
        calls: list[str] = []

        # When/Then: 반복 시도도 mutation callback을 한 번도 실행하지 않습니다.
        for _ in range(3):
            with pytest.raises(EmergencyStopActiveError):
                gate.run(lambda: None, lambda: calls.append("sent"))
        assert calls == []

    def test_local_reset_script_what_if_is_read_only(self, tmp_path: Path) -> None:
        # Given/When: 격리된 local root로 reset 계획만 실행합니다.
        command = ["powershell", "-NoProfile", "-File",
                   "scripts/enable-remote-input.ps1", "-LocalDataRoot", str(tmp_path),
                   "-Apply", "-WhatIf", "-Json"]
        report = json.loads(sp.run(command, check=True, capture_output=True, text=True).stdout)

        # Then: marker나 외부 상태를 바꾸지 않은 machine-readable 계획입니다.
        assert (report["mode"], report["applied"], report["externalCalls"]) == ("what-if", False, 0)
        assert not (tmp_path / "HermesWindowsBridge" / "remote-input.disabled").exists()
