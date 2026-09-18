# pyright: reportAny=false
# pyright: reportMissingTypeStubs=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from time import monotonic
from typing import TYPE_CHECKING, Never, final
from uuid import UUID, uuid4

import anyio
import psutil
import pytest
import win32gui
import win32process
from pydantic import JsonValue, ValidationError
from pywinauto import Desktop

from hermes_windows_bridge.gateway.mcp_server import create_gateway_server
from hermes_windows_bridge.tools.uia import (
    UiaActionInput,
    UiaFindInput,
    UiaSelectorInput,
    UiaTools,
    register_uia_tools,
)
from hermes_windows_bridge.worker.desktop_lock import DesktopMutationGate, RemoteInputState
from hermes_windows_bridge.worker.uia import (
    UiaAction,
    UiaControl,
    UiaExecution,
    UiaQuery,
    UiaResolvedTarget,
    UiaSecurityProbes,
    UiaTargetIdentity,
    UiaWorker,
)
from hermes_windows_bridge.worker.uia_backend import create_uia_worker

if TYPE_CHECKING:
    from pathlib import Path

    from hermes_windows_bridge.gateway.dispatcher import DispatchCall

OPERATION_ID = UUID("00000000-0000-4000-8000-000000000015")


def _terminate_fixture_processes(title: str, launcher: subprocess.Popen[bytes]) -> None:
    pids = {launcher.pid}

    def collect(hwnd: int, _: None) -> None:
        if title.casefold() in win32gui.GetWindowText(hwnd).casefold():
            pids.add(int(win32process.GetWindowThreadProcessId(hwnd)[1]))

    win32gui.EnumWindows(collect, None)
    for pid in pids:
        try:
            process = psutil.Process(pid)
        except psutil.NoSuchProcess:
            continue
        process.terminate()
        try:
            _ = process.wait(timeout=3)
        except psutil.TimeoutExpired:
            process.kill()
            _ = process.wait(timeout=3)
    _ = launcher.wait(timeout=3)


@dataclass(frozen=True, slots=True)
class FakeTarget:
    identity: UiaTargetIdentity
    control: UiaControl


@final
class RecordingUiaBackend:
    def __init__(self, *, target_elevated: bool = False) -> None:
        self.target_elevated = target_elevated
        self.actions: list[tuple[UiaAction, str | None]] = []

    def resolve(
        self, query: UiaQuery, limit: int, execution: UiaExecution
    ) -> tuple[UiaResolvedTarget, ...]:
        del query
        execution.check()
        control = UiaControl(
            path="0/1",
            title="Document",
            automation_id="Text Area",
            control_type="Edit",
            class_name="RichEditD2DPT",
            enabled=True,
            visible=True,
            process_id=42,
        )
        return (FakeTarget(UiaTargetIdentity(42, 100, (1, 2)), control),)[:limit]

    def revalidate(self, target: UiaResolvedTarget, execution: UiaExecution) -> bool:
        execution.check()
        return target.identity == UiaTargetIdentity(42, 100, (1, 2))

    def apply(
        self,
        target: UiaResolvedTarget,
        action: UiaAction,
        text: str | None,
        execution: UiaExecution,
    ) -> None:
        del target
        execution.check()
        self.actions.append((action, text))


class UnusedDispatcher:
    async def dispatch(self, call: DispatchCall) -> Never:
        del call
        raise AssertionError


def _worker(tmp_path: Path, backend: RecordingUiaBackend) -> UiaWorker:
    return UiaWorker(
        backend=backend,
        mutation_gate=DesktopMutationGate(RemoteInputState(tmp_path / "stop")),
        security=UiaSecurityProbes(
            secure_desktop=lambda: False,
            worker_elevated=lambda: False,
            target_elevated=lambda _pid: backend.target_elevated,
        ),
    )


@pytest.mark.integration
class TestUiaBoundary:
    @pytest.mark.parametrize(
        ("model", "payload"),
        [
            (UiaSelectorInput, {}),
            (UiaSelectorInput, {"title": "x", "unknown": True}),
            (UiaFindInput, {"selector": {"title": "x"}, "max_results": 51}),
            (
                UiaActionInput,
                {"selector": {"control_type": "Edit"}, "action": "set_text"},
            ),
            (
                UiaActionInput,
                {"selector": {"control_type": "Button"}, "action": "invoke", "text": "x"},
            ),
            (
                UiaActionInput,
                {"selector": {"control_type": "Button"}, "action": "invoke"},
            ),
        ],
    )
    def test_malformed_selectors_and_actions_are_rejected(
        self,
        model: type[UiaSelectorInput | UiaFindInput | UiaActionInput],
        payload: dict[str, JsonValue],
    ) -> None:
        with pytest.raises(ValidationError):
            _ = model.model_validate(payload)

    def test_find_is_bounded_and_returns_semantic_fields(self, tmp_path: Path) -> None:
        tools = UiaTools(_worker(tmp_path, RecordingUiaBackend()))
        result = tools.uia_find(
            UiaFindInput(
                operation_id=OPERATION_ID,
                selector=UiaSelectorInput(
                    window_title_contains="Fixture Window", control_type="Edit"
                ),
                max_results=1,
            )
        )

        assert result.ok is True
        assert len(result.controls) == 1
        assert result.controls[0].automation_id == "Text Area"

    def test_action_prefers_semantic_backend_without_coordinate_fallback(
        self, tmp_path: Path
    ) -> None:
        backend = RecordingUiaBackend()
        tools = UiaTools(_worker(tmp_path, backend))

        result = tools.uia_action(
            UiaActionInput(
                operation_id=OPERATION_ID,
                selector=UiaSelectorInput(
                    window_title_contains="Fixture Window", control_type="Edit"
                ),
                action="set_text",
                text="literal {ENTER} $(whoami)",
            )
        )

        assert result.ok is True
        assert backend.actions == [(UiaAction.SET_TEXT, "literal {ENTER} $(whoami)")]

    def test_registered_tools_have_closed_bounded_schemas(self) -> None:
        server = create_gateway_server("test-token")
        register_uia_tools(server, UnusedDispatcher())

        listed = anyio.run(server.list_tools)
        tools = {tool.name: tool for tool in listed}

        assert {"uia_find", "uia_action"} <= tools.keys()
        assert tools["uia_find"].input_schema["additionalProperties"] is False
        assert tools["uia_action"].input_schema["additionalProperties"] is False


@pytest.mark.integration
class TestUiaTools:
    def test_elevated_target_reports_limitation(self, tmp_path: Path) -> None:
        backend = RecordingUiaBackend(target_elevated=True)
        tools = UiaTools(_worker(tmp_path, backend))

        result = tools.uia_action(
            UiaActionInput(
                operation_id=OPERATION_ID,
                selector=UiaSelectorInput(
                    window_title_contains="Fixture Window", control_type="Edit"
                ),
                action="set_text",
                text="blocked",
            )
        )

        assert result.ok is False
        assert result.error_code == "elevated_target_not_automatable"
        assert backend.actions == []

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows UI Automation")
    def test_notepad_find_and_type_via_uia(self, tmp_path: Path) -> None:
        fixture = tmp_path / f"hermes-uia-fixture-{uuid4().hex}.txt"
        _ = fixture.write_text("", encoding="utf-8")
        process = subprocess.Popen([f"{os.environ['WINDIR']}/System32/notepad.exe", str(fixture)])
        tools = UiaTools(create_uia_worker())
        selector = UiaSelectorInput(
            window_title_contains=fixture.name,
            control_type="Document",
        )
        try:
            deadline = monotonic() + 8
            found = None
            while monotonic() < deadline:
                found = tools.uia_find(UiaFindInput(selector=selector, max_results=5))
                if found.ok and found.controls:
                    break
            assert found is not None
            assert found.ok is True
            assert found.controls

            result = tools.uia_action(
                UiaActionInput(
                    selector=selector, action="set_text", text="Hermes semantic UIA fixture"
                )
            )

            assert result.ok is True
            assert result.controls
            windows = [
                window
                for window in Desktop(backend="uia").windows(
                    process=result.controls[0].process_id, visible_only=True
                )
                if fixture.name.casefold() in window.window_text().casefold()
            ]
            assert len(windows) == 1
            editor = next(
                control for control in windows[0].descendants()
                if control.element_info.control_type == "Document"
            )
            assert editor.iface_value.CurrentValue == "Hermes semantic UIA fixture"
            ambiguous = tools.uia_action(
                UiaActionInput(
                    selector=UiaSelectorInput(
                        window_title_contains=fixture.name,
                        control_type="Button",
                    ),
                    action="invoke",
                )
            )
            assert ambiguous.ok is False
            assert ambiguous.error_code == "ambiguous_selector"
        finally:
            _terminate_fixture_processes(fixture.name, process)
            shutil.rmtree(tmp_path, ignore_errors=True)
