"""pywinauto UIA adapter와 Windows desktop/integrity probes입니다."""

# pyright: reportAny=false
# pyright: reportMissingTypeStubs=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false
# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

import ctypes
import os
import re
from collections import deque
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING, Final, assert_never, final

from pywinauto import Desktop
from pywinauto.controls.uia_controls import NoPatternInterfaceError
from pywinauto.findwindows import ElementNotFoundError
from pywinauto.timings import Timings
from pywintypes import com_error
from pywintypes import error as win32_error

from hermes_windows_bridge.worker.desktop_lock import DesktopMutationGate, RemoteInputState
from hermes_windows_bridge.worker.uia import (
    UiaAction,
    UiaControl,
    UiaExecution,
    UiaOperationError,
    UiaQuery,
    UiaResolvedTarget,
    UiaSecurityProbes,
    UiaWorker,
)
from hermes_windows_bridge.worker.uia_value_pattern import (
    PywinautoValueTarget,
    set_text_when_ready,
)

if TYPE_CHECKING:
    from pywinauto.controls.uiawrapper import UIAWrapper

MAX_TREE_CONTROLS: Final = 500
MAX_TREE_DEPTH: Final = 8
UIA_FIND_TIMEOUT_SECONDS: Final = 1.0


@final
class PywinautoUiaBackend:
    """Foreground 또는 named window UIA tree를 bounded BFS로 탐색합니다."""

    def __init__(self) -> None:
        """Worker process의 pywinauto 내부 대기 상한을 낮춥니다."""
        Timings.window_find_timeout = min(Timings.window_find_timeout, UIA_FIND_TIMEOUT_SECONDS)
        Timings.window_find_retry = min(Timings.window_find_retry, 0.1)
        Timings.after_setfocus_wait = min(Timings.after_setfocus_wait, 0.05)

    def _root(self, query: UiaQuery, execution: UiaExecution) -> UIAWrapper:
        import win32gui  # noqa: PLC0415 - interactive Worker에서만 foreground를 읽습니다.

        execution.check()
        desktop = Desktop(backend="uia")
        try:
            if query.window_title_contains is not None:
                matches: list[UIAWrapper] = []
                title_re = rf"(?i).*{re.escape(query.window_title_contains)}.*"
                for window in desktop.windows(title_re=title_re, visible_only=True)[
                    :MAX_TREE_CONTROLS
                ]:
                    execution.check()
                    matches.append(window)
                    if len(matches) > 1:
                        raise UiaOperationError(code="ambiguous_selector")
                if not matches:
                    raise UiaOperationError(code="control_not_found")
                return matches[0]
            handle = win32gui.GetForegroundWindow()
            if handle == 0:
                raise UiaOperationError(code="control_not_found")
            return desktop.window(handle=handle).wrapper_object()
        except ElementNotFoundError as exc:
            raise UiaOperationError(code="control_not_found") from exc
        except com_error as exc:
            raise UiaOperationError(code="elevated_target_not_automatable") from exc

    def target_pid(self, query: UiaQuery, execution: UiaExecution | None = None) -> int:
        """기존 probe API도 ambiguous root를 first-match 처리하지 않습니다."""
        return int(self._root(query, execution or UiaExecution()).process_id())

    def _matches(self, wrapper: UIAWrapper, query: UiaQuery) -> bool:
        info = wrapper.element_info
        title = str(wrapper.window_text())
        return (
            (query.title is None or title == query.title)
            and (
                query.title_contains is None or query.title_contains.casefold() in title.casefold()
            )
            and (query.automation_id is None or str(info.automation_id) == query.automation_id)
            and (query.control_type is None or str(info.control_type) == query.control_type)
            and (query.class_name is None or str(info.class_name) == query.class_name)
        )

    def _control(self, wrapper: UIAWrapper, path: str) -> UiaControl:
        info = wrapper.element_info
        return UiaControl(
            path=path,
            title=str(wrapper.window_text())[:512],
            automation_id=str(info.automation_id)[:260],
            control_type=str(info.control_type)[:128],
            class_name=str(info.class_name)[:260],
            enabled=bool(wrapper.is_enabled()),
            visible=bool(wrapper.is_visible()),
            process_id=int(wrapper.process_id()),
        )

    def _target(self, wrapper: UIAWrapper, path: str) -> PywinautoValueTarget:
        control = self._control(wrapper, path)
        return PywinautoValueTarget.from_wrapper(wrapper, control)

    def resolve(
        self, query: UiaQuery, limit: int, execution: UiaExecution
    ) -> tuple[UiaResolvedTarget, ...]:
        """Unique root 아래를 deadline-aware bounded BFS로 한 번 열거합니다."""
        queue = deque([(self._root(query, execution), "0", 0)])
        visited = 0
        matches: list[PywinautoValueTarget] = []
        while queue and visited < MAX_TREE_CONTROLS and len(matches) < limit:
            execution.check()
            wrapper, path, depth = queue.popleft()
            visited += 1
            if self._matches(wrapper, query):
                matches.append(self._target(wrapper, path))
            capacity = MAX_TREE_CONTROLS - visited - len(queue)
            if depth < MAX_TREE_DEPTH and capacity > 0:
                execution.check()
                for index, child in enumerate(wrapper.children()[:capacity]):
                    execution.check()
                    queue.append((child, f"{path}/{index}", depth + 1))
        return tuple(matches)

    def revalidate(self, target: UiaResolvedTarget, execution: UiaExecution) -> bool:
        """Pinned wrapper가 같은 PID/handle/runtime id로 여전히 보이는지 확인합니다."""
        execution.check()
        if not isinstance(target, PywinautoValueTarget):
            return False
        try:
            current = self._target(target.wrapper, target.control.path)
            return current.identity == target.identity and target.wrapper.is_visible()
        except ElementNotFoundError, com_error:
            return False

    def apply(
        self,
        target: UiaResolvedTarget,
        action: UiaAction,
        text: str | None,
        execution: UiaExecution,
    ) -> None:
        """재탐색 없이 pinned element의 UIA pattern만 실행합니다."""
        execution.check()
        if not isinstance(target, PywinautoValueTarget):
            raise UiaOperationError(code="state_conflict")
        try:
            match action:
                case UiaAction.INVOKE:
                    _ = target.wrapper.invoke()
                case UiaAction.SET_TEXT:
                    if text is None:
                        raise UiaOperationError(code="action_not_supported")
                    set_text_when_ready(target, text, execution)
                case UiaAction.FOCUS:
                    _ = target.wrapper.set_focus()
                case UiaAction.SELECT:
                    _ = target.wrapper.select()
                case unreachable:
                    assert_never(unreachable)
        except (AttributeError, NoPatternInterfaceError) as exc:
            raise UiaOperationError(code="action_not_supported") from exc
        except com_error as exc:
            raise UiaOperationError(code="elevated_target_not_automatable") from exc


def process_is_elevated(pid: int) -> bool:
    """Target token을 읽을 수 없으면 integrity 경계를 fail closed 처리합니다."""
    import win32api  # noqa: PLC0415 - token 검사를 Windows 경계에 격리합니다.
    import win32con  # noqa: PLC0415 - Win32 access mask입니다.
    import win32security  # noqa: PLC0415 - TokenElevation query입니다.

    try:
        process = win32api.OpenProcess(
            win32con.PROCESS_QUERY_LIMITED_INFORMATION,
            False,  # noqa: FBT003 - Win32 positional API입니다.
            pid,
        )
    except win32_error:
        return True
    try:
        try:
            token = win32security.OpenProcessToken(process, win32con.TOKEN_QUERY)
        except win32_error:
            return True
        try:
            return bool(win32security.GetTokenInformation(token, win32security.TokenElevation))
        finally:
            win32api.CloseHandle(token)
    finally:
        win32api.CloseHandle(process)


def current_process_is_elevated() -> bool:
    """Worker 자체 token이 elevated인지 확인합니다."""
    return process_is_elevated(os.getpid())


def secure_desktop_active() -> bool:
    """현재 input desktop이 전환 불가능하면 secure/locked로 처리합니다."""
    user32 = ctypes.windll.user32
    user32.OpenInputDesktop.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    user32.OpenInputDesktop.restype = wintypes.HANDLE
    user32.SwitchDesktop.argtypes = (wintypes.HANDLE,)
    user32.SwitchDesktop.restype = wintypes.BOOL
    user32.CloseDesktop.argtypes = (wintypes.HANDLE,)
    user32.CloseDesktop.restype = wintypes.BOOL
    desktop = user32.OpenInputDesktop(0, False, 0x0100)  # noqa: FBT003
    if not desktop:
        return True
    try:
        return not bool(user32.SwitchDesktop(desktop))
    finally:
        _ = user32.CloseDesktop(desktop)


def default_security_probes() -> UiaSecurityProbes:
    """Production Windows probes를 하나의 immutable dependency로 묶습니다."""
    return UiaSecurityProbes(
        secure_desktop=secure_desktop_active,
        worker_elevated=current_process_is_elevated,
        target_elevated=process_is_elevated,
    )


def create_uia_worker(mutation_gate: DesktopMutationGate | None = None) -> UiaWorker:
    """Production adapter를 주입된 shared gate 또는 기본 persistent gate와 묶습니다."""
    root = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
    return UiaWorker(
        backend=PywinautoUiaBackend(),
        mutation_gate=mutation_gate
        or DesktopMutationGate(
            RemoteInputState(root / "HermesWindowsBridge" / "remote-input.disabled")
        ),
        security=default_security_probes(),
    )
