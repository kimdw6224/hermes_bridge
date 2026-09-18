"""TaskDialogIndirect FFI 경계를 local approval 수명주기에서 분리합니다."""

# pyright: reportAny=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false
# pyright: reportUnannotatedClassAttribute=false

from __future__ import annotations

import ctypes
from collections.abc import Callable
from ctypes import wintypes
from datetime import UTC, datetime
from typing import TYPE_CHECKING, final

if TYPE_CHECKING:
    from threading import Event

    from hermes_windows_bridge.worker.local_approval_types import (
        LocalApprovalRequest,
        LocalDialogDecision,
    )

from hermes_windows_bridge.worker.local_approval_types import LocalDialogDecision

_APPROVE_BUTTON: int = 1001
_DENY_BUTTON: int = 1002
_IDCANCEL: int = 2
_S_OK: int = 0
_TDF_ALLOW_DIALOG_CANCELLATION: int = 0x0008
_TDF_CALLBACK_TIMER: int = 0x0800
_TDN_TIMER: int = 4
_WM_CLOSE: int = 0x0010


type Clock = Callable[[], datetime]


@final
class Win32TaskDialogBackend:
    """TaskDialogIndirect callback으로만 닫히는 Windows local dialog backend입니다."""

    def __init__(self, *, clock: Clock = lambda: datetime.now(UTC)) -> None:
        """테스트 가능한 만료 clock을 보관합니다."""
        self._clock = clock

    def present(
        self, request: LocalApprovalRequest, cancellation: Event
    ) -> LocalDialogDecision:
        """사용자 click만 승인으로 해석하고 timeout/cancel이면 dialog를 닫습니다."""
        if cancellation.is_set() or self._clock() >= request.expires_at:
            return LocalDialogDecision.CANCEL
        try:
            return self._present_windows(request, cancellation)
        except (AttributeError, OSError):
            return LocalDialogDecision.CANCEL

    def _present_windows(
        self, request: LocalApprovalRequest, cancellation: Event
    ) -> LocalDialogDecision:
        class _TaskDialogButton(ctypes.Structure):
            _fields_ = [("iButton", ctypes.c_int), ("pszButtonText", wintypes.LPCWSTR)]

        callback_type = ctypes.WINFUNCTYPE(
            ctypes.c_long,
            wintypes.HWND,
            wintypes.UINT,
            wintypes.WPARAM,
            wintypes.LPARAM,
            ctypes.c_ssize_t,
        )

        class _TaskDialogConfig(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.UINT), ("hwndParent", wintypes.HWND),
                ("hInstance", wintypes.HINSTANCE), ("dwFlags", wintypes.UINT),
                ("dwCommonButtons", wintypes.UINT), ("pszWindowTitle", wintypes.LPCWSTR),
                ("pszMainIcon", wintypes.LPCWSTR),
                ("pszMainInstruction", wintypes.LPCWSTR), ("pszContent", wintypes.LPCWSTR),
                ("cButtons", wintypes.UINT), ("pButtons", ctypes.POINTER(_TaskDialogButton)),
                ("nDefaultButton", ctypes.c_int), ("cRadioButtons", wintypes.UINT),
                ("pRadioButtons", ctypes.c_void_p), ("nDefaultRadioButton", ctypes.c_int),
                ("pszVerificationText", wintypes.LPCWSTR),
                ("pszExpandedInformation", wintypes.LPCWSTR),
                ("pszExpandedControlText", wintypes.LPCWSTR),
                ("pszCollapsedControlText", wintypes.LPCWSTR),
                ("pszFooterIcon", wintypes.LPCWSTR), ("pszFooter", wintypes.LPCWSTR),
                ("pfCallback", callback_type), ("lpCallbackData", ctypes.c_ssize_t),
                ("cxWidth", wintypes.UINT),
            ]

        user32 = ctypes.windll.user32
        user32.PostMessageW.argtypes = (
            wintypes.HWND,
            wintypes.UINT,
            wintypes.WPARAM,
            wintypes.LPARAM,
        )
        user32.PostMessageW.restype = wintypes.BOOL
        task_dialog_indirect = ctypes.windll.comctl32.TaskDialogIndirect
        task_dialog_indirect.argtypes = (
            ctypes.POINTER(_TaskDialogConfig), ctypes.POINTER(ctypes.c_int),
            ctypes.c_void_p, ctypes.c_void_p,
        )
        task_dialog_indirect.restype = ctypes.c_long

        @callback_type
        def callback(
            hwnd: int, notification: int, _wparam: int, _lparam: int, _data: int
        ) -> int:
            should_close = cancellation.is_set() or self._clock() >= request.expires_at
            if notification == _TDN_TIMER and should_close:
                user32.PostMessageW(hwnd, _WM_CLOSE, 0, 0)
            return _S_OK

        buttons = (_TaskDialogButton * 2)(
            _TaskDialogButton(_APPROVE_BUTTON, "Approve once"),
            _TaskDialogButton(_DENY_BUTTON, "Deny"),
        )
        content = _display_summary(request) + (
            f"Operation: {request.operation_id}\nTool: {request.tool_name}\n"
            f"Frozen payload digest: {request.payload_digest}\n\n"
            "This decision authorizes exactly this request once."
        )
        config = _TaskDialogConfig(
            ctypes.sizeof(_TaskDialogConfig), None, None,
            _TDF_ALLOW_DIALOG_CANCELLATION | _TDF_CALLBACK_TIMER, 0,
            "Hermes Windows Bridge approval", None,
            "Approve a privileged Windows operation?", content, 2, buttons, _DENY_BUTTON,
            0, None, 0, None, None, None, None, None,
            "Timeout, close, or cancellation denies this request.", callback, 0, 0,
        )
        pressed = ctypes.c_int(_IDCANCEL)
        result = task_dialog_indirect(ctypes.byref(config), ctypes.byref(pressed), None, None)
        if result != _S_OK or cancellation.is_set() or self._clock() >= request.expires_at:
            return LocalDialogDecision.CANCEL
        if pressed.value == _APPROVE_BUTTON:
            return LocalDialogDecision.APPROVE
        return LocalDialogDecision.DENY


def _display_summary(request: LocalApprovalRequest) -> str:
    """Validated typed power summary가 있을 때만 사용자 표시 정보를 추가합니다."""
    summary = request.summary
    if summary is None:
        return ""
    return (
        f"Action: {summary.action}\nReason: {summary.reason}\n"
        f"Delay: {summary.delay_seconds} seconds\n"
    )
