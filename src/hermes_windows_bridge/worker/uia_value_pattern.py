"""Pinned UIA ValuePattern mutation의 readiness 확인을 분리합니다."""

# pyright: reportAny=false
# pyright: reportMissingTypeStubs=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pywinauto.controls.uia_controls import NoPatternInterfaceError
from pywinauto.findwindows import ElementNotFoundError
from pywintypes import com_error

from hermes_windows_bridge.worker.uia import (
    UiaControl,
    UiaExecution,
    UiaOperationError,
    UiaTargetIdentity,
)

if TYPE_CHECKING:
    from pywinauto.controls.uiawrapper import UIAWrapper


@dataclass(frozen=True, slots=True)
class PywinautoValueTarget:
    """값 변경 전후 동일성을 확인할 concrete UIA wrapper입니다."""

    identity: UiaTargetIdentity
    control: UiaControl
    wrapper: UIAWrapper

    @classmethod
    def from_wrapper(cls, wrapper: UIAWrapper, control: UiaControl) -> PywinautoValueTarget:
        """한 번 찾은 wrapper와 immutable UIA identity를 함께 고정합니다."""
        info = wrapper.element_info
        return cls(
            identity=UiaTargetIdentity(
                process_id=control.process_id,
                native_handle=int(info.handle or 0),
                runtime_id=tuple(int(part) for part in info.runtime_id),
            ),
            control=control,
            wrapper=wrapper,
        )


def _identity(wrapper: UIAWrapper) -> UiaTargetIdentity:
    """Focus 뒤에도 기존 wrapper가 같은 UIA element인지 판별합니다."""
    info = wrapper.element_info
    return UiaTargetIdentity(
        process_id=int(wrapper.process_id()),
        native_handle=int(info.handle or 0),
        runtime_id=tuple(int(part) for part in info.runtime_id),
    )


def set_text_when_ready(target: PywinautoValueTarget, text: str, execution: UiaExecution) -> None:
    """Focus 후 같은 ValuePattern이 literal 값을 게시할 때만 성공을 반환합니다."""
    try:
        _ = target.wrapper.set_focus()
        execution.check()
        if _identity(target.wrapper) != target.identity:
            raise UiaOperationError(code="state_conflict")
        value_pattern = target.wrapper.iface_value
        if value_pattern is None:
            raise UiaOperationError(code="action_not_supported")
        value_pattern.SetValue(text)
        while value_pattern.CurrentValue != text:
            execution.check()
    except ElementNotFoundError as exc:
        raise UiaOperationError(code="state_conflict") from exc
    except (AttributeError, NoPatternInterfaceError) as exc:
        raise UiaOperationError(code="action_not_supported") from exc
    except com_error as exc:
        raise UiaOperationError(code="elevated_target_not_automatable") from exc
