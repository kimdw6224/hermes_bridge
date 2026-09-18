from __future__ import annotations

import ctypes
from threading import Event
from typing import TYPE_CHECKING, final

import pytest

from hermes_windows_bridge.worker.desktop_lock import DesktopMutationGate, RemoteInputState
from hermes_windows_bridge.worker.emergency_hotkey import (
    HotkeyMessage,
    LocalEmergencyHotkey,
    Win32EmergencyHotkey,
    win32_error_from_saved_last_error,
)

if TYPE_CHECKING:
    from pathlib import Path


def test_registration_failure_prevents_worker_hotkey_from_starting(tmp_path: Path) -> None:
    # Given: 다른 프로그램이 같은 global hotkey를 이미 점유합니다.
    class DeniedHotkey:
        def register(self) -> None:
            raise OSError(1409, "hotkey already registered")

        def next_message(self) -> HotkeyMessage:
            pytest.fail("registration failure must not enter message loop")

        def request_quit(self) -> None:
            pytest.fail("failed registration owns no quit target")

        def unregister(self) -> None:
            return None

    gate = DesktopMutationGate(RemoteInputState(tmp_path / "remote-input.disabled"))
    hotkey = LocalEmergencyHotkey(gate, backend_factory=DeniedHotkey)

    # When/Then: pipe server보다 먼저 fail-closed 됩니다.
    with pytest.raises(OSError, match="1409"):
        hotkey.start()
    hotkey.close()


def test_win32_failure_uses_ctypes_saved_last_error() -> None:
    # Given: use_last_error WinDLL call이 thread-local copy에 저장한 Win32 오류입니다.
    _ = ctypes.set_last_error(1409)

    # When: backend가 saved copy로 OSError를 만듭니다.
    error = win32_error_from_saved_last_error()

    # Then: GetLastError 재조회로 0이 되지 않고 충돌 코드가 보존됩니다.
    assert error.winerror == 1409


def test_hotkey_activation_persists_marker_and_wakes_queued_mutation(tmp_path: Path) -> None:
    # Given: message loop에 한 번의 hotkey와 종료를 전달할 fake backend입니다.
    @final
    class TriggeringHotkey:
        def __init__(self) -> None:
            self.registered: Event = Event()
            self.release: Event = Event()
            self.unregistered: Event = Event()
            self.messages: list[int] = [0x0312, 0x0012]

        def register(self) -> None:
            self.registered.set()

        def next_message(self) -> HotkeyMessage:
            assert self.release.wait(1)
            return HotkeyMessage(message_id=self.messages.pop(0), hotkey_id=0x4842)

        def request_quit(self) -> None:
            self.release.set()

        def unregister(self) -> None:
            self.unregistered.set()

    backend = TriggeringHotkey()
    state = RemoteInputState(tmp_path / "remote-input.disabled")
    gate = DesktopMutationGate(state)
    hotkey = LocalEmergencyHotkey(gate, backend_factory=lambda: backend)

    # When: local message loop가 hotkey를 받습니다.
    hotkey.start()
    backend.release.set()
    hotkey.close()

    # Then: marker는 영속되고 hotkey owner도 해제됩니다.
    assert state.enabled is False
    assert backend.unregistered.is_set()


def test_audit_failure_after_activation_keeps_marker_and_surfaces_failure(tmp_path: Path) -> None:
    # Given: local stop 뒤 audit 저장이 실패하는 message loop입니다.
    @final
    class FailingAuditHotkey:
        def __init__(self) -> None:
            self.release: Event = Event()

        def register(self) -> None:
            return None

        def next_message(self) -> HotkeyMessage:
            assert self.release.wait(1)
            return HotkeyMessage(message_id=0x0312, hotkey_id=0x4842)

        def request_quit(self) -> None:
            self.release.set()

        def unregister(self) -> None:
            return None

    state = RemoteInputState(tmp_path / "remote-input.disabled")
    backend = FailingAuditHotkey()

    def activation() -> None:
        state.disable()
        raise OSError(5, "worker audit write failed")

    hotkey = LocalEmergencyHotkey(
        DesktopMutationGate(state),
        backend_factory=lambda: backend,
        activation=activation,
    )

    # When/Then: marker는 유지되고 오류는 cleanup caller까지 전파됩니다.
    hotkey.start()
    backend.release.set()
    with pytest.raises(OSError, match="5"):
        hotkey.close()
    assert state.enabled is False
    assert hotkey.failed() is True


@pytest.mark.integration
def test_real_win32_hotkey_registers_and_unregisters_without_key_input(tmp_path: Path) -> None:
    # Given: 운영 marker와 분리된 임시 gate입니다.
    state = RemoteInputState(tmp_path / "remote-input.disabled")
    hotkey = LocalEmergencyHotkey(
        gate=DesktopMutationGate(state),
        backend_factory=lambda: Win32EmergencyHotkey(virtual_key=0x87),
    )

    # When: 실제 global hotkey를 등록한 뒤 입력 없이 정리합니다.
    hotkey.start()
    hotkey.close()

    # Then: 입력 marker를 만들지 않고 registration thread가 종료됩니다.
    assert state.enabled is True
