"""로그인한 비승격 Worker 세션에서만 실행하는 전원 Win32 어댑터입니다."""

# pyright: reportAny=false

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from typing import Literal, Protocol, final, override

type SessionPowerOperation = Literal["system_lock", "system_sleep"]


class SessionPowerBackend(Protocol):
    """OS 호출을 좁은 capability로 제한하는 injected Win32 경계입니다."""

    def lock_workstation(self) -> bool:
        """LockWorkStation 시작 성공 여부를 반환합니다."""
        ...

    def set_suspend_state(
        self,
        *,
        hibernate: bool,
        force: bool,
        wakeup_events_disabled: bool,
    ) -> bool:
        """SetSuspendState 시작 성공 여부를 반환합니다."""
        ...


class WorkerPowerSession(Protocol):
    """이미 확인된 Worker process token/session 상태입니다."""

    @property
    def session_id(self) -> int:
        """현재 Worker process의 Windows session ID입니다."""
        ...

    @property
    def elevated(self) -> bool:
        """현재 Worker token이 elevated인지 반환합니다."""
        ...

    @property
    def active(self) -> bool:
        """현재 process가 interactive user desktop에 연결됐는지 반환합니다."""
        ...


@dataclass(frozen=True, slots=True)
class SessionPowerResult:
    """Win32가 요청 수락을 시작했음을 나타내는 Worker 결과입니다."""

    operation: SessionPowerOperation
    initiated: bool


@dataclass(frozen=True, slots=True)
class SessionPowerUnavailableError(PermissionError):
    """비대화형·승격·다른 session에서 전원 요청을 fail-closed 처리합니다."""

    reason: Literal["noninteractive_worker", "elevated_worker", "wrong_session"]

    @override
    def __str__(self) -> str:
        """원문 session 정보를 노출하지 않는 typed error를 반환합니다."""
        return self.reason


@dataclass(frozen=True, slots=True)
class SessionPowerApiError(OSError):
    """Win32 API가 전원 전환 요청 시작을 거부했습니다."""

    operation: SessionPowerOperation

    @override
    def __str__(self) -> str:
        """민감한 OS error detail 없이 typed operation을 반환합니다."""
        return f"session power API rejected: {self.operation}"


@final
class WindowsSessionPowerBackend:
    """공식 LockWorkStation/SetSuspendState 호출만 보유하는 production backend입니다."""

    def lock_workstation(self) -> bool:
        """User32 LockWorkStation을 호출해 현재 workstation lock을 시작합니다."""
        library = ctypes.WinDLL("user32", use_last_error=True)
        function = library.LockWorkStation
        function.argtypes = ()
        function.restype = wintypes.BOOL
        return bool(function())

    def set_suspend_state(
        self,
        *,
        hibernate: bool,
        force: bool,
        wakeup_events_disabled: bool,
    ) -> bool:
        """PowrProf SetSuspendState로 hibernate 없이 normal sleep을 시작합니다."""
        library = ctypes.WinDLL("powrprof", use_last_error=True)
        function = library.SetSuspendState
        function.argtypes = (wintypes.BOOL, wintypes.BOOL, wintypes.BOOL)
        function.restype = wintypes.BOOL
        return bool(function(hibernate, force, wakeup_events_disabled))


@final
class SessionPowerWorker:
    """하나의 verified interactive user session에 전원 mutation을 한정합니다."""

    def __init__(
        self,
        *,
        session: WorkerPowerSession,
        expected_session_id: int,
        backend: SessionPowerBackend | None = None,
    ) -> None:
        """Worker startup에서 확정한 session과 optional fake backend를 보관합니다."""
        self._session = session
        self._expected_session_id = expected_session_id
        self._backend = backend or WindowsSessionPowerBackend()

    def system_lock(self) -> SessionPowerResult:
        """검증된 user session에서만 LockWorkStation을 시작합니다."""
        self._require_interactive_non_elevated_session()
        if not self._backend.lock_workstation():
            raise SessionPowerApiError(operation="system_lock")
        return SessionPowerResult(operation="system_lock", initiated=True)

    def system_sleep(self) -> SessionPowerResult:
        """검증된 user session에서만 hibernate 없는 sleep 전환을 시작합니다."""
        self._require_interactive_non_elevated_session()
        if not self._backend.set_suspend_state(
            hibernate=False,
            force=False,
            wakeup_events_disabled=False,
        ):
            raise SessionPowerApiError(operation="system_sleep")
        return SessionPowerResult(operation="system_sleep", initiated=True)

    def _require_interactive_non_elevated_session(self) -> None:
        """Worker runtime invariant가 손상됐으면 OS boundary 전에 요청을 중단합니다."""
        if not self._session.active or self._session.session_id == 0:
            raise SessionPowerUnavailableError(reason="noninteractive_worker")
        if self._session.elevated:
            raise SessionPowerUnavailableError(reason="elevated_worker")
        if self._session.session_id != self._expected_session_id:
            raise SessionPowerUnavailableError(reason="wrong_session")
