"""세션 desktop 직렬화 mutex와 persistent local emergency stop입니다."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from threading import Condition
from typing import TYPE_CHECKING, Literal, final, override
from uuid import uuid4

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

type DesktopErrorCode = Literal[
    "desktop_busy", "emergency_stop", "limitation", "state_conflict", "state_uncertain"
]


@dataclass(slots=True)
class DesktopMutationError(RuntimeError):
    """Desktop mutation의 공개 가능한 typed 거부입니다."""

    code: DesktopErrorCode
    before: tuple[int, int] | None = None
    observed: tuple[int, int] | None = None
    target: tuple[int, int] | None = None

    @override
    def __str__(self) -> str:
        return f"desktop mutation rejected: {self.code}"


class EmergencyStopActiveError(DesktopMutationError):
    """로컬 비상정지 때문에 입력이 차단됐습니다."""

    def __init__(self) -> None:
        """Stable public error code를 설정합니다."""
        super().__init__(code="emergency_stop")


class DesktopBusyError(DesktopMutationError):
    """Bounded lock 획득 시간이 지났습니다."""

    def __init__(self) -> None:
        """Stable public error code를 설정합니다."""
        super().__init__(code="desktop_busy")


class DesktopLimitationError(DesktopMutationError):
    """현재 desktop 또는 integrity 경계는 자동화할 수 없습니다."""

    def __init__(
        self,
        *,
        before: tuple[int, int] | None = None,
        observed: tuple[int, int] | None = None,
        target: tuple[int, int] | None = None,
    ) -> None:
        """Stable public error code를 설정합니다."""
        super().__init__(
            code="limitation", before=before, observed=observed, target=target
        )


class DesktopStateConflictError(DesktopMutationError):
    """관찰 뒤 foreground 또는 좌표 상태가 바뀌었습니다."""

    def __init__(self) -> None:
        """Stable public error code를 설정합니다."""
        super().__init__(code="state_conflict")


@dataclass(slots=True)
class DesktopStateUncertainError(RuntimeError):
    """보상 입력 뒤에도 pointer 위치를 확정할 수 없습니다."""

    before: tuple[int, int] | None
    observed: tuple[int, int] | None
    target: tuple[int, int] | None
    code: DesktopErrorCode = field(default="state_uncertain", init=False)

    @override
    def __str__(self) -> str:
        return "desktop mutation left pointer state uncertain"


@final
class RemoteInputState:
    """로컬 marker 존재를 fail-closed 비상정지 상태로 해석합니다."""

    def __init__(self, path: Path) -> None:
        """Fixed local marker path를 보관합니다."""
        self.path = path

    @property
    def enabled(self) -> bool:
        """Marker가 없을 때만 입력 허용을 반환합니다."""
        return not self.path.exists()

    def disable(self) -> None:
        """비민감 marker를 원자적으로 교체해 재시작 뒤에도 정지를 유지합니다."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{uuid4().hex}.tmp")
        try:
            with temporary.open("x", encoding="ascii", newline="\n") as stream:
                _ = stream.write('{"remote_input_enabled":false,"reason":"local_emergency_stop"}\n')
                stream.flush()
                os.fsync(stream.fileno())
            _ = temporary.replace(self.path)
        finally:
            temporary.unlink(missing_ok=True)


@final
class DesktopMutationGate:
    """한 Worker 세션의 모든 desktop mutation을 bounded하게 직렬화합니다."""

    def __init__(
        self,
        state: RemoteInputState,
        *,
        acquire_timeout_seconds: float = 5.0,
    ) -> None:
        """State와 bounded acquire timeout을 세션 gate에 결합합니다."""
        self.state = state
        self._timeout = acquire_timeout_seconds
        self._condition = Condition()
        self._occupied = False

    def run(self, validate: Callable[[], None], mutate: Callable[[], None]) -> None:
        """Lock 내부에서 상태 재검증 뒤 mutation을 한 번 실행합니다."""
        deadline = time.monotonic() + self._timeout
        with self._condition:
            while self._occupied:
                if not self.state.enabled:
                    raise EmergencyStopActiveError
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise DesktopBusyError
                _ = self._condition.wait(remaining)
            if not self.state.enabled:
                raise EmergencyStopActiveError
            self._occupied = True
        try:
            validate()
            if not self.state.enabled:
                raise EmergencyStopActiveError
            mutate()
        finally:
            with self._condition:
                self._occupied = False
                self._condition.notify_all()

    def activate_emergency_stop(self) -> None:
        """상태를 지속하고 현재 대기 중인 mutation을 즉시 깨웁니다."""
        self.state.disable()
        with self._condition:
            self._condition.notify_all()
