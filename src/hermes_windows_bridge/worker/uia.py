"""UI Automation의 typed domain과 desktop-gated Worker orchestration입니다."""

# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from time import monotonic
from typing import TYPE_CHECKING, Literal, Protocol, assert_never, final, override

from hermes_windows_bridge.worker.desktop_lock import DesktopMutationError, DesktopMutationGate

if TYPE_CHECKING:
    from collections.abc import Callable

type UiaErrorCode = Literal[
    "action_not_supported",
    "ambiguous_selector",
    "control_not_found",
    "desktop_busy",
    "elevated_target_not_automatable",
    "emergency_stop",
    "operation_cancelled",
    "operation_timed_out",
    "secure_desktop_not_automatable",
    "state_conflict",
    "worker_must_be_non_elevated",
]
DEFAULT_UIA_TIMEOUT_SECONDS = 10.0


class UiaAction(StrEnum):
    """UIA pattern으로만 수행하는 지원 동작입니다."""

    INVOKE = "invoke"
    SET_TEXT = "set_text"
    FOCUS = "focus"
    SELECT = "select"


@dataclass(frozen=True, slots=True)
class UiaQuery:
    """검증된 selector의 내부 표현입니다."""

    title: str | None = None
    title_contains: str | None = None
    automation_id: str | None = None
    control_type: str | None = None
    class_name: str | None = None
    window_title_contains: str | None = None


@dataclass(frozen=True, slots=True)
class UiaControl:
    """원문 value를 제외한 compact UIA control metadata입니다."""

    path: str
    title: str
    automation_id: str
    control_type: str
    class_name: str
    enabled: bool
    visible: bool
    process_id: int


@dataclass(frozen=True, slots=True)
class UiaTargetIdentity:
    """PID와 UIA identity를 함께 고정해 다른 element로의 재해석을 막습니다."""

    process_id: int
    native_handle: int
    runtime_id: tuple[int, ...]


class UiaResolvedTarget(Protocol):
    """Backend가 exact UIA element와 공개 metadata를 함께 고정합니다."""

    @property
    def identity(self) -> UiaTargetIdentity:
        """Resolve 시점에 고정된 identity입니다."""
        ...

    @property
    def control(self) -> UiaControl:
        """Resolve 시점의 bounded 공개 metadata입니다."""
        ...


def _never_cancelled() -> bool:
    return False


@dataclass(frozen=True, slots=True)
class UiaExecution:
    """UIA 열거와 mutation 사이에 공유하는 monotonic deadline/cancel token입니다."""

    deadline: float = field(default_factory=lambda: monotonic() + DEFAULT_UIA_TIMEOUT_SECONDS)
    cancelled: Callable[[], bool] = _never_cancelled

    def check(self) -> None:
        """새 UIA 호출을 시작하기 전에 cooperative 중단 상태를 확인합니다."""
        if self.cancelled():
            raise UiaOperationError(code="operation_cancelled")
        if monotonic() >= self.deadline:
            raise UiaOperationError(code="operation_timed_out")


@dataclass(frozen=True, slots=True)
class UiaFindResult:
    """의미 기반 탐색의 bounded 결과입니다."""

    ok: bool
    controls: tuple[UiaControl, ...] = ()
    error_code: UiaErrorCode | None = None


@dataclass(frozen=True, slots=True)
class UiaActionResult:
    """의미 기반 mutation의 typed 결과입니다."""

    ok: bool
    control: UiaControl | None = None
    error_code: UiaErrorCode | None = None


class UiaBackend(Protocol):
    """UIA 구현이 Worker에 제공하는 최소 capability입니다."""

    def resolve(
        self, query: UiaQuery, limit: int, execution: UiaExecution
    ) -> tuple[UiaResolvedTarget, ...]:
        """Bounded exact target과 identity를 한 번만 resolve합니다."""
        ...

    def revalidate(self, target: UiaResolvedTarget, execution: UiaExecution) -> bool:
        """Pinned identity가 아직 같은 available element인지 확인합니다."""
        ...

    def apply(
        self,
        target: UiaResolvedTarget,
        action: UiaAction,
        text: str | None,
        execution: UiaExecution,
    ) -> None:
        """Pinned element에 semantic UIA pattern을 실행합니다."""
        ...


@dataclass(frozen=True, slots=True)
class UiaSecurityProbes:
    """테스트 가능하게 분리한 desktop/integrity read-only probes입니다."""

    secure_desktop: Callable[[], bool]
    worker_elevated: Callable[[], bool]
    target_elevated: Callable[[int], bool]


@dataclass(frozen=True, slots=True)
class UiaOperationError(RuntimeError):
    """공개 가능한 stable UIA 오류입니다."""

    code: UiaErrorCode

    @override
    def __str__(self) -> str:
        return f"UI Automation rejected: {self.code}"


@final
class UiaWorker:
    """UIA 조회와 shared desktop gate의 semantic mutation을 제공합니다."""

    def __init__(
        self,
        backend: UiaBackend,
        mutation_gate: DesktopMutationGate,
        security: UiaSecurityProbes,
    ) -> None:
        """Bounded backend, shared desktop gate, integrity probes를 결합합니다."""
        self._backend = backend
        self._gate = mutation_gate
        self._security = security

    def _guard_worker(self) -> None:
        if self._security.secure_desktop():
            raise UiaOperationError(code="secure_desktop_not_automatable")
        if self._security.worker_elevated():
            raise UiaOperationError(code="worker_must_be_non_elevated")

    def _guard_target(self, target: UiaResolvedTarget) -> None:
        if self._security.target_elevated(target.identity.process_id):
            raise UiaOperationError(code="elevated_target_not_automatable")

    def _resolve_action_target(self, query: UiaQuery, execution: UiaExecution) -> UiaResolvedTarget:
        execution.check()
        self._guard_worker()
        targets = self._backend.resolve(query, 2, execution)
        if len(targets) != 1:
            code: UiaErrorCode = "control_not_found" if not targets else "ambiguous_selector"
            raise UiaOperationError(code=code)
        target = next(iter(targets))
        self._guard_target(target)
        return target

    @staticmethod
    def _desktop_error(exc: DesktopMutationError) -> UiaErrorCode:
        match exc.code:
            case "desktop_busy" | "emergency_stop" as code:
                return code
            case "limitation":
                return "action_not_supported"
            case "state_conflict" | "state_uncertain":
                return "state_conflict"
            case unreachable:
                assert_never(unreachable)

    def find(
        self, query: UiaQuery, limit: int, execution: UiaExecution | None = None
    ) -> UiaFindResult:
        """보안 경계를 확인한 뒤 read-only metadata를 조회합니다."""
        try:
            current = execution or UiaExecution()
            current.check()
            self._guard_worker()
            targets = self._backend.resolve(query, limit, current)
            for target in targets:
                self._guard_target(target)
            return UiaFindResult(ok=True, controls=tuple(target.control for target in targets))
        except UiaOperationError as exc:
            return UiaFindResult(ok=False, error_code=exc.code)

    def action(
        self,
        query: UiaQuery,
        action: UiaAction,
        text: str | None,
        execution: UiaExecution | None = None,
    ) -> UiaActionResult:
        """동일 desktop gate 안에서 target을 재검증하고 action을 실행합니다."""
        current = execution or UiaExecution()
        target: UiaResolvedTarget | None = None

        def resolve_and_guard() -> None:
            nonlocal target
            target = self._resolve_action_target(query, current)

        def revalidate_and_apply() -> None:
            current.check()
            if target is None or not self._backend.revalidate(target, current):
                raise UiaOperationError(code="state_conflict")
            current.check()
            self._backend.apply(target, action, text, current)

        try:
            self._gate.run(resolve_and_guard, revalidate_and_apply)
        except UiaOperationError as exc:
            return UiaActionResult(ok=False, error_code=exc.code)
        except DesktopMutationError as exc:
            return UiaActionResult(ok=False, error_code=self._desktop_error(exc))
        return UiaActionResult(ok=True, control=None if target is None else target.control)
