"""Interactive Worker의 typed desktop mutation과 User32 SendInput adapter입니다."""

# pyright: reportAny=false
# pyright: reportUnannotatedClassAttribute=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Literal, Protocol, assert_never, final

from hermes_windows_bridge.worker.desktop_lock import (
    DesktopErrorCode,
    DesktopLimitationError,
    DesktopMutationError,
    DesktopMutationGate,
    DesktopStateConflictError,
    DesktopStateUncertainError,
    EmergencyStopActiveError,
)

if TYPE_CHECKING:
    from collections.abc import Callable

type CoordinateSpace = Literal["physical", "observation"]
type MouseButton = Literal["left", "middle", "right"]

KEY_CODES: Final = {
    **dict(
        zip(
            ["backspace", "tab", "enter", "shift", "ctrl", "alt", "escape", "space"],
            (8, 9, 13, 16, 17, 18, 27, 32),
            strict=True,
        )
    ),
    **dict(
        zip(
            ["pageup", "pagedown", "end", "home", "left", "up", "right", "down", "delete", "win"],
            (33, 34, 35, 36, 37, 38, 39, 40, 46, 91),
            strict=True,
        )
    ),
    **{chr(code).lower(): code for code in range(65, 91)},
    **{str(number): 48 + number for number in range(10)},
    **{f"f{number}": 111 + number for number in range(1, 13)},
}
SUPPORTED_KEYS: Final = frozenset(KEY_CODES)


@dataclass(frozen=True, slots=True)
class InputPoint:
    """물리 또는 최근 observation 좌표계의 점입니다."""

    x: int
    y: int
    coordinate_space: CoordinateSpace = "physical"


@dataclass(frozen=True, slots=True)
class InputGuard:
    """Mutation 직전 재검증할 foreground 조건입니다."""

    expected_process: str | None = None
    expected_window_title_contains: str | None = None
    state_token: str | None = None


@dataclass(frozen=True, slots=True)
class ClickPointer:
    """버튼과 반복 횟수를 포함한 pointer click입니다."""

    point: InputPoint
    button: MouseButton = "left"
    clicks: int = 1


@dataclass(frozen=True, slots=True)
class MovePointer:
    """Pointer를 지정 좌표로 이동합니다."""

    point: InputPoint


@dataclass(frozen=True, slots=True)
class ScrollWheel:
    """수평/수직 wheel delta입니다."""

    delta_x: int = 0
    delta_y: int = 0


@dataclass(frozen=True, slots=True)
class TypeText:
    """명령 해석 없이 입력할 literal text입니다."""

    text: str


@dataclass(frozen=True, slots=True)
class Hotkey:
    """동시에 누른 뒤 역순으로 놓을 key chord입니다."""

    keys: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PressKey:
    """단일 named key와 반복 횟수입니다."""

    key: str
    presses: int = 1


type DesktopMutation = ClickPointer | MovePointer | ScrollWheel | TypeText | Hotkey | PressKey


@dataclass(frozen=True, slots=True)
class ForegroundState:
    """Mutation 직전에 확인한 foreground identity입니다."""

    title: str
    process_name: str | None
    pid: int
    bounds: tuple[int, int, int, int]
    handle: int | None = None


@dataclass(frozen=True, slots=True)
class DesktopRuntimeState:
    """Interactive desktop의 입력 가능 상태입니다."""

    available: bool
    unlocked: bool
    foreground: ForegroundState | None


@dataclass(frozen=True, slots=True)
class ObservationTransform:
    """최근 screenshot 좌표를 physical desktop으로 변환하는 정보입니다."""

    token: str
    left: int
    top: int
    width: int
    height: int
    scale_x: float
    scale_y: float


@dataclass(frozen=True, slots=True)
class DesktopMutationResult:
    """Win32 상세를 노출하지 않는 mutation 결과입니다."""

    ok: bool
    error_code: DesktopErrorCode | None = None
    physical_point: InputPoint | None = None
    before_point: InputPoint | None = None
    observed_point: InputPoint | None = None
    target_point: InputPoint | None = None


class DesktopInputBackend(Protocol):
    """하나의 mutation을 하나의 입력 batch로 보내는 Worker backend입니다."""

    def send(self, mutation: DesktopMutation, boundary_check: Callable[[], None]) -> None:
        """Mutation을 입력 queue에 보냅니다."""
        ...


def desktop_state_token(foreground: ForegroundState | None) -> str:
    """Foreground identity를 원문 없는 짧은 재검증 token으로 만듭니다."""
    material = "no-foreground-window" if foreground is None else repr(foreground)
    return hashlib.sha256(material.encode()).hexdigest()[:16]


@final
class DesktopInputController:
    """Lock 내부의 상태 재검증, 좌표 변환, 입력 전송을 결합합니다."""

    def __init__(
        self,
        backend: DesktopInputBackend,
        runtime_probe: Callable[[], DesktopRuntimeState],
        gate: DesktopMutationGate,
    ) -> None:
        """Session gate와 runtime probe를 하나의 controller로 묶습니다."""
        self._backend = backend
        self._probe = runtime_probe
        self._gate = gate
        self._transform: ObservationTransform | None = None

    @property
    def remote_input_enabled(self) -> bool:
        """Persistent emergency marker 기준 입력 허용 여부입니다."""
        return self._gate.state.enabled

    def remember(self, transform: ObservationTransform | None) -> None:
        """다음 observation-space mutation에 사용할 최신 변환만 보관합니다."""
        self._transform = transform

    def activate_emergency_stop(self) -> None:
        """Local adapter가 호출하는 persistent one-way stop입니다."""
        self._gate.activate_emergency_stop()

    def mutate(self, mutation: DesktopMutation, guard: InputGuard) -> DesktopMutationResult:
        """직렬화 lock 내부에서 조건을 재확인한 뒤 입력을 전송합니다."""
        point: InputPoint | None = None
        initial_foreground: ForegroundState | None = None
        validated = False

        def validate() -> None:
            nonlocal initial_foreground, validated
            initial_foreground = self._validate(
                guard, initial_foreground, enforce_identity=validated
            )
            validated = True

        def send() -> None:
            nonlocal point
            mapped = self._map(mutation, guard)
            match mapped:
                case ClickPointer(point=value) | MovePointer(point=value):
                    point = value
                case ScrollWheel() | TypeText() | Hotkey() | PressKey():
                    pass
                case unreachable:
                    assert_never(unreachable)
            def boundary_check() -> None:
                if not self._gate.state.enabled:
                    raise EmergencyStopActiveError
                validate()

            validate()
            self._backend.send(mapped, boundary_check)
            try:
                validate()
            except DesktopStateConflictError as error:
                # 입력 뒤 창 전환은 이미 수행된 동작을 재전송해도 된다는 뜻이 아닙니다.
                raise DesktopStateUncertainError(before=None, observed=None, target=None) from error

        try:
            self._gate.run(validate, send)
        except (DesktopMutationError, DesktopStateUncertainError) as error:
            return self._failure(error)
        return DesktopMutationResult(ok=True, physical_point=point)

    def _validate(
        self,
        guard: InputGuard,
        initial: ForegroundState | None,
        *,
        enforce_identity: bool,
    ) -> ForegroundState | None:
        state = self._probe()
        if not state.available or not state.unlocked:
            raise DesktopLimitationError
        foreground = state.foreground
        if enforce_identity and foreground != initial:
            raise DesktopStateConflictError
        if guard.expected_process is not None and (
            foreground is None
            or foreground.process_name is None
            or foreground.process_name.casefold() != guard.expected_process.casefold()
        ):
            raise DesktopStateConflictError
        if guard.expected_window_title_contains is not None and (
            foreground is None
            or guard.expected_window_title_contains.casefold() not in foreground.title.casefold()
        ):
            raise DesktopStateConflictError
        if guard.state_token is not None and guard.state_token != desktop_state_token(foreground):
            raise DesktopStateConflictError
        return foreground

    @staticmethod
    def _failure(error: DesktopMutationError | DesktopStateUncertainError) -> DesktopMutationResult:
        match error:
            case DesktopStateUncertainError(before=before, observed=observed, target=target):
                return DesktopMutationResult(
                    ok=False,
                    error_code=error.code,
                    before_point=InputPoint(*before) if before is not None else None,
                    observed_point=InputPoint(*observed) if observed is not None else None,
                    target_point=InputPoint(*target) if target is not None else None,
                )
            case DesktopMutationError(
                code=code, before=before, observed=observed, target=target
            ):
                return DesktopMutationResult(
                    ok=False,
                    error_code=code,
                    before_point=InputPoint(*before) if before is not None else None,
                    observed_point=InputPoint(*observed) if observed is not None else None,
                    target_point=InputPoint(*target) if target is not None else None,
                )
            case unreachable:
                assert_never(unreachable)

    def _map(self, mutation: DesktopMutation, guard: InputGuard) -> DesktopMutation:
        match mutation:
            case ClickPointer(point=point, button=button, clicks=clicks):
                return ClickPointer(self._point(point, guard), button, clicks)
            case MovePointer(point=point):
                return MovePointer(self._point(point, guard))
            case ScrollWheel() | TypeText() | Hotkey() | PressKey():
                return mutation
            case unreachable:
                assert_never(unreachable)

    def _point(self, point: InputPoint, guard: InputGuard) -> InputPoint:
        if point.coordinate_space == "physical":
            return point
        transform = self._transform
        if transform is None or guard.state_token != transform.token:
            raise DesktopStateConflictError
        if point.x < 0 or point.y < 0 or point.x >= transform.width or point.y >= transform.height:
            raise DesktopStateConflictError
        return InputPoint(
            transform.left + round(point.x * transform.scale_x),
            transform.top + round(point.y * transform.scale_y),
        )
