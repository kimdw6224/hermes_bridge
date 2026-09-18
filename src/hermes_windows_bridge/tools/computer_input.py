"""Desktop mutation의 strict MCP schemas와 Worker dispatch adapter입니다."""

# pyright: reportAny=false

from __future__ import annotations

from datetime import UTC, datetime
from inspect import Parameter, Signature
from typing import TYPE_CHECKING, Annotated, ClassVar, Literal, Protocol, final, runtime_checkable
from uuid import UUID, uuid4

from mcp.types import CallToolResult, ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from hermes_windows_bridge.gateway.dispatcher import DispatchCall
from hermes_windows_bridge.worker.desktop_input import (
    SUPPORTED_KEYS,
    ClickPointer,
    DesktopMutation,
    DesktopMutationResult,
    Hotkey,
    InputGuard,
    InputPoint,
    MovePointer,
    PressKey,
    ScrollWheel,
    TypeText,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from hermes_windows_bridge.gateway.mcp_server import GatewayMCPServer
    from hermes_windows_bridge.ipc.protocol import JsonPayload


@runtime_checkable
class DesktopMutator(Protocol):
    """Worker가 제공하는 단일 직렬화 mutation capability입니다."""

    def mutate(self, mutation: DesktopMutation, guard: InputGuard) -> DesktopMutationResult:
        """검증된 guard와 mutation을 같은 session lock에서 실행합니다."""
        ...


class _DispatchResult(Protocol):
    @property
    def result(self) -> CallToolResult:
        """Bounded Worker 결과입니다."""
        ...


class ComputerDispatcher(Protocol):
    """입력 요청을 Worker IPC로 전달하는 gateway 경계입니다."""

    async def dispatch(self, call: DispatchCall) -> _DispatchResult:
        """Policy가 허용한 호출을 Worker로 전달합니다."""
        ...


class ComputerMutationInput(BaseModel):
    """모든 mutating computer tool의 공통 검증 경계입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)

    operation_id: UUID = Field(default_factory=uuid4)
    expected_process: Annotated[str, Field(min_length=1, max_length=260)] | None = None
    expected_window_title_contains: Annotated[str, Field(min_length=1, max_length=512)] | None = (
        None
    )
    state_token: Annotated[str, Field(pattern=r"^[0-9a-f]{16}$")] | None = None

    @field_validator("operation_id", mode="before")
    @classmethod
    def parse_operation_id(cls, value: JsonValue | UUID) -> UUID:
        """JSON UUID 문자열만 명시적으로 typed identifier로 변환합니다."""
        if isinstance(value, UUID):
            return value
        if not isinstance(value, str):
            raise InvalidComputerInputError
        return UUID(value)


class _CoordinateInput(ComputerMutationInput):
    x: Annotated[int, Field(ge=-100_000, le=100_000)]
    y: Annotated[int, Field(ge=-100_000, le=100_000)]
    coordinate_space: Literal["physical", "observation"] = "physical"

    @model_validator(mode="after")
    def observation_coordinates_need_token(self) -> _CoordinateInput:
        if self.coordinate_space == "observation" and (
            self.x < 0 or self.y < 0 or self.state_token is None
        ):
            raise InvalidComputerInputError
        return self


class ComputerClickInput(_CoordinateInput):
    """검증된 pointer click 경계입니다."""

    button: Literal["left", "middle", "right"] = "left"
    clicks: Annotated[int, Field(ge=1, le=3)] = 1


class ComputerMoveInput(_CoordinateInput):
    """검증된 pointer move 경계입니다."""


class ComputerScrollInput(ComputerMutationInput):
    """검증된 non-empty wheel delta 경계입니다."""

    delta_x: Annotated[int, Field(ge=-12_000, le=12_000)] = 0
    delta_y: Annotated[int, Field(ge=-12_000, le=12_000)] = 0

    @model_validator(mode="after")
    def delta_is_not_empty(self) -> ComputerScrollInput:
        """동작이 없는 scroll을 거부합니다."""
        if self.delta_x == 0 and self.delta_y == 0:
            raise InvalidComputerInputError
        return self


class ComputerTypeInput(ComputerMutationInput):
    """Win32 Unicode 입력에 literal로 전달할 문자열 경계입니다."""

    text: Annotated[str, Field(min_length=1, max_length=10_000)]


class ComputerHotkeyInput(ComputerMutationInput):
    """닫힌 key allowlist로 구성된 hotkey 경계입니다."""

    keys: Annotated[tuple[str, ...], Field(min_length=2, max_length=4, strict=False)]

    @field_validator("keys")
    @classmethod
    def keys_are_supported_and_unique(cls, keys: tuple[str, ...]) -> tuple[str, ...]:
        """Key 이름을 정규화하고 중복 또는 미지원 key를 거부합니다."""
        normalized = tuple(key.casefold() for key in keys)
        if len(set(normalized)) != len(normalized) or any(
            key not in SUPPORTED_KEYS for key in normalized
        ):
            raise InvalidComputerInputError
        return normalized


class ComputerKeyInput(ComputerMutationInput):
    """단일 named key 반복 입력 경계입니다."""

    key: Annotated[str, Field(min_length=1, max_length=16)]
    presses: Annotated[int, Field(ge=1, le=20)] = 1

    @field_validator("key")
    @classmethod
    def key_is_supported(cls, key: str) -> str:
        """단일 key를 정규화하고 allowlist로 제한합니다."""
        normalized = key.casefold()
        if normalized not in SUPPORTED_KEYS:
            raise InvalidComputerInputError
        return normalized


class ComputerActionResult(BaseModel):
    """원격 호출자가 분기할 수 있는 bounded mutation 결과입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)

    ok: bool
    error_code: (
        Literal["desktop_busy", "emergency_stop", "limitation", "state_conflict", "state_uncertain"]
        | None
    )
    physical_x: int | None = None
    physical_y: int | None = None
    before: tuple[int, int] | None = None
    observed: tuple[int, int] | None = None
    target: tuple[int, int] | None = None


class InvalidComputerInputError(ValueError):
    """Desktop input payload의 필드 조합이 안전하지 않습니다."""


def _guard(request: ComputerMutationInput) -> InputGuard:
    return InputGuard(
        expected_process=request.expected_process,
        expected_window_title_contains=request.expected_window_title_contains,
        state_token=request.state_token,
    )


def _handler_signature(model: type[ComputerMutationInput]) -> Signature:
    parameters = tuple(
        Parameter(
            name,
            kind=Parameter.KEYWORD_ONLY,
            default=None,
            annotation=JsonValue | UUID | tuple[str, ...],
        )
        for name in model.model_fields
    )
    return Signature(parameters=parameters)


@final
class ComputerInputTools:
    """Typed mutation을 Worker capability에만 전달합니다."""

    def __init__(self, worker: DesktopMutator | None) -> None:
        """Runtime-checkable Worker capability를 보관합니다."""
        self._worker = worker

    def _mutate(
        self, mutation: DesktopMutation, request: ComputerMutationInput
    ) -> ComputerActionResult:
        if not isinstance(self._worker, DesktopMutator):
            return ComputerActionResult(ok=False, error_code="limitation")
        result = self._worker.mutate(mutation, _guard(request))
        point = result.physical_point
        return ComputerActionResult(
            ok=result.ok,
            error_code=result.error_code,
            physical_x=point.x if point is not None else None,
            physical_y=point.y if point is not None else None,
            before=(result.before_point.x, result.before_point.y)
            if result.before_point is not None
            else None,
            observed=(result.observed_point.x, result.observed_point.y)
            if result.observed_point is not None
            else None,
            target=(result.target_point.x, result.target_point.y)
            if result.target_point is not None
            else None,
        )

    def computer_click(self, request: ComputerClickInput) -> ComputerActionResult:
        """검증된 click을 Worker에 전달합니다."""
        return self._mutate(
            ClickPointer(
                InputPoint(request.x, request.y, request.coordinate_space),
                request.button,
                request.clicks,
            ),
            request,
        )

    def computer_move(self, request: ComputerMoveInput) -> ComputerActionResult:
        """검증된 pointer move를 Worker에 전달합니다."""
        return self._mutate(
            MovePointer(InputPoint(request.x, request.y, request.coordinate_space)), request
        )

    def computer_scroll(self, request: ComputerScrollInput) -> ComputerActionResult:
        """검증된 wheel delta를 Worker에 전달합니다."""
        return self._mutate(ScrollWheel(request.delta_x, request.delta_y), request)

    def computer_type(self, request: ComputerTypeInput) -> ComputerActionResult:
        """검증된 literal text를 Worker에 전달합니다."""
        return self._mutate(TypeText(request.text), request)

    def computer_hotkey(self, request: ComputerHotkeyInput) -> ComputerActionResult:
        """검증된 key chord를 Worker에 전달합니다."""
        return self._mutate(Hotkey(request.keys), request)

    def computer_key(self, request: ComputerKeyInput) -> ComputerActionResult:
        """검증된 named key를 Worker에 전달합니다."""
        return self._mutate(PressKey(request.key, request.presses), request)


def register_computer_input_tools(server: GatewayMCPServer, dispatcher: ComputerDispatcher) -> None:
    """Reset surface 없이 여섯 mutating 도구만 MCP에 등록합니다."""
    annotations = ToolAnnotations(
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=False,
        open_world_hint=False,
    )

    def handler_for(
        name: str, model: type[ComputerMutationInput]
    ) -> Callable[..., Awaitable[CallToolResult]]:
        async def handler(**arguments: JsonValue) -> CallToolResult:
            request = model.model_validate(arguments)
            payload: JsonPayload = request.model_dump(mode="json", exclude={"operation_id"})
            outcome = await dispatcher.dispatch(
                DispatchCall(
                    operation_id=request.operation_id,
                    tool_name=name,
                    payload=payload,
                    requested_at=datetime.now(UTC),
                    timeout_ms=30_000,
                )
            )
            return outcome.result

        handler.__dict__["__signature__"] = _handler_signature(model)
        return handler

    models = (
        ComputerClickInput,
        ComputerMoveInput,
        ComputerScrollInput,
        ComputerTypeInput,
        ComputerHotkeyInput,
        ComputerKeyInput,
    )
    for model in models:
        name = f"computer_{model.__name__.removeprefix('Computer').removesuffix('Input').lower()}"
        server.add_closed_tool(
            handler_for(name, model),
            input_model=model,
            name=name,
            description=f"Perform serialized Worker-only {name.removeprefix('computer_')} input.",
            annotations=annotations,
            structured_output=False,
        )
