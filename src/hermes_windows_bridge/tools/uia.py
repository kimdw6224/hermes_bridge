"""UI Automation 도구의 strict 외부 경계와 Worker IPC 등록입니다."""

from __future__ import annotations

from datetime import UTC, datetime
from inspect import Parameter, Signature
from typing import TYPE_CHECKING, Annotated, ClassVar, Literal, Protocol, final
from uuid import UUID, uuid4

from mcp.types import CallToolResult, ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from hermes_windows_bridge.gateway.dispatcher import DispatchCall
from hermes_windows_bridge.worker.uia import (
    UiaAction,
    UiaActionResult,
    UiaControl,
    UiaFindResult,
    UiaQuery,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from hermes_windows_bridge.gateway.mcp_server import GatewayMCPServer
    from hermes_windows_bridge.ipc.protocol import JsonPayload


class UiaSelectorInput(BaseModel):
    """작은 exact selector 집합만 허용하는 UIA parse 경계입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)

    title: Annotated[str, Field(min_length=1, max_length=512)] | None = None
    title_contains: Annotated[str, Field(min_length=1, max_length=512)] | None = None
    automation_id: Annotated[str, Field(min_length=1, max_length=260)] | None = None
    control_type: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    class_name: Annotated[str, Field(min_length=1, max_length=260)] | None = None
    window_title_contains: Annotated[str, Field(min_length=1, max_length=512)] | None = None

    @model_validator(mode="after")
    def has_semantic_key(self) -> UiaSelectorInput:
        """빈 selector가 foreground 전체를 무조건 선택하지 못하게 합니다."""
        if all(
            value is None
            for value in (
                self.title,
                self.title_contains,
                self.automation_id,
                self.control_type,
                self.class_name,
                self.window_title_contains,
            )
        ):
            raise InvalidUiaInputError
        return self

    def to_query(self) -> UiaQuery:
        """검증된 selector를 내부 immutable query로 변환합니다."""
        return UiaQuery(
            title=self.title,
            title_contains=self.title_contains,
            automation_id=self.automation_id,
            control_type=self.control_type,
            class_name=self.class_name,
            window_title_contains=self.window_title_contains,
        )


class UiaFindInput(BaseModel):
    """bounded semantic 탐색 요청입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)

    operation_id: UUID = Field(default_factory=uuid4)
    selector: UiaSelectorInput
    max_results: Annotated[int, Field(ge=1, le=50)] = 20


class UiaActionInput(BaseModel):
    """좌표 없는 UIA pattern mutation 요청입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)

    operation_id: UUID = Field(default_factory=uuid4)
    selector: UiaSelectorInput
    action: Literal["invoke", "set_text", "focus", "select"]
    text: Annotated[str, Field(min_length=1, max_length=10_000)] | None = None

    @model_validator(mode="after")
    def text_matches_action(self) -> UiaActionInput:
        """Action은 stable window scope와 동작에 맞는 text만 허용합니다."""
        if self.selector.window_title_contains is None:
            raise InvalidUiaInputError
        if (self.action == "set_text") != (self.text is not None):
            raise InvalidUiaInputError
        return self


class UiaControlPayload(BaseModel):
    """UIA value를 노출하지 않는 compact control metadata입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)

    path: Annotated[str, Field(pattern=r"^0(?:/[0-9]+)*$")]
    title: Annotated[str, Field(max_length=512)]
    automation_id: Annotated[str, Field(max_length=260)]
    control_type: Annotated[str, Field(max_length=128)]
    class_name: Annotated[str, Field(max_length=260)]
    enabled: bool
    visible: bool
    process_id: Annotated[int, Field(ge=0)]


class UiaToolResult(BaseModel):
    """호출자가 제한과 일반 실패를 구분할 수 있는 bounded 결과입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)

    ok: bool
    controls: Annotated[tuple[UiaControlPayload, ...], Field(max_length=50)] = ()
    error_code: (
        Literal[
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
        | None
    ) = None

    @model_validator(mode="after")
    def outcome_is_consistent(self) -> UiaToolResult:
        """성공과 stable error code가 동시에 존재하거나 함께 빠지지 않게 합니다."""
        if self.ok == (self.error_code is not None):
            raise InvalidUiaInputError
        return self


class InvalidUiaInputError(ValueError):
    """UIA selector/action payload 조합이 유효하지 않습니다."""


class UiaCapability(Protocol):
    """Interactive Worker가 제공해야 하는 UIA capability입니다."""

    def find(self, query: UiaQuery, limit: int) -> UiaFindResult:
        """의미 기반 control을 bounded하게 찾습니다."""
        ...

    def action(self, query: UiaQuery, action: UiaAction, text: str | None) -> UiaActionResult:
        """UIA pattern action을 하나 실행합니다."""
        ...


class _DispatchResult(Protocol):
    @property
    def result(self) -> CallToolResult: ...


class UiaDispatcher(Protocol):
    """Gateway dispatcher의 UIA 호출 seam입니다."""

    async def dispatch(self, call: DispatchCall) -> _DispatchResult:
        """검증된 UIA call을 Worker로 전달합니다."""
        ...


def _payload(control: UiaControl) -> UiaControlPayload:
    return UiaControlPayload(
        path=control.path,
        title=control.title,
        automation_id=control.automation_id,
        control_type=control.control_type,
        class_name=control.class_name,
        enabled=control.enabled,
        visible=control.visible,
        process_id=control.process_id,
    )


def _handler_signature(model: type[UiaFindInput | UiaActionInput]) -> Signature:
    """SDK가 평탄 MCP arguments를 검증하도록 model field signature를 노출합니다."""
    value_type = JsonValue | UUID
    parameters = tuple(
        Parameter(
            name,
            kind=Parameter.KEYWORD_ONLY,
            default=None,
            annotation=value_type,
        )
        for name in model.model_fields
    )
    return Signature(parameters=parameters)


@final
class UiaTools:
    """검증된 요청만 Interactive Worker capability에 전달합니다."""

    def __init__(self, worker: UiaCapability) -> None:
        """로그인 사용자 Worker capability만 보관합니다."""
        self._worker = worker

    def uia_find(self, request: UiaFindInput) -> UiaToolResult:
        """검증된 selector로 compact control metadata를 반환합니다."""
        result = self._worker.find(request.selector.to_query(), request.max_results)
        return UiaToolResult(
            ok=result.ok,
            controls=tuple(_payload(control) for control in result.controls),
            error_code=result.error_code,
        )

    def uia_action(self, request: UiaActionInput) -> UiaToolResult:
        """좌표 fallback 없이 semantic UIA action을 요청합니다."""
        result = self._worker.action(
            request.selector.to_query(), UiaAction(request.action), request.text
        )
        controls = () if result.control is None else (_payload(result.control),)
        return UiaToolResult(ok=result.ok, controls=controls, error_code=result.error_code)


def register_uia_tools(server: GatewayMCPServer, dispatcher: UiaDispatcher) -> None:
    """UIA find/action을 동일한 Worker dispatch 경계에 등록합니다."""

    def handler_for(
        name: Literal["uia_find", "uia_action"], model: type[UiaFindInput | UiaActionInput]
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

    find_annotations = ToolAnnotations(
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    )
    action_annotations = ToolAnnotations(
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=False,
        open_world_hint=False,
    )
    server.add_closed_tool(
        handler_for("uia_find", UiaFindInput),
        input_model=UiaFindInput,
        name="uia_find",
        description="Find bounded controls on the interactive desktop with semantic UIA selectors.",
        annotations=find_annotations,
        structured_output=False,
    )
    server.add_closed_tool(
        handler_for("uia_action", UiaActionInput),
        input_model=UiaActionInput,
        name="uia_action",
        description=(
            "Perform a serialized semantic UIA pattern action without privilege escalation."
        ),
        annotations=action_annotations,
        structured_output=False,
    )
