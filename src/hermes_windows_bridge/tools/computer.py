"""엄격한 computer_observe 입력과 Worker IPC/MCP 이미지 변환입니다."""

# pyright: reportAny=false

from __future__ import annotations

import base64
import binascii
import hashlib
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, ClassVar, Protocol, final, runtime_checkable
from uuid import UUID, uuid4

from mcp.types import CallToolResult, ContentBlock, ImageContent, TextContent, ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, model_validator

from hermes_windows_bridge.gateway.dispatcher import DispatchCall
from hermes_windows_bridge.models.policy import canonicalize_payload
from hermes_windows_bridge.tools.computer_input import (
    ComputerActionResult,
    ComputerClickInput,
    ComputerHotkeyInput,
    ComputerInputTools,
    ComputerKeyInput,
    ComputerMoveInput,
    ComputerScrollInput,
    ComputerTypeInput,
    DesktopMutator,
    register_computer_input_tools,
)
from hermes_windows_bridge.tools.uia import register_uia_tools
from hermes_windows_bridge.worker.desktop import (
    Bounds,
    DesktopObservation,
    DesktopObserveRequest,
)

if TYPE_CHECKING:
    from hermes_windows_bridge.gateway.mcp_server import GatewayMCPServer
    from hermes_windows_bridge.ipc.protocol import JsonPayload


@runtime_checkable
class DesktopObserver(Protocol):
    """로그인 사용자 Worker가 제공해야 하는 관찰 capability입니다."""

    def observe(self, request: DesktopObserveRequest) -> DesktopObservation:
        """현재 desktop snapshot을 반환합니다."""
        ...


class _DispatchResult(Protocol):
    @property
    def result(self) -> CallToolResult: ...


class _ComputerDispatcher(Protocol):
    async def dispatch(self, call: DispatchCall) -> _DispatchResult: ...


class ComputerObserveInput(BaseModel):
    """외부 computer_observe payload의 유일한 parse 경계입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    operation_id: UUID = Field(default_factory=uuid4)
    screenshot: bool = True
    monitor: Annotated[int, Field(ge=1)] | None = None
    uia: bool = False
    max_controls: Annotated[int, Field(ge=1, le=500)] = 150


class _BoundsPayload(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    left: int
    top: int
    width: int = Field(ge=1)
    height: int = Field(ge=1)


class _MonitorPayload(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    index: int = Field(ge=1)
    is_primary: bool
    physical_bounds: _BoundsPayload
    logical_bounds: _BoundsPayload
    dpi_scale: float = Field(gt=0)


class _MousePayload(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    x: int
    y: int


class _ActiveWindowPayload(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    title: str
    pid: int = Field(ge=0)
    process_name: str | None
    bounds: _BoundsPayload


class _ScreenshotPayload(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    image_data: str = Field(max_length=900_000, repr=False)
    mime_type: str = Field(pattern=r"^image/png$")
    width: int = Field(ge=1)
    height: int = Field(ge=1)
    physical_bounds: _BoundsPayload
    scale_x: float = Field(gt=0)
    scale_y: float = Field(gt=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def image_matches_digest(self) -> _ScreenshotPayload:
        """Worker 이미지가 canonical base64이고 선언한 digest와 일치하게 합니다."""
        try:
            body = base64.b64decode(self.image_data, validate=True)
        except binascii.Error as exc:
            raise InvalidScreenshotPayloadError from exc
        if hashlib.sha256(body).hexdigest() != self.sha256:
            raise InvalidScreenshotPayloadError
        return self


class _ObservationPayload(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    monitors: tuple[_MonitorPayload, ...]
    mouse: _MousePayload
    active_window: _ActiveWindowPayload | None
    screenshot: _ScreenshotPayload | None
    state_token: Annotated[str, Field(pattern=r"^[0-9a-f]{16}$")] | None = None


class InvalidScreenshotPayloadError(ValueError):
    """Worker 이미지의 base64 또는 digest가 응답과 일치하지 않습니다."""


def _bounds_payload(bounds: Bounds) -> _BoundsPayload:
    return _BoundsPayload(
        left=bounds.left, top=bounds.top, width=bounds.width, height=bounds.height
    )


def observation_to_ipc_payload(observation: DesktopObservation) -> JsonPayload:
    """Worker 결과를 bounded JSON IPC payload로 바꿉니다."""
    payload = _ObservationPayload(
        monitors=tuple(
            _MonitorPayload(
                index=monitor.index,
                is_primary=monitor.is_primary,
                physical_bounds=_bounds_payload(monitor.physical_bounds),
                logical_bounds=_bounds_payload(monitor.logical_bounds),
                dpi_scale=monitor.dpi_scale,
            )
            for monitor in observation.monitors
        ),
        mouse=_MousePayload(x=observation.mouse.x, y=observation.mouse.y),
        active_window=(
            _ActiveWindowPayload(
                title=observation.active_window.title,
                pid=observation.active_window.pid,
                process_name=observation.active_window.process_name,
                bounds=_bounds_payload(observation.active_window.bounds),
            )
            if observation.active_window is not None
            else None
        ),
        screenshot=(
            _ScreenshotPayload(
                image_data=base64.b64encode(observation.screenshot.png).decode("ascii"),
                mime_type="image/png",
                width=observation.screenshot.width,
                height=observation.screenshot.height,
                physical_bounds=_bounds_payload(observation.screenshot.physical_bounds),
                scale_x=observation.screenshot.scale_x,
                scale_y=observation.screenshot.scale_y,
                sha256=observation.screenshot.sha256,
            )
            if observation.screenshot is not None
            else None
        ),
        state_token=observation.state_token,
    )
    return payload.model_dump(mode="json")


@final
class ComputerTools:
    """Gateway/Helper에서 GUI를 읽지 않고 Worker 구현만 호출합니다."""

    def __init__(self, worker: DesktopObserver | DesktopMutator) -> None:
        """실제 GUI 접근 capability를 가진 Worker만 보관합니다."""
        self._worker = worker
        self._input = ComputerInputTools(worker if isinstance(worker, DesktopMutator) else None)

    def computer_observe(self, request: ComputerObserveInput) -> DesktopObservation:
        """검증된 관찰 옵션만 현재 interactive Worker로 전달합니다."""
        if not isinstance(self._worker, DesktopObserver):
            raise DesktopCapabilityUnavailableError
        return self._worker.observe(
            DesktopObserveRequest(screenshot=request.screenshot, monitor=request.monitor)
        )

    def computer_click(self, request: ComputerClickInput) -> ComputerActionResult:
        """검증된 pointer click을 Worker에 전달합니다."""
        return self._input.computer_click(request)

    def computer_move(self, request: ComputerMoveInput) -> ComputerActionResult:
        """검증된 pointer move를 Worker에 전달합니다."""
        return self._input.computer_move(request)

    def computer_scroll(self, request: ComputerScrollInput) -> ComputerActionResult:
        """검증된 wheel delta를 Worker에 전달합니다."""
        return self._input.computer_scroll(request)

    def computer_type(self, request: ComputerTypeInput) -> ComputerActionResult:
        """검증된 text를 literal Unicode 입력으로 전달합니다."""
        return self._input.computer_type(request)

    def computer_hotkey(self, request: ComputerHotkeyInput) -> ComputerActionResult:
        """검증된 key chord를 Worker에 전달합니다."""
        return self._input.computer_hotkey(request)

    def computer_key(self, request: ComputerKeyInput) -> ComputerActionResult:
        """검증된 named key 입력을 Worker에 전달합니다."""
        return self._input.computer_key(request)


class DesktopCapabilityUnavailableError(RuntimeError):
    """주입된 Worker가 요청한 desktop capability를 제공하지 않습니다."""


def observation_result_to_mcp(outcome: CallToolResult) -> CallToolResult:
    """Dispatcher의 Worker payload를 검증하고 이미지/metadata content로 분리합니다."""
    if outcome.is_error:
        return outcome
    payload = _ObservationPayload.model_validate(outcome.structured_content)
    metadata = payload.model_dump(mode="json")
    screenshot = payload.screenshot
    if screenshot is not None:
        metadata["screenshot"] = screenshot.model_dump(mode="json", exclude={"image_data"})
    content: list[ContentBlock] = [TextContent(text=canonicalize_payload(metadata).decode("utf-8"))]
    if screenshot is not None:
        content.append(ImageContent(data=screenshot.image_data, mime_type=screenshot.mime_type))
    return CallToolResult(
        content=content,
        structured_content=metadata,
        is_error=False,
        _meta=outcome.meta,
    )


def register_computer_tool(server: GatewayMCPServer, dispatcher: _ComputerDispatcher) -> None:
    """공식 MCP API에 Worker IPC 전용 observe/input 도구를 등록합니다."""

    async def computer_observe(
        operation_id: UUID | None = None,
        screenshot: bool = True,  # noqa: FBT001, FBT002 - MCP schema의 명명된 인자입니다.
        monitor: Annotated[int, Field(ge=1)] | None = None,
        uia: bool = False,  # noqa: FBT001, FBT002 - MCP schema의 명명된 인자입니다.
        max_controls: Annotated[int, Field(ge=1, le=500)] = 150,
    ) -> CallToolResult:
        request = ComputerObserveInput(
            operation_id=operation_id or uuid4(),
            screenshot=screenshot,
            monitor=monitor,
            uia=uia,
            max_controls=max_controls,
        )
        payload: JsonPayload = {
            "screenshot": request.screenshot,
            "monitor": request.monitor,
            "uia": request.uia,
            "max_controls": request.max_controls,
        }
        outcome = await dispatcher.dispatch(
            DispatchCall(
                operation_id=request.operation_id,
                tool_name="computer_observe",
                payload=payload,
                requested_at=datetime.now(UTC),
                timeout_ms=30_000,
            )
        )
        return observation_result_to_mcp(outcome.result)

    server.add_closed_tool(
        computer_observe,
        input_model=ComputerObserveInput,
        name="computer_observe",
        description="Observe the interactive desktop without persisting screenshot bytes.",
        annotations=ToolAnnotations(
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
        structured_output=False,
    )
    register_computer_input_tools(server, dispatcher)
    register_uia_tools(server, dispatcher)
