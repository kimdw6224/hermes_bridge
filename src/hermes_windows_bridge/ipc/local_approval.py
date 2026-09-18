"""Gateway와 Worker가 공유하는 internal-only local approval wire 모델입니다."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime  # noqa: TC003 - Pydantic가 runtime annotation을 해석합니다.
from typing import Annotated, ClassVar, Final, Literal, override
from uuid import UUID  # noqa: TC003 - Pydantic가 runtime annotation을 해석합니다.

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator, model_validator

from hermes_windows_bridge.ipc.protocol import JsonPayload

__all__ = (
    "LocalApprovalPowerSummary",
    "LocalApprovalWireRequest",
    "LocalApprovalWireResult",
    "parse_local_approval_wire_request",
    "wire_result_payload",
)

type PayloadDigest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
type PowerAction = Literal["reboot", "shutdown"]
type PowerTool = Literal["system_reboot", "system_shutdown"]

_JSON_PAYLOAD: TypeAdapter[JsonPayload] = TypeAdapter(JsonPayload)
_TOOL_BY_ACTION: Final[dict[PowerAction, PowerTool]] = {
    "reboot": "system_reboot",
    "shutdown": "system_shutdown",
}


class _StrictWireModel(BaseModel):
    """Local approval IPC boundary의 closed immutable base입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)


class LocalApprovalPowerSummary(_StrictWireModel):
    """원문 payload 대신 표시 가능한 typed power summary입니다."""

    action: PowerAction
    delay_seconds: int = Field(ge=0, le=300)
    reason: str = Field(min_length=1, max_length=200)


class LocalApprovalWireRequest(_StrictWireModel):
    """Gateway가 local Worker dialog에 전달하는 one-request wire model입니다."""

    request_id: UUID
    approval_id: UUID
    operation_id: UUID
    tool_name: PowerTool
    payload_digest: PayloadDigest
    expires_at: datetime
    summary: LocalApprovalPowerSummary

    @field_validator("expires_at")
    @classmethod
    def require_aware_expiry(cls, value: datetime) -> datetime:
        """Worker와 Gateway가 같은 absolute expiry를 비교하게 합니다."""
        if value.tzinfo is None:
            raise LocalApprovalWireExpiryError
        return value

    @model_validator(mode="after")
    def require_matching_tool_and_action(self) -> LocalApprovalWireRequest:
        """Typed action과 tool alias가 다른 권한을 뜻하지 않게 고정합니다."""
        expected_tool = _TOOL_BY_ACTION[self.summary.action]
        if self.tool_name != expected_tool:
            raise LocalApprovalWireBindingError(
                tool_name=self.tool_name,
                action=self.summary.action,
            )
        return self


class LocalApprovalWireResult(_StrictWireModel):
    """Worker가 approval store를 소비하지 않고 반환하는 correlation 결과입니다."""

    request_id: UUID
    approval_id: UUID
    operation_id: UUID
    tool_name: PowerTool
    action: PowerAction
    payload_digest: PayloadDigest
    expires_at: datetime
    approved: bool

    @field_validator("expires_at")
    @classmethod
    def require_aware_expiry(cls, value: datetime) -> datetime:
        """결과도 request와 같은 absolute expiry를 보존합니다."""
        if value.tzinfo is None:
            raise LocalApprovalWireExpiryError
        return value


def parse_local_approval_wire_request(payload: JsonPayload) -> LocalApprovalWireRequest:
    """JSON IPC payload를 strict wire request로 한 번만 parse합니다."""
    serialized = json.dumps(payload, allow_nan=False, separators=(",", ":"), sort_keys=True)
    return LocalApprovalWireRequest.model_validate_json(serialized)


def wire_result_payload(result: LocalApprovalWireResult) -> JsonPayload:
    """검증된 result를 일반 IPC response payload로 변환합니다."""
    return _JSON_PAYLOAD.validate_python(result.model_dump(mode="json"))


@dataclass(frozen=True, slots=True)
class LocalApprovalWireExpiryError(ValueError):
    """Wire expiry가 timezone-aware timestamp가 아닐 때 발생합니다."""

    @override
    def __str__(self) -> str:
        return "local approval expiry must be timezone-aware"


@dataclass(frozen=True, slots=True)
class LocalApprovalWireBindingError(ValueError):
    """Tool/action pair가 allowlisted power mapping과 다를 때 발생합니다."""

    tool_name: str
    action: PowerAction

    @override
    def __str__(self) -> str:
        return f"local approval action mismatch: {self.tool_name} / {self.action}"
