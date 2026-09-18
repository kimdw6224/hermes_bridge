"""정책, 승인, 도구 annotation의 엄격한 경계 모델입니다."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime  # noqa: TC003 - Pydantic가 runtime annotation을 해석합니다.
from enum import StrEnum
from typing import Annotated, ClassVar, override
from uuid import UUID  # noqa: TC003 - Pydantic가 runtime annotation을 해석합니다.

from pydantic import BaseModel, ConfigDict, Field, model_validator

type JsonValue = str | int | float | bool | list[JsonValue] | dict[str, JsonValue] | None
Sha256Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


def canonicalize_payload(payload: JsonValue) -> bytes:
    """JSON payload를 키 순서와 공백에 독립적인 bytes로 고정합니다."""
    try:
        serialized = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return serialized.encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise CanonicalPayloadError(reason=type(error).__name__) from error


def payload_digest(canonical_payload: bytes) -> str:
    """감사 및 비교에 사용하는 SHA-256 digest를 계산합니다."""
    return hashlib.sha256(canonical_payload).hexdigest()


class StrictFrozenModel(BaseModel):
    """외부 입력을 추가 필드 없이 파싱하는 불변 모델입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True, strict=True, extra="forbid", populate_by_name=True
    )


class TrustTier(StrEnum):
    """Hermes MCP 서버 신뢰 등급입니다."""

    FULL = "full"
    UNTRUSTED = "untrusted"


class PolicyDecision(StrEnum):
    """Gateway가 dispatch 전에 내리는 정책 결정입니다."""

    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class OperationClass(StrEnum):
    """작업 성격 분류이며 DESTRUCTIVE 자체가 사용자 승인을 뜻하지 않습니다."""

    READ_ONLY = "read_only"
    USER_MUTATION = "user_mutation"
    DESTRUCTIVE = "destructive"
    PRIVILEGED = "privileged"


class ToolAnnotations(StrictFrozenModel):
    """MCP ToolAnnotations와 동일한 JSON alias를 쓰는 완전한 힌트 집합입니다."""

    read_only_hint: bool = Field(alias="readOnlyHint")
    destructive_hint: bool = Field(alias="destructiveHint")
    idempotent_hint: bool = Field(alias="idempotentHint")
    open_world_hint: bool = Field(alias="openWorldHint")


class ToolPolicy(StrictFrozenModel):
    """MCP 힌트, 작업 분류, 독립 승인 요구를 서로 다른 필드로 표현합니다."""

    name: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$")]
    operation_class: OperationClass
    annotations: ToolAnnotations
    approval_required: bool

    @model_validator(mode="after")
    def ensure_consistent_read_only_policy(self) -> ToolPolicy:
        """읽기 전용 힌트가 실제 내부 읽기 분류에만 사용되도록 합니다."""
        is_read_only = self.operation_class is OperationClass.READ_ONLY
        if self.annotations.read_only_hint != is_read_only:
            raise ToolPolicyConsistencyError(tool_name=self.name)
        if is_read_only and (self.annotations.destructive_hint or self.approval_required):
            raise ToolPolicyConsistencyError(tool_name=self.name)
        return self


class ApprovalMethod(StrEnum):
    """원격 모델 도구가 아닌 독립 사용자 승인 경로입니다."""

    ELICITATION = "elicitation"
    LOCAL = "local"


class ApprovalState(StrEnum):
    """승인 요청의 단방향 수명주기 상태입니다."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    CONSUMED = "consumed"
    EXPIRED = "expired"


class ApprovalSubmission(StrictFrozenModel):
    """정책 검사 뒤 exact payload를 동결하기 위한 승인 요청 입력입니다."""

    operation_id: UUID
    tool_name: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$")]
    payload: JsonValue
    requested_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def ensure_valid_window(self) -> ApprovalSubmission:
        """승인 시각은 timezone-aware이고 만료 시각보다 앞서야 합니다."""
        if self.requested_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ApprovalWindowError(reason="timezone_required")
        if self.expires_at <= self.requested_at:
            raise ApprovalWindowError(reason="expiry_must_follow_request")
        _ = canonicalize_payload(self.payload)
        return self


class ApprovalDecision(StrictFrozenModel):
    """elicitation 또는 local IPC에서 수신한 사용자 결정입니다."""

    approval_id: UUID
    approved: bool
    method: ApprovalMethod
    decided_at: datetime


class ApprovalAttempt(StrictFrozenModel):
    """승인된 frozen payload를 한 번 소비하려는 실행 입력입니다."""

    approval_id: UUID
    operation_id: UUID | None = None
    tool_name: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$")] | None = None
    payload: JsonValue
    attempted_at: datetime


class ApprovalRecord(StrictFrozenModel):
    """원문 secret 대신 canonical bytes와 digest를 보관하는 승인 상태입니다."""

    approval_id: UUID
    operation_id: UUID
    tool_name: str
    canonical_payload: bytes = Field(repr=False)
    payload_digest: Sha256Digest
    requested_at: datetime
    expires_at: datetime
    state: ApprovalState
    method: ApprovalMethod | None = None


class ApprovedPayload(StrictFrozenModel):
    """one-shot 승인을 소비한 dispatch용 exact payload입니다."""

    operation_id: UUID
    tool_name: str
    canonical_payload: bytes = Field(repr=False)
    payload_digest: Sha256Digest
    approval_method: ApprovalMethod


@dataclass(frozen=True, slots=True)
class ToolPolicyConsistencyError(ValueError):
    """Tool annotation이 내부 분류와 모순될 때 발생합니다."""

    tool_name: str

    @override
    def __str__(self) -> str:
        """모순된 도구명을 포함합니다."""
        return f"inconsistent tool policy: {self.tool_name}"


@dataclass(frozen=True, slots=True)
class ApprovalWindowError(ValueError):
    """승인 요청 시간 범위가 유효하지 않을 때 발생합니다."""

    reason: str

    @override
    def __str__(self) -> str:
        """잘못된 시간 범위의 이유를 포함합니다."""
        return f"invalid approval window: {self.reason}"


@dataclass(frozen=True, slots=True)
class CanonicalPayloadError(ValueError):
    """입력이 canonical JSON으로 안전하게 표현되지 않을 때 발생합니다."""

    reason: str

    @override
    def __str__(self) -> str:
        """Canonical 변환 실패 유형을 포함합니다."""
        return f"invalid canonical payload: {self.reason}"


@dataclass(frozen=True, slots=True)
class ApprovalNotFoundError(LookupError):
    """알 수 없는 승인 식별자입니다."""

    approval_id: UUID

    @override
    def __str__(self) -> str:
        """찾지 못한 승인 식별자를 포함합니다."""
        return f"approval not found: {self.approval_id}"


@dataclass(frozen=True, slots=True)
class ApprovalStateError(RuntimeError):
    """현재 상태에서 허용되지 않는 승인 전이입니다."""

    approval_id: UUID
    state: ApprovalState

    @override
    def __str__(self) -> str:
        """승인 식별자와 현재 상태를 포함합니다."""
        return f"approval {self.approval_id} has invalid state {self.state}"


@dataclass(frozen=True, slots=True)
class ApprovalLifecycleError(RuntimeError):
    """승인 수명주기에서 예상된 실행 거부입니다."""

    approval_id: UUID

    @override
    def __str__(self) -> str:
        """오류 유형과 승인 식별자를 포함합니다."""
        return f"{type(self).__name__}: {self.approval_id}"


class ApprovalPendingError(ApprovalLifecycleError):
    """아직 사용자가 승인하지 않은 요청입니다."""


class ApprovalConsumedError(ApprovalLifecycleError):
    """이미 one-shot 실행에 소비된 승인입니다."""


class ApprovalDeniedError(ApprovalLifecycleError):
    """사용자가 거부한 승인입니다."""


class ApprovalExpiredError(ApprovalLifecycleError):
    """사용 기한이 지난 승인입니다."""


class ApprovalPayloadMismatchError(ApprovalLifecycleError):
    """승인 뒤 변경되어 frozen payload와 일치하지 않는 실행입니다."""


class ApprovalBindingMismatchError(ApprovalLifecycleError):
    """승인된 operation 또는 tool과 다른 실행입니다."""
