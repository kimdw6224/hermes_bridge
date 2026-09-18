"""Secret과 대용량 본문을 저장하지 않는 구조화 감사 metadata입니다."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Final, assert_never, final, override
from uuid import UUID  # noqa: TC003 - Pydantic가 runtime annotation을 해석합니다.

from pydantic import Field, model_validator

from hermes_windows_bridge.models.policy import (
    ApprovalMethod,
    JsonValue,
    Sha256Digest,
    StrictFrozenModel,
    canonicalize_payload,
    payload_digest,
)

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

_SECRET_KEYS: Final = (
    "authorization",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
)


class AuditOutcome(StrEnum):
    """감사 대상 작업의 경계 결과입니다."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REJECTED = "rejected"


class AuditErrorCode(StrEnum):
    """본문 없이 보존 가능한 제한된 terminal failure 분류입니다."""

    JOB_CANCELLED = "job_cancelled"
    JOB_FAILED = "job_failed"
    JOB_INTERRUPTED = "job_interrupted"


class ContentMetadata(StrictFrozenModel):
    """원문을 대신하는 비가역 길이와 digest입니다."""

    size_bytes: int = Field(ge=0)
    sha256: Sha256Digest


class ApprovalAuditMetadata(StrictFrozenModel):
    """실제 소비된 frozen 승인 receipt의 원문 없는 provenance입니다."""

    approval_id: UUID
    method: ApprovalMethod
    frozen_payload_digest: Sha256Digest


class AuditInput(StrictFrozenModel):
    """감사 경계에 들어오는 실행 data이며 recorder 밖에는 보관하지 않습니다."""

    event_id: UUID
    occurred_at: datetime
    tool_name: str
    operation_id: UUID | None
    payload: JsonValue
    outcome: AuditOutcome
    error_code: AuditErrorCode | None = None
    approval: ApprovalAuditMetadata | None = None
    stdout: str | None = Field(default=None, repr=False)
    stderr: str | None = Field(default=None, repr=False)
    screenshot_body: bytes | None = Field(default=None, repr=False)
    untrusted_text: str | None = Field(default=None, repr=False)

    @model_validator(mode="after")
    def ensure_aware_time(self) -> AuditInput:
        """서로 다른 local timezone의 감사 순서 혼동을 방지합니다."""
        if self.occurred_at.tzinfo is None:
            raise AuditTimeError
        return self


class AuditEvent(StrictFrozenModel):
    """지속 가능한 redacted 감사 이벤트입니다."""

    event_id: UUID
    occurred_at: datetime
    tool_name: str
    operation_id: UUID | None
    outcome: AuditOutcome
    error_code: AuditErrorCode | None
    approval: ApprovalAuditMetadata | None = None
    redacted_payload_json: str
    payload_digest: Sha256Digest
    stdout: ContentMetadata | None
    stderr: ContentMetadata | None
    screenshot: ContentMetadata | None
    untrusted_text: ContentMetadata | None


@dataclass(frozen=True, slots=True)
class AuditRetentionReceipt:
    """원문 body 없이 retention cleanup 결과만 보관합니다."""

    deleted_paths: tuple[Path, ...]


@final
class AuditJsonlStore:
    """Redacted event만 날짜별 JSONL로 기록하고 legacy body를 만료 처리합니다."""

    def __init__(self, root: Path, *, retention: timedelta) -> None:
        """Private root와 양수 retention을 고정합니다."""
        if retention <= timedelta(0):
            raise AuditRetentionConfigurationError
        self._root = root
        self._root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._retention = retention

    def record(self, event: AuditEvent) -> None:
        """본문 field가 없는 sanitized event만 append합니다."""
        path = self.path_for(event.occurred_at)
        with path.open("a", encoding="utf-8", newline="\n") as output:
            _ = output.write(f"{event.model_dump_json()}\n")
        _ = path.chmod(0o600)

    def path_for(self, occurred_at: datetime) -> Path:
        """Timezone-aware event를 고정된 rotation 파일로 매핑합니다."""
        if occurred_at.tzinfo is None:
            raise AuditTimeError
        return self._root / f"audit-{occurred_at.astimezone(UTC).date().isoformat()}.jsonl"

    def cleanup_expired_sensitive_artifacts(self, now: datetime) -> AuditRetentionReceipt:
        """Legacy raw body만 삭제하고 redacted JSONL metadata는 항상 보존합니다."""
        if now.tzinfo is None:
            raise AuditTimeError
        expiry = now - self._retention
        deleted = tuple(
            path
            for path in self._sensitive_artifact_paths()
            if datetime.fromtimestamp(path.stat().st_mtime, UTC) < expiry
        )
        for path in deleted:
            path.unlink(missing_ok=True)
        return AuditRetentionReceipt(deleted_paths=deleted)

    def _sensitive_artifact_paths(self) -> Iterable[Path]:
        """명시적 legacy body suffix만 cleanup 대상으로 제한합니다."""
        suffixes = (".screenshot.body", ".stdout.body", ".stderr.body")
        return tuple(
            path
            for path in self._root.iterdir()
            if path.is_file() and path.name.endswith(suffixes)
        )


def _summarize_key(key: str) -> str:
    """동적 key 원문을 충돌 저항적인 canonical token으로 치환합니다."""
    body = key.encode("utf-8")
    return f"key:{len(body)}:{payload_digest(body)}"


def _summarize_payload(value: JsonValue) -> JsonValue:
    """자유형 문자열 원문을 비가역 metadata로 치환합니다."""
    match value:
        case None:
            return None
        case str():
            body = value.encode("utf-8")
            return {
                "type": "string",
                "size_bytes": len(body),
                "sha256": payload_digest(body),
            }
        case bool():
            return value
        case int() | float():
            return value
        case list():
            return [_summarize_payload(item) for item in value]
        case dict():
            redacted: dict[str, JsonValue] = {}
            for key, item in value.items():
                normalized = key.casefold()
                summary_key = _summarize_key(key)
                if any(secret_key in normalized for secret_key in _SECRET_KEYS):
                    redacted[summary_key] = "[REDACTED]"
                else:
                    redacted[summary_key] = _summarize_payload(item)
            return redacted
        case _:
            assert_never(value)


def _content_metadata(value: str | bytes | None) -> ContentMetadata | None:
    match value:
        case None:
            return None
        case str():
            body = value.encode("utf-8")
        case bytes():
            body = value
        case _:
            assert_never(value)
    return ContentMetadata(size_bytes=len(body), sha256=payload_digest(body))


class AuditRecorder:
    """테스트 가능한 in-memory sink이며 오직 sanitized AuditEvent만 유지합니다."""

    def __init__(self, *, store: AuditJsonlStore | None = None) -> None:
        """빈 sanitized event sink를 초기화합니다."""
        self._records: list[AuditEvent] = []
        self._store: AuditJsonlStore | None = store

    @property
    def records(self) -> tuple[AuditEvent, ...]:
        """호출자가 내부 목록을 변경할 수 없는 snapshot을 반환합니다."""
        return tuple(self._records)

    def record(self, event_input: AuditInput) -> AuditEvent:
        """본문을 digest metadata로 바꾸고 secret을 제거한 이벤트를 추가합니다."""
        redacted_payload = canonicalize_payload(_summarize_payload(event_input.payload))
        event = AuditEvent(
            event_id=event_input.event_id,
            occurred_at=event_input.occurred_at,
            tool_name=event_input.tool_name,
            operation_id=event_input.operation_id,
            outcome=event_input.outcome,
            error_code=event_input.error_code,
            approval=event_input.approval,
            redacted_payload_json=redacted_payload.decode("utf-8"),
            payload_digest=payload_digest(redacted_payload),
            stdout=_content_metadata(event_input.stdout),
            stderr=_content_metadata(event_input.stderr),
            screenshot=_content_metadata(event_input.screenshot_body),
            untrusted_text=_content_metadata(event_input.untrusted_text),
        )
        self._records.append(event)
        if self._store is not None:
            self._store.record(event)
        return event


class AuditTimeError(ValueError):
    """감사 시각에 timezone 정보가 없습니다."""

    @override
    def __str__(self) -> str:
        """Timezone 요구사항을 설명합니다."""
        return "audit occurred_at must be timezone-aware"


class AuditRetentionConfigurationError(ValueError):
    """Audit retention은 양수여야 합니다."""
