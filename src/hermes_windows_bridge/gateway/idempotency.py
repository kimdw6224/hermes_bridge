"""Canonical payload hash로 완료 결과를 재생하는 bounded TTL cache입니다."""

from __future__ import annotations

from collections.abc import Callable  # noqa: TC003 - Pydantic method signature에 필요합니다.
from dataclasses import dataclass
from datetime import datetime, timedelta
from threading import Lock
from typing import override
from uuid import UUID  # noqa: TC003 - Pydantic가 runtime annotation을 해석합니다.

from pydantic import model_validator

from hermes_windows_bridge.models.policy import (
    JsonValue,
    Sha256Digest,
    StrictFrozenModel,
    canonicalize_payload,
    payload_digest,
)


class OperationCall(StrictFrozenModel):
    """멱등성 경계에서 파싱된 작업 ID, payload, 요청 시각입니다."""

    operation_id: UUID
    payload: JsonValue
    requested_at: datetime

    @model_validator(mode="after")
    def ensure_aware_time_and_canonical_payload(self) -> OperationCall:
        """Wall clock 혼동과 JSON 비결정 입력을 경계에서 거부합니다."""
        if self.requested_at.tzinfo is None:
            raise OperationTimeError
        _ = canonicalize_payload(self.payload)
        return self


class IdempotencyResult(StrictFrozenModel):
    """최초 또는 replay 응답 bytes와 관찰 가능한 replay 여부입니다."""

    payload: bytes
    replayed: bool
    payload_digest: Sha256Digest


@dataclass(frozen=True, slots=True)
class _CacheEntry:
    request_digest: str
    result: bytes
    result_digest: str
    expires_at: datetime


class IdempotencyStore:
    """동시 중복 실행을 막기 위해 callback 실행까지 하나의 lock으로 직렬화합니다."""

    def __init__(self, *, ttl: timedelta) -> None:
        """양수 TTL을 사용하는 빈 cache를 초기화합니다."""
        if ttl <= timedelta(0):
            raise InvalidCacheTtlError(ttl=ttl)
        self._ttl: timedelta = ttl
        self._entries: dict[UUID, _CacheEntry] = {}
        self._lock: Lock = Lock()

    def execute(self, call: OperationCall, operation: Callable[[], bytes]) -> IdempotencyResult:
        """완료 결과만 cache하며 같은 ID의 변경 payload는 fail-closed 합니다."""
        canonical_payload = canonicalize_payload(call.payload)
        request_digest = payload_digest(canonical_payload)
        with self._lock:
            cached = self._entries.get(call.operation_id)
            if cached is not None and call.requested_at >= cached.expires_at:
                del self._entries[call.operation_id]
                cached = None
            if cached is not None:
                if cached.request_digest != request_digest:
                    raise IdempotencyConflictError(operation_id=call.operation_id)
                return IdempotencyResult(
                    payload=cached.result,
                    replayed=True,
                    payload_digest=cached.result_digest,
                )
            result = operation()
            result_digest = payload_digest(result)
            self._entries[call.operation_id] = _CacheEntry(
                request_digest=request_digest,
                result=result,
                result_digest=result_digest,
                expires_at=call.requested_at + self._ttl,
            )
            return IdempotencyResult(
                payload=result,
                replayed=False,
                payload_digest=result_digest,
            )


@dataclass(frozen=True, slots=True)
class IdempotencyConflictError(RuntimeError):
    """같은 operation ID가 다른 canonical payload에 재사용되었습니다."""

    operation_id: UUID

    @override
    def __str__(self) -> str:
        """충돌한 operation ID를 포함합니다."""
        return f"operation id reused with altered payload: {self.operation_id}"


@dataclass(frozen=True, slots=True)
class InvalidCacheTtlError(ValueError):
    """Cache TTL이 양수가 아닙니다."""

    ttl: timedelta

    @override
    def __str__(self) -> str:
        """잘못된 TTL을 포함합니다."""
        return f"idempotency cache ttl must be positive: {self.ttl}"


class OperationTimeError(ValueError):
    """Operation 시각에 timezone 정보가 없습니다."""

    @override
    def __str__(self) -> str:
        """Timezone 요구사항을 설명합니다."""
        return "operation requested_at must be timezone-aware"
