"""독립 승인 surface 선택, timeout, post-await 결정을 조율합니다."""

from __future__ import annotations

from collections.abc import Callable  # noqa: TC003 - 생성자 runtime annotation입니다.
from datetime import UTC, datetime
from typing import TYPE_CHECKING, NamedTuple, Protocol, final

from anyio import fail_after

from hermes_windows_bridge.models.policy import (
    ApprovalDecision,
    ApprovalDeniedError,
    ApprovalExpiredError,
    ApprovalMethod,
    ApprovalRecord,
    ApprovalSubmission,
)

if TYPE_CHECKING:
    from uuid import UUID


class ApprovalStore(Protocol):
    """Coordinator가 사용하는 승인 상태 저장소의 최소 계약입니다."""

    def request(self, submission: ApprovalSubmission) -> ApprovalRecord:
        """승인 요청을 동결합니다."""
        ...

    def decide(self, decision: ApprovalDecision) -> ApprovalRecord:
        """독립 결정을 반영합니다."""
        ...


class ApprovalSurface(Protocol):
    """모델 입력과 독립된 사용자 승인 surface입니다."""

    async def resolve(self, record: ApprovalRecord) -> bool:
        """고정된 승인 record에 대한 명시적 사용자 결정을 반환합니다."""
        ...


class ApprovalSurfaceUnavailableError(ConnectionError):
    """사용자 승인 surface가 현재 요청을 처리할 수 없습니다."""


class ApprovalReceipt(NamedTuple):
    """원문 payload 없이 dispatch와 감사에 사용할 승인 provenance입니다."""

    approval_id: UUID
    method: ApprovalMethod
    payload_digest: str


@final
class ApprovalCoordinator:
    """Elicitation 우선, local fallback으로 one-shot receipt를 발급합니다."""

    def __init__(
        self, manager: ApprovalStore,
        surfaces: tuple[ApprovalSurface | None, ApprovalSurface | None], *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        """승인 상태 저장소와 elicitation/local surface를 순서대로 보관합니다."""
        self._manager, (self._elicitation, self._local) = manager, surfaces
        self._clock = clock

    async def resolve(self, submission: ApprovalSubmission) -> ApprovalReceipt:
        """Payload를 먼저 동결하고 독립 surface 결정만 승인 상태에 반영합니다."""
        record = self._manager.request(submission)
        remaining = (record.expires_at - self._clock()).total_seconds()
        try:
            with fail_after(remaining):
                approved, method = await self._resolve_surface(record)
        except TimeoutError:
            raise ApprovalExpiredError(approval_id=record.approval_id) from None
        _ = self._manager.decide(
            ApprovalDecision(
                approval_id=record.approval_id,
                approved=approved,
                method=method,
                decided_at=self._clock(),
            )
        )
        if not approved:
            raise ApprovalDeniedError(approval_id=record.approval_id)
        return ApprovalReceipt(record.approval_id, method, record.payload_digest)

    async def _resolve_surface(self, record: ApprovalRecord) -> tuple[bool, ApprovalMethod]:
        surfaces = (
            (self._elicitation, ApprovalMethod.ELICITATION),
            (self._local, ApprovalMethod.LOCAL),
        )
        for surface, method in surfaces:
            if surface is None:
                continue
            try:
                return await surface.resolve(record), method
            except ApprovalSurfaceUnavailableError:
                continue
        return False, ApprovalMethod.LOCAL
