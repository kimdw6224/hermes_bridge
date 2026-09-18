"""Durable job registry의 typed 상태와 오류 모델입니다."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path  # noqa: TC003 - Pydantic runtime annotation입니다.
from typing import TYPE_CHECKING, Annotated, Final, Literal, Protocol, final, override
from uuid import UUID  # noqa: TC003 - Pydantic runtime annotation입니다.

from pydantic import Field, model_validator

from hermes_windows_bridge.models.policy import (
    JsonValue,
    Sha256Digest,
    StrictFrozenModel,
    canonicalize_payload,
    payload_digest,
)

if TYPE_CHECKING:
    from hermes_windows_bridge.worker.job_process import JobProcessSpec, RunningJobProcess

type JobOutputStream = Literal["stdout", "stderr"]
MAX_JOB_OUTPUT_CHUNK_BYTES: Final = 65_536


class JobProcessFactory(Protocol):
    """로그인 사용자 Worker가 제공해야 하는 process 생성 계약입니다."""

    def __call__(
        self,
        spec: JobProcessSpec,
        *,
        max_output_bytes: int,
    ) -> RunningJobProcess:
        """Bounded output과 Job Object를 소유한 process를 시작합니다."""
        ...


class JobKind(StrEnum):
    """후속 adapter가 구분할 장기 작업 종류입니다."""

    PROCESS = "process"
    SHELL = "shell"
    CODEX = "codex"


class JobState(StrEnum):
    """Durable job의 단방향 수명주기입니다."""

    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


TERMINAL_JOB_STATES = frozenset(
    {JobState.SUCCEEDED, JobState.FAILED, JobState.CANCELLED, JobState.INTERRUPTED}
)


@dataclass(frozen=True, slots=True)
class JobSpec:
    """외부 도구 경계에서 검증된 background process 요청입니다."""

    operation_id: UUID
    kind: JobKind
    argv: tuple[str, ...]
    cwd: Path


@dataclass(frozen=True, slots=True)
class JobLimits:
    """Job concurrency, output, retention의 함께 검증되는 구성입니다."""

    max_concurrent: int = 4
    max_output_bytes: int = 200_000
    retention: timedelta = timedelta(hours=24)


def job_request_digest(spec: JobSpec, limits: JobLimits) -> str:
    """Replay identity를 전체 실행 payload와 유효 상한에 고정합니다."""
    payload: dict[str, JsonValue] = {
        "argv": list(spec.argv),
        "cwd": str(spec.cwd),
        "kind": spec.kind.value,
        "limits": {
            "max_concurrent": limits.max_concurrent,
            "max_output_bytes": limits.max_output_bytes,
            "retention_seconds": int(limits.retention.total_seconds()),
        },
    }
    return payload_digest(canonicalize_payload(payload))


def interrupt_on_recovery(snapshot: JobSnapshot, updated_at: datetime) -> JobSnapshot:
    """재시작 시 실제 process handle이 없는 active metadata만 중단 처리합니다."""
    if snapshot.state not in {JobState.QUEUED, JobState.RUNNING}:
        return snapshot
    return snapshot.model_copy(
        update={"state": JobState.INTERRUPTED, "pid": None, "updated_at": updated_at}
    )


@final
class JobRecord:
    """실행 중 process reference를 의도적으로 변경하는 registry state입니다."""

    def __init__(self, snapshot: JobSnapshot) -> None:
        """Immutable 공개 snapshot과 선택적 Worker process를 보관합니다."""
        self.snapshot = snapshot
        self.process: RunningJobProcess | None = None


class JobSnapshot(StrictFrozenModel):
    """Disk와 MCP 응답이 공유하는 bounded job metadata입니다."""

    job_id: UUID
    operation_id: UUID
    request_digest: Sha256Digest
    kind: JobKind
    state: JobState
    created_at: datetime
    updated_at: datetime
    exit_code: int | None = None
    pid: Annotated[int, Field(gt=0)] | None = None
    stdout_bytes: Annotated[int, Field(ge=0)] = 0
    stderr_bytes: Annotated[int, Field(ge=0)] = 0
    retained_bytes: Annotated[int, Field(ge=0)] = 0
    truncated: bool = False

    @model_validator(mode="after")
    def ensure_valid_timeline_and_state(self) -> JobSnapshot:
        """Disk metadata의 시각과 실행 상태 모순을 거부합니다."""
        if self.created_at.tzinfo is None or self.updated_at.tzinfo is None:
            raise InvalidJobMetadataStateError(reason="timezone_required")
        if self.updated_at < self.created_at:
            raise InvalidJobMetadataStateError(reason="updated_before_created")
        if self.state is JobState.RUNNING and self.pid is None:
            raise InvalidJobMetadataStateError(reason="running_pid_required")
        if self.state is JobState.SUCCEEDED and self.exit_code != 0:
            raise InvalidJobMetadataStateError(reason="success_exit_code")
        return self


class JobOutput(StrictFrozenModel):
    """UTF-8 byte window와 전체/보존 길이를 분리한 결과입니다."""

    job_id: UUID
    stream: JobOutputStream
    data: str
    offset: int
    next_offset: int
    complete: bool
    total_bytes: int
    retained_bytes: int
    truncated: bool


class InvalidJobConfigurationError(ValueError):
    """Job registry 상한과 보존 기간이 유효하지 않습니다."""


class InvalidJobSpecError(ValueError):
    """Job argv는 비어 있거나 NUL을 포함할 수 없습니다."""


class InvalidOutputWindowError(ValueError):
    """Output byte window가 허용 범위를 벗어났습니다."""


class JobRegistryClosedError(RuntimeError):
    """닫힌 registry에는 새 작업을 등록할 수 없습니다."""


@dataclass(frozen=True, slots=True)
class JobReplayConflictError(RuntimeError):
    """같은 operation ID를 변경된 job payload에 재사용했습니다."""

    operation_id: UUID

    @override
    def __str__(self) -> str:
        return f"job operation id reused with altered payload: {self.operation_id}"


@dataclass(frozen=True, slots=True)
class JobNotFoundError(LookupError):
    """요청한 durable job ID가 없습니다."""

    job_id: UUID

    @override
    def __str__(self) -> str:
        return f"job not found: {self.job_id}"


@dataclass(frozen=True, slots=True)
class InvalidJobMetadataError(RuntimeError):
    """Disk의 durable metadata가 strict schema와 일치하지 않습니다."""

    path: Path

    @override
    def __str__(self) -> str:
        return f"invalid job metadata: {self.path.name}"


@dataclass(frozen=True, slots=True)
class InvalidJobMetadataStateError(ValueError):
    """Job metadata의 timeline 또는 state invariant가 깨졌습니다."""

    reason: str

    @override
    def __str__(self) -> str:
        return f"invalid job metadata state: {self.reason}"
