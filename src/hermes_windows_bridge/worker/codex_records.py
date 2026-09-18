"""Codex Git preflight metadata의 strict atomic persistence입니다."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path  # noqa: TC003 - Pydantic runtime annotation입니다.
from typing import final, override
from uuid import UUID, uuid4

from pydantic import ValidationError

from hermes_windows_bridge.models.policy import StrictFrozenModel
from hermes_windows_bridge.tools.codex import GitSnapshot  # noqa: TC001


class CodexPreflightRecord(StrictFrozenModel):
    """Prompt나 CLI 출력 없이 postflight에 필요한 최소 metadata만 보관합니다."""

    job_id: UUID
    cwd: Path
    preflight: GitSnapshot


@dataclass(frozen=True, slots=True)
class InvalidCodexRecordError(RuntimeError):
    """Disk record가 strict schema 또는 filename identity와 일치하지 않습니다."""

    path: Path

    @override
    def __str__(self) -> str:
        return f"invalid_codex_record:{self.path.name}"


@dataclass(frozen=True, slots=True)
class CodexRecordWriteError(RuntimeError):
    """Atomic metadata 기록에 실패했습니다."""

    path: Path

    @override
    def __str__(self) -> str:
        return f"codex_record_write_failed:{self.path.name}"


@dataclass(frozen=True, slots=True)
class CodexRecordCollisionError(RuntimeError):
    """Caller가 제공한 새 job ID의 record가 이미 존재합니다."""

    job_id: UUID

    @override
    def __str__(self) -> str:
        return f"codex_record_already_exists:{self.job_id}"


@dataclass(frozen=True, slots=True)
class StaleCodexRecordError(RuntimeError):
    """Preflight는 남았지만 durable job metadata가 없습니다."""

    job_id: UUID

    @override
    def __str__(self) -> str:
        return f"stale_codex_record:{self.job_id}"


@final
class CodexRecordStore:
    """한 directory에서 job ID별 immutable preflight를 소유합니다."""

    def __init__(self, root: Path) -> None:
        """Restrictive record directory를 준비합니다."""
        self._root = root
        self._root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def load(self) -> tuple[CodexPreflightRecord, ...]:
        """모든 JSON을 strict parse하고 filename/job ID 불일치를 거부합니다."""
        return tuple(self._read(path) for path in self._root.glob("*.json"))

    def write(self, record: CodexPreflightRecord) -> None:
        """새 job record만 atomic replace하고 기존 ID는 거부합니다."""
        path = self.path(record.job_id)
        if path.exists():
            raise CodexRecordCollisionError(job_id=record.job_id)
        temporary = self._root / f"{record.job_id}.{uuid4()}.tmp"
        try:
            _ = temporary.write_text(record.model_dump_json(), encoding="utf-8")
            _ = temporary.chmod(0o600)
            _ = temporary.replace(path)
        except OSError as error:
            temporary.unlink(missing_ok=True)
            raise CodexRecordWriteError(path=path) from error

    def read(self, job_id: UUID) -> CodexPreflightRecord:
        """한 job의 strict record를 읽습니다."""
        return self._read(self.path(job_id))

    def delete(self, job_id: UUID) -> None:
        """Registry start 실패 또는 replay candidate의 한 record만 제거합니다."""
        self.path(job_id).unlink(missing_ok=True)

    def path(self, job_id: UUID) -> Path:
        """Job ID에 대응하는 record path를 반환합니다."""
        return self._root / f"{job_id}.json"

    def _read(self, path: Path) -> CodexPreflightRecord:
        try:
            record = CodexPreflightRecord.model_validate_json(path.read_bytes())
            filename_id = UUID(path.stem)
        except (OSError, ValidationError, ValueError) as error:
            raise InvalidCodexRecordError(path=path) from error
        if filename_id != record.job_id:
            raise InvalidCodexRecordError(path=path)
        return record
