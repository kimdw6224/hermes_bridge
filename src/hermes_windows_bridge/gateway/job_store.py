"""Durable job metadata와 bounded output file persistence를 소유합니다."""

# pyright: reportMissingModuleSource=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, final

from pydantic import ValidationError

from hermes_windows_bridge.gateway.job_models import (
    InvalidJobMetadataError,
    JobOutputStream,
    JobSnapshot,
)
from hermes_windows_bridge.ipc.acl import (
    ADMINISTRATORS_SID,
    LOCAL_SERVICE_SID,
    LOCAL_SYSTEM_SID,
    current_process_sid,
)

if TYPE_CHECKING:
    from pathlib import Path
    from uuid import UUID


@final
class JobStore:
    """Restrictive inherited directory 아래의 job file 수명을 관리합니다."""

    def __init__(self, root: Path, retention: timedelta) -> None:
        """저장 경로를 만들고 terminal metadata 보존 기간을 고정합니다."""
        self._root = root
        self._root.mkdir(parents=True, exist_ok=True, mode=0o700)
        _protect_directory(self._root)
        self._retention = retention

    def load(self) -> tuple[JobSnapshot, ...]:
        """Strict metadata만 복원하고 보존 기간을 지난 artifact는 제거합니다."""
        expiry = datetime.now(UTC) - self._retention
        snapshots: list[JobSnapshot] = []
        for path in self._root.glob("*.json"):
            try:
                snapshot = JobSnapshot.model_validate_json(path.read_bytes())
            except (OSError, ValidationError) as error:
                raise InvalidJobMetadataError(path=path) from error
            if snapshot.updated_at < expiry:
                self.delete(snapshot.job_id, path)
            else:
                snapshots.append(snapshot)
        return tuple(snapshots)

    def write_snapshot(self, snapshot: JobSnapshot) -> None:
        """완전한 metadata를 임시 파일에서 atomic replace합니다."""
        path = self.metadata_path(snapshot.job_id)
        temporary = path.with_suffix(".tmp")
        _ = temporary.write_text(snapshot.model_dump_json(), encoding="utf-8")
        _ = temporary.chmod(0o600)
        _ = temporary.replace(path)

    def write_output(self, job_id: UUID, stream: JobOutputStream, value: str) -> None:
        """이미 bounded된 UTF-8 output만 restrictive file로 저장합니다."""
        path = self.output_path(job_id, stream)
        _ = path.write_text(value, encoding="utf-8")
        _ = path.chmod(0o600)

    def read_output(self, job_id: UUID, stream: JobOutputStream) -> bytes:
        """존재하지 않는 running-job output을 빈 bytes로 표현합니다."""
        path = self.output_path(job_id, stream)
        return path.read_bytes() if path.exists() else b""

    def delete(self, job_id: UUID, metadata_path: Path | None = None) -> None:
        """보존 기간이 지난 한 job의 세 artifact만 제거합니다."""
        path = metadata_path or self.metadata_path(job_id)
        path.unlink(missing_ok=True)
        self.output_path(job_id, "stdout").unlink(missing_ok=True)
        self.output_path(job_id, "stderr").unlink(missing_ok=True)

    def metadata_path(self, job_id: UUID) -> Path:
        """Job ID에 대응하는 metadata path를 반환합니다."""
        return self._root / f"{job_id}.json"

    def output_path(self, job_id: UUID, stream: JobOutputStream) -> Path:
        """Job ID와 stream에 대응하는 output path를 반환합니다."""
        return self._root / f"{job_id}.{stream}.output"


def _protect_directory(path: Path) -> None:
    """Broad principal 없이 현재 사용자와 Bridge service SID만 허용합니다."""
    import win32con  # noqa: PLC0415 - Windows ACL 경계를 이 함수로 격리합니다.
    import win32file  # noqa: PLC0415 - File access mask를 Windows 경계에 격리합니다.
    import win32security  # noqa: PLC0415 - Windows ACL 경계를 이 함수로 격리합니다.

    discretionary_acl = win32security.ACL()
    inheritance = win32con.CONTAINER_INHERIT_ACE | win32con.OBJECT_INHERIT_ACE
    allowed = dict.fromkeys(
        (current_process_sid(), LOCAL_SERVICE_SID, ADMINISTRATORS_SID, LOCAL_SYSTEM_SID)
    )
    for sid_text in allowed:
        discretionary_acl.AddAccessAllowedAceEx(
            win32security.ACL_REVISION,
            inheritance,
            win32file.FILE_ALL_ACCESS,
            win32security.ConvertStringSidToSid(sid_text),
        )
    win32security.SetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None,
        None,
        discretionary_acl,
        None,
    )
