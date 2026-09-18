"""허용된 Windows 루트 안에서만 동작하는 동기 파일 시스템 worker입니다."""

from __future__ import annotations

import base64
import os
import shutil
import tempfile
from collections.abc import Callable
from contextlib import ExitStack
from pathlib import Path
from typing import TYPE_CHECKING, Literal, final

from hermes_windows_bridge.tools.filesystem import (
    BulkDeleteApprovalRequiredError,
    FileStat,
    FilesystemLimits,
    InlineSizeLimitError,
    ListResult,
    MutationResult,
    ReadResult,
    UnavailableFileEntry,
    UnsafeMutationError,
    delete_safely,
)
from hermes_windows_bridge.worker.path_safety import (
    PathPolicyError,
    SafePathPolicy,
    SafeWindowsPath,
    guard_directory,
    open_verified_binary,
)

if TYPE_CHECKING:
    from hermes_windows_bridge.models.config import BridgeSettings, PolicySettings

type BulkDeleteAuthorizer = Callable[[Path, int], bool]
_READ: Literal["read"] = "read"
_WRITE: Literal["write"] = "write"


@final
class FilesystemWorker:
    """각 호출 직전에 경로를 재해석하고 bounded I/O를 수행합니다."""

    def __init__(
        self,
        *,
        path_policy: SafePathPolicy,
        limits: FilesystemLimits,
        bulk_delete_authorizer: BulkDeleteAuthorizer | None = None,
    ) -> None:
        """검증 정책과 모델이 직접 바꿀 수 없는 승인 callback을 보관합니다."""
        self._path_policy = path_policy
        self._limits = limits
        self._bulk_delete_authorizer = bulk_delete_authorizer or _deny_bulk_delete

    @property
    def max_inline_write_bytes(self) -> int:
        """Boundary가 allocation 전 검사에 사용할 write 한도를 반환합니다."""
        return self._limits.max_inline_write_bytes

    @classmethod
    def from_settings(
        cls,
        *,
        bridge: BridgeSettings,
        policy: PolicySettings,
        bulk_delete_authorizer: BulkDeleteAuthorizer | None = None,
    ) -> FilesystemWorker:
        """Typed bridge/policy 설정에서 roots, limits, approval category를 구성합니다."""
        filesystem = policy.filesystem
        path_policy = SafePathPolicy(
            allowed_roots=(
                bridge.paths.program_data,
                bridge.paths.user_data,
                *filesystem.additional_allowed_roots,
            ),
            deny_device_paths=filesystem.deny_device_paths,
            allow_unc=filesystem.allow_unc,
            allow_alternate_data_streams=filesystem.allow_alternate_data_streams,
        )
        limits = FilesystemLimits(
            max_inline_read_bytes=filesystem.max_inline_read_bytes,
            max_inline_write_bytes=filesystem.max_inline_write_bytes,
            bulk_delete_threshold=policy.approval.bulk_delete_threshold,
            approval_categories=frozenset(policy.approval.required_for),
        )
        return cls(
            path_policy=path_policy,
            limits=limits,
            bulk_delete_authorizer=bulk_delete_authorizer,
        )

    def list(self, path: Path) -> ListResult:
        """Directory의 직접 자식을 이름순으로 반환합니다."""
        with guard_directory(path, policy=self._path_policy) as target:
            children = sorted(target.iterdir(), key=lambda item: item.name)
            entries: list[FileStat] = []
            unavailable: list[UnavailableFileEntry] = []
            for child in children:
                try:
                    entries.append(self.stat(child))
                except PathPolicyError as error:
                    unavailable.append(UnavailableFileEntry(child.name, error.reason))
                except PermissionError:
                    unavailable.append(UnavailableFileEntry(child.name, "access_denied"))
                except FileNotFoundError:
                    unavailable.append(UnavailableFileEntry(child.name, "not_found"))
                except OSError:
                    unavailable.append(UnavailableFileEntry(child.name, "metadata_unavailable"))
        return ListResult(target, tuple(entries), tuple(unavailable))

    def stat(self, path: Path) -> FileStat:
        """Final path와 크기, 수정 시각, 종류를 반환합니다."""
        with guard_directory(path, policy=self._path_policy) as target:
            metadata = target.stat()
            kind: Literal["file", "directory"] = "directory" if target.is_dir() else "file"
        return FileStat(target, target.name, metadata.st_size, metadata.st_mtime_ns, kind)

    def read(
        self,
        path: Path,
        *,
        offset: int,
        length: int | None,
        encoding: Literal["utf-8", "base64"],
    ) -> ReadResult:
        """요청한 byte 범위만 UTF-8 또는 base64로 읽습니다."""
        with open_verified_binary(path, policy=self._path_policy) as opened:
            metadata = os.fstat(opened.stream.fileno())
            target = opened.final_path
            requested = max(metadata.st_size - offset, 0) if length is None else length
            if requested > self._limits.max_inline_read_bytes:
                raise InlineSizeLimitError(_READ, self._limits.max_inline_read_bytes)
            _ = opened.stream.seek(offset)
            data = opened.stream.read(requested + 1)
        if len(data) > requested:
            data = data[:requested]
        if encoding == "utf-8":
            return ReadResult(target, metadata.st_size, metadata.st_mtime_ns, text=data.decode())
        return ReadResult(
            target,
            metadata.st_size,
            metadata.st_mtime_ns,
            base64_data=base64.b64encode(data).decode("ascii"),
        )

    def write(self, path: Path, data: bytes) -> MutationResult:
        """동일 directory의 임시 파일을 fsync한 뒤 atomic replace합니다."""
        if len(data) > self._limits.max_inline_write_bytes:
            raise InlineSizeLimitError(_WRITE, self._limits.max_inline_write_bytes)
        with guard_directory(path.parent, policy=self._path_policy):
            target = self._resolve(path).final_path
            if self._file_matches(path, data):
                return self._mutation_stat(target, changed=False)
            temp_path = self._write_temporary(target, data)
            try:
                target = self._resolve(path).final_path
                os.replace(  # noqa: PTH105 - guarded-parent atomic replace를 명시합니다.
                    temp_path,
                    target,
                )
            finally:
                temp_path.unlink(missing_ok=True)
        return self._mutation_stat(target, changed=True)

    def move(self, source: Path, destination: Path) -> MutationResult:
        """Gateway의 operation-id 멱등성 아래에서 존재하는 source만 이동합니다."""
        with ExitStack() as guards:
            _ = guards.enter_context(guard_directory(source.parent, policy=self._path_policy))
            _ = guards.enter_context(guard_directory(destination.parent, policy=self._path_policy))
            source_target = self._resolve(source, require_exists=True).final_path
            destination_target = self._resolve(destination).final_path
            if not source_target.is_file():
                raise UnsafeMutationError
            if destination_target.exists():
                raise FileExistsError(destination_target)
            opened_source = self._copy_file(source, destination_target)
            latest_source = self._resolve(source, require_exists=True).final_path
            if os.path.normcase(opened_source) != os.path.normcase(latest_source):
                raise UnsafeMutationError
            source_target.unlink()
        return self._mutation_stat(destination_target, changed=True)

    def copy(self, source: Path, destination: Path) -> MutationResult:
        """File 또는 directory를 재실행 가능한 overwrite 방식으로 복사합니다."""
        with guard_directory(destination.parent, policy=self._path_policy):
            source_target = self._resolve(source, require_exists=True).final_path
            destination_target = self._resolve(destination).final_path
            if not source_target.is_file():
                raise UnsafeMutationError
            _ = self._copy_file(source, destination_target)
        return self._mutation_stat(destination_target, changed=True)

    def delete(self, path: Path, *, recursive: bool) -> MutationResult:
        """설정된 category와 threshold가 모두 맞을 때만 bulk 승인을 요구합니다."""
        target = self._resolve(path).final_path
        if not target.exists():
            return MutationResult(target, changed=False)
        target = self._resolve(path, require_exists=True).final_path
        item_count = _count_items(target)
        requires_approval = (
            "bulk_delete" in self._limits.approval_categories
            and item_count >= self._limits.bulk_delete_threshold
        )
        if requires_approval and not self._bulk_delete_authorizer(target, item_count):
            raise BulkDeleteApprovalRequiredError(target, item_count)
        with guard_directory(path.parent, policy=self._path_policy):
            delete_safely(path, policy=self._path_policy, recursive=recursive)
        return MutationResult(target, changed=True)

    def mkdir(self, path: Path, *, parents: bool) -> MutationResult:
        """이미 존재하는 directory를 성공 replay로 처리합니다."""
        if parents and not path.parent.exists():
            raise UnsafeMutationError
        with guard_directory(path.parent, policy=self._path_policy):
            target = self._resolve(path).final_path
            existed = target.exists()
            target.mkdir(parents=False, exist_ok=True)
            target = self._resolve(path, require_exists=True).final_path
        return self._mutation_stat(target, changed=not existed)

    def _resolve(self, path: Path, *, require_exists: bool = False) -> SafeWindowsPath:
        return SafeWindowsPath.parse(path, policy=self._path_policy, require_exists=require_exists)

    def _mutation_stat(self, path: Path, *, changed: bool) -> MutationResult:
        metadata = path.stat()
        return MutationResult(path, changed, metadata.st_size, metadata.st_mtime_ns)

    def _file_matches(self, path: Path, expected: bytes) -> bool:
        if not path.is_file() or path.stat().st_size != len(expected):
            return False
        with open_verified_binary(path, policy=self._path_policy) as opened:
            return opened.stream.read(len(expected) + 1) == expected

    def _write_temporary(self, target: Path, data: bytes) -> Path:
        with tempfile.NamedTemporaryFile(
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temp_path = Path(stream.name)
            _ = stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        return temp_path

    def _copy_file(self, source: Path, destination: Path) -> Path:
        temp_path: Path | None = None
        try:
            with open_verified_binary(source, policy=self._path_policy) as opened:
                with tempfile.NamedTemporaryFile(
                    dir=destination.parent,
                    prefix=f".{destination.name}.",
                    suffix=".tmp",
                    delete=False,
                ) as target_stream:
                    temp_path = Path(target_stream.name)
                    shutil.copyfileobj(opened.stream, target_stream)
                    target_stream.flush()
                    os.fsync(target_stream.fileno())
                os.replace(  # noqa: PTH105 - guarded-parent atomic replace를 명시합니다.
                    temp_path,
                    destination,
                )
                temp_path = None
                return opened.final_path
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)


def _count_items(path: Path) -> int:
    if not path.is_dir() or path.is_symlink():
        return 1
    return 1 + sum(len(directories) + len(files) for _, directories, files in os.walk(path))


def _deny_bulk_delete(_path: Path, _item_count: int) -> bool:
    return False
