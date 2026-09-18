"""파일 시스템 worker의 엄격한 Pydantic 도구 입력 경계입니다."""

# pyright: reportImportCycles=false

from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, ClassVar, Literal, final, override

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, model_validator

from hermes_windows_bridge.worker.path_safety import (
    SafePathPolicy,
    SafeWindowsPath,
    guard_directory,
    open_verified_binary,
)

if TYPE_CHECKING:
    from hermes_windows_bridge.models.config import BridgeSettings, PolicySettings
    from hermes_windows_bridge.worker.filesystem import BulkDeleteAuthorizer, FilesystemWorker

type InlineOperation = Literal["read", "write"]

_READ: InlineOperation = "read"
_WRITE: InlineOperation = "write"
_ASCII_MAX = 127
_UTF8_ONE_BYTE_MAX = 0x7F
_UTF8_TWO_BYTE_MAX = 0x7FF
_UTF8_THREE_BYTE_MAX = 0xFFFF


@dataclass(frozen=True, slots=True)
class FilesystemLimits:
    """인라인 I/O 및 bulk delete의 정책 한도입니다."""

    max_inline_read_bytes: int
    max_inline_write_bytes: int
    bulk_delete_threshold: int
    approval_categories: frozenset[str]


@dataclass(frozen=True, slots=True)
class FileStat:
    """정책 검사를 통과한 파일 메타데이터입니다."""

    final_path: Path
    name: str
    size: int
    modified_time_ns: int
    kind: Literal["file", "directory"]


@dataclass(frozen=True, slots=True)
class UnavailableFileEntry:
    """목록에서 메타데이터를 조회하지 못한 항목과 비밀값 없는 이유입니다."""

    name: str
    reason: str


@dataclass(frozen=True, slots=True)
class ListResult:
    """조회 가능한 직접 자식과 조회하지 못한 항목을 구분한 목록입니다."""

    final_path: Path
    entries: tuple[FileStat, ...]
    unavailable_entries: tuple[UnavailableFileEntry, ...] = ()


@dataclass(frozen=True, slots=True)
class ReadResult:
    """UTF-8 또는 base64로 표현된 bounded read 결과입니다."""

    final_path: Path
    size: int
    modified_time_ns: int
    text: str | None = None
    base64_data: str | None = None


@dataclass(frozen=True, slots=True)
class MutationResult:
    """재실행 여부를 포함하는 파일 변경 결과입니다."""

    final_path: Path
    changed: bool
    size: int | None = None
    modified_time_ns: int | None = None


@dataclass(frozen=True, slots=True)
class BulkDeleteApprovalRequiredError(PermissionError):
    """설정된 bulk delete 경계에서 외부 승인이 필요합니다."""

    path: Path
    item_count: int

    @override
    def __str__(self) -> str:
        return f"bulk_delete approval required for {self.item_count} items: {self.path}"


@dataclass(frozen=True, slots=True)
class InlineSizeLimitError(ValueError):
    """인라인 파일 I/O 크기가 구성 한도를 초과했습니다."""

    operation: InlineOperation
    limit: int

    @override
    def __str__(self) -> str:
        return f"{self.operation}_size_limit: {self.limit}"


class InvalidBase64Error(ValueError):
    """Binary write payload가 canonical base64가 아닙니다."""

    @override
    def __str__(self) -> str:
        return "invalid_base64"


class UnsafeMutationError(PermissionError):
    """Handle-bound 구현이 없는 mutation 형태를 실패 폐쇄합니다."""

    @override
    def __str__(self) -> str:
        return "filesystem mutation cannot be performed safely"


class _Input(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)


def _parse_path(value: str | Path) -> Path:
    return Path(value)


type InputPath = Annotated[Path, BeforeValidator(_parse_path)]


def encode_utf8(value: str, *, max_bytes: int) -> bytes:
    """할당 전에 UTF-8 byte 수를 계산하고 구성 한도 안에서만 encode합니다."""
    byte_count = sum(_utf8_codepoint_size(character) for character in value)
    if byte_count > max_bytes:
        raise InlineSizeLimitError(_WRITE, max_bytes)
    encoded = value.encode("utf-8")
    if len(encoded) > max_bytes:
        raise InlineSizeLimitError(_WRITE, max_bytes)
    return encoded


def decode_base64(value: str, *, max_bytes: int) -> bytes:
    """할당 전 길이 제한과 canonical 표현을 만족하는 base64만 decode합니다."""
    max_encoded_length = ((max_bytes + 2) // 3) * 4
    if len(value) > max_encoded_length:
        raise InlineSizeLimitError(_WRITE, max_bytes)
    if len(value) % 4 != 0 or any(ord(character) > _ASCII_MAX for character in value):
        raise InvalidBase64Error
    try:
        decoded = base64.b64decode(value, validate=True)
    except binascii.Error as error:
        raise InvalidBase64Error from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise InvalidBase64Error
    if len(decoded) > max_bytes:
        raise InlineSizeLimitError(_WRITE, max_bytes)
    return decoded


def _utf8_codepoint_size(character: str) -> int:
    codepoint = ord(character)
    if codepoint <= _UTF8_ONE_BYTE_MAX:
        return 1
    if codepoint <= _UTF8_TWO_BYTE_MAX:
        return 2
    if codepoint <= _UTF8_THREE_BYTE_MAX:
        return 3
    return 4


def delete_safely(path: Path, *, policy: SafePathPolicy, recursive: bool) -> None:
    """Handle 검증된 snapshot만 삭제하고 새 항목이나 경로 교체에는 실패합니다."""
    safe = SafeWindowsPath.parse(path, policy=policy, require_exists=True)
    target = safe.final_path
    if target.is_dir():
        with guard_directory(path, policy=policy) as guarded:
            children = tuple(guarded.iterdir())
            if children and not recursive:
                guarded.rmdir()
            for child in children:
                delete_safely(child, policy=policy, recursive=True)
        latest = SafeWindowsPath.parse(path, policy=policy, require_exists=True).final_path
    else:
        with open_verified_binary(path, policy=policy) as opened:
            target = opened.final_path
        latest = SafeWindowsPath.parse(path, policy=policy, require_exists=True).final_path
    if os.path.normcase(latest) != os.path.normcase(target):
        raise UnsafeMutationError
    if latest.is_dir():
        latest.rmdir()
    else:
        latest.unlink()


class ListInput(_Input):
    """fs_list 입력입니다."""

    path: InputPath


class ReadInput(_Input):
    """fs_read/fs_stat 입력입니다."""

    path: InputPath
    offset: int = Field(default=0, ge=0)
    length: int | None = Field(default=None, ge=0)
    encoding: Literal["utf-8", "base64"] = "utf-8"


class WriteInput(_Input):
    """UTF-8 text 또는 작은 base64 binary 쓰기 입력입니다."""

    path: InputPath
    text: str | None = None
    base64_data: str | None = None

    @model_validator(mode="after")
    def require_exactly_one_payload(self) -> WriteInput:
        """Text와 binary payload의 모호한 조합을 거부합니다."""
        if (self.text is None) == (self.base64_data is None):
            message = "exactly one of text or base64_data is required"
            raise ValueError(message)
        return self


class MoveInput(_Input):
    """fs_move/fs_copy의 source와 destination입니다."""

    source: InputPath
    destination: InputPath


class DeleteInput(_Input):
    """단일 또는 recursive delete 입력입니다."""

    path: InputPath
    recursive: bool = False


class MkdirInput(_Input):
    """Directory 생성 입력입니다."""

    path: InputPath
    parents: bool = False


@final
class FilesystemTools:
    """모델 입력과 신뢰된 worker 호출을 분리하는 파일 도구 집합입니다."""

    def __init__(self, worker: FilesystemWorker) -> None:
        """신뢰된 logged-in-user worker를 연결합니다."""
        self._worker = worker

    @classmethod
    def from_settings(
        cls,
        *,
        bridge: BridgeSettings,
        policy: PolicySettings,
        bulk_delete_authorizer: BulkDeleteAuthorizer | None = None,
    ) -> FilesystemTools:
        """Typed production 설정에서 worker와 tool adapter를 함께 구성합니다."""
        from hermes_windows_bridge.worker.filesystem import (  # noqa: PLC0415 - cycle break
            FilesystemWorker,
        )

        worker = FilesystemWorker.from_settings(
            bridge=bridge,
            policy=policy,
            bulk_delete_authorizer=bulk_delete_authorizer,
        )
        return cls(worker)

    def fs_list(self, request: ListInput) -> ListResult:
        """허용된 directory를 나열합니다."""
        return self._worker.list(request.path)

    def fs_stat(self, request: ReadInput) -> FileStat:
        """허용된 path의 metadata를 반환합니다."""
        return self._worker.stat(request.path)

    def fs_read(self, request: ReadInput) -> ReadResult:
        """허용된 file의 bounded 범위를 읽습니다."""
        return self._worker.read(
            request.path,
            offset=request.offset,
            length=request.length,
            encoding=request.encoding,
        )

    def fs_write(self, request: WriteInput) -> MutationResult:
        """Text 또는 base64 payload를 atomic replace로 기록합니다."""
        max_bytes = self._worker.max_inline_write_bytes
        data = (
            encode_utf8(request.text, max_bytes=max_bytes)
            if request.text is not None
            else decode_base64(request.base64_data or "", max_bytes=max_bytes)
        )
        return self._worker.write(request.path, data)

    def fs_move(self, request: MoveInput) -> MutationResult:
        """허용된 두 path 사이에서 항목을 이동합니다."""
        return self._worker.move(request.source, request.destination)

    def fs_copy(self, request: MoveInput) -> MutationResult:
        """허용된 두 path 사이에서 항목을 복사합니다."""
        return self._worker.copy(request.source, request.destination)

    def fs_delete(self, request: DeleteInput) -> MutationResult:
        """필요할 때 외부 bulk 승인을 확인한 뒤 항목을 삭제합니다."""
        return self._worker.delete(request.path, recursive=request.recursive)

    def fs_mkdir(self, request: MkdirInput) -> MutationResult:
        """허용된 path에 directory를 생성합니다."""
        return self._worker.mkdir(request.path, parents=request.parents)
