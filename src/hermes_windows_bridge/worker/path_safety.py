"""파일 작업 전에 Windows 경로를 최종 대상 기준으로 제한합니다."""

from __future__ import annotations

import msvcrt
import os
import re
from ctypes import WinDLL, addressof, create_unicode_buffer, get_last_error
from ctypes.wintypes import DWORD, HANDLE, LPCWSTR, LPVOID, LPWSTR
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, Final, override

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType
    from typing import Self

_KERNEL32: Final = WinDLL("kernel32", use_last_error=True)
_GET_FINAL_PATH: Callable[[HANDLE, LPWSTR | None, int, int], int] = (
    _KERNEL32.GetFinalPathNameByHandleW
)
_GET_FINAL_PATH.argtypes = (HANDLE, LPWSTR, DWORD, DWORD)
_GET_FINAL_PATH.restype = DWORD
_CREATE_FILE: Callable[[str, int, int, LPVOID | None, int, int, int | None], int] = (
    _KERNEL32.CreateFileW
)
_CREATE_FILE.argtypes = (LPCWSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE)
_CREATE_FILE.restype = HANDLE
_CLOSE_HANDLE: Callable[[int], bool] = _KERNEL32.CloseHandle
_CLOSE_HANDLE.argtypes = (HANDLE,)
_CLOSE_HANDLE.restype = bool

_FILE_READ_ATTRIBUTES: Final = 0x80
_FILE_SHARE_READ_WRITE: Final = 0x3
_OPEN_EXISTING: Final = 3
_FILE_FLAG_BACKUP_SEMANTICS: Final = 0x02000000
_INVALID_HANDLE_VALUE: Final = -1
_OPEN_HANDLE_FAILED: Final = "CreateFileW directory guard failed"
_FINAL_HANDLE_FAILED: Final = "GetFinalPathNameByHandleW failed"
_FINAL_HANDLE_EMPTY: Final = "GetFinalPathNameByHandleW returned no path"

_DEVICE_PREFIXES: Final = ("\\\\.\\", "\\\\?\\", "\\??\\")
_RESERVED_DEVICE: Final = re.compile(
    r"^(?:CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])$",
    re.IGNORECASE,
)
_ADS_DENIED: Final = "alternate_data_stream_denied"
_DEVICE_DENIED: Final = "device_namespace_denied"
_INVALID_ROOT: Final = "invalid_allowed_root"
_MALFORMED: Final = "malformed_path"
_OUTSIDE_ROOTS: Final = "outside_allowed_roots"
_ROOT_NOT_DIRECTORY: Final = "allowed_root_not_directory"
_ROOTS_EMPTY: Final = "allowed_roots_empty"
_UNC_DENIED: Final = "unc_denied"


@dataclass(frozen=True, slots=True)
class PathPolicyError(PermissionError):
    """신뢰되지 않은 경로가 파일 정책을 벗어났습니다."""

    reason: str
    path: str

    @override
    def __str__(self) -> str:
        return f"{self.reason}: {self.path}"


@dataclass(frozen=True, slots=True)
class SafePathPolicy:
    """최종 경로가 머물 수 있는 로컬 루트와 namespace 정책입니다."""

    allowed_roots: tuple[Path, ...]
    deny_device_paths: bool = True
    allow_unc: bool = False
    allow_alternate_data_streams: bool = False

    def __post_init__(self) -> None:
        """허용 루트 자체도 final directory로 동결합니다."""
        if not self.allowed_roots:
            raise PathPolicyError(_ROOTS_EMPTY, "")
        resolved: list[Path] = []
        for root in self.allowed_roots:
            try:
                final_root = root.resolve(strict=True)
            except (OSError, RuntimeError) as error:
                raise PathPolicyError(_INVALID_ROOT, os.fspath(root)) from error
            if not final_root.is_dir():
                raise PathPolicyError(_ROOT_NOT_DIRECTORY, os.fspath(root))
            resolved.append(final_root)
        object.__setattr__(self, "allowed_roots", tuple(resolved))


@dataclass(frozen=True, slots=True)
class SafeWindowsPath:
    """정책 검사 시점에 OS가 해석한 canonical 파일 경로입니다."""

    requested_path: Path
    final_path: Path

    @classmethod
    def parse(
        cls,
        raw_path: str | Path,
        *,
        policy: SafePathPolicy,
        require_exists: bool = False,
    ) -> SafeWindowsPath:
        """Namespace를 거부한 뒤 reparse-aware final path를 허용 루트와 비교합니다."""
        raw_text = os.fspath(raw_path)
        _validate_namespace(raw_text, policy)
        requested = Path(raw_text)
        try:
            final_path = requested.resolve(strict=require_exists)
        except FileNotFoundError:
            raise
        except (OSError, RuntimeError, ValueError) as error:
            raise PathPolicyError(_MALFORMED, raw_text) from error
        if not any(_is_within(final_path, root) for root in policy.allowed_roots):
            raise PathPolicyError(_OUTSIDE_ROOTS, raw_text)
        return cls(requested_path=requested, final_path=final_path)


@dataclass(frozen=True, slots=True)
class VerifiedBinaryFile:
    """OS handle의 실제 final path가 정책을 통과한 binary stream입니다."""

    stream: BinaryIO
    final_path: Path

    def __enter__(self) -> Self:
        """검증된 stream 소유권을 현재 context에 유지합니다."""
        return self

    def __exit__(
        self,
        _error_type: type[BaseException] | None,
        _error: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        """Context 종료 시 file handle을 닫습니다."""
        self.stream.close()


@dataclass(frozen=True, slots=True)
class DirectoryGuard:
    """교체 불가 share mode로 열린 directory chain입니다."""

    handles: tuple[int, ...]
    final_path: Path

    def __enter__(self) -> Path:
        """잠긴 chain이 가리키는 final directory를 반환합니다."""
        return self.final_path

    def __exit__(
        self,
        _error_type: type[BaseException] | None,
        _error: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        """안쪽부터 directory handle 잠금을 해제합니다."""
        for handle in reversed(self.handles):
            _ = _CLOSE_HANDLE(handle)


def open_verified_binary(
    raw_path: str | Path,
    *,
    policy: SafePathPolicy,
) -> VerifiedBinaryFile:
    """열린 handle의 final path를 재검증하고 같은 handle을 호출자에게 제공합니다."""
    safe = SafeWindowsPath.parse(raw_path, policy=policy, require_exists=True)
    stream = safe.final_path.open("rb")
    try:
        handle = msvcrt.get_osfhandle(stream.fileno())
        actual = _normalize_handle_path(_final_path_from_handle(handle))
        _require_allowed(actual, raw_path=os.fspath(raw_path), policy=policy)
    except OSError, PathPolicyError:
        stream.close()
        raise
    return VerifiedBinaryFile(stream=stream, final_path=actual)


def guard_directory(
    raw_path: str | Path,
    *,
    policy: SafePathPolicy,
) -> DirectoryGuard:
    """Root부터 target까지 directory handle을 잠가 reparse 교체를 막습니다."""
    safe = SafeWindowsPath.parse(raw_path, policy=policy, require_exists=True)
    root = max(
        (item for item in policy.allowed_roots if _is_within(safe.final_path, item)),
        key=lambda item: len(item.parts),
    )
    relative = safe.final_path.relative_to(root)
    guarded_paths: list[Path] = [root]
    for part in relative.parts:
        guarded_paths.append(guarded_paths[-1] / part)
    handles: list[int] = []
    final_directory = root
    try:
        for directory in guarded_paths:
            handle = _open_directory_handle(directory)
            handles.append(handle)
            final_directory = _normalize_handle_path(_final_path_from_handle(handle))
            _require_allowed(final_directory, raw_path=os.fspath(raw_path), policy=policy)
        latest = SafeWindowsPath.parse(raw_path, policy=policy, require_exists=True).final_path
        _require_same_path(latest, final_directory, raw_path=os.fspath(raw_path))
    except OSError, PathPolicyError:
        for handle in reversed(handles):
            _ = _CLOSE_HANDLE(handle)
        raise
    return DirectoryGuard(handles=tuple(handles), final_path=final_directory)


def _validate_namespace(raw_path: str, policy: SafePathPolicy) -> None:
    if not raw_path or "\0" in raw_path:
        raise PathPolicyError(_MALFORMED, raw_path)
    windows_path = raw_path.replace("/", "\\")
    folded = windows_path.casefold()
    if policy.deny_device_paths and folded.startswith(_DEVICE_PREFIXES):
        raise PathPolicyError(_DEVICE_DENIED, raw_path)
    if not policy.allow_unc and windows_path.startswith("\\\\"):
        raise PathPolicyError(_UNC_DENIED, raw_path)
    colon_indexes = [index for index, character in enumerate(windows_path) if character == ":"]
    if not policy.allow_alternate_data_streams and any(index != 1 for index in colon_indexes):
        raise PathPolicyError(_ADS_DENIED, raw_path)
    components = (
        component.rstrip(" .").split(".", maxsplit=1)[0] for component in windows_path.split("\\")
    )
    if policy.deny_device_paths and any(_RESERVED_DEVICE.fullmatch(item) for item in components):
        raise PathPolicyError(_DEVICE_DENIED, raw_path)


def _is_within(path: Path, root: Path) -> bool:
    try:
        common = os.path.commonpath((os.fspath(path), os.fspath(root)))
    except ValueError:
        return False
    return os.path.normcase(common) == os.path.normcase(os.fspath(root))


def _require_allowed(path: Path, *, raw_path: str, policy: SafePathPolicy) -> None:
    if not any(_is_within(path, root) for root in policy.allowed_roots):
        raise PathPolicyError(_OUTSIDE_ROOTS, raw_path)


def _require_same_path(latest: Path, opened: Path, *, raw_path: str) -> None:
    if os.path.normcase(latest) != os.path.normcase(opened):
        raise PathPolicyError(_OUTSIDE_ROOTS, raw_path)


def _normalize_handle_path(raw_path: str) -> Path:
    folded = raw_path.casefold()
    if folded.startswith("\\\\?\\unc\\"):
        return Path(f"\\\\{raw_path[8:]}")
    if folded.startswith("\\\\?\\"):
        return Path(raw_path[4:])
    return Path(raw_path)


def _final_path_from_handle(handle: int) -> str:
    required = _GET_FINAL_PATH(HANDLE(handle), None, 0, 0)
    if required == 0:
        raise OSError(get_last_error(), _FINAL_HANDLE_FAILED)
    buffer = create_unicode_buffer(required + 1)
    pointer = LPWSTR(addressof(buffer))
    copied = _GET_FINAL_PATH(HANDLE(handle), pointer, len(buffer), 0)
    if copied == 0 or copied >= len(buffer):
        raise OSError(get_last_error(), _FINAL_HANDLE_FAILED)
    value = pointer.value
    if value is None:
        raise OSError(get_last_error(), _FINAL_HANDLE_EMPTY)
    return value


def _open_directory_handle(path: Path) -> int:
    handle = _CREATE_FILE(
        os.fspath(path),
        _FILE_READ_ATTRIBUTES,
        _FILE_SHARE_READ_WRITE,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        raise OSError(get_last_error(), _OPEN_HANDLE_FAILED, os.fspath(path))
    return handle
