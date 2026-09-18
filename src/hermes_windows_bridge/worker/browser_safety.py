"""Browser profile, query, output redaction의 순수 fail-closed 경계입니다."""

from __future__ import annotations

import os
from ctypes import WINFUNCTYPE, WinDLL, create_unicode_buffer, get_last_error, wintypes
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal, Protocol, Self, cast, final, override
from urllib.parse import urlsplit, urlunsplit

if TYPE_CHECKING:
    from types import TracebackType

    from pydantic import JsonValue

_SECRET_KEY_FRAGMENTS: Final = frozenset(
    ("authorization", "cookie", "credential", "password", "secret", "session", "token",
     "apikey", "accesskey", "privatekey", "clientsecret")
)
_FILE_SHARE_READ: Final = 0x00000001
_FILE_SHARE_WRITE: Final = 0x00000002
_FILE_READ_ATTRIBUTES: Final = 0x00000080
_DELETE: Final = 0x00010000
_OPEN_EXISTING: Final = 3
_FILE_FLAG_BACKUP_SEMANTICS: Final = 0x02000000
_FINAL_PATH_BUFFER_CHARS: Final = 32_768
_INVALID_HANDLE_VALUE: Final = cast("int", wintypes.HANDLE(-1).value)


class _CreateFile(Protocol):
    def __call__(  # noqa: PLR0913, PLR0917 - Win32 CreateFileW ABI
        self,
        file_name: str,
        desired_access: int,
        share_mode: int,
        security_attributes: None,
        creation_disposition: int,
        flags_and_attributes: int,
        template_file: None,
    ) -> int | None: ...


class _WideBuffer(Protocol):
    value: str


class _GetFinalPath(Protocol):
    def __call__(self, handle: int, buffer: _WideBuffer, size: int, flags: int) -> int: ...


class _CloseHandle(Protocol):
    def __call__(self, handle: int) -> int: ...

_KERNEL32 = WinDLL("kernel32", use_last_error=True)
_CREATE_FILE = cast(
    "_CreateFile",
    WINFUNCTYPE(
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )(("CreateFileW", _KERNEL32)),
)
_GET_FINAL_PATH = cast(
    "_GetFinalPath",
    WINFUNCTYPE(
        wintypes.DWORD,
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    )(("GetFinalPathNameByHandleW", _KERNEL32)),
)
_CLOSE_HANDLE = cast(
    "_CloseHandle",
    WINFUNCTYPE(wintypes.BOOL, wintypes.HANDLE)(("CloseHandle", _KERNEL32)),
)


@dataclass(frozen=True, slots=True)
class BrowserStatus:
    """브라우저 실행 상태와 안전한 현재 위치입니다."""

    running: bool
    url: str | None
    profile_dir: Path


@dataclass(frozen=True, slots=True)
class BrowserContentResult:
    """비밀값이 제거된 bounded open-world page content입니다."""

    url: str
    content: str
    truncated: bool
    untrusted_content: bool = True


@dataclass(frozen=True, slots=True)
class BrowserEvaluationResult:
    """비밀 key/value가 제거된 read-only query 결과입니다."""

    url: str
    value: JsonValue
    untrusted_content: bool = True


type BrowserErrorCode = Literal[
    "invalid_profile",
    "invalid_timeout",
    "browser_not_open",
    "unsafe_evaluation",
    "output_limit",
    "operation_cancelled",
]


@dataclass(frozen=True, slots=True)
class BrowserWorkerError(RuntimeError):
    """Fail-closed browser 경계의 machine-readable 오류입니다."""

    code: BrowserErrorCode

    @override
    def __str__(self) -> str:
        return self.code


@final
class BrowserProfileGuard:
    """검증된 전용 profile 객체의 rename/delete를 수명 동안 막습니다."""

    __slots__ = ("_handles", "profile_dir")

    def __init__(self, profile_dir: Path) -> None:
        """전용 parent/profile을 만들고 검증된 객체 handle을 확보합니다."""
        self.profile_dir = validated_profile_dir(profile_dir)
        self.profile_dir.parent.mkdir(parents=True, exist_ok=True)
        self.profile_dir.mkdir(exist_ok=True)
        self._handles: tuple[int, int] | tuple[()] = ()
        parent_handle = _open_directory_handle(self.profile_dir.parent)
        try:
            profile_handle = _open_directory_handle(self.profile_dir)
        except OSError, BrowserWorkerError:
            _ = _CLOSE_HANDLE(parent_handle)
            raise
        try:
            _require_handle_path(parent_handle, self.profile_dir.parent)
            _require_handle_path(profile_handle, self.profile_dir)
        except OSError, BrowserWorkerError:
            _ = _CLOSE_HANDLE(profile_handle)
            _ = _CLOSE_HANDLE(parent_handle)
            raise
        self._handles = (parent_handle, profile_handle)

    def __enter__(self) -> Self:
        """Guard handle이 유지되는 context를 반환합니다."""
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Context 종료 시 두 directory handle을 반환합니다."""
        del exception_type, exception, traceback
        self.close()

    def close(self) -> None:
        """보유한 Windows directory handle을 정확히 한 번 반환합니다."""
        handles, self._handles = self._handles, ()
        for handle in reversed(handles):
            _ = _CLOSE_HANDLE(handle)


def _open_directory_handle(path: Path) -> int:
    handle = _CREATE_FILE(
        str(path),
        _FILE_READ_ATTRIBUTES | _DELETE,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )
    if handle in (None, _INVALID_HANDLE_VALUE):
        raise BrowserWorkerError("invalid_profile") from OSError(get_last_error())  # noqa: EM101
    return handle


def _require_handle_path(handle: int, expected: Path) -> None:
    buffer = create_unicode_buffer(_FINAL_PATH_BUFFER_CHARS)
    length = _GET_FINAL_PATH(handle, buffer, len(buffer), 0)
    if length == 0 or length >= len(buffer):
        raise BrowserWorkerError("invalid_profile") from OSError(get_last_error())  # noqa: EM101
    final_path = cast("str", buffer.value)
    if final_path.startswith("\\\\?\\UNC\\"):
        final_path = "\\\\" + final_path[8:]
    elif final_path.startswith("\\\\?\\"):
        final_path = final_path[4:]
    if os.path.normcase(str(Path(final_path).resolve())) != os.path.normcase(
        str(expected.resolve())
    ):
        raise BrowserWorkerError("invalid_profile")  # noqa: EM101


class BrowserReadQuery(StrEnum):
    """Caller code 실행 없이 지원하는 read-only browser query입니다."""

    TITLE = "document.title"
    URL = "document.URL"
    LOCATION = "location.href"
    BODY_TEXT = "document.body.innerText"


def parse_browser_read_query(expression: str) -> BrowserReadQuery:
    """정확히 정의된 query 문자열만 enum으로 파싱합니다."""
    try:
        return BrowserReadQuery(expression)
    except ValueError as error:
        raise BrowserWorkerError("unsafe_evaluation") from error  # noqa: EM101


def validated_profile_dir(profile_dir: Path) -> Path:
    """Resolved LOCALAPPDATA 아래의 전용 non-link profile만 반환합니다."""
    local_value = os.environ.get("LOCALAPPDATA")
    if not local_value:
        raise BrowserWorkerError("invalid_profile")  # noqa: EM101
    local_raw = Path(local_value).absolute()
    profile_raw = profile_dir.absolute()
    try:
        relative = profile_raw.relative_to(local_raw)
        local_resolved = local_raw.resolve()
        profile_resolved = profile_raw.resolve()
        _ = profile_resolved.relative_to(local_resolved)
    except (OSError, ValueError) as error:
        raise BrowserWorkerError("invalid_profile") from error  # noqa: EM101
    current = local_raw
    for part in relative.parts:
        current /= part
        if current.is_symlink() or current.is_junction():
            raise BrowserWorkerError("invalid_profile")  # noqa: EM101
    suffix = tuple(part.casefold() for part in profile_resolved.parts)[-2:]
    if suffix != ("hermeswindowsbridge", "browser-profile"):
        raise BrowserWorkerError("invalid_profile")  # noqa: EM101
    return profile_resolved


def safe_browser_url(url: str) -> str:
    """URL에서 userinfo, query, fragment를 제외합니다."""
    parsed = urlsplit(url)
    hostname = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port is not None else ""
    return urlunsplit((parsed.scheme, hostname + port, parsed.path, "", ""))


def bounded_utf8(value: str, limit: int) -> tuple[str, bool]:
    """UTF-8 byte 상한에서 깨진 code point 없이 자릅니다."""
    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        return value, False
    return encoded[:limit].decode("utf-8", errors="ignore"), True


def redact_browser_text(value: str, secrets: frozenset[str]) -> str:
    """수집된 exact secret 값을 길이 역순으로 제거합니다."""
    redacted = value
    for secret in sorted(secrets, key=len, reverse=True):
        redacted = redacted.replace(secret, "[REDACTED]")
    return redacted


def _secret_shaped_key(key: str) -> bool:
    normalized = "".join(character for character in key.casefold() if character.isalnum())
    return any(fragment in normalized for fragment in _SECRET_KEY_FRAGMENTS)


def redact_browser_json(value: JsonValue, secrets: frozenset[str]) -> JsonValue:
    """Page JSON에서 secret-shaped key와 알려진 값을 재귀 제거합니다."""
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return redact_browser_text(value, secrets)
    if isinstance(value, list):
        return [redact_browser_json(item, secrets) for item in value]
    return {
        key: "[REDACTED]"
        if _secret_shaped_key(key)
        else redact_browser_json(item, secrets)
        for key, item in value.items()
    }
