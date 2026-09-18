"""Named Pipe DACL 사양과 pywin32 security descriptor 경계입니다."""

# pyright: reportMissingModuleSource=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false
# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final, override

if TYPE_CHECKING:
    import _win32typing

EVERYONE_SID: Final = "S-1-1-0"
AUTHENTICATED_USERS_SID: Final = "S-1-5-11"
INTERACTIVE_USERS_SID: Final = "S-1-5-4"
BUILTIN_USERS_SID: Final = "S-1-5-32-545"
LOCAL_SERVICE_SID: Final = "S-1-5-19"
LOCAL_SYSTEM_SID: Final = "S-1-5-18"
ADMINISTRATORS_SID: Final = "S-1-5-32-544"

# FILE_APPEND_DATA/FILE_CREATE_PIPE_INSTANCE(0x4)는 의도적으로 제외합니다.
PIPE_CLIENT_ACCESS: Final = 0x0012019B
_SID_PATTERN: Final = re.compile(r"^S-1-[0-9]+(?:-[0-9]+)+$")
_FORBIDDEN_SIDS: Final = frozenset(
    {EVERYONE_SID, AUTHENTICATED_USERS_SID, INTERACTIVE_USERS_SID, BUILTIN_USERS_SID}
)


@dataclass(frozen=True, slots=True)
class PipeAcl:
    """Named Pipe에 허용할 정확한 SID 집합입니다."""

    allowed_sids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PipeAclError(Exception):
    """SID가 잘못됐거나 pipe 정책에 허용되지 않습니다."""

    sid: str
    reason: str

    @override
    def __str__(self) -> str:
        """거부된 SID와 이유를 표시합니다."""
        return f"named-pipe SID {self.sid!r} rejected: {self.reason}"


class PipeAclVerificationError(Exception):
    """DACL 불일치를 전파하며 exception traceback 연결을 위해 내부 mutation을 허용합니다."""

    reason: str

    def __init__(self, reason: str) -> None:
        """비밀을 포함하지 않는 안정된 실패 이유만 보관합니다."""
        self.reason = reason
        super().__init__(reason)

    @override
    def __str__(self) -> str:
        """외부 identity를 노출하지 않는 검증 실패 이유를 표시합니다."""
        return f"named-pipe ACL verification failed: {self.reason}"


class PipeAclProbeState(StrEnum):
    """현재 Gateway client handle에서 읽은 불투명 DACL 관찰 결과입니다."""

    VERIFIED = "verified"
    MISMATCH = "mismatch"
    UNVERIFIED = "unverified"


def build_worker_pipe_acl(target_user_sid: str) -> PipeAcl:
    """Gateway, target user, Administrators, SYSTEM만 Worker pipe에 허용합니다."""
    target_sid = _parse_sid(target_user_sid)
    if target_sid in _FORBIDDEN_SIDS:
        raise PipeAclError(sid=target_sid, reason="broad principals are forbidden")
    return _make_acl((LOCAL_SERVICE_SID, target_sid, ADMINISTRATORS_SID, LOCAL_SYSTEM_SID))


def build_privileged_pipe_acl() -> PipeAcl:
    """Gateway, Administrators, SYSTEM만 Privileged Helper pipe에 허용합니다."""
    return _make_acl((LOCAL_SERVICE_SID, ADMINISTRATORS_SID, LOCAL_SYSTEM_SID))


def require_allowed_sid(acl: PipeAcl, actual_sid: str) -> str:
    """실제 peer SID가 DACL의 명시적 allowlist에 있는지 확인합니다."""
    normalized = _parse_sid(actual_sid)
    if normalized not in acl.allowed_sids:
        raise PipeAclError(sid=normalized, reason="peer identity is not explicitly allowed")
    return normalized


def require_expected_sid(expected_sid: str, actual_sid: str) -> str:
    """실제 peer SID가 연결 방향별 단일 expected SID와 같은지 확인합니다."""
    expected = _parse_sid(expected_sid)
    actual = _parse_sid(actual_sid)
    if actual != expected:
        raise PipeAclError(sid=actual, reason=f"peer identity must be {expected}")
    return actual


def build_security_attributes(acl: PipeAcl) -> _win32typing.PySECURITY_ATTRIBUTES:
    """순수 ACL 사양을 explicit pywin32 DACL로 변환합니다."""
    import pywintypes  # noqa: PLC0415 - portable pure ACL import를 유지합니다.
    import win32security  # noqa: PLC0415 - Windows API 경계를 이 함수로 격리합니다.

    descriptor = win32security.SECURITY_DESCRIPTOR()
    discretionary_acl = win32security.ACL()
    for sid_text in acl.allowed_sids:
        sid = win32security.ConvertStringSidToSid(sid_text)
        discretionary_acl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            PIPE_CLIENT_ACCESS,
            sid,
        )
    descriptor.SetSecurityDescriptorDacl(
        True,  # noqa: FBT003 - Win32 positional API입니다.
        discretionary_acl,
        False,  # noqa: FBT003 - Win32 positional API입니다.
    )
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    return attributes


def security_descriptor_sids(
    attributes: _win32typing.PySECURITY_ATTRIBUTES,
) -> frozenset[str]:
    """실제 pywin32 security descriptor의 allow ACE SID를 열거합니다."""
    return descriptor_acl_sids(attributes.SECURITY_DESCRIPTOR)


def descriptor_acl_sids(
    descriptor: _win32typing.PySECURITY_DESCRIPTOR,
) -> frozenset[str]:
    """실제 pywin32 security descriptor의 DACL SID를 열거합니다."""
    import win32security  # noqa: PLC0415 - Windows API 경계를 이 함수로 격리합니다.

    discretionary_acl = descriptor.GetSecurityDescriptorDacl()
    return frozenset(
        win32security.ConvertSidToStringSid(discretionary_acl.GetAce(index)[2])
        for index in range(discretionary_acl.GetAceCount())
    )


def verify_pipe_security_descriptor(
    expected: PipeAcl,
    descriptor: _win32typing.PySECURITY_DESCRIPTOR,
) -> None:
    """DACL의 ACE 전체가 Bridge가 만든 allow template과 정확히 같은지 확인합니다."""
    import win32security  # noqa: PLC0415 - Windows descriptor 경계를 이 함수로 격리합니다.

    discretionary_acl = descriptor.GetSecurityDescriptorDacl()
    if discretionary_acl is None:
        raise PipeAclVerificationError(reason="DACL is null")
    actual_aces = tuple(
        discretionary_acl.GetAce(index) for index in range(discretionary_acl.GetAceCount())
    )
    template_headers = tuple(
        (win32security.ACCESS_ALLOWED_ACE_TYPE, 0, PIPE_CLIENT_ACCESS, sid)
        for sid in expected.allowed_sids
    )
    actual_headers = tuple((ace[0][0], ace[0][1], ace[1]) for ace in actual_aces)
    if actual_headers != tuple(header[:3] for header in template_headers):
        raise PipeAclVerificationError(reason="DACL ACE template mismatch")
    actual_sids = tuple(win32security.ConvertSidToStringSid(ace[2]) for ace in actual_aces)
    if actual_sids != expected.allowed_sids:
        raise PipeAclVerificationError(reason="DACL ACE template mismatch")


def read_pipe_security_descriptor(
    handle: int,
) -> _win32typing.PySECURITY_DESCRIPTOR:
    """호출자가 이미 소유한 pipe handle에서만 실제 DACL descriptor를 읽습니다."""
    import pywintypes  # noqa: PLC0415 - pywin32 오류를 typed failure로 바꿉니다.
    import win32security  # noqa: PLC0415 - Windows kernel-object 경계를 이 함수로 격리합니다.

    try:
        return win32security.GetSecurityInfo(
            handle,
            win32security.SE_KERNEL_OBJECT,
            win32security.DACL_SECURITY_INFORMATION,
        )
    except (OSError, pywintypes.error) as exc:
        raise PipeAclVerificationError(reason="GetSecurityInfo failed") from exc


def read_server_pipe_security_descriptor(
    handle: int,
) -> _win32typing.PySECURITY_DESCRIPTOR:
    """기존 server 검증 caller와의 호환용 named alias입니다."""
    return read_pipe_security_descriptor(handle)


def observe_client_pipe_acl(handle: int, expected: PipeAcl) -> PipeAclProbeState:
    """이미 연결된 Gateway client handle의 DACL을 descriptor 비공개로 exact 검증합니다."""
    try:
        verify_pipe_security_descriptor(expected, read_pipe_security_descriptor(handle))
    except PipeAclVerificationError as error:
        match error.reason:
            case "DACL is null" | "DACL ACE template mismatch":
                return PipeAclProbeState.MISMATCH
            case "GetSecurityInfo failed":
                return PipeAclProbeState.UNVERIFIED
            case _:
                return PipeAclProbeState.UNVERIFIED
    return PipeAclProbeState.VERIFIED


def current_process_sid() -> str:
    """실제 Windows process token의 user SID를 반환합니다."""
    import win32api  # noqa: PLC0415 - Windows API 경계를 이 함수로 격리합니다.
    import win32security  # noqa: PLC0415 - Windows API 경계를 이 함수로 격리합니다.

    token: int = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(),
        win32security.TOKEN_QUERY,
    )
    try:
        token_user: tuple[_win32typing.PySID, int] = win32security.GetTokenInformation(
            token,
            win32security.TokenUser,
        )
        return win32security.ConvertSidToStringSid(token_user[0])
    finally:
        win32api.CloseHandle(token)


def _make_acl(sids: tuple[str, ...]) -> PipeAcl:
    normalized = tuple(dict.fromkeys(_parse_sid(sid) for sid in sids))
    forbidden = _FORBIDDEN_SIDS.intersection(normalized)
    if forbidden:
        raise PipeAclError(sid=min(forbidden), reason="broad principals are forbidden")
    return PipeAcl(allowed_sids=normalized)


def _parse_sid(sid: str) -> str:
    normalized = sid.strip().upper()
    if _SID_PATTERN.fullmatch(normalized) is None:
        raise PipeAclError(sid=sid, reason="invalid SID syntax")
    return normalized
