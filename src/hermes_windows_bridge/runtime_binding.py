"""Protected installer-produced runtime binding boundary."""

# pyright: reportMissingModuleSource=false, reportUnknownMemberType=false

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, final, override

from pydantic import TypeAdapter, ValidationError

_PREFIX: Final = "HermesWindowsBridgeEval-"
_BINDING_DIRECTORY: Final = "bindings"
_RUNTIME_DIRECTORY: Final = "HermesWindowsBridge"
_CONFIG_NAME: Final = "config.yaml"
_POLICY_NAME: Final = "policy.yaml"
_SHA256_PATTERN: Final = re.compile(r"^[0-9a-f]{64}$", flags=re.ASCII)
_NONCE_PATTERN: Final = re.compile(r"^[0-9a-f]{32}$", flags=re.ASCII)
_REPARSE_ATTRIBUTE: Final = 0x400
_CSIDL_PROGRAM_FILES: Final = 0x0026
_CSIDL_COMMON_APPDATA: Final = 0x0023
_MAX_BINDING_BYTES: Final = 64 * 1024
_MAX_CONFIG_BYTES: Final = 1_024 * 1_024
_SID_PATTERN: Final = re.compile(r"^S-1-(?:0|[1-9][0-9]*)(?:-[0-9]+)+$", flags=re.ASCII)
_SERVICE_SIDS: Final = frozenset({"S-1-5-18", "S-1-5-19", "S-1-5-20"})
_TRUSTED_OWNER_SIDS: Final = frozenset({"S-1-5-18", "S-1-5-32-544"})


class RuntimeProfile(StrEnum):
    """설치자가 만든 런타임 바인딩 프로필입니다."""

    GATEWAY = "gateway"
    PRIVILEGED = "privileged"
    WORKER = "worker"


@final
class RuntimeBindingError(Exception):
    """신뢰할 수 있는 시작 선택을 만들지 못했습니다."""

    reason: str

    def __init__(self, *, reason: str) -> None:
        """Traceback 할당을 막지 않도록 고정된 거부 사유만 보관합니다."""
        super().__init__()
        self.reason = reason

    @override
    def __str__(self) -> str:
        """비밀 없는 고정 시작 실패를 반환합니다."""
        return f"runtime binding rejected: {self.reason}"


@dataclass(frozen=True, slots=True)
class RuntimeRoots:
    """정확한 바인딩과 런타임 위치를 유도하는 OS 루트입니다."""

    program_files: Path
    program_data: Path


@dataclass(frozen=True, slots=True)
class RuntimeBinding:
    """재검증된 완전 시작 선택이며 Worker SID는 private 값입니다."""

    profile: RuntimeProfile
    context_nonce: str
    config_path: Path
    config_sha256: str
    worker_sid: str
    policy_path: Path | None = None
    policy_sha256: str | None = None


def parse_runtime_binding_args(argv: tuple[str, ...]) -> tuple[Path, str] | None:
    """Legacy 빈 argv 또는 정확한 binding/hash 쌍만 허용합니다."""
    if not argv:
        return None
    if (
        len(argv) != _BINDING_ARG_COUNT
        or argv[0] != "--runtime-binding"
        or argv[2] != "--runtime-binding-sha256"
    ):
        raise RuntimeBindingError(reason="argv")
    binding_path, binding_sha256 = argv[1], argv[3]
    if (
        not binding_path
        or _contains_dot_segments(binding_path)
        or _SHA256_PATTERN.fullmatch(binding_sha256) is None
    ):
        raise RuntimeBindingError(reason="argv")
    return Path(binding_path), binding_sha256


def load_runtime_binding(
    profile: RuntimeProfile,
    binding_path: Path,
    binding_sha256: str,
    *,
    roots: RuntimeRoots | None = None,
) -> RuntimeBinding:
    """설치자 바인딩 하나를 파싱하고 선택된 모든 입력 해시를 다시 확인합니다."""
    active_roots = _runtime_roots() if roots is None else roots
    binding_bytes = _read_protected_bytes(binding_path, maximum_bytes=_MAX_BINDING_BYTES)
    payload = _load_exact_json(binding_bytes)
    binding = _parse_binding(profile, payload, binding_path, active_roots)
    if _sha256_bytes(binding_bytes) != binding_sha256:
        raise RuntimeBindingError(reason="binding_hash")
    _recheck_content(binding.config_path, binding.config_sha256, "config_hash")
    if binding.policy_path is not None and binding.policy_sha256 is not None:
        _recheck_content(binding.policy_path, binding.policy_sha256, "policy_hash")
    return binding


def _runtime_roots() -> RuntimeRoots:
    """환경 변수가 아닌 Windows 특수 폴더에서 machine 루트를 구합니다."""
    return RuntimeRoots(
        program_files=_known_folder_path(_CSIDL_PROGRAM_FILES),
        program_data=_known_folder_path(_CSIDL_COMMON_APPDATA),
    )


def _known_folder_path(folder: int) -> Path:
    """Shell32로 canonical Windows 특수 폴더 하나를 읽습니다."""
    from win32com.shell import shell  # noqa: PLC0415 - Windows 시작 경계입니다.

    path = shell.SHGetFolderPath(0, folder, 0, 0)
    if not path:
        raise RuntimeBindingError(reason="roots")
    return Path(path)


def _parse_binding(
    profile: RuntimeProfile,
    payload: dict[str, str | int],
    binding_path: Path,
    roots: RuntimeRoots,
) -> RuntimeBinding:
    """정확한 JSON 객체를 경로 결합 immutable 값으로 바꿉니다."""
    required = {
        "schemaVersion",
        "profile",
        "contextNonce",
        "configPath",
        "configSha256",
        "workerSid",
    }
    if profile is RuntimeProfile.WORKER:
        required |= {"policyPath", "policySha256"}
    if set(payload) != required or payload.get("schemaVersion") != 1:
        raise RuntimeBindingError(reason="schema")
    context_nonce = _required_string(payload, "contextNonce")
    if _NONCE_PATTERN.fullmatch(context_nonce) is None:
        raise RuntimeBindingError(reason="nonce")
    if _required_string(payload, "profile") != profile.value:
        raise RuntimeBindingError(reason="profile")
    prefix = f"{_PREFIX}{context_nonce}"
    expected_binding = roots.program_files / prefix / _BINDING_DIRECTORY / f"{profile.value}.json"
    if not _same_path(binding_path, expected_binding):
        raise RuntimeBindingError(reason="binding_path")
    expected_config = roots.program_data / prefix / _RUNTIME_DIRECTORY / _CONFIG_NAME
    config_path = Path(_required_string(payload, "configPath"))
    if not _same_path(config_path, expected_config):
        raise RuntimeBindingError(reason="config_path")
    config_sha256 = _required_hash(payload, "configSha256")
    worker_sid = _require_worker_sid(_required_string(payload, "workerSid"))
    if profile is not RuntimeProfile.WORKER:
        return RuntimeBinding(profile, context_nonce, config_path, config_sha256, worker_sid)
    expected_policy = roots.program_data / prefix / _RUNTIME_DIRECTORY / _POLICY_NAME
    policy_path = Path(_required_string(payload, "policyPath"))
    if not _same_path(policy_path, expected_policy):
        raise RuntimeBindingError(reason="policy_path")
    return RuntimeBinding(
        profile,
        context_nonce,
        config_path,
        config_sha256,
        worker_sid,
        policy_path,
        _required_hash(payload, "policySha256"),
    )


def _load_exact_json(raw: bytes) -> dict[str, str | int]:
    """중복 키와 schema 기본형 밖의 값을 거부합니다."""
    try:
        json.JSONDecoder(object_pairs_hook=_reject_duplicate_keys).decode(raw.decode("utf-8"))
        values = TypeAdapter(dict[str, str | int]).validate_json(raw, strict=True)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RuntimeBindingError,
        ValidationError,
    ) as error:
        raise RuntimeBindingError(reason="json") from error
    if any(type(value) not in {str, int} for value in values.values()):
        raise RuntimeBindingError(reason="schema")
    return values


def _reject_duplicate_keys(pairs: list[tuple[str, str | int]]) -> dict[str, str | int]:
    """last-wins 대신 JSON 객체 키를 strict schema 입력으로 만듭니다."""
    result: dict[str, str | int] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeBindingError(reason="duplicate_key")
        result[key] = value
    return result


def load_installed_worker_sid() -> str:
    """운영 설치자가 보호한 계정으로만 Worker ACL 검증 대상을 선택합니다."""
    path = _runtime_roots().program_files / _RUNTIME_DIRECTORY / "worker-identity.json"
    payload = _load_exact_json(_read_protected_bytes(path, maximum_bytes=1024))
    if set(payload) != {"schemaVersion", "workerSid"} or payload["schemaVersion"] != 1:
        raise RuntimeBindingError(reason="schema")
    return _require_worker_sid(_required_string(payload, "workerSid"))


def _required_string(payload: dict[str, str | int], field: str) -> str:
    """비어 있지 않은 strict JSON 문자열 필드를 반환합니다."""
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        raise RuntimeBindingError(reason="schema")
    return value


def _required_hash(payload: dict[str, str | int], field: str) -> str:
    """Canonical lower-case SHA-256 digest를 반환합니다."""
    value = _required_string(payload, field)
    if _SHA256_PATTERN.fullmatch(value) is None:
        raise RuntimeBindingError(reason="hash")
    return value


def _recheck_content(
    path: Path,
    expected_hash: str,
    reason: str,
) -> None:
    """선택된 configuration이 보호되고 content-bound 상태인지 다시 확인합니다."""
    if _sha256_bytes(_read_protected_bytes(path, maximum_bytes=_MAX_CONFIG_BYTES)) != expected_hash:
        raise RuntimeBindingError(reason=reason)


def _read_protected_bytes(path: Path, *, maximum_bytes: int) -> bytes:
    """경로와 소유권 경계를 통과한 로컬 보호 파일만 읽습니다."""
    _require_safe_file(path)
    try:
        with path.open("rb") as source:
            contents = source.read(maximum_bytes + 1)
    except OSError as error:
        raise RuntimeBindingError(reason="read") from error
    if len(contents) > maximum_bytes:
        raise RuntimeBindingError(reason="size")
    return contents


def _require_safe_file(path: Path) -> None:
    """network, device, reparse, directory, multiply-linked 경로를 거부합니다."""
    raw = str(path)
    if (
        raw.startswith(("\\\\?\\", "\\\\.\\", "\\\\"))
        or ".." in path.parts
        or not path.is_absolute()
    ):
        raise RuntimeBindingError(reason="path")
    for component in (path, *path.parents):
        try:
            metadata = component.lstat()
        except OSError as error:
            raise RuntimeBindingError(reason="path") from error
        attributes = getattr(metadata, "st_file_attributes", 0)
        if stat.S_ISLNK(metadata.st_mode) or attributes & _REPARSE_ATTRIBUTE:
            raise RuntimeBindingError(reason="reparse")
    try:
        metadata = path.stat()
    except OSError as error:
        raise RuntimeBindingError(reason="path") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise RuntimeBindingError(reason="path")
    _require_protected_tree(path)


def _require_protected_tree(path: Path) -> None:
    """설치 루트 아래의 trusted owner와 mutation 불가 ACL을 요구합니다."""
    for component in _protected_components(path):
        _require_protected_acl(component)


def _protected_components(path: Path) -> tuple[Path, ...]:
    """leaf부터 nonce 루트 또는 OS가 지정한 운영 설치 루트까지 반환합니다."""
    components: list[Path] = []
    for component in (path, *path.parents):
        components.append(component)
        if component.name.startswith(_PREFIX):
            return tuple(components)
        if component.name == _RUNTIME_DIRECTORY and _same_path(
            component, _runtime_roots().program_files / _RUNTIME_DIRECTORY
        ):
            return tuple(components)
    raise RuntimeBindingError(reason="path")


def _require_protected_acl(path: Path) -> None:
    """Bound file을 교체할 수 있는 nonce-tree owner 또는 ACE를 거부합니다."""
    import pywintypes  # noqa: PLC0415 - Windows security descriptor 경계입니다.
    import win32security  # noqa: PLC0415 - Windows security descriptor 경계입니다.

    try:
        descriptor = win32security.GetNamedSecurityInfo(
            str(path),
            win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION,
        )
        owner_sid = win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())
        discretionary_acl = descriptor.GetSecurityDescriptorDacl()
        if owner_sid not in _TRUSTED_OWNER_SIDS:
            raise RuntimeBindingError(reason="acl")
        mutation_mask = mutation_access_mask()
        for index in range(discretionary_acl.GetAceCount()):
            header, access_mask, trustee = discretionary_acl.GetAce(index)
            ace_type = header[0]
            if ace_type == win32security.ACCESS_ALLOWED_ACE_TYPE and access_mask & mutation_mask:
                trustee_sid = win32security.ConvertSidToStringSid(trustee)
                if trustee_sid not in _TRUSTED_OWNER_SIDS:
                    raise RuntimeBindingError(reason="acl")
    except pywintypes.error as error:
        raise RuntimeBindingError(reason="acl") from error


def mutation_access_mask() -> int:
    """읽기 공유 비트 없이 파일 교체가 가능한 권한 비트만 반환합니다."""
    import ntsecuritycon  # noqa: PLC0415 - Windows ACL 상수 경계입니다.
    import win32con  # noqa: PLC0415 - Windows ACL 상수 경계입니다.

    return (
        ntsecuritycon.FILE_WRITE_DATA
        | ntsecuritycon.FILE_APPEND_DATA
        | ntsecuritycon.FILE_WRITE_EA
        | ntsecuritycon.FILE_WRITE_ATTRIBUTES
        | ntsecuritycon.DELETE
        | ntsecuritycon.FILE_DELETE_CHILD
        | ntsecuritycon.WRITE_DAC
        | ntsecuritycon.WRITE_OWNER
        | win32con.GENERIC_WRITE
        | win32con.GENERIC_ALL
    )


def _require_worker_sid(value: str) -> str:
    """peer나 ACL에서 identity를 유도하지 않고 non-service Windows SID를 파싱합니다."""
    if _SID_PATTERN.fullmatch(value) is None or value in _SERVICE_SIDS:
        raise RuntimeBindingError(reason="worker_sid")
    import pywintypes  # noqa: PLC0415 - Windows SID parsing 경계입니다.
    import win32security  # noqa: PLC0415 - Windows SID parser 경계입니다.

    try:
        _ = win32security.ConvertStringSidToSid(value)
    except (ValueError, OSError, pywintypes.error) as error:
        raise RuntimeBindingError(reason="worker_sid") from error
    return value


def _same_path(actual: Path, expected: Path) -> bool:
    """Reparse point를 resolve하지 않고 canonical absolute local path를 비교합니다."""
    return os.path.normcase(os.path.abspath(actual)) == os.path.normcase(  # noqa: PTH100 - reparse를 따라가지 않습니다.
        os.path.abspath(expected)  # noqa: PTH100 - reparse를 따라가지 않습니다.
    )


def _sha256_bytes(contents: bytes) -> str:
    """파싱하거나 시작 소비자에 넘긴 exact bytes를 hash합니다."""
    digest = hashlib.sha256()
    digest.update(contents)
    return digest.hexdigest()


def _contains_dot_segments(path_text: str) -> bool:
    """CLI 원문에서 canonical path가 아닌 dot segment를 먼저 거부합니다."""
    return any(segment in {".", ".."} for segment in re.split(r"[\\/]+", path_text))


_BINDING_ARG_COUNT: Final = 4
