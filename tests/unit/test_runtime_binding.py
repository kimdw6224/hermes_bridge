"""Protected runtime binding parse and startup-selection contracts."""

# pyright: reportMissingModuleSource=false, reportPrivateUsage=false

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING

import ntsecuritycon
import pytest
import pywintypes
import win32security

from hermes_windows_bridge import runtime_binding
from hermes_windows_bridge.runtime_binding import (
    RuntimeBindingError,
    RuntimeProfile,
    RuntimeRoots,
    load_runtime_binding,
    parse_runtime_binding_args,
)

if TYPE_CHECKING:
    import _win32typing


_TRUSTED_SYSTEM_SID = "S-1-5-18"
_TRUSTED_ADMINISTRATORS_SID = "S-1-5-32-544"
_UNTRUSTED_SID = "S-1-5-21-1-2-3-4"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _skip_protected_tree(path: Path) -> None:
    """Test fixture가 Windows ACL 경계 대신 content binding만 검증하도록 합니다."""
    del path


def _native_acl_descriptor(owner_sid: str, trustee_sid: str) -> _win32typing.PySECURITY_DESCRIPTOR:
    """실제 pywin32 SID·ACL·descriptor로 protected file read 결과를 구성합니다."""
    owner = win32security.ConvertStringSidToSid(owner_sid)
    trustee = win32security.ConvertStringSidToSid(trustee_sid)
    discretionary_acl = win32security.ACL()
    discretionary_acl.AddAccessAllowedAce(
        win32security.ACL_REVISION,
        runtime_binding.mutation_access_mask(),
        trustee,
    )
    descriptor = win32security.SECURITY_DESCRIPTOR()
    descriptor.SetSecurityDescriptorOwner(
        owner,
        False,  # noqa: FBT003 - Win32 positional API입니다.
    )
    descriptor.SetSecurityDescriptorDacl(
        True,  # noqa: FBT003 - Win32 positional API입니다.
        discretionary_acl,
        False,  # noqa: FBT003 - Win32 positional API입니다.
    )
    return descriptor


def _return_descriptor(
    monkeypatch: pytest.MonkeyPatch,
    descriptor: _win32typing.PySECURITY_DESCRIPTOR,
) -> None:
    """파일 시스템 조회만 대체하고 SID·ACL 변환은 실제 pywin32로 유지합니다."""

    def get_named_security_info(
        path: str,
        object_type: int,
        security_information: int,
    ) -> _win32typing.PySECURITY_DESCRIPTOR:
        del path, object_type, security_information
        return descriptor

    monkeypatch.setattr(win32security, "GetNamedSecurityInfo", get_named_security_info)


def _prepared_binding(tmp_path: Path, profile: RuntimeProfile) -> tuple[Path, str, RuntimeRoots]:
    nonce = "0123456789abcdef0123456789abcdef"
    roots = RuntimeRoots(tmp_path / "ProgramFiles", tmp_path / "ProgramData")
    config = (
        roots.program_data
        / f"HermesWindowsBridgeEval-{nonce}"
        / "HermesWindowsBridge"
        / "config.yaml"
    )
    policy = config.with_name("policy.yaml")
    binding = (
        roots.program_files
        / f"HermesWindowsBridgeEval-{nonce}"
        / "bindings"
        / f"{profile.value}.json"
    )
    config.parent.mkdir(parents=True)
    binding.parent.mkdir(parents=True)
    _ = config.write_text("server: {}\n", encoding="utf-8")
    payload: dict[str, str | int] = {
        "schemaVersion": 1,
        "profile": profile.value,
        "contextNonce": nonce,
        "configPath": str(config),
        "configSha256": _digest(config),
        "workerSid": "S-1-5-21-1-2-3-4",
    }
    if profile is RuntimeProfile.WORKER:
        _ = policy.write_text("shell: {}\n", encoding="utf-8")
        payload["policyPath"] = str(policy)
        payload["policySha256"] = _digest(policy)
    _ = binding.write_text(json.dumps(payload), encoding="utf-8")
    return binding, _digest(binding), roots


@pytest.fixture
def installed_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """운영 설치의 OS 루트만 치환하고 경로·ACL 검증은 그대로 실행합니다."""
    roots = RuntimeRoots(tmp_path / "ProgramFiles", tmp_path / "ProgramData")
    path = roots.program_files / "HermesWindowsBridge" / "worker-identity.json"
    path.parent.mkdir(parents=True)
    monkeypatch.setattr(runtime_binding, "_runtime_roots", lambda: roots)
    _return_descriptor(
        monkeypatch,
        _native_acl_descriptor(_TRUSTED_ADMINISTRATORS_SID, _TRUSTED_SYSTEM_SID),
    )
    return path


def test_installed_identity_uses_protected_account(installed_identity: Path) -> None:
    _ = installed_identity.write_text(
        json.dumps({"schemaVersion": 1, "workerSid": _UNTRUSTED_SID}), encoding="utf-8"
    )
    assert runtime_binding.load_installed_worker_sid() == _UNTRUSTED_SID
    assert runtime_binding._protected_components(installed_identity) == (
        installed_identity,
        installed_identity.parent,
    )


@pytest.mark.parametrize(
    "body",
    [
        None,
        "{}",
        '{"schemaVersion":true,"workerSid":"S-1-5-21-1-2-3-4"}',
        '{"schemaVersion":1,"workerSid":"S-1-5-18"}',
        '{"schemaVersion":1,"workerSid":"S-1-5-19"}',
        '{"schemaVersion":1,"workerSid":"S-1-5-20"}',
        '{"schemaVersion":1,"workerSid":"invalid"}',
        '{"schemaVersion":1,"workerSid":"S-1-5-21-1-2-3-4","extra":1}',
        '{"schemaVersion":1,"workerSid":"S-1-5-21-1-2-3-4","workerSid":"S-1-5-18"}',
        " " * 1025,
    ],
)
def test_installed_identity_rejects_missing_or_invalid(
    installed_identity: Path, body: str | None
) -> None:
    if body is not None:
        _ = installed_identity.write_text(body, encoding="utf-8")
    with pytest.raises(RuntimeBindingError):
        _ = runtime_binding.load_installed_worker_sid()


def test_installed_identity_rejects_user_writable_anchor(
    installed_identity: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _ = installed_identity.write_text(
        json.dumps({"schemaVersion": 1, "workerSid": _UNTRUSTED_SID}), encoding="utf-8"
    )
    _return_descriptor(
        monkeypatch,
        _native_acl_descriptor(_TRUSTED_ADMINISTRATORS_SID, _UNTRUSTED_SID),
    )
    with pytest.raises(RuntimeBindingError, match="acl"):
        _ = runtime_binding.load_installed_worker_sid()


def test_binding_loads_only_exact_profile_paths_and_rechecks_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: installer-owned gateway binding, config, and matching protected digests.
    binding, binding_hash, roots = _prepared_binding(tmp_path, RuntimeProfile.GATEWAY)
    monkeypatch.setattr(
        runtime_binding,
        "_require_protected_tree",
        _skip_protected_tree,
    )

    # When: the service child parses the paired startup selection.
    selected = load_runtime_binding(RuntimeProfile.GATEWAY, binding, binding_hash, roots=roots)

    # Then: only the immutable selected paths are returned and SID stays private data.
    assert selected.config_path.name == "config.yaml"
    assert selected.policy_path is None
    assert selected.worker_sid == "S-1-5-21-1-2-3-4"


def test_binding_rejects_tampered_config_after_binding_was_hashed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: a valid Worker binding whose config is changed after preparation.
    binding, binding_hash, roots = _prepared_binding(tmp_path, RuntimeProfile.WORKER)
    monkeypatch.setattr(
        runtime_binding,
        "_require_protected_tree",
        _skip_protected_tree,
    )
    config = (
        roots.program_data
        / "HermesWindowsBridgeEval-0123456789abcdef0123456789abcdef"
        / "HermesWindowsBridge"
        / "config.yaml"
    )
    _ = config.write_text("server:\n  port: 65535\n", encoding="utf-8")

    # When / Then: startup rejects the content before it can select runtime configuration.
    with pytest.raises(RuntimeBindingError, match="config_hash"):
        _ = load_runtime_binding(RuntimeProfile.WORKER, binding, binding_hash, roots=roots)


def test_binding_error_keeps_the_original_traceback() -> None:
    # Given: a typed binding boundary error that pytest must attach a traceback to.
    error = RuntimeBindingError(reason="schema")

    # When: the error crosses a normal Python exception boundary.
    with pytest.raises(RuntimeBindingError):
        raise error

    # Then: Exception traceback assignment was not blocked by frozen dataclass state.
    assert error.__traceback__ is not None


def test_binding_rejects_oversized_json_before_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: a binding-sized file exceeding the fixed 64 KiB parser boundary.
    oversized = tmp_path / "oversized.json"
    _ = oversized.write_bytes(b"{" + (b" " * (64 * 1024)))
    monkeypatch.setattr(runtime_binding, "_require_safe_file", _skip_protected_tree)

    # When / Then: parsing cannot allocate or trust an oversized binding document.
    with pytest.raises(RuntimeBindingError, match="size"):
        _ = runtime_binding._read_protected_bytes(oversized, maximum_bytes=64 * 1024)


def test_binding_cli_rejects_noncanonical_dot_segments() -> None:
    # Given: a complete argument pair containing a lexical parent traversal segment.
    argv = (
        "--runtime-binding",
        r"C:\\safe\\..\\binding.json",
        "--runtime-binding-sha256",
        "a" * 64,
    )

    # When / Then: path normalization cannot hide the noncanonical source argument.
    with pytest.raises(RuntimeBindingError, match="argv"):
        _ = parse_runtime_binding_args(argv)


def test_binding_acl_mutation_mask_does_not_classify_read_access_as_replacement() -> None:
    # Given: Windows file generic read shares synchronization and control bits with generic write.
    # When: binding validation selects only replacement-capable access bits.
    mutation_mask = runtime_binding.mutation_access_mask()

    # Then: an ordinary read/read-execute ACE cannot cause a false ACL rejection.
    assert mutation_mask & ntsecuritycon.FILE_GENERIC_READ == 0


def test_binding_acl_accepts_trusted_real_pysid_owner_and_mutation_trustee(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: 실제 pywin32 SID·ACL의 문자열 표현이 canonical SID 텍스트와 다릅니다.
    owner = win32security.ConvertStringSidToSid(_TRUSTED_SYSTEM_SID)
    trustee = win32security.ConvertStringSidToSid(_TRUSTED_ADMINISTRATORS_SID)
    assert str(owner) != _TRUSTED_SYSTEM_SID
    assert str(trustee) != _TRUSTED_ADMINISTRATORS_SID
    descriptor = _native_acl_descriptor(_TRUSTED_SYSTEM_SID, _TRUSTED_ADMINISTRATORS_SID)
    _return_descriptor(monkeypatch, descriptor)

    # When: 파일 descriptor 조회만 대체한 protected ACL 검증을 수행합니다.
    runtime_binding._require_protected_acl(Path(r"C:\fixture"))


def test_binding_acl_rejects_untrusted_real_pysid_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: 고정 trusted owner 집합 밖의 실제 descriptor입니다.
    descriptor = _native_acl_descriptor(_UNTRUSTED_SID, _TRUSTED_SYSTEM_SID)
    _return_descriptor(monkeypatch, descriptor)

    # When: owner SID를 canonical 텍스트로 변환해 검증합니다.
    with pytest.raises(RuntimeBindingError) as captured:
        runtime_binding._require_protected_acl(Path(r"C:\fixture"))

    # Then: 변환 후에도 fail-closed ACL 거부 이유를 보존합니다.
    assert captured.value.reason == "acl"


def test_binding_acl_rejects_untrusted_real_pysid_mutation_trustee(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: trusted set 밖의 replacement-capable ACE가 든 실제 descriptor입니다.
    descriptor = _native_acl_descriptor(_TRUSTED_SYSTEM_SID, _UNTRUSTED_SID)
    _return_descriptor(monkeypatch, descriptor)

    # When: trustee SID를 canonical 텍스트로 변환해 검증합니다.
    with pytest.raises(RuntimeBindingError) as captured:
        runtime_binding._require_protected_acl(Path(r"C:\fixture"))

    # Then: 변환 후에도 fail-closed ACL 거부 이유를 보존합니다.
    assert captured.value.reason == "acl"


@pytest.mark.parametrize("failure_call", [1, 2])
def test_binding_acl_converter_failure_maps_to_acl_rejection(
    monkeypatch: pytest.MonkeyPatch,
    failure_call: int,
) -> None:
    # Given: trusted 실제 descriptor와 owner 또는 trustee converter 실패입니다.
    descriptor = _native_acl_descriptor(_TRUSTED_SYSTEM_SID, _TRUSTED_ADMINISTRATORS_SID)
    _return_descriptor(monkeypatch, descriptor)
    converter = win32security.ConvertSidToStringSid
    calls = 0

    def fail_selected_conversion(sid: _win32typing.PySID) -> str:
        nonlocal calls
        calls += 1
        if calls == failure_call:
            raise pywintypes.error(5, "ConvertSidToStringSid", "denied")
        return converter(sid)

    monkeypatch.setattr(win32security, "ConvertSidToStringSid", fail_selected_conversion)

    # When: 두 conversion 위치 중 지정된 위치가 pywintypes.error를 냅니다.
    with pytest.raises(RuntimeBindingError) as captured:
        runtime_binding._require_protected_acl(Path(r"C:\fixture"))

    # Then: 기존 ACL error boundary가 fail-closed 이유로 변환합니다.
    assert captured.value.reason == "acl"


@pytest.mark.parametrize(
    "argv",
    [
        ("--runtime-binding", "binding.json"),
        ("--runtime-binding", "binding.json", "--runtime-binding-sha256", "A" * 64),
        ("--runtime-binding-sha256", "a" * 64, "--runtime-binding", "binding.json"),
        ("--runtime-binding", "binding.json", "--runtime-binding-sha256", "a" * 63),
    ],
)
def test_binding_cli_requires_the_complete_canonical_pair(argv: tuple[str, ...]) -> None:
    # Given: an incomplete, reordered, or noncanonical child binding argument pair.
    # When / Then: it cannot fall back to an ambient selection.
    with pytest.raises(RuntimeBindingError, match="argv"):
        _ = parse_runtime_binding_args(argv)
