"""현재 Gateway client handle의 DACL 관찰 경계를 검증합니다."""

# pyright: reportMissingModuleSource=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownLambdaType=false

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import pytest
import win32security

from hermes_windows_bridge.ipc import acl
from hermes_windows_bridge.ipc.acl import (
    EVERYONE_SID,
    PIPE_CLIENT_ACCESS,
    PipeAclProbeState,
    build_privileged_pipe_acl,
    build_worker_pipe_acl,
    observe_client_pipe_acl,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    import _win32typing


def _descriptor_for_sids(sids: tuple[str, ...]) -> _win32typing.PySECURITY_DESCRIPTOR:
    descriptor = win32security.SECURITY_DESCRIPTOR()
    discretionary_acl = win32security.ACL()
    for sid in sids:
        discretionary_acl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            PIPE_CLIENT_ACCESS,
            win32security.ConvertStringSidToSid(sid),
        )
    descriptor.SetSecurityDescriptorDacl(True, discretionary_acl, False)  # noqa: FBT003
    return descriptor


def _descriptor_reader(
    descriptor: _win32typing.PySECURITY_DESCRIPTOR,
) -> Callable[[int], _win32typing.PySECURITY_DESCRIPTOR]:
    def read(handle: int) -> _win32typing.PySECURITY_DESCRIPTOR:
        del handle
        return descriptor

    return read


@pytest.mark.skipif(sys.platform != "win32", reason="Windows security descriptor required")
@pytest.mark.parametrize(
    ("actual_sids", "expected_state"),
    [
        (build_privileged_pipe_acl().allowed_sids, PipeAclProbeState.VERIFIED),
        (build_privileged_pipe_acl().allowed_sids[:-1], PipeAclProbeState.MISMATCH),
        (
            (*build_privileged_pipe_acl().allowed_sids, EVERYONE_SID),
            PipeAclProbeState.MISMATCH,
        ),
    ],
)
def test_client_handle_observation_exact_missing_and_broad_acl(
    monkeypatch: pytest.MonkeyPatch,
    actual_sids: tuple[str, ...],
    expected_state: PipeAclProbeState,
) -> None:
    # Given: production pipe가 아닌 synthetic client-handle descriptor입니다.
    descriptor = _descriptor_for_sids(actual_sids)
    monkeypatch.setattr(acl, "read_pipe_security_descriptor", _descriptor_reader(descriptor))

    # When: Gateway가 자신이 이미 소유한 client handle을 exact template으로 읽습니다.
    observed = observe_client_pipe_acl(123, build_privileged_pipe_acl())

    # Then: exact만 verified이고 missing/extra/broad ACE는 mismatch입니다.
    assert observed is expected_state


@pytest.mark.skipif(sys.platform != "win32", reason="Windows security descriptor required")
def test_client_handle_observation_does_not_infer_worker_sid_from_descriptor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: observed DACL의 dynamic ACE는 binding이 기대하는 SID와 다릅니다.
    expected = build_worker_pipe_acl("S-1-5-21-1-2-3-1001")
    forged = build_worker_pipe_acl("S-1-5-21-1-2-3-2002")
    descriptor = _descriptor_for_sids(forged.allowed_sids)
    monkeypatch.setattr(acl, "read_pipe_security_descriptor", _descriptor_reader(descriptor))

    # When: protected binding의 expected template으로 재검증합니다.
    observed = observe_client_pipe_acl(123, expected)

    # Then: descriptor에 있는 다른 SID를 신뢰하지 않고 mismatch로 닫습니다.
    assert observed is PipeAclProbeState.MISMATCH


def test_client_handle_observation_maps_native_read_failure_to_unverified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: GetSecurityInfo 단계가 실패합니다.
    def unavailable(handle: int) -> _win32typing.PySECURITY_DESCRIPTOR:
        del handle
        raise acl.PipeAclVerificationError(reason="GetSecurityInfo failed")

    monkeypatch.setattr(acl, "read_pipe_security_descriptor", unavailable)

    # When: already-connected handle을 관찰합니다.
    observed = observe_client_pipe_acl(123, build_privileged_pipe_acl())

    # Then: native detail을 공개하지 않고 unverified로 fail closed합니다.
    assert observed is PipeAclProbeState.UNVERIFIED
