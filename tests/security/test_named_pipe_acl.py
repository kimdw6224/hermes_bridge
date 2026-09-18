"""Named Pipe ACL과 peer identity 보안 불변식을 검증합니다."""

# pyright: reportMissingModuleSource=false

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor
from os import getpid
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import pytest
import win32security

if TYPE_CHECKING:
    import _win32typing

from hermes_windows_bridge.ipc.acl import (
    AUTHENTICATED_USERS_SID,
    EVERYONE_SID,
    LOCAL_SERVICE_SID,
    PipeAclError,
    PipeAclVerificationError,
    build_privileged_pipe_acl,
    build_security_attributes,
    build_worker_pipe_acl,
    current_process_sid,
    require_expected_sid,
    security_descriptor_sids,
    verify_pipe_security_descriptor,
)
from hermes_windows_bridge.ipc.chunk_errors import ChunkBoundsError
from hermes_windows_bridge.ipc.named_pipe import (
    PipeEndpoint,
    PipeTimeoutError,
    connect_named_pipe_client,
    create_server_pipe,
    server_security_sids,
)
from hermes_windows_bridge.ipc.operation_policy import PrivilegedOperation
from hermes_windows_bridge.ipc.protocol import (
    IpcRequest,
    IpcResponse,
    JobOutputChunkRequest,
    JobOutputChunkResponse,
    PeerRole,
    ProtocolMessageError,
    RebootIpcRequest,
    correlate_chunk_response,
    parse_message,
)

REQUEST_ID = UUID("6dd4aabf-09d1-4fa2-aeb4-9f558e3e7564")
JOB_ID = UUID("50e704d3-fcc1-48f8-a679-feb861cab4bc")


class TestPipeAcl:
    def test_privileged_operation_is_runtime_enum_but_worker_operation_is_string(self) -> None:
        # Given: 같은 operation text를 helper와 worker가 각각 보냅니다.
        helper_raw = (
            b'{"kind":"request","version":1,"request_id":"6dd4aabf-09d1-4fa2-aeb4-9f558e3e7564",'
            b'"source":"gateway","target":"privileged_helper","operation":"reboot",'
            b'"payload":{"delay_seconds":30,"reason":"maintenance"},"timeout_ms":1000}'
        )
        worker_raw = helper_raw.replace(b'"privileged_helper"', b'"worker"')

        # When: target-discriminated request를 parsing합니다.
        helper = parse_message(helper_raw)
        worker = parse_message(worker_raw)

        # Then: helper operation만 explicit runtime enum이고 worker는 string입니다.
        assert isinstance(helper, RebootIpcRequest)
        assert helper.operation is PrivilegedOperation.REBOOT
        assert isinstance(worker, IpcRequest)
        assert type(worker.operation) is str

    def test_privileged_payload_rejects_shell_fields_and_invalid_delay(self) -> None:
        # Given: allowlisted operation을 가장했지만 shell-shaped fields와 음수 delay가 있습니다.
        unsafe = (
            b'{"kind":"request","version":1,"request_id":"6dd4aabf-09d1-4fa2-aeb4-9f558e3e7564",'
            b'"source":"gateway","target":"privileged_helper","operation":"reboot",'
            b'"payload":{"command":"whoami","delay_seconds":-1,"unexpected":true},'
            b'"timeout_ms":1000}'
        )

        # When/Then: operation 실행 전에 strict structured payload가 거부합니다.
        with pytest.raises(ProtocolMessageError):
            _ = parse_message(unsafe)

    def test_chunk_response_cannot_exceed_exact_request_limit(self) -> None:
        # Given: global 상한 안이지만 요청한 1 byte보다 큰 2-byte 응답입니다.
        request = JobOutputChunkRequest(
            request_id=REQUEST_ID,
            job_id=JOB_ID,
            offset=0,
            limit=1,
        )
        response = JobOutputChunkResponse(
            request_id=REQUEST_ID,
            job_id=JOB_ID,
            offset=0,
            data="AB",
            next_offset=2,
            complete=False,
        )

        # When/Then: correlation boundary가 exact request window로 fail closed합니다.
        with pytest.raises(ChunkBoundsError):
            _ = correlate_chunk_response(request, response)

    def test_unexpected_sid_rejected(self) -> None:
        # Given: Privileged Helper가 허용한 SID와 무관한 계정 SID입니다.
        acl = build_privileged_pipe_acl()

        # When/Then: peer identity 경계가 typed error로 거부합니다.
        with pytest.raises(PipeAclError):
            _ = require_expected_sid(
                LOCAL_SERVICE_SID,
                "S-1-5-21-111-222-333-1001",
            )

        # Then: DACL의 관리자 권한도 Gateway identity를 대신하지 못합니다.
        with pytest.raises(PipeAclError):
            _ = require_expected_sid(LOCAL_SERVICE_SID, acl.allowed_sids[1])

    def test_broad_principals_cannot_be_configured(self) -> None:
        # Given: broad principal을 target user로 가장하려는 설정입니다.
        broad_sids = (EVERYONE_SID, AUTHENTICATED_USERS_SID)

        # When/Then: DACL 생성 전에 모두 거부됩니다.
        for sid in broad_sids:
            with pytest.raises(PipeAclError):
                _ = build_worker_pipe_acl(sid)

    def test_privileged_acl_contains_only_intended_sids(self) -> None:
        # Given: Privileged Helper용 최소 ACL입니다.
        acl = build_privileged_pipe_acl()

        # When: 허용 SID 집합을 확인합니다.
        allowed = acl.allowed_sids

        # Then: Gateway LocalService와 관리자·SYSTEM만 포함됩니다.
        assert LOCAL_SERVICE_SID in allowed
        assert EVERYONE_SID not in allowed
        assert AUTHENTICATED_USERS_SID not in allowed
        assert len(allowed) == 3

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows security descriptor required")
    @pytest.mark.parametrize(
        "mutation",
        ["deny", "flags", "mask", "extra", "duplicate"],
    )
    def test_descriptor_rejects_any_ace_template_deviation(self, mutation: str) -> None:
        # Given: 하나의 ACE 속성만 바꾼 실제 Windows DACL입니다.
        expected = build_privileged_pipe_acl()
        descriptor = win32security.SECURITY_DESCRIPTOR()
        actual = win32security.ACL()
        first_sid = expected.allowed_sids[0]
        if mutation == "deny":
            actual.AddAccessDeniedAce(
                win32security.ACL_REVISION,
                0x0012019B,
                win32security.ConvertStringSidToSid(first_sid),
            )
        else:
            flags = 0x10 if mutation == "flags" else 0
            mask = 0x0012019A if mutation == "mask" else 0x0012019B
            actual.AddAccessAllowedAceEx(
                win32security.ACL_REVISION,
                flags,
                mask,
                win32security.ConvertStringSidToSid(first_sid),
            )
        for sid in expected.allowed_sids[1:]:
            actual.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                0x0012019B,
                win32security.ConvertStringSidToSid(sid),
            )
        if mutation == "extra":
            actual.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                0x0012019B,
                win32security.ConvertStringSidToSid(EVERYONE_SID),
            )
        if mutation == "duplicate":
            actual.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                0x0012019B,
                win32security.ConvertStringSidToSid(first_sid),
            )
        descriptor.SetSecurityDescriptorDacl(True, actual, False)  # noqa: FBT003 - Win32 positional API입니다.

        # When/Then: SID 집합이 아니라 ACE 전체 template 차이를 fail closed합니다.
        with pytest.raises(PipeAclVerificationError):
            verify_pipe_security_descriptor(expected, descriptor)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows security descriptor required")
    def test_descriptor_rejects_non_allow_ace_before_sid_decoding(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Given: SID field 형식이 달라질 수 있는 deny ACE descriptor입니다.
        descriptor = win32security.SECURITY_DESCRIPTOR()
        discretionary_acl = win32security.ACL()
        discretionary_acl.AddAccessDeniedAce(
            win32security.ACL_REVISION,
            0x0012019B,
            win32security.ConvertStringSidToSid(LOCAL_SERVICE_SID),
        )
        descriptor.SetSecurityDescriptorDacl(
            True,  # noqa: FBT003 - Win32 positional API입니다.
            discretionary_acl,
            False,  # noqa: FBT003 - Win32 positional API입니다.
        )
        def unexpected_sid_decoding(sid: _win32typing.PySID) -> str:
            del sid
            pytest.fail("non-allow ACE must be rejected before SID decoding")

        monkeypatch.setattr(win32security, "ConvertSidToStringSid", unexpected_sid_decoding)

        # When/Then: ACE type mismatch는 SID 구조를 해석하기 전에 typed failure가 됩니다.
        with pytest.raises(PipeAclVerificationError, match="DACL ACE template mismatch"):
            verify_pipe_security_descriptor(build_privileged_pipe_acl(), descriptor)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows security descriptor required")
    def test_descriptor_rejects_absent_dacl(self) -> None:
        # Given: DACL이 없는 descriptor는 Windows에서 null DACL입니다.
        descriptor = win32security.SECURITY_DESCRIPTOR()

        # When/Then: null DACL은 allowlist 정책과 무관하게 거부합니다.
        with pytest.raises(PipeAclVerificationError):
            verify_pipe_security_descriptor(build_privileged_pipe_acl(), descriptor)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows security descriptor required")
    def test_real_pipe_descriptor_contains_only_intended_sids(self) -> None:
        # Given: pywin32로 구성한 Privileged Helper DACL입니다.
        acl = build_privileged_pipe_acl()
        attributes = build_security_attributes(acl)

        # When: 실제 security descriptor의 allow ACE SID를 읽습니다.
        actual_sids = security_descriptor_sids(attributes)

        # Then: 순수 ACL 사양과 byte-independent하게 같은 SID만 들어 있습니다.
        assert actual_sids == set(acl.allowed_sids)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows named pipe required")
    def test_server_pipe_uses_restrictive_descriptor(self) -> None:
        # Given: 충돌하지 않는 임시 Named Pipe 이름입니다.
        target_sid = current_process_sid()
        pipe_name = rf"\\.\pipe\HermesWindowsBridgeTest-{uuid4()}"

        # When: restrictive worker pipe를 실제로 생성합니다.
        with create_server_pipe(
            PipeEndpoint.WORKER,
            pipe_name=pipe_name,
            target_user_sid=target_sid,
        ) as server:
            actual_sids = server_security_sids(server)

        # Then: 실제 kernel object도 broad SID 없이 의도한 SID만 허용합니다.
        assert actual_sids == set(build_worker_pipe_acl(target_sid).allowed_sids)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows named pipe required")
    def test_server_wait_is_bounded_when_no_client_connects(self) -> None:
        # Given: client가 없는 임시 Privileged Helper pipe입니다.
        pipe_name = rf"\\.\pipe\HermesWindowsBridgeTest-{uuid4()}"

        # When/Then: 연결 대기는 지정 timeout에 typed error로 끝납니다.
        with (
            create_server_pipe(
                PipeEndpoint.PRIVILEGED_HELPER,
                pipe_name=pipe_name,
            ) as server,
            pytest.raises(PipeTimeoutError),
        ):
            server.wait_for_client(timeout_ms=10)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows named pipe required")
    def test_same_sid_kernel_pipe_framed_round_trip(self) -> None:
        # Given: 현재 계정만 허용한 실제 Windows kernel Named Pipe입니다.
        pipe_name = rf"\\.\pipe\HermesWindowsBridgeTest-{uuid4()}"
        request = IpcRequest(
            request_id=uuid4(),
            target=PeerRole.WORKER,
            operation="status",
            payload={},
            timeout_ms=1_000,
        )

        def client_round_trip() -> IpcResponse:
            with connect_named_pipe_client(pipe_name, timeout_ms=1_000) as client:
                client.write_message(request)
                response = client.read_message()
            assert isinstance(response, IpcResponse)
            return response

        # When: client와 server가 connect/read/write하고 token SID와 PID를 확인합니다.
        with ThreadPoolExecutor(max_workers=1) as executor, create_server_pipe(
            PipeEndpoint.WORKER,
            pipe_name=pipe_name,
            target_user_sid=current_process_sid(),
        ) as server:
            client_result = executor.submit(client_round_trip)
            server.wait_for_client(timeout_ms=1_000)
            received = server.read_message()
            assert received == request
            peer = server.verify_peer(expected_process_id=getpid())
            response = IpcResponse(
                request_id=request.request_id,
                ok=True,
                payload={"ready": True},
            )
            server.write_message(response)
            received_response = client_result.result(timeout=2)

        # Then: actual DACL access, impersonated SID/PID, framed correlation이 모두 일치합니다.
        assert peer.sid == current_process_sid()
        assert received_response == response
