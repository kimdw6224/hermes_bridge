"""IPC 프로토콜과 framing의 순수 계약을 검증합니다."""

from __future__ import annotations

import json
from io import BytesIO
from uuid import UUID

import pytest

from hermes_windows_bridge.ipc.chunk_errors import ChunkCorrelationError
from hermes_windows_bridge.ipc.framing import (
    FrameDecoder,
    FrameTooLargeError,
    TruncatedFrameError,
    decode_frame,
    encode_frame,
    read_frame,
)
from hermes_windows_bridge.ipc.operation_policy import PrivilegedOperation, RebootPayload
from hermes_windows_bridge.ipc.protocol import (
    MAX_OUTPUT_CHUNK_BYTES,
    PROTOCOL_VERSION,
    CorrelationError,
    Heartbeat,
    IpcRequest,
    IpcResponse,
    JobOutputChunkRequest,
    JobOutputChunkResponse,
    PeerRole,
    ProtocolMessageError,
    ProtocolVersionError,
    RebootIpcRequest,
    WorkerRegistration,
    correlate_chunk_response,
    correlate_response,
    parse_message,
)
from hermes_windows_bridge.ipc.registration import (
    RegistrationConflictError,
    accept_registration,
)

REQUEST_ID = UUID("6dd4aabf-09d1-4fa2-aeb4-9f558e3e7564")
REGISTRATION_ID = UUID("50e704d3-fcc1-48f8-a679-feb861cab4bc")


class TestFraming:
    def test_request_response_round_trip(self) -> None:
        # Given: Gateway 요청과 같은 ID를 가진 Worker 응답입니다.
        request = IpcRequest(
            request_id=REQUEST_ID,
            target=PeerRole.WORKER,
            operation="shell_run",
            payload={"command": "hostname"},
            timeout_ms=1_000,
        )
        response = IpcResponse(
            request_id=request.request_id,
            ok=True,
            payload={"hostname": "pc"},
        )

        # When: 응답을 framing한 뒤 다시 해석하고 요청과 연관시킵니다.
        decoded = decode_frame(encode_frame(response))
        correlated = correlate_response(request, decoded)

        # Then: 원래 요청 ID와 현재 프로토콜 버전이 보존됩니다.
        assert correlated == response
        assert correlated.version == PROTOCOL_VERSION

    def test_incremental_decoder_resumes_after_partial_frame(self) -> None:
        # Given: 한 요청 프레임이 중간에서 나뉘어 도착합니다.
        request = RebootIpcRequest(
            request_id=REQUEST_ID,
            operation=PrivilegedOperation.REBOOT,
            payload=RebootPayload(delay_seconds=30, reason="maintenance"),
            timeout_ms=2_000,
        )
        frame = encode_frame(request)
        decoder = FrameDecoder()

        # When: 첫 조각과 나머지 조각을 순서대로 공급합니다.
        first_messages = decoder.feed(frame[:7])
        second_messages = decoder.feed(frame[7:])

        # Then: 완성 전에는 결과가 없고 완성 뒤 정확히 한 메시지가 나옵니다.
        assert first_messages == ()
        assert second_messages == (request,)

    def test_decoder_reset_after_cancel_discards_partial_frame(self) -> None:
        # Given: 취소된 요청의 불완전 프레임과 새 요청 프레임입니다.
        stale = encode_frame(
            IpcRequest(
                request_id=REQUEST_ID,
                target=PeerRole.WORKER,
                operation="stale",
                payload={},
                timeout_ms=100,
            )
        )
        resumed = IpcRequest(
            request_id=UUID("2d8996d1-bf88-45a8-b5e1-b5a3994c962e"),
            target=PeerRole.WORKER,
            operation="resumed",
            payload={},
            timeout_ms=100,
        )
        decoder = FrameDecoder()
        _ = decoder.feed(stale[:5])

        # When: 대기를 취소해 상태를 초기화하고 새 프레임을 공급합니다.
        decoder.reset()
        messages = decoder.feed(encode_frame(resumed))

        # Then: 취소된 프레임 없이 새 요청만 해석됩니다.
        assert messages == (resumed,)

    def test_oversized_frame_is_rejected_before_body_read(self) -> None:
        # Given: 허용 크기보다 큰 길이 prefix만 가진 스트림입니다.
        stream = BytesIO((65).to_bytes(4, "big"))

        # When/Then: 본문을 기다리지 않고 크기 오류를 냅니다.
        with pytest.raises(FrameTooLargeError):
            _ = read_frame(stream, max_message_size=64)

    def test_disconnect_with_partial_frame_is_rejected(self) -> None:
        # Given: 선언 길이보다 짧은 본문입니다.
        stream = BytesIO((10).to_bytes(4, "big") + b"{}")

        # When/Then: 연결 종료를 정상 메시지로 오인하지 않습니다.
        with pytest.raises(TruncatedFrameError):
            _ = read_frame(stream)

    def test_incremental_disconnect_reports_declared_frame_size(self) -> None:
        # Given: prefix는 완성됐지만 body 일부만 도착한 decoder입니다.
        decoder = FrameDecoder()
        _ = decoder.feed((10).to_bytes(4, "big") + b"{}")

        # When: 연결 종료를 알립니다.
        with pytest.raises(TruncatedFrameError) as captured:
            decoder.finish()

        # Then: 전체 frame 기준 기대 길이와 실제 길이를 보고합니다.
        assert captured.value.expected == 14
        assert captured.value.received == 6


class TestProtocol:
    def test_privileged_shell_operation_is_rejected_at_ipc_boundary(self) -> None:
        # Given: Gateway를 가장했지만 privileged helper에 generic shell을 요청합니다.
        unsafe = (
            b'{"kind":"request","version":1,'
            b'"request_id":"6dd4aabf-09d1-4fa2-aeb4-9f558e3e7564",'
            b'"source":"gateway","target":"privileged_helper","operation":"shell",'
            b'"payload":{"command":"whoami"},"timeout_ms":1000}'
        )

        # When/Then: helper까지 전달되기 전에 typed protocol error로 거부됩니다.
        with pytest.raises(ProtocolMessageError):
            _ = parse_message(unsafe)

    def test_privileged_reboot_operation_remains_allowed(self) -> None:
        # Given: v1 explicit privileged allowlist의 reboot 요청입니다.
        safe = RebootIpcRequest(
            request_id=REQUEST_ID,
            operation=PrivilegedOperation.REBOOT,
            payload=RebootPayload(delay_seconds=30, reason="maintenance"),
            timeout_ms=1_000,
        )

        # When: wire format을 왕복합니다.
        decoded = decode_frame(encode_frame(safe))

        # Then: allowlist operation은 보존됩니다.
        assert decoded == safe

    def test_job_output_chunk_round_trip_is_bounded_and_correlated(self) -> None:
        # Given: offset과 limit이 명시된 chunk 요청과 실제 byte 길이를 가진 응답입니다.
        request = JobOutputChunkRequest(
            request_id=REQUEST_ID,
            job_id=REGISTRATION_ID,
            offset=4,
            limit=16,
        )
        response = JobOutputChunkResponse(
            request_id=REQUEST_ID,
            job_id=REGISTRATION_ID,
            offset=4,
            data="한글",
            next_offset=10,
            complete=False,
        )

        # When: request와 response를 각각 framing 왕복합니다.
        decoded_request = decode_frame(encode_frame(request))
        decoded_response = correlate_chunk_response(request, decode_frame(encode_frame(response)))

        # Then: offset/limit 및 UTF-8 byte 기반 next offset이 보존됩니다.
        assert decoded_request == request
        assert decoded_response == response
        wrong_job = response.model_copy(
            update={"job_id": UUID("f24ee68b-aac4-4132-ad73-26e1ead5c190")}
        )
        with pytest.raises(ChunkCorrelationError):
            _ = correlate_chunk_response(request, wrong_job)

    @pytest.mark.parametrize(
        ("offset", "limit"),
        [(-1, 1), (0, 0), (0, MAX_OUTPUT_CHUNK_BYTES + 1), (2**63 - 1, 2)],
    )
    def test_job_output_chunk_invalid_bounds_fail_closed(self, offset: int, limit: int) -> None:
        # Given: negative, oversized 또는 signed 64-bit 범위를 넘는 chunk window입니다.
        payload = {
            "kind": "job_output_chunk_request",
            "version": 1,
            "request_id": str(REQUEST_ID),
            "source": "gateway",
            "target": "worker",
            "job_id": str(REGISTRATION_ID),
            "offset": offset,
            "limit": limit,
        }

        # When/Then: wire boundary가 잘못된 window를 typed error로 거부합니다.
        with pytest.raises(ProtocolMessageError):
            _ = parse_message(json.dumps(payload).encode())

    @pytest.mark.parametrize(
        ("data", "next_offset"),
        [("한" * (MAX_OUTPUT_CHUNK_BYTES // 3 + 1), MAX_OUTPUT_CHUNK_BYTES + 2), ("한", 1)],
        ids=["oversized_utf8", "wrong_next_offset"],
    )
    def test_job_output_chunk_response_rejects_invalid_utf8_bounds(
        self,
        data: str,
        next_offset: int,
    ) -> None:
        # Given: UTF-8 byte 상한 또는 실제 byte offset이 맞지 않는 응답입니다.
        payload = {
            "kind": "job_output_chunk_response",
            "version": 1,
            "request_id": str(REQUEST_ID),
            "job_id": str(REGISTRATION_ID),
            "offset": 0,
            "data": data,
            "next_offset": next_offset,
            "complete": False,
        }

        # When/Then: transport message가 만들어지기 전에 byte 상한으로 거부됩니다.
        with pytest.raises(ProtocolMessageError):
            _ = parse_message(json.dumps(payload).encode())

    def test_heartbeat_round_trip_preserves_registration_state(self) -> None:
        # Given: 등록 ID, sequence, session, username을 가진 heartbeat입니다.
        heartbeat = Heartbeat(
            registration_id=REGISTRATION_ID,
            sequence=8,
            session_id=2,
            username="DOMAIN\\worker",
        )

        # When: heartbeat를 wire format으로 왕복합니다.
        decoded = decode_frame(encode_frame(heartbeat))

        # Then: Gateway가 stale 판단에 필요한 상태가 그대로 보존됩니다.
        assert decoded == heartbeat

    def test_non_gateway_request_source_is_rejected(self) -> None:
        # Given: Worker가 Gateway 정책 경계를 우회해 직접 만든 요청입니다.
        direct_peer = (
            b'{"kind":"request","version":1,'
            b'"request_id":"6dd4aabf-09d1-4fa2-aeb4-9f558e3e7564",'
            b'"source":"worker","target":"privileged_helper","operation":"reboot",'
            b'"payload":{},"timeout_ms":1000}'
        )

        # When/Then: source 고정 schema가 direct peer 요청을 거부합니다.
        with pytest.raises(ProtocolMessageError):
            _ = parse_message(direct_peer)

    def test_malformed_message_is_rejected(self) -> None:
        # Given: 허용하지 않은 필드가 포함된 IPC JSON입니다.
        malformed = b'{"kind":"heartbeat","version":1,"unexpected":true}'

        # When/Then: 경계 parser가 typed error로 거부합니다.
        with pytest.raises(ProtocolMessageError):
            _ = parse_message(malformed)

    def test_version_mismatch_fails_closed(self) -> None:
        # Given: 현재 버전보다 오래된 요청입니다.
        stale = (
            b'{"kind":"request","version":0,'
            b'"request_id":"6dd4aabf-09d1-4fa2-aeb4-9f558e3e7564",'
            b'"source":"gateway","target":"worker","operation":"status",'
            b'"payload":{},"timeout_ms":1000}'
        )

        # When/Then: 호환되지 않는 버전을 별도 오류로 거부합니다.
        with pytest.raises(ProtocolVersionError):
            _ = parse_message(stale)

    def test_response_with_different_request_id_is_rejected(self) -> None:
        # Given: 서로 다른 ID의 요청과 응답입니다.
        request = IpcRequest(
            request_id=REQUEST_ID,
            target=PeerRole.WORKER,
            operation="status",
            payload={},
            timeout_ms=1_000,
        )
        response = IpcResponse(
            request_id=UUID("f20dc4ca-5438-454e-857c-f3eaa250c1dd"),
            ok=True,
            payload={},
        )

        # When/Then: 응답 내용과 무관하게 correlation 검증이 실패합니다.
        with pytest.raises(CorrelationError):
            _ = correlate_response(request, response)

    def test_duplicate_or_stale_registration_is_rejected(self) -> None:
        # Given: 현재 등록보다 generation이 작고 ID도 같은 Worker 등록입니다.
        current = WorkerRegistration(
            registration_id=REGISTRATION_ID,
            generation=3,
            session_id=1,
            username="DOMAIN\\worker",
        )
        stale = current.model_copy(update={"generation": 2})

        # When/Then: 중복·stale 등록은 Gateway 상태를 대체하지 못합니다.
        with pytest.raises(RegistrationConflictError):
            _ = accept_registration(current, stale)
