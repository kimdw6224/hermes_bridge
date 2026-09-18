"""Gateway와 로컬 peer 사이의 버전 고정 IPC 메시지 계약입니다."""

# noqa: SIZE_OK - 전체 versioned wire schema를 한 discriminated union으로 유지합니다.

# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, ClassVar, Final, Literal, assert_never, override
from uuid import UUID  # noqa: TC003 - Pydantic가 runtime annotation을 해석합니다.

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    TypeAdapter,
    ValidationError,
    model_validator,
)

from hermes_windows_bridge.ipc.chunk_errors import (
    ChunkBoundsError,
    ChunkCorrelationError,
    ChunkOffsetError,
)
from hermes_windows_bridge.ipc.operation_policy import (
    PrivilegedOperation,
    RebootPayload,
    ShutdownPayload,
)
from hermes_windows_bridge.ipc.protocol_errors import (
    CorrelationError as _CorrelationError,
)
from hermes_windows_bridge.ipc.protocol_errors import (
    ResponseStateError as _ResponseStateError,
)

CorrelationError = _CorrelationError
ResponseStateError = _ResponseStateError

PROTOCOL_VERSION: Final = 1
HEARTBEAT_INTERVAL_SECONDS: Final = 5
HEARTBEAT_OFFLINE_SECONDS: Final = 15
MAX_OUTPUT_CHUNK_BYTES: Final = 65_536
MAX_OUTPUT_OFFSET: Final = 2**63 - 1

type JsonPayload = dict[str, JsonValue]


class PeerRole(StrEnum):
    """IPC 경계에서 허용되는 프로세스 역할입니다."""

    GATEWAY = "gateway"
    WORKER = "worker"
    PRIVILEGED_HELPER = "privileged_helper"


class _StrictMessage(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal[1] = PROTOCOL_VERSION


class GatewayHello(_StrictMessage):
    """Worker가 SID를 검증하기 전에 Gateway가 보내는 handshake입니다."""

    kind: Literal["gateway_hello"] = "gateway_hello"
    source: Literal[PeerRole.GATEWAY] = PeerRole.GATEWAY
    target: Literal[PeerRole.WORKER, PeerRole.PRIVILEGED_HELPER]


class WorkerRegistration(_StrictMessage):
    """로그인 세션 Worker가 Gateway에 제공하는 등록 정보입니다."""

    kind: Literal["worker_register"] = "worker_register"
    registration_id: UUID
    generation: int = Field(ge=0)
    session_id: int = Field(ge=0)
    username: str = Field(min_length=1, max_length=256)


class Heartbeat(_StrictMessage):
    """등록된 Worker의 순서가 있는 생존 신호입니다."""

    kind: Literal["heartbeat"] = "heartbeat"
    registration_id: UUID
    sequence: int = Field(ge=0)
    session_id: int = Field(ge=0)
    username: str = Field(min_length=1, max_length=256)


class HelperRegistration(_StrictMessage):
    """Privileged Helper가 Gateway에 제공하는 generation identity입니다."""

    kind: Literal["helper_register"] = "helper_register"
    registration_id: UUID
    generation: int = Field(ge=0)


class HelperHeartbeat(_StrictMessage):
    """현재 Helper registration에 연관된 순서 있는 생존 신호입니다."""

    kind: Literal["helper_heartbeat"] = "helper_heartbeat"
    registration_id: UUID
    sequence: int = Field(ge=0)


class IpcRequest(_StrictMessage):
    """Gateway가 정책 검사를 마친 뒤 Worker로 보내는 요청입니다."""

    kind: Literal["request"] = "request"
    request_id: UUID
    source: Literal[PeerRole.GATEWAY] = PeerRole.GATEWAY
    target: Literal[PeerRole.WORKER]
    operation: str = Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_]*$")
    payload: JsonPayload
    timeout_ms: int = Field(gt=0, le=300_000)


class RebootIpcRequest(_StrictMessage):
    """Gateway가 Privileged Helper에 보내는 typed reboot 요청입니다."""

    kind: Literal["request"] = "request"
    request_id: UUID
    source: Literal[PeerRole.GATEWAY] = PeerRole.GATEWAY
    target: Literal[PeerRole.PRIVILEGED_HELPER] = PeerRole.PRIVILEGED_HELPER
    operation: Literal[PrivilegedOperation.REBOOT] = PrivilegedOperation.REBOOT
    payload: RebootPayload
    timeout_ms: int = Field(gt=0, le=300_000)


class ShutdownIpcRequest(_StrictMessage):
    """Gateway가 Privileged Helper에 보내는 typed shutdown 요청입니다."""

    kind: Literal["request"] = "request"
    request_id: UUID
    source: Literal[PeerRole.GATEWAY] = PeerRole.GATEWAY
    target: Literal[PeerRole.PRIVILEGED_HELPER] = PeerRole.PRIVILEGED_HELPER
    operation: Literal[PrivilegedOperation.SHUTDOWN] = PrivilegedOperation.SHUTDOWN
    payload: ShutdownPayload
    timeout_ms: int = Field(gt=0, le=300_000)


type PrivilegedIpcRequest = Annotated[
    RebootIpcRequest | ShutdownIpcRequest,
    Field(discriminator="operation"),
]
type RequestMessage = Annotated[
    IpcRequest | PrivilegedIpcRequest,
    Field(discriminator="target"),
]


class IpcResponse(_StrictMessage):
    """요청 ID로 반드시 연관되는 peer 응답입니다."""

    kind: Literal["response"] = "response"
    request_id: UUID
    ok: bool
    payload: JsonPayload | None = None
    error_code: str | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def result_matches_status(self) -> IpcResponse:
        """성공 응답과 실패 응답의 모순된 상태를 차단합니다."""
        if self.ok and self.error_code is not None:
            raise ResponseStateError(ok=self.ok, error_code=self.error_code)
        if not self.ok and self.error_code is None:
            raise ResponseStateError(ok=self.ok, error_code=self.error_code)
        return self


class JobOutputChunkRequest(_StrictMessage):
    """bounded job output window를 요청하는 Gateway 메시지입니다."""

    kind: Literal["job_output_chunk_request"] = "job_output_chunk_request"
    request_id: UUID
    source: Literal[PeerRole.GATEWAY] = PeerRole.GATEWAY
    target: Literal[PeerRole.WORKER] = PeerRole.WORKER
    job_id: UUID
    offset: int = Field(ge=0, le=MAX_OUTPUT_OFFSET)
    limit: int = Field(gt=0, le=MAX_OUTPUT_CHUNK_BYTES)

    @model_validator(mode="after")
    def window_fits_offset_domain(self) -> JobOutputChunkRequest:
        """Offset + limit 계산이 signed 64-bit 범위를 넘지 않게 합니다."""
        if self.offset > MAX_OUTPUT_OFFSET - self.limit:
            raise ChunkBoundsError(offset=self.offset, size=self.limit)
        return self


class JobOutputChunkResponse(_StrictMessage):
    """UTF-8 byte offset을 명시하는 bounded job output chunk입니다."""

    kind: Literal["job_output_chunk_response"] = "job_output_chunk_response"
    request_id: UUID
    source: Literal[PeerRole.WORKER] = PeerRole.WORKER
    target: Literal[PeerRole.GATEWAY] = PeerRole.GATEWAY
    job_id: UUID
    offset: int = Field(ge=0, le=MAX_OUTPUT_OFFSET)
    data: str
    next_offset: int = Field(ge=0, le=MAX_OUTPUT_OFFSET)
    complete: bool

    @model_validator(mode="after")
    def data_matches_byte_offsets(self) -> JobOutputChunkResponse:
        """Chunk 상한과 UTF-8 byte 기반 next offset을 함께 검증합니다."""
        size = len(self.data.encode("utf-8"))
        if size > MAX_OUTPUT_CHUNK_BYTES or self.offset > MAX_OUTPUT_OFFSET - size:
            raise ChunkBoundsError(offset=self.offset, size=size)
        expected_next_offset = self.offset + size
        if self.next_offset != expected_next_offset:
            raise ChunkOffsetError(expected=expected_next_offset, received=self.next_offset)
        return self


class CancelRequest(_StrictMessage):
    """대기 중인 요청을 request ID 기준으로 취소합니다."""

    kind: Literal["cancel"] = "cancel"
    request_id: UUID
    reason: str = Field(min_length=1, max_length=256)


type IpcMessage = (
    GatewayHello
    | WorkerRegistration
    | Heartbeat
    | HelperRegistration
    | HelperHeartbeat
    | RequestMessage
    | IpcResponse
    | JobOutputChunkRequest
    | JobOutputChunkResponse
    | CancelRequest
)


class _VersionEnvelope(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", strict=True)

    version: int


_MESSAGE_ADAPTER: Final[TypeAdapter[IpcMessage]] = TypeAdapter(IpcMessage)


@dataclass(frozen=True, slots=True)
class ProtocolMessageError(Exception):
    """입력이 IPC schema와 일치하지 않습니다."""

    detail: str

    @override
    def __str__(self) -> str:
        """Schema 오류 상세를 표시합니다."""
        return f"invalid IPC message: {self.detail}"


@dataclass(frozen=True, slots=True)
class ProtocolVersionError(Exception):
    """상대 peer의 IPC version이 현재 version과 다릅니다."""

    received: int
    expected: int = PROTOCOL_VERSION

    @override
    def __str__(self) -> str:
        """기대 version과 받은 version을 표시합니다."""
        return f"IPC protocol version {self.received} is not supported; expected {self.expected}"


def parse_message(raw: bytes) -> IpcMessage:
    """신뢰하지 않는 JSON bytes를 versioned IPC 메시지로 parse합니다."""
    try:
        envelope = _VersionEnvelope.model_validate_json(raw)
    except ValidationError as exc:
        raise ProtocolMessageError(detail=str(exc)) from exc
    if envelope.version != PROTOCOL_VERSION:
        raise ProtocolVersionError(received=envelope.version)
    try:
        return _MESSAGE_ADAPTER.validate_json(raw)
    except ValidationError as exc:
        raise ProtocolMessageError(detail=str(exc)) from exc


def serialize_message(message: IpcMessage) -> bytes:
    """검증된 IPC 메시지를 canonical compact JSON bytes로 변환합니다."""
    return _MESSAGE_ADAPTER.dump_json(message)


def correlate_response(request: RequestMessage, response: IpcMessage) -> IpcResponse:
    """응답 종류와 request ID를 함께 확인합니다."""
    match response:
        case IpcResponse(request_id=request_id):
            if request_id != request.request_id:
                raise CorrelationError(expected=request.request_id, received=request_id)
            return response
        case (
            GatewayHello()
            | WorkerRegistration()
            | Heartbeat()
            | HelperRegistration()
            | HelperHeartbeat()
            | IpcRequest()
            | RebootIpcRequest()
            | ShutdownIpcRequest()
            | JobOutputChunkRequest()
            | JobOutputChunkResponse()
            | CancelRequest()
        ):
            raise CorrelationError(expected=request.request_id, received=None)
        case _ as unreachable:
            assert_never(unreachable)


def correlate_chunk_response(
    request: JobOutputChunkRequest,
    response: IpcMessage,
) -> JobOutputChunkResponse:
    """Chunk 응답의 request와 job identity를 함께 확인합니다."""
    match response:
        case JobOutputChunkResponse(request_id=request_id):
            if request_id != request.request_id:
                raise CorrelationError(expected=request.request_id, received=request_id)
            if response.job_id != request.job_id or response.offset != request.offset:
                raise ChunkCorrelationError(
                    expected_job_id=request.job_id,
                    received_job_id=response.job_id,
                    expected_offset=request.offset,
                    received_offset=response.offset,
                )
            size = len(response.data.encode("utf-8"))
            if size > request.limit:
                raise ChunkBoundsError(offset=response.offset, size=size)
            return response
        case (
            GatewayHello()
            | WorkerRegistration()
            | Heartbeat()
            | HelperRegistration()
            | HelperHeartbeat()
            | IpcRequest()
            | RebootIpcRequest()
            | ShutdownIpcRequest()
            | IpcResponse()
            | JobOutputChunkRequest()
            | CancelRequest()
        ):
            raise CorrelationError(expected=request.request_id, received=None)
        case _ as unreachable:
            assert_never(unreachable)
