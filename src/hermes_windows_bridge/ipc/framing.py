"""IPC JSON 메시지용 4-byte big-endian length framing입니다."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Protocol, final, override

from hermes_windows_bridge.ipc.protocol import IpcMessage, parse_message, serialize_message

LENGTH_PREFIX_SIZE: Final = 4
MAX_MESSAGE_SIZE: Final = 1_048_576


class ByteReader(Protocol):
    """동기 framed 입력에 필요한 최소 read 계약입니다."""

    def read(self, size: int, /) -> bytes:
        """최대 size bytes를 반환합니다."""
        ...


@dataclass(frozen=True, slots=True)
class FrameTooLargeError(Exception):
    """선언되거나 직렬화된 frame이 정책 상한을 넘었습니다."""

    size: int
    maximum: int

    @override
    def __str__(self) -> str:
        """크기 제한과 실제 크기를 표시합니다."""
        return f"IPC frame size {self.size} exceeds maximum {self.maximum}"


@dataclass(frozen=True, slots=True)
class TruncatedFrameError(Exception):
    """연결이 length prefix 또는 body 완성 전에 종료되었습니다."""

    expected: int
    received: int

    @override
    def __str__(self) -> str:
        """기대한 길이와 실제 수신 길이를 표시합니다."""
        return f"IPC frame truncated: expected {self.expected} bytes, received {self.received}"


@dataclass(frozen=True, slots=True)
class TrailingFrameDataError(Exception):
    """단일 frame API에 추가 bytes가 전달되었습니다."""

    trailing_size: int

    @override
    def __str__(self) -> str:
        """추가로 발견된 byte 수를 표시합니다."""
        return f"IPC frame contains {self.trailing_size} trailing bytes"


def encode_frame(
    message: IpcMessage,
    *,
    max_message_size: int = MAX_MESSAGE_SIZE,
) -> bytes:
    """검증된 메시지에 unsigned 4-byte length prefix를 붙입니다."""
    payload = serialize_message(message)
    if len(payload) > max_message_size:
        raise FrameTooLargeError(size=len(payload), maximum=max_message_size)
    return len(payload).to_bytes(LENGTH_PREFIX_SIZE, "big") + payload


def decode_frame(
    frame: bytes,
    *,
    max_message_size: int = MAX_MESSAGE_SIZE,
) -> IpcMessage:
    """메모리의 정확히 한 frame을 typed IPC 메시지로 parse합니다."""
    if len(frame) < LENGTH_PREFIX_SIZE:
        raise TruncatedFrameError(expected=LENGTH_PREFIX_SIZE, received=len(frame))
    body_size = int.from_bytes(frame[:LENGTH_PREFIX_SIZE], "big")
    if body_size > max_message_size:
        raise FrameTooLargeError(size=body_size, maximum=max_message_size)
    expected_size = LENGTH_PREFIX_SIZE + body_size
    if len(frame) < expected_size:
        raise TruncatedFrameError(expected=expected_size, received=len(frame))
    if len(frame) > expected_size:
        raise TrailingFrameDataError(trailing_size=len(frame) - expected_size)
    return parse_message(frame[LENGTH_PREFIX_SIZE:])


def read_frame(
    stream: ByteReader,
    *,
    max_message_size: int = MAX_MESSAGE_SIZE,
) -> IpcMessage:
    """부분 read를 허용하되 EOF에는 fail closed하는 framed read입니다."""
    prefix = _read_exact(stream, LENGTH_PREFIX_SIZE)
    body_size = int.from_bytes(prefix, "big")
    if body_size > max_message_size:
        raise FrameTooLargeError(size=body_size, maximum=max_message_size)
    return parse_message(_read_exact(stream, body_size))


def _read_exact(stream: ByteReader, size: int) -> bytes:
    chunks: list[bytes] = []
    received = 0
    while received < size:
        chunk = stream.read(size - received)
        if not chunk:
            raise TruncatedFrameError(expected=size, received=received)
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)


@final
class FrameDecoder:
    """부분 수신과 취소 후 재사용을 위해 buffer 상태를 소유합니다."""

    __slots__: tuple[str, str] = ("_buffer", "_max_message_size")

    def __init__(self, max_message_size: int = MAX_MESSAGE_SIZE) -> None:
        """빈 decoder를 주어진 최대 message 크기로 초기화합니다."""
        self._buffer: bytearray = bytearray()
        self._max_message_size: int = max_message_size

    def feed(self, chunk: bytes) -> tuple[IpcMessage, ...]:
        """새 bytes를 추가하고 현재 완성된 frame들을 반환합니다."""
        self._buffer.extend(chunk)
        messages: list[IpcMessage] = []
        while len(self._buffer) >= LENGTH_PREFIX_SIZE:
            body_size = int.from_bytes(self._buffer[:LENGTH_PREFIX_SIZE], "big")
            if body_size > self._max_message_size:
                self.reset()
                raise FrameTooLargeError(size=body_size, maximum=self._max_message_size)
            frame_size = LENGTH_PREFIX_SIZE + body_size
            if len(self._buffer) < frame_size:
                break
            frame = bytes(self._buffer[:frame_size])
            del self._buffer[:frame_size]
            messages.append(decode_frame(frame, max_message_size=self._max_message_size))
        return tuple(messages)

    def finish(self) -> None:
        """연결 종료 시 남은 partial frame을 오류로 변환합니다."""
        if self._buffer:
            received = len(self._buffer)
            expected = LENGTH_PREFIX_SIZE
            if received >= LENGTH_PREFIX_SIZE:
                expected += int.from_bytes(self._buffer[:LENGTH_PREFIX_SIZE], "big")
            self.reset()
            raise TruncatedFrameError(expected=expected, received=received)

    def reset(self) -> None:
        """취소되거나 끊긴 요청의 partial bytes를 폐기합니다."""
        self._buffer.clear()
