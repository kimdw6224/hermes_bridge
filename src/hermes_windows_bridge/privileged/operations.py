"""권한 helper가 인식하는 좁은 typed operation allowlist입니다."""

# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, ClassVar, Final, Literal, Protocol, assert_never, final, override

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

__all__ = (
    "InvalidPrivilegedOperationError",
    "PowerActionExecutor",
    "PowerActionResult",
    "PowerActionService",
    "PrivilegedOperation",
    "PrivilegedRequest",
    "RebootRequest",
    "ShutdownRequest",
    "parse_privileged_operation",
    "supported_operations",
)

type PrivilegedOperation = Literal["reboot", "shutdown"]
_SUPPORTED_OPERATIONS: Final[frozenset[PrivilegedOperation]] = frozenset({"reboot", "shutdown"})


class RebootRequest(BaseModel):
    """승인 계층이 별도로 처리할 reboot 요청입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    operation: Literal["reboot"]
    delay_seconds: int = Field(ge=0, le=300)
    reason: str = Field(min_length=1, max_length=200)


class ShutdownRequest(BaseModel):
    """승인 계층이 별도로 처리할 shutdown 요청입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    operation: Literal["shutdown"]
    delay_seconds: int = Field(ge=0, le=300)
    reason: str = Field(min_length=1, max_length=200)


type PrivilegedRequest = Annotated[
    RebootRequest | ShutdownRequest,
    Field(discriminator="operation"),
]

_REQUEST_ADAPTER: TypeAdapter[PrivilegedRequest] = TypeAdapter(PrivilegedRequest)


@dataclass(frozen=True, slots=True)
class InvalidPrivilegedOperationError(ValueError):
    """요청이 helper의 typed allowlist와 일치하지 않습니다."""

    @override
    def __str__(self) -> str:
        """고정된 boundary error를 반환합니다."""
        return "invalid privileged operation"


class PowerActionExecutor(Protocol):
    """검증된 전원 요청만 실행할 수 있는 좁은 Helper capability입니다."""

    def reboot(self, request: RebootRequest) -> None:
        """검증된 reboot 요청을 실행합니다."""
        ...

    def shutdown(self, request: ShutdownRequest) -> None:
        """검증된 shutdown 요청을 실행합니다."""
        ...


@dataclass(frozen=True, slots=True)
class PowerActionResult:
    """Helper 경계에서 실행된 allowlisted operation입니다."""

    operation: PrivilegedOperation


@final
class PowerActionService:
    """Strict parser 뒤에 주입된 executor만 호출하는 Helper service입니다."""

    def __init__(self, executor: PowerActionExecutor) -> None:
        """명시적으로 제공된 executor만 보관합니다."""
        self._executor = executor

    def execute_json(self, payload: str) -> PowerActionResult:
        """신뢰하지 않는 JSON을 먼저 strict request로 변환해 실행합니다."""
        return self.execute(parse_privileged_operation(payload))

    def execute(self, request: PrivilegedRequest) -> PowerActionResult:
        """Closed request variant를 해당 executor capability로 전달합니다."""
        match request:
            case RebootRequest():
                self._executor.reboot(request)
            case ShutdownRequest():
                self._executor.shutdown(request)
            case unreachable:
                assert_never(unreachable)
        return PowerActionResult(operation=request.operation)


def supported_operations() -> frozenset[PrivilegedOperation]:
    """Helper의 완전한 public operation registry를 반환합니다."""
    return _SUPPORTED_OPERATIONS


def parse_privileged_operation(payload: str) -> PrivilegedRequest:
    """JSON trust boundary에서 allowlisted operation만 파싱합니다."""
    try:
        return _REQUEST_ADAPTER.validate_json(payload)
    except ValidationError as error:
        raise InvalidPrivilegedOperationError from error
