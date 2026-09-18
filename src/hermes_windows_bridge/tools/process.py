"""타입화된 process/app Worker 도구 어댑터입니다."""

from __future__ import annotations

from pathlib import Path  # noqa: TC003 - Pydantic runtime annotation입니다.
from typing import Annotated, ClassVar, final

from pydantic import BaseModel, ConfigDict, Field, field_validator

from hermes_windows_bridge.worker.processes import (
    ProcessInfo,
    ProcessManager,
    ProcessStartSpec,
    ProcessTermination,
    StartedProcess,
)


class _ToolModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)


class ProcessStartInput(_ToolModel):
    """process_start의 신뢰 경계 입력입니다."""

    argv: Annotated[tuple[str, ...], Field(min_length=1, max_length=256)]
    cwd: Path | None = None
    lifecycle_managed: bool = True

    @field_validator("argv")
    @classmethod
    def argv_has_no_empty_or_nul_values(cls, argv: tuple[str, ...]) -> tuple[str, ...]:
        """CreateProcess에 부적합한 빈/NUL argv를 거부합니다."""
        if any(not value or "\0" in value for value in argv):
            raise InvalidArgumentValueError
        return argv


class ProcessKillInput(_ToolModel):
    """process_kill의 exact owned PID 입력입니다."""

    pid: Annotated[int, Field(gt=0)]


class AppOpenInput(_ToolModel):
    """실행 파일 앱과 literal arguments 입력입니다."""

    target: Annotated[str, Field(min_length=1, max_length=32_767)]
    arguments: Annotated[tuple[str, ...], Field(max_length=255)] = ()
    cwd: Path | None = None

    @field_validator("target", "arguments")
    @classmethod
    def values_have_no_nul(cls, value: str | tuple[str, ...]) -> str | tuple[str, ...]:
        """Win32 문자열 경계를 자르는 NUL을 거부합니다."""
        values = (value,) if isinstance(value, str) else value
        if any("\0" in item for item in values):
            raise InvalidArgumentValueError
        return value


class ProcessListResult(_ToolModel):
    """process_list의 타입화된 snapshot입니다."""

    processes: tuple[ProcessInfo, ...]


@final
class ProcessToolService:
    """Gateway policy/idempotency 이후 Worker에서 실행되는 process 도구 집합입니다."""

    def __init__(self, manager: ProcessManager) -> None:
        """Worker process manager를 연결합니다."""
        self._manager = manager

    def process_list(self) -> ProcessListResult:
        """현재 프로세스 snapshot을 반환합니다."""
        return ProcessListResult(processes=self._manager.list_processes())

    def process_start(self, request: ProcessStartInput) -> StartedProcess:
        """검증된 argv로 user-level 프로세스를 시작합니다."""
        return self._manager.start(
            ProcessStartSpec(request.argv, request.cwd, request.lifecycle_managed)
        )

    def process_kill(self, request: ProcessKillInput) -> ProcessTermination:
        """Gateway가 허용한 destructive 요청을 소유 handle에만 적용합니다."""
        return self._manager.terminate(request.pid)

    def app_open(self, request: AppOpenInput) -> StartedProcess:
        """파일 연관 shell 없이 명시된 앱 executable을 시작합니다."""
        return self._manager.start(
            ProcessStartSpec(
                argv=(request.target, *request.arguments),
                cwd=request.cwd,
                lifecycle_managed=True,
            )
        )


class InvalidArgumentValueError(ValueError):
    """argv/target의 빈 값 또는 NUL을 거부합니다."""
