"""Windows Job Object 수명과 전체 프로세스 트리 취소를 소유합니다."""

# pyright: reportArgumentType=false
# pyright: reportAssignmentType=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportMissingModuleSource=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Self, final, override

if TYPE_CHECKING:
    from types import TracebackType

_CANCEL_EXIT_CODE: Final = 1


@dataclass(frozen=True, slots=True)
class JobCancelReceipt:
    """Job 전체 취소의 관찰 가능한 결과입니다."""

    terminated: bool
    already_terminated: bool


@dataclass(frozen=True, slots=True)
class JobClosedError(RuntimeError):
    """이미 닫힌 kernel Job handle 사용을 거부합니다."""

    operation: str

    @override
    def __str__(self) -> str:
        return f"job handle is closed: {self.operation}"


@final
class WindowsJob:
    """Kill-on-close가 설정된 익명 Windows Job Object를 소유합니다."""

    __slots__: tuple[str, ...] = ("_cancelled", "_closed", "_handle")

    def __init__(self, handle: int) -> None:
        """CreateJobObject가 반환한 유일한 owning handle을 보관합니다."""
        self._handle = handle
        self._cancelled = False
        self._closed = False

    @classmethod
    def create(cls) -> Self:
        """자식 breakaway 없이 kill-on-close Job Object를 만듭니다."""
        import pywintypes  # noqa: PLC0415 - Windows 전용 오류 경계를 격리합니다.
        import win32job  # noqa: PLC0415 - Windows 전용 FFI 경계를 격리합니다.

        handle: int = win32job.CreateJobObject(None, "")
        try:
            limits = win32job.QueryInformationJobObject(
                handle,
                win32job.JobObjectExtendedLimitInformation,
            )
            limits["BasicLimitInformation"]["LimitFlags"] |= (
                win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            )
            win32job.SetInformationJobObject(
                handle,
                win32job.JobObjectExtendedLimitInformation,
                limits,
            )
        except OSError, pywintypes.error:
            handle.Close()
            raise
        return cls(handle)

    @property
    def closed(self) -> bool:
        """Kernel handle 폐기 여부를 반환합니다."""
        return self._closed

    def __enter__(self) -> Self:
        """소유 Job을 context에 제공합니다."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """정상/예외 경로 모두에서 Job handle을 닫습니다."""
        del exc_type, exc_value, traceback
        self.close()

    def assign_process(self, process_handle: int) -> None:
        """CREATE_SUSPENDED 상태의 exact process handle을 Job에 연결합니다."""
        if self._closed:
            raise JobClosedError(operation="assign_process")
        import win32job  # noqa: PLC0415 - Windows 전용 FFI 경계를 격리합니다.

        win32job.AssignProcessToJobObject(self._handle, process_handle)

    def cancel(self) -> JobCancelReceipt:
        """Job과 상속된 모든 descendant를 한 번만 종료합니다."""
        if self._closed or self._cancelled:
            return JobCancelReceipt(terminated=True, already_terminated=True)
        import win32job  # noqa: PLC0415 - Windows 전용 FFI 경계를 격리합니다.

        win32job.TerminateJobObject(self._handle, _CANCEL_EXIT_CODE)
        self._cancelled = True
        return JobCancelReceipt(terminated=True, already_terminated=False)

    def close(self) -> None:
        """마지막 Job handle을 폐기해 남은 descendant를 kill-on-close로 정리합니다."""
        if self._closed:
            return
        self._handle.Close()
        self._closed = True
        self._cancelled = True
