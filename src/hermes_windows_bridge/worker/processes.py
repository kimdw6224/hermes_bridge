"""사용자 세션 프로세스를 exact handle과 Job Object로 관리합니다."""

# pyright: reportArgumentType=false
# pyright: reportAny=false
# pyright: reportMissingModuleSource=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Self, final, override

import psutil

from hermes_windows_bridge.worker.job_object import JobCancelReceipt, WindowsJob

if TYPE_CHECKING:
    from pathlib import Path
    from types import TracebackType

_WAIT_SIGNALED: Final = 0
_WAIT_TIMEOUT: Final = 258
_FAILED_START_CLEANUP_TIMEOUT_MS: Final = 5_000


@dataclass(frozen=True, slots=True)
class ProcessStartSpec:
    """검증된 argv 기반 프로세스 시작 사양입니다."""

    argv: tuple[str, ...]
    cwd: Path | None
    lifecycle_managed: bool


@dataclass(frozen=True, slots=True)
class ProcessInfo:
    """권한 부족 필드를 None으로 유지하는 프로세스 목록 항목입니다."""

    pid: int
    name: str
    executable: str | None
    create_time: float


@dataclass(frozen=True, slots=True)
class StartedProcess:
    """Worker가 보유한 exact process identity와 kernel handle입니다."""

    pid: int
    process_handle: int
    lifecycle_managed: bool


@dataclass(frozen=True, slots=True)
class ProcessTermination:
    """소유 프로세스 종료 receipt입니다."""

    pid: int
    terminated: bool
    already_terminated: bool


@dataclass(frozen=True, slots=True)
class ProcessNotOwnedError(PermissionError):
    """Worker가 생성하지 않은 PID 제어를 거부합니다."""

    pid: int

    @override
    def __str__(self) -> str:
        return f"process is not owned by this worker: {self.pid}"


@dataclass(frozen=True, slots=True)
class ExecutableNotFoundError(FileNotFoundError):
    """argv[0] 실행 파일을 안전하게 해석할 수 없습니다."""

    executable: str

    @override
    def __str__(self) -> str:
        return f"executable not found: {self.executable}"


@final
class _OwnedProcess:
    """Kernel resource 수명 상태를 의도적으로 변경하는 내부 소유 레코드입니다."""

    __slots__: tuple[str, ...] = ("handle", "job", "terminated")

    def __init__(self, handle: int, job: WindowsJob | None) -> None:
        self.handle: int = handle
        self.job: WindowsJob | None = job
        self.terminated: bool = False


@final
class ProcessManager:
    """이 인스턴스가 시작한 프로세스만 exact handle로 제어합니다."""

    def __init__(self) -> None:
        """빈 process handle registry를 만듭니다."""
        self._owned: dict[int, _OwnedProcess] = {}
        self._closed = False

    def __enter__(self) -> Self:
        """소유 manager를 context에 제공합니다."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """정상/예외 경로 모두에서 소유 프로세스를 정리합니다."""
        del exc_type, exc_value, traceback
        self.close()

    def list_processes(self) -> tuple[ProcessInfo, ...]:
        """현재 접근 가능한 프로세스를 PID 순으로 snapshot합니다."""
        processes: list[ProcessInfo] = []
        for process in psutil.process_iter(("pid", "name", "exe", "create_time")):
            try:
                info = process.as_dict(attrs=("pid", "name", "exe", "create_time"))
                processes.append(
                    ProcessInfo(
                        pid=int(info["pid"]),
                        name=str(info["name"] or ""),
                        executable=str(info["exe"]) if info["exe"] is not None else None,
                        create_time=float(info["create_time"]),
                    )
                )
            except psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess:
                continue
        return tuple(sorted(processes, key=lambda item: item.pid))

    def start(self, spec: ProcessStartSpec) -> StartedProcess:
        """프로세스를 suspended로 만들고 Job 할당 후에만 실행을 재개합니다."""
        if self._closed:
            raise ProcessManagerClosedError
        executable = shutil.which(spec.argv[0])
        if executable is None:
            raise ExecutableNotFoundError(executable=spec.argv[0])
        import pywintypes  # noqa: PLC0415 - Windows 전용 오류 경계를 격리합니다.
        import win32api  # noqa: PLC0415 - Windows 전용 FFI 경계를 격리합니다.
        import win32con  # noqa: PLC0415 - Windows 전용 FFI 경계를 격리합니다.
        import win32event  # noqa: PLC0415 - Windows 전용 FFI 경계를 격리합니다.
        import win32process  # noqa: PLC0415 - Windows 전용 FFI 경계를 격리합니다.

        command_line = subprocess.list2cmdline(spec.argv)
        process_handle, thread_handle, pid, _ = win32process.CreateProcess(
            executable,
            command_line,
            None,
            None,
            False,  # noqa: FBT003 - Win32 positional API입니다.
            win32con.CREATE_SUSPENDED,
            None,
            str(spec.cwd) if spec.cwd is not None else None,
            win32process.STARTUPINFO(),
        )
        job: WindowsJob | None = None
        try:
            if spec.lifecycle_managed:
                job = WindowsJob.create()
            if job is not None:
                job.assign_process(process_handle)
            _ = win32process.ResumeThread(thread_handle)
        except OSError, pywintypes.error:
            try:
                win32process.TerminateProcess(process_handle, 1)
                # 종료 요청은 비동기이므로 핸들을 닫기 전에 실제 종료를 확인합니다.
                wait_result = win32event.WaitForSingleObject(
                    process_handle, _FAILED_START_CLEANUP_TIMEOUT_MS
                )
                if wait_result != _WAIT_SIGNALED:
                    raise OSError(wait_result, "failed-start process cleanup did not complete")
            finally:
                try:
                    if job is not None:
                        job.close()
                finally:
                    win32api.CloseHandle(process_handle)
            raise
        finally:
            win32api.CloseHandle(thread_handle)
        self._owned[pid] = _OwnedProcess(process_handle, job)
        return StartedProcess(pid, process_handle, spec.lifecycle_managed)

    def terminate(self, pid: int) -> ProcessTermination:
        """소유 registry의 exact handle 또는 Job만 종료하며 PID를 재개방하지 않습니다."""
        owned = self._get_owned(pid)
        if owned.terminated or self.wait(pid, timeout_ms=0):
            owned.terminated = True
            return ProcessTermination(pid, terminated=True, already_terminated=True)
        if owned.job is not None:
            _ = owned.job.cancel()
        else:
            import win32process  # noqa: PLC0415 - Windows 전용 FFI 경계를 격리합니다.

            win32process.TerminateProcess(owned.handle, 1)
        owned.terminated = True
        return ProcessTermination(pid, terminated=True, already_terminated=False)

    def cancel_tree(self, pid: int) -> JobCancelReceipt:
        """Managed process의 Job 전체를 취소합니다."""
        owned = self._get_owned(pid)
        if owned.job is None:
            raise ProcessHasNoJobError(pid=pid)
        receipt = owned.job.cancel()
        owned.terminated = True
        return receipt

    def job_for(self, pid: int) -> WindowsJob:
        """Task 9/17 소비자가 소유 Job 수명을 연결할 수 있게 반환합니다."""
        owned = self._get_owned(pid)
        if owned.job is None:
            raise ProcessHasNoJobError(pid=pid)
        return owned.job

    def wait(self, pid: int, *, timeout_ms: int) -> bool:
        """PID가 아닌 exact process handle의 signaled 상태를 bounded wait합니다."""
        import win32event  # noqa: PLC0415 - Windows 전용 FFI 경계를 격리합니다.

        result = win32event.WaitForSingleObject(self._get_owned(pid).handle, timeout_ms)
        if result == _WAIT_SIGNALED:
            return True
        if result == _WAIT_TIMEOUT:
            return False
        raise OSError(result, "WaitForSingleObject failed")

    def close(self) -> None:
        """예외 경로에서도 모든 소유 Job/process handle을 정리합니다."""
        if self._closed:
            return
        import win32api  # noqa: PLC0415 - Windows 전용 FFI 경계를 격리합니다.
        import win32process  # noqa: PLC0415 - Windows 전용 FFI 경계를 격리합니다.

        for pid, owned in self._owned.items():
            if not owned.terminated and not self.wait(pid, timeout_ms=0):
                if owned.job is not None:
                    _ = owned.job.cancel()
                else:
                    win32process.TerminateProcess(owned.handle, 1)
            if owned.job is not None:
                owned.job.close()
            win32api.CloseHandle(owned.handle)
        self._closed = True

    def _get_owned(self, pid: int) -> _OwnedProcess:
        owned = self._owned.get(pid)
        if owned is None:
            raise ProcessNotOwnedError(pid=pid)
        return owned


class ProcessManagerClosedError(RuntimeError):
    """닫힌 manager는 새 kernel resource를 소유할 수 없습니다."""


@dataclass(frozen=True, slots=True)
class ProcessHasNoJobError(RuntimeError):
    """unmanaged process에는 tree cancellation Job이 없습니다."""

    pid: int

    @override
    def __str__(self) -> str:
        return f"process has no lifecycle job: {self.pid}"
