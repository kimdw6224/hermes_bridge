"""Suspended Windows child와 bounded output/handle 수명을 소유합니다."""

# pyright: reportArgumentType=false
# pyright: reportAssignmentType=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportMissingModuleSource=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from threading import Lock, Thread
from typing import IO, TYPE_CHECKING, cast, final

from hermes_windows_bridge.worker.job_object import JobCancelReceipt, WindowsJob

if TYPE_CHECKING:
    from pathlib import Path

_CANCEL_EXIT_CODE = 1


@dataclass(frozen=True, slots=True)
class JobProcessSpec:
    """Worker 계정으로 실행할 literal argv와 작업 디렉터리입니다."""

    argv: tuple[str, ...]
    cwd: Path


@dataclass(frozen=True, slots=True)
class JobProcessResult:
    """종료 코드와 전역 상한이 적용된 출력입니다."""

    exit_code: int
    stdout: str
    stderr: str
    stdout_bytes: int
    stderr_bytes: int
    truncated: bool


@final
class _ByteBudget:
    def __init__(self, limit: int) -> None:
        self._remaining = limit
        self._lock = Lock()

    def take(self, chunk: bytes) -> bytes:
        with self._lock:
            kept = chunk[: self._remaining]
            self._remaining -= len(kept)
            return kept


@final
class _Capture:
    def __init__(self, budget: _ByteBudget) -> None:
        self._budget = budget
        self._chunks: list[bytes] = []
        self.total_bytes = 0

    def drain(self, pipe: IO[bytes]) -> None:
        with pipe:
            while chunk := pipe.read(8_192):
                self.total_bytes += len(chunk)
                kept = self._budget.take(chunk)
                if kept:
                    self._chunks.append(kept)

    def text(self) -> str:
        return b"".join(self._chunks).decode("utf-8", errors="ignore")


@dataclass(frozen=True, slots=True)
class _SuspendedProcess:
    process_handle: int
    thread_handle: int
    pid: int
    stdout: IO[bytes]
    stderr: IO[bytes]


def _create_suspended(spec: JobProcessSpec, environment: dict[str, str]) -> _SuspendedProcess:
    executable = shutil.which(spec.argv[0])
    if executable is None:
        raise FileNotFoundError(spec.argv[0])
    import msvcrt  # noqa: PLC0415 - Windows HANDLE을 Python pipe로 이전합니다.

    import pywintypes  # noqa: PLC0415 - Windows security attributes입니다.
    import win32api  # noqa: PLC0415 - Handle 상속 제어 경계입니다.
    import win32con  # noqa: PLC0415 - Win32 process/handle flags입니다.
    import win32file  # noqa: PLC0415 - NUL stdin handle을 만듭니다.
    import win32pipe  # noqa: PLC0415 - Child output pipe를 만듭니다.
    import win32process  # noqa: PLC0415 - exact suspended handles를 반환합니다.

    security = pywintypes.SECURITY_ATTRIBUTES()
    security.bInheritHandle = True
    stdout_read, stdout_write = win32pipe.CreatePipe(security, 0)
    stderr_read, stderr_write = win32pipe.CreatePipe(security, 0)
    stdin_handle = win32file.CreateFile(
        "NUL",
        win32con.GENERIC_READ,
        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
        security,
        win32con.OPEN_EXISTING,
        0,
        None,
    )
    win32api.SetHandleInformation(stdout_read, win32con.HANDLE_FLAG_INHERIT, 0)
    win32api.SetHandleInformation(stderr_read, win32con.HANDLE_FLAG_INHERIT, 0)
    stdout = os.fdopen(
        msvcrt.open_osfhandle(stdout_read.Detach(), os.O_RDONLY | os.O_BINARY),
        "rb",
        buffering=0,
    )
    stderr = os.fdopen(
        msvcrt.open_osfhandle(stderr_read.Detach(), os.O_RDONLY | os.O_BINARY),
        "rb",
        buffering=0,
    )
    startup = win32process.STARTUPINFO()
    startup.dwFlags |= win32process.STARTF_USESTDHANDLES
    startup.hStdInput = stdin_handle
    startup.hStdOutput = stdout_write
    startup.hStdError = stderr_write
    try:
        process_handle, thread_handle, pid, _ = cast(
            "tuple[int, int, int, int]",
            win32process.CreateProcess(
                executable,
                subprocess.list2cmdline(spec.argv),
                None,
                None,
                True,  # noqa: FBT003 - 지정한 stdio handle만 상속합니다.
                win32con.CREATE_SUSPENDED | win32con.CREATE_NO_WINDOW,
                environment,
                str(spec.cwd),
                startup,
            ),
        )
    except OSError, pywintypes.error:
        stdout.close()
        stderr.close()
        raise
    finally:
        win32api.CloseHandle(stdin_handle)
        win32api.CloseHandle(stdout_write)
        win32api.CloseHandle(stderr_write)
    return _SuspendedProcess(process_handle, thread_handle, pid, stdout, stderr)


@final
class RunningJobProcess:
    """단일 child, bounded drain, exact kernel handle 수명을 소유합니다."""

    def __init__(self, spec: JobProcessSpec, *, max_output_bytes: int) -> None:
        """Child를 suspended로 만들고 Job 할당 뒤에만 실행합니다."""
        environment = os.environ.copy()
        _ = environment.setdefault("PYTHONIOENCODING", "utf-8")
        process = _create_suspended(spec, environment)
        import pywintypes  # noqa: PLC0415 - Windows 오류 경계를 격리합니다.
        import win32api  # noqa: PLC0415 - exact handle을 닫습니다.
        import win32process  # noqa: PLC0415 - 할당 후 primary thread를 재개합니다.

        job: WindowsJob | None = None
        try:
            job = WindowsJob.create()
            job.assign_process(process.process_handle)
            _ = win32process.ResumeThread(process.thread_handle)
        except OSError, pywintypes.error:
            win32process.TerminateProcess(process.process_handle, _CANCEL_EXIT_CODE)
            if job is not None:
                job.close()
            win32api.CloseHandle(process.process_handle)
            process.stdout.close()
            process.stderr.close()
            raise
        finally:
            win32api.CloseHandle(process.thread_handle)
        budget = _ByteBudget(max_output_bytes)
        self._process_handle = process.process_handle
        self._pid = process.pid
        self._job = job
        self._stdout = _Capture(budget)
        self._stderr = _Capture(budget)
        self._stdout_thread = self._start_drain(process.stdout, self._stdout)
        self._stderr_thread = self._start_drain(process.stderr, self._stderr)
        self._lifecycle_lock = Lock()
        self._closed = False

    @property
    def pid(self) -> int:
        """소유한 root process ID입니다."""
        return self._pid

    def wait(self) -> JobProcessResult:
        """종료와 pipe EOF 뒤 bounded immutable 결과를 반환합니다."""
        try:
            import win32event  # noqa: PLC0415 - exact process handle을 기다립니다.
            import win32process  # noqa: PLC0415 - exact handle의 exit code를 읽습니다.

            _ = win32event.WaitForSingleObject(self._process_handle, win32event.INFINITE)
            exit_code: int = win32process.GetExitCodeProcess(self._process_handle)
            self._stdout_thread.join()
            self._stderr_thread.join()
            stdout, stderr = self._stdout.text(), self._stderr.text()
            retained = len(stdout.encode()) + len(stderr.encode())
            return JobProcessResult(
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                stdout_bytes=self._stdout.total_bytes,
                stderr_bytes=self._stderr.total_bytes,
                truncated=retained < self._stdout.total_bytes + self._stderr.total_bytes,
            )
        finally:
            self.close()

    def cancel(self) -> JobCancelReceipt:
        """Job Object로 전체 process tree를 종료합니다."""
        with self._lifecycle_lock:
            return self._job.cancel()

    def close(self) -> None:
        """Job과 exact process handle을 한 번만 닫습니다."""
        with self._lifecycle_lock:
            if self._closed:
                return
            import win32api  # noqa: PLC0415 - exact process handle을 닫습니다.

            self._job.close()
            win32api.CloseHandle(self._process_handle)
            self._closed = True

    @staticmethod
    def _start_drain(pipe: IO[bytes], capture: _Capture) -> Thread:
        thread = Thread(target=capture.drain, args=(pipe,), daemon=True)
        thread.start()
        return thread
