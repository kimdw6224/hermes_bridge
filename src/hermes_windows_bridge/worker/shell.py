"""로그인 사용자 토큰을 상속하는 bounded Windows shell 실행기입니다."""

# pyright: reportArgumentType=false
# pyright: reportMissingModuleSource=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false
# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from threading import Lock, Thread
from time import monotonic
from typing import IO, Final, assert_never

import psutil

from hermes_windows_bridge.worker.job_object import WindowsJob

DEFAULT_TIMEOUT_SECONDS: Final = 60
MAX_SYNC_SECONDS: Final = 110
DEFAULT_MAX_OUTPUT_BYTES: Final = 200_000


class ShellKind(StrEnum):
    """지원하는 명시적 shell launcher입니다."""

    POWERSHELL = "powershell"
    CMD = "cmd"
    GIT_BASH = "git-bash"


@dataclass(frozen=True, slots=True)
class ShellWarning:
    """보안 판정이 아닌 heuristic accident warning입니다."""

    code: str


@dataclass(frozen=True, slots=True)
class ShellRequest:
    """도구 경계에서 이미 검증된 Worker 요청입니다."""

    command: str
    cwd: Path
    shell: ShellKind
    timeout_s: int = DEFAULT_TIMEOUT_SECONDS


@dataclass(frozen=True, slots=True)
class ShellResult:
    """프로세스 결과와 bounded-output 관찰 metadata입니다."""

    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    truncated: bool
    stdout_bytes: int
    stderr_bytes: int
    timed_out: bool
    execution_user: str
    is_elevated: bool
    process_tree_managed: bool
    warnings: tuple[ShellWarning, ...]


class GitBashNotInstalledError(FileNotFoundError):
    """Git for Windows의 bash executable을 찾지 못했습니다."""


class ShellTimeoutLimitError(ValueError):
    """구성된 동기 실행 상한보다 긴 요청을 거부합니다."""


_ACCIDENT_PATTERNS: Final = {
    "format_volume": r"(?i)(?:^|[;&|]\s*)format(?:\.com)?\b",
    "clear_disk": r"(?i)\bClear-Disk\b",
    "remove_partition": r"(?i)\bRemove-Partition\b",
    "diskpart_clean": r"(?is)\bdiskpart\b.*\bclean(?:\s+all)?\b",
    "bcd_mutation": r"(?i)\bbcdedit\b.*\/(?:set|delete|deletevalue|import)\b",
    "recursive_delete": r"(?i)(?:\bRemove-Item\b.*\b-Recurse\b|\b(?:rd|rmdir)\b.*\/s\b)",
    "security_disable": r"(?i)(?:DisableRealtimeMonitoring|\bSet-MpPreference\b.*\bDisable\w*\b)",
    "opaque_encoded_command": r"(?i)(?:-EncodedCommand\b|\s-enc\s)",
}


def inspect_command(command: str) -> tuple[ShellWarning, ...]:
    """명백한 사고 징후만 경고하며 command 허용 여부를 판정하지 않습니다."""
    return tuple(
        ShellWarning(code=code)
        for code, pattern in _ACCIDENT_PATTERNS.items()
        if re.search(pattern, command) is not None
    )


class _OutputBudget:
    def __init__(self, limit: int) -> None:
        self._remaining: int = limit
        self._lock: Lock = Lock()

    def take(self, chunk: bytes) -> bytes:
        with self._lock:
            kept = chunk[: self._remaining]
            self._remaining -= len(kept)
            return kept


class _PipeCapture:
    def __init__(self, budget: _OutputBudget) -> None:
        self._budget: _OutputBudget = budget
        self._chunks: list[bytes] = []
        self.total_bytes: int = 0

    def drain(self, pipe: IO[bytes]) -> None:
        with pipe:
            while chunk := pipe.read(8_192):
                self.total_bytes += len(chunk)
                kept = self._budget.take(chunk)
                if kept:
                    self._chunks.append(kept)

    def text(self, encoding: str, utf8_budget: _OutputBudget) -> tuple[str, bool]:
        decoded = b"".join(self._chunks).decode(encoding, errors="ignore")
        encoded = decoded.encode("utf-8")
        kept = utf8_budget.take(encoded)
        text = kept.decode("utf-8", errors="ignore")
        return text, len(text.encode("utf-8")) < len(encoded)


class ShellWorker:
    """현재 Worker 계정으로 shell child와 Job Object 수명을 소유합니다."""

    def __init__(
        self,
        *,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        max_sync_seconds: int = MAX_SYNC_SECONDS,
        inspect_commands_for_accident_prevention: bool = True,
    ) -> None:
        """Policy 상한을 전역 hard cap 안에서 보관합니다."""
        self._max_output_bytes: int = max_output_bytes
        self._max_sync_seconds: int = min(max_sync_seconds, MAX_SYNC_SECONDS)
        self._inspect_commands: bool = inspect_commands_for_accident_prevention

    def run(self, request: ShellRequest) -> ShellResult:
        """명시적 argv로 실행하고 timeout 시 전체 process tree를 정리합니다."""
        if request.timeout_s > self._max_sync_seconds:
            raise ShellTimeoutLimitError
        started_at = monotonic()
        warnings = list(inspect_command(request.command)) if self._inspect_commands else []
        process = subprocess.Popen(  # noqa: S603 - shell=False인 명시적 launcher argv입니다.
            _shell_argv(request.shell, request.command),
            cwd=request.cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        job = _assign_job(process.pid)
        warnings += [ShellWarning(code="job_object_unavailable")] if job is None else []
        budget = _OutputBudget(self._max_output_bytes)
        stdout, stderr = _PipeCapture(budget), _PipeCapture(budget)
        stdout_thread = _start_drain(process.stdout, stdout)
        stderr_thread = _start_drain(process.stderr, stderr)
        timed_out = False
        try:
            try:
                exit_code = process.wait(timeout=request.timeout_s)
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate_tree(process, job)
                exit_code = process.wait(timeout=5)
        finally:
            if job is not None:
                job.close()
        stdout_thread.join(5)
        stderr_thread.join(5)
        utf8_budget = _OutputBudget(self._max_output_bytes)
        encoding = "utf-16-le" if request.shell is ShellKind.CMD else "utf-8"
        stdout_text, stdout_trimmed = stdout.text(encoding, utf8_budget)
        stderr_text, stderr_trimmed = stderr.text(encoding, utf8_budget)
        trimmed = stdout_trimmed or stderr_trimmed
        return ShellResult(
            exit_code=exit_code,
            stdout=stdout_text,
            stderr=stderr_text,
            duration_ms=round((monotonic() - started_at) * 1_000),
            truncated=stdout.total_bytes + stderr.total_bytes > self._max_output_bytes or trimmed,
            stdout_bytes=stdout.total_bytes,
            stderr_bytes=stderr.total_bytes,
            timed_out=timed_out,
            execution_user=psutil.Process().username(),
            is_elevated=_current_process_is_elevated(),
            process_tree_managed=job is not None,
            warnings=tuple(warnings),
        )


def _start_drain(pipe: IO[bytes] | None, capture: _PipeCapture) -> Thread:
    if pipe is None:
        raise RuntimeError
    thread = Thread(target=capture.drain, args=(pipe,), daemon=True)
    thread.start()
    return thread


def _shell_argv(shell: ShellKind, command: str) -> tuple[str, ...]:
    match shell:
        case ShellKind.POWERSHELL:
            executable = shutil.which("powershell.exe") or "powershell.exe"
            utf8_command = "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);" + command
            flags = ("-NoLogo", "-NoProfile", "-NonInteractive", "-Command")
            return (executable, *flags, utf8_command)
        case ShellKind.CMD:
            executable = os.environ.get("COMSPEC") or shutil.which("cmd.exe") or "cmd.exe"
            return (executable, "/U", "/D", "/S", "/C", command)
        case ShellKind.GIT_BASH:
            return (_find_git_bash(), "--noprofile", "--norc", "-c", command)
        case _ as unreachable:
            assert_never(unreachable)


def _find_git_bash() -> str:
    git = shutil.which("git.exe")
    candidates: list[Path] = []
    if git is not None:
        root = Path(git).parent.parent
        candidates.extend((root / "bin" / "bash.exe", root / "usr" / "bin" / "bash.exe"))
    for environment_name in ("ProgramFiles", "LOCALAPPDATA"):
        base = os.environ.get(environment_name)
        if base is not None:
            candidates.append(Path(base) / "Git" / "bin" / "bash.exe")
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    raise GitBashNotInstalledError


def _assign_job(pid: int) -> WindowsJob | None:
    import pywintypes  # noqa: PLC0415 - Windows Job API 실패만 fallback합니다.
    import win32api  # noqa: PLC0415 - exact child handle을 잠깐 엽니다.
    import win32con  # noqa: PLC0415 - 최소 access mask 상수입니다.

    job: WindowsJob | None = None
    try:
        job = WindowsJob.create()
        handle = win32api.OpenProcess(
            win32con.PROCESS_SET_QUOTA | win32con.PROCESS_TERMINATE,
            False,  # noqa: FBT003 - Win32 positional API입니다.
            pid,
        )
        try:
            job.assign_process(handle)
        finally:
            win32api.CloseHandle(handle)
    except OSError, pywintypes.error:
        if job is not None:
            job.close()
        return None
    return job


def _terminate_tree(process: subprocess.Popen[bytes], job: WindowsJob | None) -> None:
    if job is not None:
        _ = job.cancel()
        return
    try:
        root = psutil.Process(process.pid)
        descendants = root.children(recursive=True)
    except psutil.NoSuchProcess:
        descendants = []
    for child in descendants:
        try:
            child.kill()
        except psutil.AccessDenied, psutil.NoSuchProcess:
            continue
    process.kill()
    _, alive = psutil.wait_procs(descendants, timeout=5)
    for child in alive:
        try:
            child.kill()
        except psutil.AccessDenied, psutil.NoSuchProcess:
            continue


def _current_process_is_elevated() -> bool:
    import win32api  # noqa: PLC0415 - Worker token 검사를 Windows 경계에 격리합니다.
    import win32con  # noqa: PLC0415 - TOKEN_QUERY access mask입니다.
    import win32security  # noqa: PLC0415 - TokenElevation API입니다.

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        return bool(win32security.GetTokenInformation(token, win32security.TokenElevation))
    finally:
        win32api.CloseHandle(token)
