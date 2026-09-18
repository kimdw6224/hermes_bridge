"""로그인 사용자 세션에서만 시작하는 Worker task 계약입니다."""

# pyright: reportUnnecessaryComparison=false, reportUnreachable=false

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from random import SystemRandom
from threading import Event
from typing import TYPE_CHECKING, Final, Protocol, assert_never, final, override

from hermes_windows_bridge.config import load_bridge_settings, load_policy_settings
from hermes_windows_bridge.runtime_binding import (
    RuntimeBinding,
    RuntimeBindingError,
    RuntimeProfile,
    load_runtime_binding,
    parse_runtime_binding_args,
)
from hermes_windows_bridge.worker.runtime import (
    InvalidWorkerSessionError,
    WorkerRuntime,
    build_worker_runtime,
    current_worker_session,
    installed_config_paths,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

ACCOUNT_PATTERN: Final = re.compile(
    r"^[A-Za-z0-9_.@-]+(?:\\[A-Za-z0-9_.@-]+)?$",
    flags=re.ASCII,
)
_SYSTEM_RANDOM: Final = SystemRandom()


@dataclass(frozen=True, slots=True)
class InvalidUserAccountError(ValueError):
    """예약 작업 계정이 안전한 Windows account 형식이 아닙니다."""

    user_id: str

    @override
    def __str__(self) -> str:
        """입력 원문을 노출하지 않는 validation error를 반환합니다."""
        return "worker user account is empty or malformed"


@dataclass(frozen=True, slots=True)
class WorkerTaskManifest:
    """Task Scheduler 등록 전에 검사할 사용자 세션 구성입니다."""

    name: str
    user_id: str
    trigger: str
    logon_type: str
    run_level: str
    restart_on_failure: bool
    hidden: bool
    argv: tuple[str, ...]


class WatchdogRuntime(Protocol):
    """Watchdog가 lifecycle cleanup까지 보장할 최소 Worker runtime 계약입니다."""

    def run(self, stop: Event) -> None:
        """Stop signal까지 current Worker generation을 실행합니다."""
        ...

    def close(self) -> None:
        """Generation별 transport와 adapter resource를 닫습니다."""
        ...


class WorkerRuntimeFactory(Protocol):
    """Watchdog가 새 Worker runtime을 만들기 위한 경계입니다."""

    def __call__(self) -> WatchdogRuntime:
        """새 세션/세대의 runtime을 반환합니다."""
        ...


@dataclass(frozen=True, slots=True)
class WatchdogPolicy:
    """Reconnect retry의 상한과 jitter 범위를 고정합니다."""

    initial_backoff_seconds: float = 0.25
    max_backoff_seconds: float = 5.0
    jitter_cap_seconds: float = 0.25

    def __post_init__(self) -> None:
        """Retry가 stop 반응성보다 길어지지 않는 양수 값인지 검증합니다."""
        if (
            self.initial_backoff_seconds <= 0
            or self.max_backoff_seconds < self.initial_backoff_seconds
            or self.jitter_cap_seconds < 0
        ):
            raise InvalidWatchdogPolicyError


@dataclass(frozen=True, slots=True)
class WatchdogDependencies:
    """Runtime 생성과 bounded wait/jitter의 테스트 가능한 경계입니다."""

    runtime_factory: WorkerRuntimeFactory
    wait: Callable[[float], bool]
    jitter: Callable[[float], float]


@dataclass(frozen=True, slots=True)
class WorkerWatchdogReceipt:
    """로그 문구 대신 관찰 가능한 reconnect 상태를 제공합니다."""

    attempts: int
    recoverable_failures: int
    last_failure: str | None


class WorkerRuntimeStoppedError(RuntimeError):
    """Stop signal 없이 Worker transport가 종료됐습니다."""


class InvalidWatchdogPolicyError(ValueError):
    """Watchdog retry policy가 유효하지 않습니다."""


@dataclass(frozen=True, slots=True)
class InstalledWorkerRuntimeFactory:
    """매 reconnect마다 현재 구성과 interactive session을 다시 읽습니다."""

    config_path: Path
    policy_path: Path
    expected_worker_sid: str | None = None
    binding_path: Path | None = None
    binding_sha256: str | None = None

    def __call__(self) -> WorkerRuntime:
        """Reboot/logon 뒤 stale session을 재사용하지 않는 runtime을 생성합니다."""
        session = current_worker_session()
        binding_environment: Mapping[str, str] | None
        if self.binding_path is None and self.binding_sha256 is None:
            config_path, policy_path = self.config_path, self.policy_path
            expected_worker_sid = self.expected_worker_sid
            binding_environment = None
        elif self.binding_path is not None and self.binding_sha256 is not None:
            binding = load_runtime_binding(
                RuntimeProfile.WORKER, self.binding_path, self.binding_sha256
            )
            if binding.policy_path is None:
                raise RuntimeBindingError(reason="worker_binding")
            config_path, policy_path = binding.config_path, binding.policy_path
            expected_worker_sid = binding.worker_sid
            binding_environment = {}
        else:
            raise RuntimeBindingError(reason="worker_binding")
        if expected_worker_sid is not None and session.sid != expected_worker_sid:
            raise InvalidWorkerSessionError(reason="binding_identity")
        bridge = load_bridge_settings(config_path, environ=binding_environment)
        policy = load_policy_settings(policy_path)
        return build_worker_runtime(bridge, policy, session)


@final
class WorkerWatchdog:
    """Typed runtime failure만 bounded retry하고 모든 stale runtime을 닫습니다."""

    def __init__(self, *, policy: WatchdogPolicy, dependencies: WatchdogDependencies) -> None:
        """재시도 구성과 명시적 runtime lifecycle 경계를 고정합니다."""
        self._policy = policy
        self._dependencies = dependencies
        self._receipt = WorkerWatchdogReceipt(0, 0, None)

    @property
    def receipt(self) -> WorkerWatchdogReceipt:
        """가장 최근 실행의 typed 상태 receipt를 반환합니다."""
        return self._receipt

    def run(self, stop: Event) -> WorkerWatchdogReceipt:
        """Stop 즉시 반응하며 OSError와 session 전이만 재시도합니다."""
        backoff = self._policy.initial_backoff_seconds
        while not stop.is_set():
            runtime: WatchdogRuntime | None = None
            try:
                runtime = self._dependencies.runtime_factory()
                runtime.run(stop)
            except (InvalidWorkerSessionError, OSError) as error:
                self._receipt = WorkerWatchdogReceipt(
                    attempts=self._receipt.attempts + 1,
                    recoverable_failures=self._receipt.recoverable_failures + 1,
                    last_failure=_failure_kind(error),
                )
            else:
                if stop.is_set():
                    self._receipt = WorkerWatchdogReceipt(
                        attempts=self._receipt.attempts + 1,
                        recoverable_failures=self._receipt.recoverable_failures,
                        last_failure=self._receipt.last_failure,
                    )
                else:
                    self._receipt = WorkerWatchdogReceipt(
                        attempts=self._receipt.attempts + 1,
                        recoverable_failures=self._receipt.recoverable_failures + 1,
                        last_failure=_failure_kind(WorkerRuntimeStoppedError()),
                    )
            finally:
                if runtime is not None:
                    runtime.close()
            if stop.is_set():
                return self._receipt
            jitter = min(
                max(self._dependencies.jitter(self._policy.jitter_cap_seconds), 0.0),
                self._policy.jitter_cap_seconds,
            )
            if self._dependencies.wait(min(backoff, self._policy.max_backoff_seconds) + jitter):
                return self._receipt
            backoff = min(backoff * 2, self._policy.max_backoff_seconds)
        return self._receipt


def _failure_kind(error: InvalidWorkerSessionError | OSError | WorkerRuntimeStoppedError) -> str:
    """Untrusted OS 오류 원문 없이 retry 원인을 stable receipt로 축소합니다."""
    match error:
        case InvalidWorkerSessionError():
            return "session_unavailable"
        case OSError():
            return "os_error"
        case WorkerRuntimeStoppedError():
            return "runtime_stopped"
        case _:
            assert_never(error)
            raise AssertionError


def build_worker_task_manifest(*, user_id: str) -> WorkerTaskManifest:
    """신뢰할 수 없는 계정명을 파싱해 비승격 task manifest를 만듭니다."""
    if ACCOUNT_PATTERN.fullmatch(user_id) is None:
        raise InvalidUserAccountError(user_id=user_id)
    return WorkerTaskManifest(
        name="HermesWindowsBridgeWorker",
        user_id=user_id,
        trigger="AtLogOn",
        logon_type="InteractiveToken",
        run_level="Limited",
        restart_on_failure=True,
        hidden=True,
        argv=(
            str(Path(sys.executable).with_name("pythonw.exe")),
            "-m",
            "hermes_windows_bridge.worker.main",
        ),
    )


def _run_installed_worker(
    binding: RuntimeBinding | None,
    binding_source: tuple[Path, str] | None = None,
) -> None:
    """설치된 설정으로 로그인 세션 Worker를 stop까지 실행합니다."""
    if binding is None:
        config_path, policy_path = installed_config_paths()
        expected_worker_sid = None
        binding_path, binding_sha256 = None, None
    else:
        if (
            binding.profile is not RuntimeProfile.WORKER
            or binding.policy_path is None
            or binding_source is None
        ):
            raise RuntimeBindingError(reason="worker_binding")
        config_path, policy_path = binding.config_path, binding.policy_path
        expected_worker_sid = binding.worker_sid
        binding_path, binding_sha256 = binding_source
    stop = Event()
    watchdog = WorkerWatchdog(
        policy=WatchdogPolicy(),
        dependencies=WatchdogDependencies(
            runtime_factory=InstalledWorkerRuntimeFactory(
                config_path,
                policy_path,
                expected_worker_sid=expected_worker_sid,
                binding_path=binding_path,
                binding_sha256=binding_sha256,
            ),
            wait=stop.wait,
            jitter=lambda cap: _SYSTEM_RANDOM.uniform(0.0, cap),
        ),
    )
    try:
        _ = watchdog.run(stop)
    except KeyboardInterrupt:
        stop.set()


def main(argv: tuple[str, ...] | None = None) -> None:
    """Run the legacy Worker or a verified complete runtime-binding pair."""
    command = tuple(sys.argv[1:]) if argv is None else argv
    try:
        binding_args = parse_runtime_binding_args(command)
        binding = (
            None
            if binding_args is None
            else load_runtime_binding(RuntimeProfile.WORKER, binding_args[0], binding_args[1])
        )
    except RuntimeBindingError as error:
        _ = sys.stderr.write(f"{error}\n")
        raise SystemExit(2) from error
    _run_installed_worker(binding, binding_args)


if __name__ == "__main__":
    main()
