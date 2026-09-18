"""고정 프로필 service child의 준비 신호와 parent-stop 수명주기입니다."""

from __future__ import annotations

import os
import sys
import threading
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from functools import partial
from typing import TYPE_CHECKING, Final, Protocol, final, override

import anyio
import anyio.lowlevel
from anyio import TASK_STATUS_IGNORED, to_thread

from hermes_windows_bridge.runtime_binding import (
    RuntimeBinding,
    RuntimeBindingError,
    RuntimeProfile,
    load_runtime_binding,
    parse_runtime_binding_args,
)

if TYPE_CHECKING:
    from pathlib import Path

    from anyio.abc import TaskStatus

_READY_LINE: Final = b"READY 1\n"
_STOP_LINE: Final = b"STOP\n"
_PROFILE_ARG_COUNT: Final = 2
_BOUND_ARG_COUNT: Final = 6

type ReadyCallback = Callable[[], None]
type ReadLine = Callable[[], Awaitable[bytes]]
type StopRequested = Callable[[], bool]
type GatewayRunner = Callable[[ReadyCallback, StopRequested], Awaitable[None]]
type BoundGatewayRunner = Callable[[ReadyCallback, StopRequested, RuntimeBinding], Awaitable[None]]


class HelperRuntime(Protocol):
    """service child가 중지시키는 typed Helper runtime 경계입니다."""

    def request_stop(self) -> None:
        """활성 pipe I/O 취소를 요청합니다."""
        ...

    def run_pipe_loop(
        self,
        stop_requested: Callable[[], bool],
        on_ready: ReadyCallback | None = None,
    ) -> None:
        """ACL-검증 pipe를 열고 parent stop까지 실행합니다."""
        ...


type HelperRuntimeFactory = Callable[[], HelperRuntime]
type BoundHelperRuntimeFactory = Callable[[RuntimeBinding], HelperRuntime]


class ServiceProfile(StrEnum):
    """.NET host가 허용하는 고정 자식 프로필입니다."""

    GATEWAY = "gateway"
    PRIVILEGED = "privileged"


@dataclass(frozen=True, slots=True)
class ServiceChildUsageError(Exception):
    """고정 host argv 계약을 벗어난 호출입니다."""

    @override
    def __str__(self) -> str:
        """자식의 허용 프로필만 드러내는 고정 오류를 반환합니다."""
        return "service child requires '--profile gateway' or '--profile privileged'"


@dataclass(frozen=True, slots=True)
class ServiceChildDependencies:
    """프로필 runner와 parent control pipe를 테스트 가능한 경계로 보관합니다."""

    read_line: ReadLine
    announce_ready: ReadyCallback
    gateway_runner: GatewayRunner
    helper_runtime: HelperRuntimeFactory
    bound_gateway_runner: BoundGatewayRunner | None = None
    bound_helper_runtime: BoundHelperRuntimeFactory | None = None


def parse_profile(argv: tuple[str, ...]) -> ServiceProfile:
    """host가 전달한 정확한 두 토큰 argv만 profile로 해석합니다."""
    if argv == ("--profile", "gateway"):
        return ServiceProfile.GATEWAY
    if argv == ("--profile", "privileged"):
        return ServiceProfile.PRIVILEGED
    raise ServiceChildUsageError


def parse_service_child_args(
    argv: tuple[str, ...],
) -> tuple[ServiceProfile, tuple[Path, str] | None]:
    """Parse the fixed service profile plus an optional complete binding pair."""
    if len(argv) == _PROFILE_ARG_COUNT:
        return parse_profile(argv), None
    if len(argv) != _BOUND_ARG_COUNT:
        raise ServiceChildUsageError
    profile = parse_profile(argv[:2])
    return profile, parse_runtime_binding_args(argv[2:])


@final
class _ServiceChildLifecycle:
    """parent stdin과 한 프로필 runtime의 종료 순서를 결합합니다."""

    def __init__(
        self, dependencies: ServiceChildDependencies, binding: RuntimeBinding | None
    ) -> None:
        """각 실행마다 독립적인 stop·ready 상태를 만듭니다."""
        self._dependencies = dependencies
        self._thread_stop = threading.Event()
        self._async_stop = anyio.Event()
        self._ready_lock = threading.Lock()
        self._ready_announced = False
        self._helper_runtime: HelperRuntime | None = None
        self._runtime_finished = anyio.Event()
        self._parent_stop_requested = False
        self._binding = binding

    async def run(self, profile: ServiceProfile) -> None:
        """Runtime 시작과 parent stop 중 먼저 끝나는 경로를 정리합니다."""
        async with anyio.create_task_group() as task_group:
            runtime_started = False
            await task_group.start(self._watch_parent_stop)
            await anyio.lowlevel.checkpoint()
            if not self._thread_stop.is_set():
                if profile is ServiceProfile.GATEWAY:
                    _ = task_group.start_soon(self._run_gateway)
                    runtime_started = True
                else:
                    runtime = self._create_helper_runtime()
                    self._helper_runtime = runtime
                    _ = task_group.start_soon(self._run_privileged, runtime)
                    runtime_started = True
            await self._async_stop.wait()
            if self._parent_stop_requested and runtime_started:
                await self._runtime_finished.wait()
            task_group.cancel_scope.cancel()

    async def _watch_parent_stop(
        self,
        *,
        task_status: TaskStatus[None] = TASK_STATUS_IGNORED,
    ) -> None:
        """ASCII STOP 또는 EOF를 수신할 때까지 parent control pipe를 읽습니다."""
        task_status.started()
        while True:
            line = await self._dependencies.read_line()
            if line in (_STOP_LINE, b""):
                self._parent_stop_requested = True
                self._request_stop()
                return

    async def _run_gateway(self) -> None:
        """Gateway cancellation이 watcher cleanup까지 전파되는 structured task입니다."""
        try:
            if self._binding is None:
                await self._dependencies.gateway_runner(
                    self._announce_ready, self._thread_stop.is_set
                )
            elif self._dependencies.bound_gateway_runner is not None:
                await self._dependencies.bound_gateway_runner(
                    self._announce_ready, self._thread_stop.is_set, self._binding
                )
            else:
                raise RuntimeBindingError(reason="gateway_runner")
        finally:
            self._runtime_finished.set()
            self._request_stop()

    async def _run_privileged(self, runtime: HelperRuntime) -> None:
        """Helper의 blocking pipe loop를 parent stop event와 결합합니다."""
        try:
            await to_thread.run_sync(
                runtime.run_pipe_loop,
                self._thread_stop.is_set,
                self._announce_ready,
            )
        finally:
            runtime.request_stop()
            self._runtime_finished.set()
            self._request_stop()

    def _create_helper_runtime(self) -> HelperRuntime:
        """Select a bound Helper constructor only after its binding was verified."""
        if self._binding is None:
            return self._dependencies.helper_runtime()
        if self._dependencies.bound_helper_runtime is None:
            raise RuntimeBindingError(reason="helper_runtime")
        return self._dependencies.bound_helper_runtime(self._binding)

    def _announce_ready(self) -> None:
        """실제 listener 또는 ACL-검증 pipe 뒤에 READY를 정확히 한 번 기록합니다."""
        with self._ready_lock:
            if self._ready_announced or self._thread_stop.is_set():
                return
            self._dependencies.announce_ready()
            self._ready_announced = True

    def _request_stop(self) -> None:
        """모든 종료 원인을 thread와 async runtime에 동시에 전파합니다."""
        self._thread_stop.set()
        if self._helper_runtime is not None:
            self._helper_runtime.request_stop()
        self._async_stop.set()


async def run_service_child(
    profile: ServiceProfile,
    *,
    dependencies: ServiceChildDependencies | None = None,
    binding: RuntimeBinding | None = None,
) -> None:
    """고정 profile runtime을 실행하고 stdin parent control에 따라 종료합니다."""
    active_dependencies = dependencies or _default_dependencies()
    await _ServiceChildLifecycle(active_dependencies, binding).run(profile)


async def _read_parent_line() -> bytes:
    """Binary stdin을 보존해 ASCII control frame 이외에는 stop으로 오인하지 않습니다."""
    return await to_thread.run_sync(sys.stdin.buffer.readline, 16, abandon_on_cancel=True)


def _write_ready() -> None:
    """Host control pipe에 protocol line만 쓰고 운영 로그는 stderr에 남깁니다."""
    _ = os.write(sys.stdout.fileno(), _READY_LINE)


async def _run_gateway(on_ready: ReadyCallback, stop_requested: StopRequested) -> None:
    """기본 child는 config-file Gateway composition을 사용합니다."""
    from hermes_windows_bridge.gateway.main import (  # noqa: PLC0415 - Gateway profile에서만 web stack을 가져옵니다.
        run_gateway_server,
    )

    await run_gateway_server(on_ready=on_ready, stop_requested=stop_requested)


async def _run_bound_gateway(
    on_ready: ReadyCallback, stop_requested: StopRequested, binding: RuntimeBinding
) -> None:
    """Run Gateway only with the config selection verified by the service child."""
    from hermes_windows_bridge.gateway.main import (  # noqa: PLC0415
        run_gateway_server,
    )

    await run_gateway_server(on_ready=on_ready, stop_requested=stop_requested, binding=binding)


def _create_helper_runtime() -> HelperRuntime:
    """LocalSystem child가 소유할 typed Helper runtime을 만듭니다."""
    from hermes_windows_bridge.privileged.runtime import (  # noqa: PLC0415 - LocalSystem Helper profile에서만 pywin32를 가져옵니다.
        PrivilegedHelperRuntime,
        WindowsPowerActionExecutor,
    )

    return PrivilegedHelperRuntime(executor=WindowsPowerActionExecutor())


def _create_bound_helper_runtime(binding: RuntimeBinding) -> HelperRuntime:
    """Create Helper with the binding-selected privileged IPC endpoint."""
    from hermes_windows_bridge.config import load_bridge_settings  # noqa: PLC0415
    from hermes_windows_bridge.privileged.runtime import (  # noqa: PLC0415
        PrivilegedHelperRuntime,
        WindowsPowerActionExecutor,
    )

    settings = load_bridge_settings(binding.config_path, environ={})
    return PrivilegedHelperRuntime(
        executor=WindowsPowerActionExecutor(), pipe_name=settings.ipc.privileged_pipe
    )


def _default_dependencies() -> ServiceChildDependencies:
    """CLI service child가 사용할 고정 stdin·stdout·runtime 경계를 만듭니다."""
    return ServiceChildDependencies(
        read_line=_read_parent_line,
        announce_ready=_write_ready,
        gateway_runner=_run_gateway,
        helper_runtime=_create_helper_runtime,
        bound_gateway_runner=_run_bound_gateway,
        bound_helper_runtime=_create_bound_helper_runtime,
    )


def main(argv: tuple[str, ...] | None = None) -> None:
    """고정 host argv를 검증하고 service child 수명을 시작합니다."""
    command = tuple(sys.argv[1:]) if argv is None else argv
    try:
        profile, binding_args = parse_service_child_args(command)
        binding = (
            None
            if binding_args is None
            else load_runtime_binding(
                RuntimeProfile(profile.value), binding_args[0], binding_args[1]
            )
        )
    except (ServiceChildUsageError, RuntimeBindingError) as exc:
        _ = sys.stderr.write(f"{exc}\n")
        raise SystemExit(2) from exc
    anyio.run(partial(run_service_child, profile, binding=binding))


if __name__ == "__main__":
    main()
