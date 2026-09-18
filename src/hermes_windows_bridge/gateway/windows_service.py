"""Gateway의 최소 권한 Windows Service runtime adapter입니다."""

# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false

from __future__ import annotations

import sys
from dataclasses import dataclass
from threading import Lock
from typing import TYPE_CHECKING, Final, Protocol, TypeVar, final

import anyio
import servicemanager
import win32event
import win32service
import win32serviceutil
from anyio import to_thread

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


@dataclass(frozen=True, slots=True)
class ServiceManifest:
    """서비스 설치 전에 검사할 불변 구성입니다."""

    name: str
    account: str
    startup_type: str
    delayed_start: bool
    restart_on_failure: bool
    interactive: bool
    argv: tuple[str, ...]


GATEWAY_SERVICE: Final = ServiceManifest(
    name="HermesWindowsBridgeGateway",
    account="NT AUTHORITY\\LocalService",
    startup_type="Automatic",
    delayed_start=True,
    restart_on_failure=True,
    interactive=False,
    argv=(sys.executable, "-I", "-B", "-m", "hermes_windows_bridge.gateway.windows_service"),
)

_STOP_WAIT_TIMEOUT_MILLISECONDS: Final = 100

StopEvent = TypeVar("StopEvent")


class ServiceStopEvents(Protocol[StopEvent]):
    """SCM stop signal을 서버 loop cancellation으로 연결합니다."""

    def create(self) -> StopEvent:
        """새 stop event를 생성합니다."""
        ...

    def signal(self, event: StopEvent) -> None:
        """SCM stop control을 event에 기록합니다."""
        ...

    def is_signaled(self, event: StopEvent, timeout_ms: int) -> bool:
        """Event signal 여부를 제한 시간 내에 반환합니다."""
        ...


class ServiceControlDispatcher(Protocol):
    """pywin32 SCM hosting 호출의 테스트 가능한 경계입니다."""

    def initialize(self) -> None:
        """Service manager hosting을 초기화합니다."""

    def prepare_to_host_single(self, service_class: type[GatewayWindowsService]) -> None:
        """단일 ServiceFramework class를 SCM에 준비합니다."""

    def start_service_ctrl_dispatcher(self) -> None:
        """SCM control dispatcher가 service 수명 동안 block하도록 시작합니다."""


@final
class _PywinStopEvents:
    """pywin32 event API를 제한된 runtime seam 뒤에 둡니다."""

    def create(self) -> int:
        return int(win32event.CreateEvent(None, True, False, None))  # noqa: FBT003

    def signal(self, event: int) -> None:
        win32event.SetEvent(event)

    def is_signaled(self, event: int, timeout_ms: int) -> bool:
        return win32event.WaitForSingleObject(event, timeout_ms) == win32event.WAIT_OBJECT_0


@dataclass(frozen=True, slots=True)
class GatewayRuntimeDependencies[StopEvent]:
    """Service loop가 소유하는 server와 stop-event 의존성입니다."""

    server_runner: Callable[[], Awaitable[None]]
    stop_events: ServiceStopEvents[StopEvent]


@final
class GatewayServiceRuntime[StopEvent]:
    """SCM 상태 전이와 async Gateway server 수명을 직렬화합니다."""

    def __init__(
        self,
        report_status: Callable[[int], None],
        dependencies: GatewayRuntimeDependencies[StopEvent],
    ) -> None:
        """Server lifecycle을 새 SCM stop event에 결합합니다."""
        self._report_status = report_status
        self._dependencies = dependencies
        self._stop_event = dependencies.stop_events.create()
        self._lock = Lock()
        self._run_started = False
        self._stop_requested = False
        self._stopped = False

    def request_stop(self) -> None:
        """중복 SCM stop control을 하나의 cancellation signal로 축소합니다."""
        with self._lock:
            if self._stop_requested or self._stopped:
                return
            self._stop_requested = True
            self._report_status(win32service.SERVICE_STOP_PENDING)
            self._dependencies.stop_events.signal(self._stop_event)

    def run(self) -> None:
        """Gateway server를 실행하고 모든 종료 경로에서 STOPPED를 보고합니다."""
        with self._lock:
            if self._run_started:
                return
            self._run_started = True
            should_run = not self._stop_requested
            if should_run:
                self._report_status(win32service.SERVICE_START_PENDING)
                self._report_status(win32service.SERVICE_RUNNING)

        try:
            if should_run:
                anyio.run(_run_until_stopped, self._dependencies, self._stop_event)
        finally:
            with self._lock:
                if not self._stopped:
                    self._stopped = True
                    self._report_status(win32service.SERVICE_STOPPED)


async def _run_until_stopped[StopEvent](
    dependencies: GatewayRuntimeDependencies[StopEvent], stop_event: StopEvent
) -> None:
    """Server completion 또는 SCM stop 중 먼저 발생한 경로를 정리합니다."""
    finished = anyio.Event()

    async def run_server() -> None:
        await dependencies.server_runner()
        finished.set()

    async def wait_for_stop() -> None:
        while not await to_thread.run_sync(
            dependencies.stop_events.is_signaled,
            stop_event,
            _STOP_WAIT_TIMEOUT_MILLISECONDS,
        ):
            pass
        finished.set()

    async with anyio.create_task_group() as task_group:
        _ = task_group.start_soon(run_server)
        _ = task_group.start_soon(wait_for_stop)
        await finished.wait()
        task_group.cancel_scope.cancel()


async def _run_gateway_server() -> None:
    """Production composition을 SCM service 실행 시점에만 불러옵니다."""
    from hermes_windows_bridge.gateway.main import (  # noqa: PLC0415 - worker/browser 의존성은 SCM이 service를 실행할 때만 필요합니다.
        run_gateway_server,
    )

    await run_gateway_server()


@final
class GatewayWindowsService(win32serviceutil.ServiceFramework):
    """LocalService Gateway를 pywin32 SCM control에 연결합니다."""

    _svc_name_ = GATEWAY_SERVICE.name
    _svc_display_name_ = GATEWAY_SERVICE.name

    def __init__(self, args: list[str]) -> None:
        """SCM이 만든 service instance에 runtime lifecycle을 붙입니다."""
        super().__init__(args)
        self._runtime = GatewayServiceRuntime(
            report_status=self.ReportServiceStatus,
            dependencies=GatewayRuntimeDependencies(
                server_runner=_run_gateway_server,
                stop_events=_PywinStopEvents(),
            ),
        )

    def SvcDoRun(self) -> None:  # noqa: N802 - pywin32 ServiceFramework contract입니다.
        """SCM이 시작한 Gateway 수명 전체를 block합니다."""
        self._runtime.run()

    def SvcStop(self) -> None:  # noqa: N802 - pywin32 ServiceFramework contract입니다.
        """SCM stop control을 async server cancellation으로 전달합니다."""
        self._runtime.request_stop()


@final
class _PywinServiceControlDispatcher:
    """실제 pywin32 hosting API만 호출하는 dispatcher adapter입니다."""

    def initialize(self) -> None:
        servicemanager.Initialize()

    def prepare_to_host_single(self, service_class: type[GatewayWindowsService]) -> None:
        servicemanager.PrepareToHostSingle(service_class)

    def start_service_ctrl_dispatcher(self) -> None:
        servicemanager.StartServiceCtrlDispatcher()


def main(dispatcher: ServiceControlDispatcher | None = None) -> None:
    """SCM dispatcher를 시작해 Gateway service가 즉시 종료되지 않게 합니다."""
    service_dispatcher = dispatcher if dispatcher is not None else _PywinServiceControlDispatcher()
    service_dispatcher.initialize()
    service_dispatcher.prepare_to_host_single(GatewayWindowsService)
    service_dispatcher.start_service_ctrl_dispatcher()


if __name__ == "__main__":
    main()
