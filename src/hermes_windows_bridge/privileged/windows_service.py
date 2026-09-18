"""Privileged Helper의 pywin32 ServiceFramework adapter입니다."""

# pyright: reportMissingModuleSource=false
# pyright: reportUnknownMemberType=false

from __future__ import annotations

import sys
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Protocol, final

import win32service
import win32serviceutil

from hermes_windows_bridge.privileged.runtime import (
    PrivilegedHelperRuntime,
    WindowsPowerActionExecutor,
)

if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass(frozen=True, slots=True)
class ServiceManifest:
    """설치 전 검증 가능한 LocalSystem Helper service 구성입니다."""

    name: str
    account: str
    startup_type: str
    delayed_start: bool
    network_listener: bool
    interactive: bool
    argv: tuple[str, ...]


PRIVILEGED_SERVICE: Final = ServiceManifest(
    name="HermesWindowsBridgePrivileged",
    account="LocalSystem",
    startup_type="Automatic",
    delayed_start=True,
    network_listener=False,
    interactive=False,
    argv=(sys.executable, "-I", "-B", "-m", "hermes_windows_bridge.privileged.main"),
)


class _ServiceRuntime(Protocol):
    def request_stop(self) -> None:
        ...

    def run_pipe_loop(self, stop_requested: Callable[[], bool]) -> None:
        ...


@final
class ServiceLifecycle:
    """SCM callback에서 재사용하는 stop/status 수명주기입니다."""

    def __init__(
        self,
        runtime: _ServiceRuntime,
        report_status: Callable[[int], None],
    ) -> None:
        """테스트 가능한 상태 전이와 실제 named-pipe runtime을 연결합니다."""
        self._runtime = runtime
        self._report_status = report_status
        self._stop_event = threading.Event()
        self._status_lock = threading.Lock()
        self._stop_reported = False
        self._stopped_reported = False

    def stop(self) -> None:
        """중복 stop control에도 pending status를 한 번만 보고합니다."""
        with self._status_lock:
            if self._stop_reported:
                return
            self._stop_reported = True
        self._report_status(win32service.SERVICE_STOP_PENDING)
        self._stop_event.set()
        self._runtime.request_stop()

    def run(self) -> None:
        """Runtime 예외에도 stopped status와 I/O cleanup을 보장합니다."""
        self._report_status(win32service.SERVICE_RUNNING)
        try:
            self._runtime.run_pipe_loop(self._stop_event.is_set)
        finally:
            self._stop_event.set()
            self._runtime.request_stop()
            self._report_stopped_once()

    def _report_stopped_once(self) -> None:
        with self._status_lock:
            if self._stopped_reported:
                return
            self._stopped_reported = True
        self._report_status(win32service.SERVICE_STOPPED)


@final
class PrivilegedHelperWindowsService(win32serviceutil.ServiceFramework):
    """SCM status lifecycle과 Helper pipe runtime을 결합합니다."""

    _svc_name_: str = PRIVILEGED_SERVICE.name
    _svc_display_name_ = "Hermes Windows Bridge Privileged Helper"
    _svc_description_ = "ACL-protected typed reboot and shutdown helper"

    def __init__(self, args: list[str]) -> None:
        """SCM callback과 idempotent stop state를 초기화합니다."""
        super().__init__(args)
        runtime = PrivilegedHelperRuntime(executor=WindowsPowerActionExecutor())

        def report_status(status: int) -> None:
            self.ReportServiceStatus(status)

        self._lifecycle = ServiceLifecycle(runtime, report_status)

    def SvcStop(self) -> None:  # noqa: N802 - pywin32 ServiceFramework contract입니다.
        """중복 stop control에도 한 번만 pending status와 I/O 취소를 전파합니다."""
        self._lifecycle.stop()

    def SvcDoRun(self) -> None:  # noqa: N802 - pywin32 ServiceFramework contract입니다.
        """Helper runtime failure에도 SCM stopped status를 확정합니다."""
        self._lifecycle.run()
