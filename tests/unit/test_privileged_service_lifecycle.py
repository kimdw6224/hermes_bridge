"""Privileged Helper의 pywin32 SCM lifecycle을 검증합니다."""

from __future__ import annotations

import sys
from types import ModuleType
from typing import TYPE_CHECKING, final

import pytest
import win32serviceutil

from hermes_windows_bridge.privileged import main as privileged_main
from hermes_windows_bridge.privileged.windows_service import (
    PRIVILEGED_SERVICE,
    PrivilegedHelperWindowsService,
    ServiceLifecycle,
)

if TYPE_CHECKING:
    from collections.abc import Callable


@final
class _LifecycleRuntime:
    """SCM status 수명주기를 OS host 없이 관찰합니다."""

    def __init__(self, *, raises: bool = False) -> None:
        self.stop_calls = 0
        self._raises = raises

    def request_stop(self) -> None:
        self.stop_calls += 1

    def run_pipe_loop(self, stop_requested: Callable[[], bool]) -> None:
        _ = stop_requested()
        if self._raises:
            message = "pipe runtime failed"
            raise RuntimeError(message)


@final
class _ServiceManager(ModuleType):
    """Module import seam에서 SCM entrypoint 호출 순서를 기록합니다."""

    def __init__(self, calls: list[str]) -> None:
        super().__init__("servicemanager")
        self._calls = calls

    def Initialize(self) -> None:  # noqa: N802 - pywin32 API 이름입니다.
        self._calls.append("initialize")

    def PrepareToHostSingle(self, service: type[PrivilegedHelperWindowsService]) -> None:  # noqa: N802
        del service
        self._calls.append("HermesWindowsBridgePrivileged")

    def StartServiceCtrlDispatcher(self) -> None:  # noqa: N802 - pywin32 API 이름입니다.
        self._calls.append("dispatcher")


class TestPrivilegedHelperServiceFramework:
    def test_manifest_keeps_localsystem_named_pipe_only_contract(self) -> None:
        # Given: 설치 전에 검사하는 기존 Helper manifest입니다.
        manifest = PRIVILEGED_SERVICE

        # When: runtime 구현을 추가하기 전 고정 구성을 읽습니다.
        # Then: 서비스 identity와 listener 경계가 변경되지 않았습니다.
        assert manifest.name == "HermesWindowsBridgePrivileged"
        assert manifest.account == "LocalSystem"
        assert manifest.network_listener is False
        assert manifest.argv == (
            sys.executable,
            "-I",
            "-B",
            "-m",
            "hermes_windows_bridge.privileged.main",
        )

    def test_service_framework_exposes_scm_start_stop_callbacks(self) -> None:
        # Given: pywin32에서 host할 실제 service class입니다.
        service = PrivilegedHelperWindowsService

        # When/Then: SCM callback과 persistent pipe-loop runtime이 함께 존재합니다.
        assert issubclass(service, win32serviceutil.ServiceFramework)
        assert callable(service.SvcDoRun)
        assert callable(service.SvcStop)

    def test_repeated_stop_reports_pending_once_and_run_reports_stopped(self) -> None:
        # Given: SCM callback과 같은 reporter/runtime seams입니다.
        statuses: list[int] = []
        runtime = _LifecycleRuntime()
        lifecycle = ServiceLifecycle(runtime, statuses.append)

        # When: stop control이 중복되고 service run이 종료됩니다.
        lifecycle.stop()
        lifecycle.stop()
        lifecycle.run()

        # Then: pending/stopped는 각각 한 번이며 runtime cleanup은 finalizer에서도 실행됩니다.
        assert statuses == [3, 4, 1]
        assert runtime.stop_calls == 2

    def test_runtime_exception_still_reports_service_stopped(self) -> None:
        # Given: named-pipe runtime이 service 실행 중 실패합니다.
        statuses: list[int] = []
        runtime = _LifecycleRuntime(raises=True)
        lifecycle = ServiceLifecycle(runtime, statuses.append)

        # When: SCM run callback이 runtime exception을 전달받습니다.
        with pytest.raises(RuntimeError, match="pipe runtime failed"):
            lifecycle.run()

        # Then: exception 전파와 별개로 stopped status 및 cleanup은 확정됩니다.
        assert statuses == [4, 1]
        assert runtime.stop_calls == 1

    def test_module_main_prepares_single_service_and_starts_dispatcher(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Given: SCM 호출을 기록하는 pywin32 servicemanager fake입니다.
        calls: list[str] = []
        manager = _ServiceManager(calls)
        monkeypatch.setitem(sys.modules, "servicemanager", manager)

        # When: module entrypoint를 실행합니다.
        privileged_main.main()

        # Then: 단일 Helper ServiceFramework가 dispatcher로 등록됩니다.
        assert calls == ["initialize", "HermesWindowsBridgePrivileged", "dispatcher"]
