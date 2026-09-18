"""Gateway Windows Service runtime contract tests."""

from __future__ import annotations

import sys
from threading import Event, Thread
from typing import final

import anyio
import pytest

from hermes_windows_bridge.gateway.windows_service import (
    GATEWAY_SERVICE,
    GatewayRuntimeDependencies,
    GatewayServiceRuntime,
    GatewayWindowsService,
    main,
)


class TestGatewayServiceManifest:
    def test_preserves_localservice_manifest_contract(self) -> None:
        # Given: Task 6에서 확정한 Gateway 서비스 manifest입니다.
        manifest = GATEWAY_SERVICE

        # When: 설치 전 권한과 실행 계약을 관찰합니다.
        contract = (
            manifest.name,
            manifest.account,
            manifest.startup_type,
            manifest.delayed_start,
            manifest.restart_on_failure,
            manifest.interactive,
        )

        # Then: Gateway는 LocalService·비대화형 최소 권한 경계를 유지합니다.
        assert contract == (
            "HermesWindowsBridgeGateway",
            "NT AUTHORITY\\LocalService",
            "Automatic",
            True,
            True,
            False,
        )
        assert manifest.argv == (
            sys.executable,
            "-I",
            "-B",
            "-m",
            "hermes_windows_bridge.gateway.windows_service",
        )


@final
class FakeStopEvents:
    """SCM 없는 테스트에서 stop event 호출을 관찰합니다."""

    def __init__(self) -> None:
        self.created = 0
        self.signals = 0

    def create(self) -> Event:
        self.created += 1
        return Event()

    def signal(self, event: Event) -> None:
        self.signals += 1
        event.set()

    def is_signaled(self, event: Event, timeout_ms: int) -> bool:
        return event.wait(timeout_ms / 1_000)


@final
class FakeServiceDispatcher:
    """서비스 등록 없이 SCM hosting 진입 순서를 보관합니다."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.service_class: type[GatewayWindowsService] | None = None
        self.entered = Event()
        self.release = Event()

    def initialize(self) -> None:
        self.calls.append("initialize")

    def prepare_to_host_single(self, service_class: type[GatewayWindowsService]) -> None:
        self.calls.append("prepare")
        self.service_class = service_class

    def start_service_ctrl_dispatcher(self) -> None:
        self.calls.append("dispatch")
        self.entered.set()
        assert self.release.wait(timeout=1)


def _start_runtime(runtime: GatewayServiceRuntime[Event]) -> Thread:
    thread = Thread(target=runtime.run, daemon=True)
    thread.start()
    return thread


class TestGatewayServiceRuntime:
    def test_server_return_transitions_to_stopped_without_false_running_state(self) -> None:
        # Given: 성공처럼 반환하지만 더 이상 listener를 소유하지 않는 server runner입니다.
        events = FakeStopEvents()
        statuses: list[int] = []

        async def serve() -> None:
            return

        runtime = GatewayServiceRuntime(
            report_status=statuses.append,
            dependencies=GatewayRuntimeDependencies(server_runner=serve, stop_events=events),
        )

        # When: SCM이 service run callback을 완료합니다.
        runtime.run()

        # Then: 반환 값과 무관하게 runtime은 RUNNING으로 남지 않습니다.
        assert statuses == [2, 4, 1]
        assert events.signals == 0

    def test_runs_until_stop_then_cleans_server_and_reports_scm_states(self) -> None:
        # Given: stop될 때까지 실행되는 fake MCP server와 fake SCM event입니다.
        events = FakeStopEvents()
        statuses: list[int] = []
        server_started = Event()
        server_cleaned = Event()

        def report_status(status: int) -> None:
            if status == 1:
                assert server_cleaned.is_set()
            statuses.append(status)

        async def serve() -> None:
            server_started.set()
            try:
                await anyio.sleep_forever()
            finally:
                server_cleaned.set()

        runtime = GatewayServiceRuntime(
            report_status=report_status,
            dependencies=GatewayRuntimeDependencies(server_runner=serve, stop_events=events),
        )

        # When: service가 실행 중인 상태에서 SCM stop control을 보냅니다.
        thread = _start_runtime(runtime)
        assert server_started.wait(timeout=1)
        runtime.request_stop()
        thread.join(timeout=1)

        # Then: cancellation-safe runner cleanup 후 정상적인 SCM 상태 전이가 완료됩니다.
        assert not thread.is_alive()
        assert server_cleaned.is_set()
        assert statuses == [2, 4, 3, 1]
        assert events.created == 1
        assert events.signals == 1

    def test_repeated_stop_during_start_stop_race_is_idempotent(self) -> None:
        # Given: 실행을 시작한 Gateway runtime입니다.
        events = FakeStopEvents()
        statuses: list[int] = []
        server_started = Event()

        async def serve() -> None:
            server_started.set()
            await anyio.sleep_forever()

        runtime = GatewayServiceRuntime(
            report_status=statuses.append,
            dependencies=GatewayRuntimeDependencies(server_runner=serve, stop_events=events),
        )

        # When: running 관찰 직후 중복된 SCM stop control이 경쟁합니다.
        thread = _start_runtime(runtime)
        assert server_started.wait(timeout=1)
        runtime.request_stop()
        runtime.request_stop()
        thread.join(timeout=1)

        # Then: stop signal과 STOP_PENDING은 한 번만 기록되고 실행은 종료됩니다.
        assert not thread.is_alive()
        assert statuses == [2, 4, 3, 1]
        assert events.signals == 1

    def test_server_exception_reports_stopped_after_cleanup(self) -> None:
        # Given: 시작 중 실패하지만 finally cleanup을 수행하는 server runner입니다.
        events = FakeStopEvents()
        statuses: list[int] = []
        server_cleaned = Event()
        error_message = "server failure"

        async def serve() -> None:
            try:
                raise RuntimeError(error_message)
            finally:
                server_cleaned.set()

        runtime = GatewayServiceRuntime(
            report_status=statuses.append,
            dependencies=GatewayRuntimeDependencies(server_runner=serve, stop_events=events),
        )

        # When: runtime이 server failure를 상위 service host로 전파합니다.
        with pytest.raises(ExceptionGroup) as caught:
            runtime.run()

        # Then: 실패를 숨기지 않으면서 SCM에는 STOPPED를 보고합니다.
        assert server_cleaned.is_set()
        assert isinstance(caught.value.exceptions[0], RuntimeError)
        assert str(caught.value.exceptions[0]) == error_message
        assert statuses == [2, 4, 1]


class TestGatewayServiceEntrypoint:
    def test_module_entrypoint_waits_for_scm_dispatcher_without_registration(self) -> None:
        # Given: StartServiceCtrlDispatcher를 block하는 fake SCM host입니다.
        dispatcher = FakeServiceDispatcher()
        thread = Thread(target=main, kwargs={"dispatcher": dispatcher}, daemon=True)

        # When: module entrypoint를 실행하고 dispatcher 진입을 기다립니다.
        thread.start()
        assert dispatcher.entered.wait(timeout=1)

        # Then: entrypoint는 즉시 반환하지 않고 실제 service class를 SCM에 준비합니다.
        assert thread.is_alive()
        assert dispatcher.calls == ["initialize", "prepare", "dispatch"]
        assert dispatcher.service_class is GatewayWindowsService
        dispatcher.release.set()
        thread.join(timeout=1)
        assert not thread.is_alive()
