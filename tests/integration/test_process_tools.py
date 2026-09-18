from __future__ import annotations

import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path  # noqa: TC003 - pytest fixture annotation입니다.
from uuid import UUID, uuid4

import anyio
import psutil
import pytest
from pydantic import ValidationError

from hermes_windows_bridge.gateway.audit import AuditRecorder
from hermes_windows_bridge.gateway.dispatcher import (
    DispatchCall,
    DispatcherServices,
    GatewayDispatcher,
)
from hermes_windows_bridge.gateway.idempotency import IdempotencyStore
from hermes_windows_bridge.gateway.policy import ApprovalManager
from hermes_windows_bridge.ipc import protocol as ipc
from hermes_windows_bridge.privileged.ipc_server import HelperRegistry
from hermes_windows_bridge.tools.process import (
    AppOpenInput,
    ProcessKillInput,
    ProcessStartInput,
    ProcessToolService,
)
from hermes_windows_bridge.worker.ipc_client import WorkerRegistry
from hermes_windows_bridge.worker.job_object import WindowsJob
from hermes_windows_bridge.worker.processes import ProcessManager, ProcessNotOwnedError

pytestmark = pytest.mark.integration


class _ProcessEndpoint:
    """Gateway 뒤의 실제 process service 실행 횟수를 관찰합니다."""

    def __init__(self, service: ProcessToolService) -> None:
        self._service: ProcessToolService = service
        self.executions: int = 0

    def exchange(self, request: ipc.RequestMessage) -> ipc.IpcResponse:
        self.executions += 1
        result = self._service.process_kill(ProcessKillInput.model_validate(request.payload))
        return ipc.IpcResponse(
            request_id=request.request_id,
            ok=True,
            payload={"pid": result.pid, "terminated": result.terminated},
        )

    def cancel(self, request_id: UUID, reason: str) -> bool:
        del request_id, reason
        return False


class _JobCreationProbeError(OSError):
    """Job 생성 실패 cleanup을 강제하는 test-only 오류입니다."""


def _fail_job_creation() -> WindowsJob:
    raise _JobCreationProbeError


class TestProcessTools:
    def test_start_and_kill_harmless_process(self) -> None:
        # Given: 셸을 거치지 않고 오래 대기하는 harmless Python 명령입니다.
        request = ProcessStartInput(
            argv=(sys.executable, "-c", "import threading; threading.Event().wait(300)"),
            lifecycle_managed=True,
        )

        # When: Worker 소유 manager로 시작하고 같은 소유 핸들로 종료합니다.
        with ProcessManager() as manager:
            service = ProcessToolService(manager)
            started = service.process_start(request)
            identity = psutil.Process(started.pid)
            listed = service.process_list()
            killed = service.process_kill(ProcessKillInput(pid=started.pid))

            # Then: 목록과 종료 receipt가 일치하고 독립 psutil identity도 종료됩니다.
            assert any(item.pid == started.pid for item in listed.processes)
            assert killed.pid == started.pid
            assert killed.terminated
            assert identity.wait(timeout=5) is not None
            assert not identity.is_running()

    def test_argv_is_literal_and_never_uses_a_shell(self, tmp_path: Path) -> None:
        # Given: shell 연산자처럼 보이는 문자열을 단일 argv 값으로 전달합니다.
        result_path = tmp_path / "literal.txt"
        injected_path = tmp_path / "injected.txt"
        untrusted = f"literal & echo injected>{injected_path}"
        code = "from pathlib import Path; import sys; Path(sys.argv[1]).write_text(sys.argv[2])"

        # When: process_start가 argv 배열을 그대로 실행합니다.
        with ProcessManager() as manager:
            service = ProcessToolService(manager)
            started = service.process_start(
                ProcessStartInput(argv=(sys.executable, "-c", code, str(result_path), untrusted))
            )
            assert manager.wait(started.pid, timeout_ms=5_000)

            # Then: 값은 그대로 기록되고 주입된 두 번째 명령은 실행되지 않습니다.
            assert result_path.read_text() == untrusted
            assert not injected_path.exists()

    def test_repeated_kill_is_idempotent_for_the_same_owned_handle(self) -> None:
        # Given: manager가 소유한 장기 실행 프로세스입니다.
        request = ProcessStartInput(
            argv=(sys.executable, "-c", "import threading; threading.Event().wait(300)"),
        )
        with ProcessManager() as manager:
            service = ProcessToolService(manager)
            started = service.process_start(request)

            # When: 동일 PID 종료를 두 번 요청합니다.
            first = service.process_kill(ProcessKillInput(pid=started.pid))
            second = service.process_kill(ProcessKillInput(pid=started.pid))

            # Then: 두 번째 요청은 PID를 재개방하지 않고 완료 상태를 재사용합니다.
            assert first.terminated
            assert second.terminated
            assert second.already_terminated

    def test_kill_traverses_policy_and_idempotency_before_worker(self) -> None:
        # Given: 실제 Worker process service가 Gateway registry 뒤에 연결됩니다.
        request = ProcessStartInput(
            argv=(sys.executable, "-c", "import threading; threading.Event().wait(300)"),
        )
        with ProcessManager() as manager:
            started = ProcessToolService(manager).process_start(request)
            identity = psutil.Process(started.pid)
            endpoint = _ProcessEndpoint(ProcessToolService(manager))
            workers = WorkerRegistry()
            workers.register(
                ipc.WorkerRegistration(
                    registration_id=uuid4(), generation=1, session_id=1, username="test-worker"
                ),
                endpoint,
            )
            gateway = GatewayDispatcher(
                DispatcherServices(
                    workers=workers,
                    helpers=HelperRegistry(),
                    idempotency=IdempotencyStore(ttl=timedelta(minutes=1)),
                    approvals=ApprovalManager(),
                    audit=AuditRecorder(),
                )
            )
            call = DispatchCall(
                operation_id=uuid4(),
                tool_name="process_kill",
                payload={"pid": started.pid},
                requested_at=datetime.now(UTC),
                timeout_ms=5_000,
            )

            # When: 같은 operation을 두 번 dispatch합니다.
            first = anyio.run(gateway.dispatch, call)
            replay = anyio.run(gateway.dispatch, call)

            # Then: 정책은 별도 blanket 승인을 만들지 않고 실제 kill은 한 번만 실행됩니다.
            assert not first.result.is_error
            assert not first.replayed
            assert replay.replayed
            assert endpoint.executions == 1
            assert identity.wait(timeout=5) is not None

    def test_non_owned_pid_is_rejected_without_process_control(self) -> None:
        # Given: manager가 소유하지 않는 현재 pytest 프로세스 PID입니다.
        with ProcessManager() as manager:
            service = ProcessToolService(manager)

            # When/Then: 이름 탐색이나 OpenProcess 없이 소유권 경계에서 거부합니다.
            with pytest.raises(ProcessNotOwnedError):
                _ = service.process_kill(ProcessKillInput(pid=os.getpid()))

    def test_malformed_inputs_fail_at_typed_boundary(self) -> None:
        # Given/When/Then: 빈 argv와 비양수 PID는 실행 전에 Pydantic이 거부합니다.
        with pytest.raises(ValidationError):
            _ = ProcessStartInput(argv=())
        with pytest.raises(ValidationError):
            _ = ProcessKillInput(pid=0)

    def test_app_open_launches_harmless_executable_under_owned_handle(self) -> None:
        # Given: 즉시 종료되는 Python 앱 실행 요청입니다.
        request = AppOpenInput(target=sys.executable, arguments=("-c", "raise SystemExit(0)"))

        # When: app_open 표면을 통해 실행합니다.
        with ProcessManager() as manager:
            service = ProcessToolService(manager)
            opened = service.app_open(request)

            # Then: exact owned process handle이 종료를 관찰합니다.
            assert opened.pid > 0
            assert manager.wait(opened.pid, timeout_ms=5_000)

    def test_job_creation_failure_cleans_suspended_process(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Given: 실제 프로세스 생성 뒤 Job 생성만 실패하는 고유 harmless argv입니다.
        marker = str(uuid4())
        monkeypatch.setattr(WindowsJob, "create", staticmethod(_fail_job_creation))

        # When: suspended process를 Job에 연결하기 전에 오류가 납니다.
        with ProcessManager() as manager, pytest.raises(_JobCreationProbeError):
            _ = ProcessToolService(manager).process_start(
                ProcessStartInput(
                    argv=(sys.executable, "-c", "import sys; print(sys.argv[1])", marker)
                )
            )

        # Then: 고유 argv의 process는 resume되지 않고 생성 handle로 즉시 정리됩니다.
        matches = [
            process
            for process in psutil.process_iter(("cmdline",))
            if marker in (process.info["cmdline"] or ())
        ]
        assert matches == []
