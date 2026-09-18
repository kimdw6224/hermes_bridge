from __future__ import annotations

import sys
import time
from pathlib import Path  # noqa: TC003 - pytest fixture annotation입니다.

import psutil
import pytest

from hermes_windows_bridge.tools.process import ProcessStartInput, ProcessToolService
from hermes_windows_bridge.worker.job_object import JobClosedError
from hermes_windows_bridge.worker.processes import ProcessManager

pytestmark = pytest.mark.integration


class _FixtureInterruptionError(RuntimeError):
    """Context cleanup 경로를 강제하는 test-only 신호입니다."""


def _wait_for_child(parent: psutil.Process, timeout_seconds: float = 5.0) -> psutil.Process:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        children = parent.children()
        if children:
            return children[0]
        time.sleep(0.01)
    pytest.fail("child process did not start")


class TestJobObject:
    def test_cancel_kills_children(self) -> None:
        # Given: Job Object 안의 Python 부모가 별도 Python 자식을 시작합니다.
        child_code = "import threading; threading.Event().wait(300)"
        parent_code = (
            "import subprocess,sys,threading; "
            "subprocess.Popen([sys.executable,'-c',sys.argv[1]]); "
            "threading.Event().wait(300)"
        )
        with ProcessManager() as manager:
            started = ProcessToolService(manager).process_start(
                ProcessStartInput(
                    argv=(sys.executable, "-c", parent_code, child_code),
                    lifecycle_managed=True,
                )
            )
            parent = psutil.Process(started.pid)
            child = _wait_for_child(parent)

            # When: root PID가 아니라 소유 Job Object 전체를 취소합니다.
            receipt = manager.cancel_tree(started.pid)

            # Then: 독립 process identity 관찰에서 부모와 자식 모두 종료됩니다.
            gone, alive = psutil.wait_procs((parent, child), timeout=5)
            assert receipt.terminated
            assert {process.pid for process in gone} == {parent.pid, child.pid}
            assert alive == []

    def test_closed_job_rejects_stale_assignment(self) -> None:
        # Given: 프로세스가 끝나며 닫힌 Job Object 핸들입니다.
        with ProcessManager() as manager:
            started = ProcessToolService(manager).process_start(
                ProcessStartInput(argv=(sys.executable, "-c", "raise SystemExit(0)"))
            )
            assert manager.wait(started.pid, timeout_ms=5_000)
            job = manager.job_for(started.pid)
            job.close()

            # When/Then: stale/closed Job에는 새 PID/핸들을 연결할 수 없습니다.
            with pytest.raises(JobClosedError):
                job.assign_process(started.process_handle)

    def test_repeated_cancel_and_close_are_safe(self) -> None:
        # Given: 실행 중인 managed process와 Job Object입니다.
        with ProcessManager() as manager:
            started = ProcessToolService(manager).process_start(
                ProcessStartInput(
                    argv=(sys.executable, "-c", "import threading; threading.Event().wait(300)"),
                )
            )
            job = manager.job_for(started.pid)

            # When: 취소와 close가 반복 인터럽트처럼 중복 호출됩니다.
            first = job.cancel()
            second = job.cancel()
            job.close()
            job.close()

            # Then: 최초만 종료 동작을 수행하고 프로세스 핸들은 종료를 관찰합니다.
            assert first.terminated
            assert second.already_terminated
            assert manager.wait(started.pid, timeout_ms=5_000)

    def test_context_failure_still_cleans_entire_tree(self, tmp_path: Path) -> None:
        # Given: child PID를 남기는 장기 실행 트리와 의도적 context 실패입니다.
        child_file = tmp_path / "child.pid"
        child_code = "import threading; threading.Event().wait(300)"
        parent_code = (
            "import subprocess,sys,threading,pathlib; "
            "p=subprocess.Popen([sys.executable,'-c',sys.argv[2]]); "
            "pathlib.Path(sys.argv[1]).write_text(str(p.pid)); "
            "threading.Event().wait(300)"
        )
        parent: psutil.Process | None = None
        child: psutil.Process | None = None

        # When: 관리 context 내부에서 예외가 발생합니다.
        with (  # noqa: PT012 - context 내부 setup 뒤 예외가 전체 tree cleanup을 검증합니다.
            pytest.raises(_FixtureInterruptionError),
            ProcessManager() as manager,
        ):
            started = ProcessToolService(manager).process_start(
                ProcessStartInput(
                    argv=(sys.executable, "-c", parent_code, str(child_file), child_code)
                )
            )
            parent = psutil.Process(started.pid)
            child = _wait_for_child(parent)
            raise _FixtureInterruptionError

        # Then: finally cleanup이 독립 identity 기준으로 양쪽을 모두 종료합니다.
        assert parent is not None
        assert child is not None
        gone, alive = psutil.wait_procs((parent, child), timeout=5)
        assert {process.pid for process in gone} == {parent.pid, child.pid}
        assert alive == []
