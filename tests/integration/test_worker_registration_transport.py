"""Worker-owned Named Pipe transport의 실제 process 경계 검증입니다."""

from __future__ import annotations

import multiprocessing
import sys
from threading import Event, Thread
from typing import final
from uuid import UUID, uuid4

import pytest

from hermes_windows_bridge.gateway.worker_runtime import (
    GatewayWorkerWatcher,
    WorkerPipeConfig,
    serve_worker_pipe,
)
from hermes_windows_bridge.ipc.acl import current_process_sid
from hermes_windows_bridge.ipc.protocol import (
    IpcRequest,
    IpcResponse,
    PeerRole,
    WorkerRegistration,
)
from hermes_windows_bridge.worker.ipc_client import WorkerRegistry


@final
class _ProcessDispatcher:
    """취소 상태를 process 내부에서 소유하는 실제 handler입니다."""

    def __init__(self, release: Event, requested: Event) -> None:
        self.release = release
        self.requested = requested

    def exchange(self, request: IpcRequest) -> IpcResponse:
        self.requested.set()
        if request.operation == "wait":
            _ = self.release.wait(5)
            return IpcResponse(
                request_id=request.request_id,
                ok=False,
                error_code="cancelled",
            )
        return IpcResponse(
            request_id=request.request_id,
            ok=True,
            payload={"operation": request.operation},
        )

    def cancel(self, request_id: UUID) -> bool:
        del request_id
        self.release.set()
        return True


def _serve_process(pipe_name: str, sid: str, stop: Event, requested: Event) -> None:
    config = WorkerPipeConfig(
        pipe_name=pipe_name,
        target_user_sid=sid,
        registration=WorkerRegistration(
            registration_id=uuid4(),
            generation=7,
            session_id=3,
            username="TEST\\worker",
        ),
        expected_gateway_sid=sid,
        heartbeat_interval_seconds=0.05,
    )
    serve_worker_pipe(config, _ProcessDispatcher(Event(), requested), stop)


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "win32", reason="Windows named pipe required")
def test_registration_request_cancel_disconnect_and_reconnect_across_processes() -> None:
    # Given: 별도 process의 Worker-owned pipe와 현재 SID를 허용한 test peer입니다.
    context = multiprocessing.get_context("spawn")
    stop = context.Event()
    requested = context.Event()
    pipe_name = rf"\\.\pipe\HermesWindowsBridgeTransport-{uuid4()}"
    sid = current_process_sid()
    process = context.Process(target=_serve_process, args=(pipe_name, sid, stop, requested))
    registry = WorkerRegistry()
    watcher = GatewayWorkerWatcher(pipe_name, registry, connect_timeout_ms=200)
    thread = Thread(target=watcher.run, daemon=True)
    process.start()
    thread.start()
    try:
        assert watcher.wait_for_connections(1, timeout_seconds=3)
        assert watcher.wait_for_heartbeats(1, timeout_seconds=1)
        client = registry.current()

        # When: 등록된 persistent client로 요청, 취소, 강제 disconnect를 수행합니다.
        request = IpcRequest(
            request_id=uuid4(),
            target=PeerRole.WORKER,
            operation="status",
            payload={},
            timeout_ms=1_000,
        )
        first_response: list[IpcResponse] = []
        first_exchange = Thread(target=lambda: first_response.append(client.exchange(request)))
        first_exchange.start()
        assert requested.wait(1)
        first_exchange.join(2)
        assert first_response[0].payload == {"operation": "status"}
        waiting = IpcRequest(
            request_id=uuid4(),
            target=PeerRole.WORKER,
            operation="wait",
            payload={},
            timeout_ms=1_000,
        )
        responses: list[IpcResponse] = []
        exchange_thread = Thread(target=lambda: responses.append(client.exchange(waiting)))
        exchange_thread.start()
        assert watcher.wait_for_request(waiting.request_id, timeout_seconds=1)
        assert client.cancel(waiting.request_id, "test_cancel")
        exchange_thread.join(2)
        assert responses[0].error_code == "cancelled"
        watcher.disconnect()

        # Then: offline 전환 뒤 같은 Worker process에 bounded backoff로 재등록됩니다.
        assert watcher.wait_for_connections(2, timeout_seconds=3)
        reconnected = registry.current()
        assert reconnected is not client
        assert reconnected.exchange(request.model_copy(update={"request_id": uuid4()})).ok
    finally:
        watcher.close()
        stop.set()
        process.join(3)
        if process.is_alive():
            process.terminate()
            process.join(2)
        thread.join(2)
    assert process.exitcode == 0
