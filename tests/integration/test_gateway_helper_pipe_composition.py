"""Gateway dispatcher와 Privileged Helper의 실제 pipe 경계를 검증합니다."""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Event, Thread
from uuid import UUID, uuid4

import anyio
import pytest
from mcp.types import TextContent

from hermes_windows_bridge.gateway import helper_runtime
from hermes_windows_bridge.gateway.audit import AuditRecorder
from hermes_windows_bridge.gateway.dispatcher import (
    DispatchCall,
    DispatcherServices,
    GatewayDispatcher,
)
from hermes_windows_bridge.gateway.helper_runtime import GatewayHelperWatcher
from hermes_windows_bridge.gateway.idempotency import IdempotencyStore
from hermes_windows_bridge.gateway.policy import (
    ApprovalAttempt,
    ApprovalConsumedError,
    ApprovalDecision,
    ApprovalManager,
    ApprovalMethod,
    ApprovalSubmission,
)
from hermes_windows_bridge.ipc.acl import PipeAcl, build_privileged_pipe_acl, current_process_sid
from hermes_windows_bridge.ipc.named_pipe import PipeEndpoint, create_server_pipe
from hermes_windows_bridge.ipc.protocol import (
    GatewayHello,
    HelperHeartbeat,
    HelperRegistration,
    IpcResponse,
    JsonPayload,
    PeerRole,
    RebootIpcRequest,
)
from hermes_windows_bridge.privileged.ipc_server import HelperRegistry
from hermes_windows_bridge.worker.ipc_client import WorkerRegistry

NOW = datetime(2026, 9, 6, tzinfo=UTC)


def _serve_typed_helper(
    pipe_name: str,
    sid: str,
    received: Event,
    release: Event,
) -> None:
    with create_server_pipe(
        PipeEndpoint.PRIVILEGED_HELPER,
        pipe_name=pipe_name,
        expected_peer_sid=sid,
    ) as server:
        server.wait_for_client(2_000)
        hello = server.read_message()
        assert isinstance(hello, GatewayHello)
        assert hello.target is PeerRole.PRIVILEGED_HELPER
        registration = HelperRegistration(registration_id=uuid4(), generation=1)
        server.write_message(registration)
        server.write_message(
            HelperHeartbeat(registration_id=registration.registration_id, sequence=0)
        )
        request = server.read_message()
        assert isinstance(request, RebootIpcRequest)
        assert request.payload.delay_seconds == 0
        assert request.payload.reason == "task23_pipe_contract"
        received.set()
        server.write_message(
            IpcResponse(
                request_id=request.request_id,
                ok=True,
                payload={"operation": "reboot"},
            )
        )
        assert release.wait(3)


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "win32", reason="Windows named pipe required")
def test_approved_gateway_reboot_reaches_typed_helper_over_real_named_pipe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: transport fixture는 Gateway test user ACE를 명시적으로 추가합니다.
    # 이 확장 template은 fixed production Helper ACL의 보안 증명이 아닙니다.
    pipe_name = rf"\\.\pipe\HermesWindowsBridgeTask23Helper-{uuid4()}"
    fixture_acl = PipeAcl((*build_privileged_pipe_acl().allowed_sids, current_process_sid()))
    monkeypatch.setattr(helper_runtime, "build_privileged_pipe_acl", lambda: fixture_acl)
    received, release = Event(), Event()
    helpers = HelperRegistry(offline_after=1.0)
    watcher = GatewayHelperWatcher(pipe_name, helpers, connect_timeout_ms=100)
    watcher_thread = Thread(target=watcher.run, daemon=True)
    approvals = ApprovalManager()
    dispatcher = GatewayDispatcher(
        DispatcherServices(
            workers=WorkerRegistry(),
            helpers=helpers,
            idempotency=IdempotencyStore(ttl=timedelta(minutes=30)),
            approvals=approvals,
            audit=AuditRecorder(),
        )
    )
    operation_id: UUID = uuid4()
    payload: JsonPayload = {"delay_seconds": 0, "reason": "task23_pipe_contract"}
    approval = approvals.request(
        ApprovalSubmission(
            operation_id=operation_id,
            tool_name="system_reboot",
            payload=payload,
            requested_at=NOW,
            expires_at=NOW + timedelta(minutes=1),
        )
    )
    _ = approvals.decide(
        ApprovalDecision(
            approval_id=approval.approval_id,
            approved=True,
            method=ApprovalMethod.LOCAL,
            decided_at=NOW + timedelta(seconds=1),
        )
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        helper = executor.submit(
            _serve_typed_helper,
            pipe_name,
            current_process_sid(),
            received,
            release,
        )
        watcher_thread.start()
        try:
            assert watcher.wait_for_connections(1, timeout_seconds=3)
            assert watcher.wait_for_heartbeats(1, timeout_seconds=1)

            # When: Gateway dispatcher가 승인 receipt를 소비하고 reboot를 전송합니다.
            outcome = anyio.run(
                dispatcher.dispatch,
                DispatchCall(
                    operation_id=operation_id,
                    tool_name="system_reboot",
                    payload=payload,
                    requested_at=NOW + timedelta(seconds=2),
                    timeout_ms=1_000,
                    approval_id=approval.approval_id,
                ),
            )

            # Then: generic shell 없이 typed Helper RPC의 결과와 경계 metadata가 반환됩니다.
            assert received.is_set()
            assert outcome.result.is_error is False
            assert outcome.result.content == [TextContent(text='{"operation":"reboot"}')]
            assert (outcome.result.meta or {}).get("target") == "privileged_helper"
            with pytest.raises(ApprovalConsumedError):
                _ = approvals.consume(
                    ApprovalAttempt(
                        approval_id=approval.approval_id,
                        payload=payload,
                        attempted_at=NOW + timedelta(seconds=3),
                    )
                )
        finally:
            release.set()
            watcher.close()
            watcher_thread.join(2)
        helper.result(timeout=4)
    assert not watcher_thread.is_alive()
