from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Never, assert_never, final
from uuid import UUID

import anyio

from hermes_windows_bridge.gateway.audit import AuditRecorder
from hermes_windows_bridge.gateway.dispatcher import (
    DispatchCall,
    DispatcherServices,
    GatewayDispatcher,
)
from hermes_windows_bridge.gateway.idempotency import IdempotencyStore
from hermes_windows_bridge.gateway.policy import (
    ApprovalCoordinator,
    ApprovalManager,
    ApprovalSubmission,
)
from hermes_windows_bridge.ipc import protocol as ipc
from hermes_windows_bridge.privileged.ipc_server import HelperRegistry, parse_ipc_request
from hermes_windows_bridge.privileged.operations import (
    PowerActionService,
    RebootRequest,
    ShutdownRequest,
)
from hermes_windows_bridge.worker.ipc_client import WorkerRegistry

if TYPE_CHECKING:
    import pytest

    from hermes_windows_bridge.models.policy import ApprovalRecord

# pyright: reportUnnecessaryComparison=false

NOW = datetime(2026, 9, 5, tzinfo=UTC)
OPERATION_ID = UUID("018f0000-0000-7000-8000-000000000019")


@final
class CountingPowerExecutor:
    """OS 호출 없이 helper 실행 경계만 관찰합니다."""

    def __init__(self) -> None:
        self.reboots = 0
        self.shutdowns = 0

    def reboot(self, request: RebootRequest) -> None:
        del request
        self.reboots += 1

    def shutdown(self, request: ShutdownRequest) -> None:
        del request
        self.shutdowns += 1


@final
class ApprovingSurface:
    async def resolve(self, record: ApprovalRecord) -> bool:
        del record
        return True


@final
class LoopbackHelper:
    """실제 IPC 직렬화/파싱 뒤 harmless executor를 호출합니다."""

    def __init__(self, executor: CountingPowerExecutor) -> None:
        self._service = PowerActionService(executor)

    def exchange(self, request: ipc.RequestMessage) -> ipc.IpcResponse:
        parsed = ipc.parse_message(ipc.serialize_message(request))
        match parsed:
            case ipc.RebootIpcRequest() | ipc.ShutdownIpcRequest():
                result = self._service.execute(parse_ipc_request(parsed))
            case (
                ipc.GatewayHello()
                | ipc.WorkerRegistration()
                | ipc.Heartbeat()
                | ipc.HelperRegistration()
                | ipc.HelperHeartbeat()
                | ipc.IpcRequest()
                | ipc.IpcResponse()
                | ipc.JobOutputChunkRequest()
                | ipc.JobOutputChunkResponse()
                | ipc.CancelRequest()
            ):
                raise AssertionError
            case _ as unreachable:
                assert_never(unreachable)
        return ipc.IpcResponse(
            request_id=request.request_id,
            ok=True,
            payload={"operation": result.operation},
        )

    def cancel(self, request_id: UUID, reason: str) -> bool:
        del request_id, reason
        return False


@final
class RejectingWindowsPowerApi:
    """Win32 power API 접근 자체를 실패시키고 관찰합니다."""

    def __init__(self, calls: list[str]) -> None:
        self._calls = calls

    def __getattr__(self, name: str) -> Never:
        self._calls.append(name)
        raise AssertionError


def _dispatcher(approvals: ApprovalManager, helper: LoopbackHelper) -> GatewayDispatcher:
    helpers = HelperRegistry()
    helpers.register(generation=1, client=helper)
    return GatewayDispatcher(
        DispatcherServices(
            workers=WorkerRegistry(),
            helpers=helpers,
            idempotency=IdempotencyStore(ttl=timedelta(minutes=30)),
            approvals=approvals,
            audit=AuditRecorder(),
        )
    )


class TestPrivilegedOperations:
    def test_test_operation_requires_one_shot_approval(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Given: 실제 typed IPC loopback과 harmless power executor입니다.
        blocked_os_calls: list[str] = []

        def reject_os_call(command: str) -> Never:
            blocked_os_calls.append(command)
            raise AssertionError

        monkeypatch.setattr(os, "system", reject_os_call)
        monkeypatch.setattr(subprocess, "run", reject_os_call)
        monkeypatch.setattr(ctypes, "windll", RejectingWindowsPowerApi(blocked_os_calls))
        approvals = ApprovalManager()
        executor = CountingPowerExecutor()
        gateway = _dispatcher(approvals, LoopbackHelper(executor))
        payload: ipc.JsonPayload = {"delay_seconds": 0, "reason": "maintenance"}
        call = DispatchCall(
            operation_id=OPERATION_ID,
            tool_name="system_reboot",
            payload=payload,
            requested_at=NOW,
            timeout_ms=200,
        )

        # When: 승인 전, 독립 elicitation 승인 후, 같은 receipt 재사용을 순서대로 시도합니다.
        blocked = anyio.run(gateway.dispatch, call)
        coordinator = ApprovalCoordinator(
            approvals,
            (ApprovingSurface(), None),
            clock=lambda: NOW + timedelta(seconds=1),
        )
        receipt = anyio.run(
            coordinator.resolve,
            ApprovalSubmission(
                operation_id=OPERATION_ID,
                tool_name="system_reboot",
                payload=payload,
                requested_at=NOW,
                expires_at=NOW + timedelta(minutes=1),
            ),
        )
        approved_call = call.model_copy(update={"approval_id": receipt.approval_id})
        accepted = anyio.run(gateway.dispatch, approved_call)
        replay = anyio.run(gateway.dispatch, approved_call)

        # Then: executor는 승인된 frozen request를 정확히 한 번만 받습니다.
        assert blocked.result.is_error is True
        assert accepted.result.is_error is False
        assert replay.result.is_error is True
        assert (executor.reboots, executor.shutdowns) == (1, 0)
        assert receipt.method == "elicitation"
        assert len(receipt.payload_digest) == 64
        assert "maintenance" not in repr(receipt)
        assert blocked_os_calls == []
        _ = sys.stdout.write(
            "typed_ipc=true helper_executions=1 replay_rejected=true os_power_api_calls=0\n"
        )
