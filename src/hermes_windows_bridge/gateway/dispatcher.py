"""정책과 멱등성 경계를 통과한 요청만 local IPC peer로 전달합니다."""

# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

from dataclasses import dataclass
from threading import Event
from typing import TYPE_CHECKING, Annotated, Final, assert_never, final
from uuid import UUID, uuid4

from anyio import fail_after, get_cancelled_exc_class, move_on_after, to_thread
from mcp.types import CallToolResult, TextContent
from pydantic import AwareDatetime, Field

from hermes_windows_bridge.gateway import approval_authorization, job_dispatch
from hermes_windows_bridge.gateway import audit as audit_api
from hermes_windows_bridge.gateway import policy as policy_api
from hermes_windows_bridge.gateway.idempotency import IdempotencyStore, OperationCall
from hermes_windows_bridge.gateway.result_outcome import semantic_result_outcome
from hermes_windows_bridge.ipc import protocol as ipc
from hermes_windows_bridge.ipc.protocol_errors import CorrelationError, ResponseStateError
from hermes_windows_bridge.models import policy as policy_models
from hermes_windows_bridge.privileged import ipc_server as privileged_ipc
from hermes_windows_bridge.worker import ipc_client as worker_ipc

if TYPE_CHECKING:
    from hermes_windows_bridge.gateway.jobs import JobRegistry

_SAFE_FILESYSTEM_ERRORS: Final = frozenset({"path_outside_allowed_roots", "path_policy_denied"})


class DispatchCall(policy_models.StrictFrozenModel):
    """MCP boundary에서 파싱된 단일 dispatch 입력입니다."""

    operation_id: UUID
    tool_name: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$")]
    payload: ipc.JsonPayload
    requested_at: AwareDatetime
    timeout_ms: int = Field(gt=0, le=300_000)
    approval_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class DispatchOutcome:
    """MCP 결과와 동일 실행의 sanitized 감사 receipt입니다."""

    result: CallToolResult
    audit: audit_api.AuditEvent
    replayed: bool


@dataclass(frozen=True, slots=True)
class DispatcherServices:
    """Dispatcher가 사용하는 검증된 정책·상태 service 묶음입니다."""

    workers: worker_ipc.WorkerRegistry
    helpers: privileged_ipc.HelperRegistry
    idempotency: IdempotencyStore
    approvals: policy_api.ApprovalManager
    audit: audit_api.AuditRecorder
    jobs: JobRegistry | None = None


@dataclass(frozen=True, slots=True)
class _Route:
    request: ipc.RequestMessage
    client: worker_ipc.IpcExchangeClient
    target: ipc.PeerRole


type _Presentation = tuple[ipc.JsonPayload, bool, audit_api.AuditOutcome]
_JOB_TOOL_NAMES = frozenset({"job_start", "job_status", "job_output", "job_cancel"})
@final
class GatewayDispatcher:
    """정책 → 승인 → registry → idempotency → IPC 순서를 강제합니다."""

    def __init__(self, services: DispatcherServices) -> None:
        """검증된 service 집합을 보관합니다."""
        self._services = services

    async def dispatch(self, call: DispatchCall) -> DispatchOutcome:
        """Peer 실패를 typed MCP result로 격리하고 호출자 cancellation은 전파합니다."""
        authorization = approval_authorization.authorize(call, self._services.approvals)
        if isinstance(authorization, str):
            return self._error(call, ipc.PeerRole.GATEWAY, authorization)
        if call.tool_name in _JOB_TOOL_NAMES and self._services.jobs is not None:
            return await self._dispatch_job(call, authorization)
        try:
            route = self._route(call)
        except worker_ipc.WorkerUnavailableError:
            return self._error(call, ipc.PeerRole.WORKER, "worker_unavailable", authorization)
        except privileged_ipc.HelperUnavailableError:
            return self._error(
                call, ipc.PeerRole.PRIVILEGED_HELPER, "helper_unavailable", authorization
            )
        except privileged_ipc.InvalidPrivilegedRequestError:
            return self._error(
                call, ipc.PeerRole.PRIVILEGED_HELPER, "invalid_request", authorization
            )
        return await self._send(call, route, authorization)

    async def _dispatch_job(
        self, call: DispatchCall, approval: audit_api.ApprovalAuditMetadata | None
    ) -> DispatchOutcome:
        try:
            result = await job_dispatch.dispatch_job(
                self._services.jobs,
                self._services.idempotency,
                job_dispatch.JobDispatchCall.model_validate_json(
                    call.model_dump_json(exclude={"timeout_ms", "approval_id"})
                ),
                call.timeout_ms,
            )
        except job_dispatch.JobDispatchError as error:
            return self._error(call, ipc.PeerRole.GATEWAY, error.code, approval)
        return self._present(
            call,
            ipc.PeerRole.GATEWAY,
            (result.payload, result.replayed, audit_api.AuditOutcome.SUCCEEDED),
            approval,
        )

    async def _send(
        self, call: DispatchCall, route: _Route,
        approval: audit_api.ApprovalAuditMetadata | None,
    ) -> DispatchOutcome:
        attempt = worker_ipc.ExchangeAttempt(route.client, route.request, Event())
        try:
            with fail_after(call.timeout_ms / 1_000):
                peer_result = await to_thread.run_sync(
                    self._exchange_idempotently,
                    call,
                    attempt,
                    abandon_on_cancel=True,
                )
        except TimeoutError:
            attempt.abandoned.set()
            await self._cancel(route, "timeout")
            return self._error(call, route.target, "dispatch_timeout", approval)
        except get_cancelled_exc_class():
            attempt.abandoned.set()
            await self._cancel(route, "caller_cancelled")
            _ = self._present(
                call, route.target,
                ({"error": {"code": "dispatch_cancelled"}}, False, audit_api.AuditOutcome.REJECTED),
                approval,
            )
            raise
        except worker_ipc.EndpointCancelledError:
            return self._error(call, route.target, "dispatch_cancelled", approval)
        except worker_ipc.EndpointDisconnectedError:
            self._disconnect(route)
            match route.target:
                case ipc.PeerRole.WORKER:
                    code = "worker_unavailable"
                case ipc.PeerRole.PRIVILEGED_HELPER:
                    code = "helper_unavailable"
                case ipc.PeerRole.GATEWAY:
                    code = "gateway_unavailable"
                case unreachable:
                    assert_never(unreachable)
            return self._error(call, route.target, code, approval)
        except CorrelationError, ResponseStateError, ipc.ProtocolMessageError:
            return self._error(call, route.target, "ipc_protocol_error", approval)
        response, replayed = peer_result
        if not response.ok:
            code = (
                response.error_code
                if route.target is ipc.PeerRole.WORKER
                and call.tool_name.startswith("fs_")
                and response.error_code is not None
                and response.error_code in _SAFE_FILESYSTEM_ERRORS
                else "peer_error"
            )
            return self._error(call, route.target, code, approval)
        payload = response.payload or {}
        view = payload, replayed, semantic_result_outcome(call.tool_name, payload)
        return self._present(call, route.target, view, approval)

    def _route(self, call: DispatchCall) -> _Route:
        if call.tool_name in {"system_reboot", "system_shutdown"}:
            return _Route(
                privileged_ipc.build_privileged_request(call),
                self._services.helpers.current(),
                ipc.PeerRole.PRIVILEGED_HELPER,
            )
        request = ipc.IpcRequest(
            request_id=call.operation_id,
            target=ipc.PeerRole.WORKER,
            operation=call.tool_name,
            payload=call.payload,
            timeout_ms=call.timeout_ms,
        )
        return _Route(request, self._services.workers.current(), ipc.PeerRole.WORKER)

    def _exchange_idempotently(
        self,
        call: DispatchCall,
        attempt: worker_ipc.ExchangeAttempt,
    ) -> tuple[ipc.IpcResponse, bool]:
        operation = OperationCall(
            operation_id=call.operation_id,
            payload={"tool": call.tool_name, "payload": call.payload},
            requested_at=call.requested_at,
        )
        cached = self._services.idempotency.execute(operation, attempt.run)
        response = ipc.correlate_response(attempt.request, ipc.parse_message(cached.payload))
        return response, cached.replayed

    async def _cancel(self, route: _Route, reason: str) -> None:
        with move_on_after(0.25, shield=True):
            try:
                _ = await to_thread.run_sync(
                    route.client.cancel,
                    route.request.request_id,
                    reason,
                    abandon_on_cancel=True,
                )
            except (
                worker_ipc.EndpointCancelledError,
                worker_ipc.EndpointDisconnectedError,
                worker_ipc.EndpointIoError,
                TimeoutError,
            ):
                return

    def _disconnect(self, route: _Route) -> None:
        match route.target:
            case ipc.PeerRole.WORKER:
                self._services.workers.disconnect(route.client)
            case ipc.PeerRole.PRIVILEGED_HELPER:
                self._services.helpers.disconnect(route.client)
            case ipc.PeerRole.GATEWAY:
                return
            case unreachable:
                assert_never(unreachable)

    def _error(
        self, call: DispatchCall, target: ipc.PeerRole, code: str,
        approval: audit_api.ApprovalAuditMetadata | None = None,
    ) -> DispatchOutcome:
        payload: ipc.JsonPayload = {"error": {"code": code}}
        view = payload, False, audit_api.AuditOutcome.REJECTED
        return self._present(call, target, view, approval)

    def _present(
        self,
        call: DispatchCall,
        target: ipc.PeerRole,
        view: _Presentation,
        approval: audit_api.ApprovalAuditMetadata | None = None,
    ) -> DispatchOutcome:
        payload, replayed, outcome = view
        audit = self._services.audit.record(
            audit_api.AuditInput(
                event_id=uuid4(),
                occurred_at=call.requested_at,
                tool_name=call.tool_name,
                operation_id=call.operation_id,
                payload=call.payload,
                outcome=outcome,
                approval=approval,
            )
        )
        meta = {
            "audit_event_id": str(audit.event_id),
            "operation_id": str(call.operation_id),
            "replayed": replayed,
            "target": target.value,
        }
        result = CallToolResult(
            content=[TextContent(text=policy_models.canonicalize_payload(payload).decode())],
            structured_content=payload,
            is_error=outcome is audit_api.AuditOutcome.REJECTED,
            _meta=meta,
        )
        return DispatchOutcome(result, audit, replayed)
