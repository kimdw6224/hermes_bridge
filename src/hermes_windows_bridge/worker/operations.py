"""Gateway가 승인한 요청을 completed user adapters로만 보내는 Worker 경계입니다."""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import TYPE_CHECKING, Final, Protocol, final, override

from hermes_windows_bridge.ipc.protocol import IpcRequest, IpcResponse
from hermes_windows_bridge.worker.path_safety import PathPolicyError

if TYPE_CHECKING:
    from collections.abc import Mapping
    from uuid import UUID

    from hermes_windows_bridge.ipc.protocol import JsonPayload, RequestMessage

COMPLETED_WORKER_OPERATIONS: Final = frozenset(
    {
        "app_open",
        "browser_click",
        "browser_close",
        "browser_extract",
        "browser_navigate",
        "browser_open",
        "browser_snapshot",
        "browser_status",
        "browser_type",
        "codex_run",
        "codex_status",
        "computer_click",
        "computer_hotkey",
        "computer_key",
        "computer_move",
        "computer_observe",
        "computer_scroll",
        "computer_type",
        "fs_copy",
        "fs_delete",
        "fs_list",
        "fs_mkdir",
        "fs_move",
        "fs_read",
        "fs_stat",
        "fs_write",
        "job_cancel",
        "job_output",
        "job_start",
        "job_status",
        "process_kill",
        "process_list",
        "process_start",
        "shell_run",
        "status",
        "system_lock",
        "system_sleep",
        "uia_action",
        "uia_find",
    }
)


class OperationHandler(Protocol):
    """단일 typed user operation의 실행/취소 계약입니다."""

    def __call__(self, request: IpcRequest) -> JsonPayload:
        """검증된 요청을 실행합니다."""
        ...

    def cancel(self, request_id: UUID) -> bool:
        """일치하는 실행을 중단했는지 반환합니다."""
        ...


class Closeable(Protocol):
    """Worker 종료 시 회수할 resource입니다."""

    def close(self) -> None:
        """소유 resource를 닫습니다."""
        ...


@dataclass(frozen=True, slots=True)
class InvalidWorkerOperationError(ValueError):
    """Worker 역할이 처리해서는 안 되는 IPC 요청입니다."""

    reason: str

    @override
    def __str__(self) -> str:
        return f"invalid worker operation: {self.reason}"


@final
class WorkerOperationDispatcher:
    """닫힌 operation table과 현재 request cancellation을 소유합니다."""

    def __init__(
        self,
        handlers: Mapping[str, OperationHandler],
        *,
        resources: tuple[Closeable, ...] = (),
    ) -> None:
        """허용된 handler table과 종료할 resource를 보관합니다."""
        unknown = frozenset(handlers).difference(COMPLETED_WORKER_OPERATIONS)
        if unknown:
            raise InvalidWorkerOperationError(reason="operation table contains unsupported names")
        self._handlers = dict(handlers)
        self._resources = resources
        self._active: dict[UUID, OperationHandler] = {}
        self._cancelled: set[UUID] = set()
        self._lock = Lock()
        self._closed = False

    def exchange(self, request: RequestMessage) -> IpcResponse:
        """Worker-target 요청만 실행하고 request ID가 같은 응답을 반환합니다."""
        if not isinstance(request, IpcRequest):
            raise InvalidWorkerOperationError(reason="request target is not worker")
        handler = self._handlers.get(request.operation)
        if handler is None:
            return IpcResponse(
                request_id=request.request_id,
                ok=False,
                error_code="unsupported_worker_operation",
            )
        with self._lock:
            if self._closed:
                return IpcResponse(
                    request_id=request.request_id,
                    ok=False,
                    error_code="worker_stopping",
                )
            self._active[request.request_id] = handler
        try:
            try:
                payload = handler(request)
            except PathPolicyError as error:
                return IpcResponse(
                    request_id=request.request_id,
                    ok=False,
                    error_code=(
                        "path_outside_allowed_roots"
                        if error.reason == "outside_allowed_roots"
                        else "path_policy_denied"
                    ),
                )
            except ValueError:
                return IpcResponse(
                    request_id=request.request_id,
                    ok=False,
                    error_code="invalid_worker_request",
                )
            except OSError, RuntimeError:
                return IpcResponse(
                    request_id=request.request_id,
                    ok=False,
                    error_code="worker_operation_failed",
                )
            with self._lock:
                cancelled = request.request_id in self._cancelled
            return IpcResponse(
                request_id=request.request_id,
                ok=not cancelled,
                payload=None if cancelled else payload,
                error_code="operation_cancelled" if cancelled else None,
            )
        finally:
            with self._lock:
                _ = self._active.pop(request.request_id, None)
                self._cancelled.discard(request.request_id)

    def cancel(self, request_id: UUID) -> bool:
        """현재 실행 중인 exact request만 adapter에 취소 요청합니다."""
        with self._lock:
            handler = self._active.get(request_id)
            if handler is None:
                return False
            self._cancelled.add(request_id)
        _ = handler.cancel(request_id)
        return True

    def close(self) -> None:
        """새 요청을 막고 모든 소유 adapter resource를 역순으로 닫습니다."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            active = tuple(self._active.items())
        for request_id, handler in active:
            _ = handler.cancel(request_id)
        for resource in reversed(self._resources):
            resource.close()
