"""Completed Worker adapters의 strict payload parsing과 exhaustive routing입니다."""

# pyright: reportAny=false
# pyright: reportUnnecessaryComparison=false

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, ClassVar, Final, assert_never, final

from pydantic import BaseModel, ConfigDict, TypeAdapter
from pydantic_core import to_jsonable_python

from hermes_windows_bridge.ipc.protocol import IpcRequest, JsonPayload
from hermes_windows_bridge.tools.browser import (
    BrowserClickInput,
    BrowserCloseInput,
    BrowserExtractInput,
    BrowserNavigateInput,
    BrowserOpenInput,
    BrowserSnapshotInput,
    BrowserStatusInput,
    BrowserTools,
    BrowserTypeInput,
)
from hermes_windows_bridge.tools.codex import CodexRunInput, CodexStatusInput, CodexTools
from hermes_windows_bridge.tools.computer import (
    ComputerObserveInput,
    ComputerTools,
    observation_to_ipc_payload,
)
from hermes_windows_bridge.tools.computer_input import (
    ComputerClickInput,
    ComputerHotkeyInput,
    ComputerKeyInput,
    ComputerMoveInput,
    ComputerScrollInput,
    ComputerTypeInput,
)
from hermes_windows_bridge.tools.filesystem import (
    DeleteInput,
    FilesystemTools,
    ListInput,
    MkdirInput,
    MoveInput,
    ReadInput,
    WriteInput,
)
from hermes_windows_bridge.tools.jobs import (
    JobCancelInput,
    JobOutputInput,
    JobStartInput,
    JobStatusInput,
    JobTools,
)
from hermes_windows_bridge.tools.process import (
    AppOpenInput,
    ProcessKillInput,
    ProcessStartInput,
    ProcessToolService,
)
from hermes_windows_bridge.tools.shell import ShellRunInput, ShellTools
from hermes_windows_bridge.tools.uia import UiaActionInput, UiaFindInput, UiaTools

if TYPE_CHECKING:
    from collections.abc import Callable
    from uuid import UUID

    from hermes_windows_bridge.worker.browser import BrowserWorker
    from hermes_windows_bridge.worker.session_power import SessionPowerWorker

_PAYLOAD: Final[TypeAdapter[JsonPayload]] = TypeAdapter(JsonPayload)


class _EmptyInput(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)


class WorkerOperation(StrEnum):
    """Worker가 실행할 수 있는 completed user operation입니다."""

    STATUS = "status"
    SHELL_RUN = "shell_run"
    FS_LIST = "fs_list"
    FS_STAT = "fs_stat"
    FS_READ = "fs_read"
    FS_WRITE = "fs_write"
    FS_MOVE = "fs_move"
    FS_COPY = "fs_copy"
    FS_DELETE = "fs_delete"
    FS_MKDIR = "fs_mkdir"
    PROCESS_LIST = "process_list"
    PROCESS_START = "process_start"
    PROCESS_KILL = "process_kill"
    APP_OPEN = "app_open"
    COMPUTER_OBSERVE = "computer_observe"
    COMPUTER_CLICK = "computer_click"
    COMPUTER_MOVE = "computer_move"
    COMPUTER_SCROLL = "computer_scroll"
    COMPUTER_TYPE = "computer_type"
    COMPUTER_HOTKEY = "computer_hotkey"
    COMPUTER_KEY = "computer_key"
    UIA_FIND = "uia_find"
    UIA_ACTION = "uia_action"
    BROWSER_STATUS = "browser_status"
    BROWSER_OPEN = "browser_open"
    BROWSER_NAVIGATE = "browser_navigate"
    BROWSER_SNAPSHOT = "browser_snapshot"
    BROWSER_CLICK = "browser_click"
    BROWSER_TYPE = "browser_type"
    BROWSER_EXTRACT = "browser_extract"
    BROWSER_CLOSE = "browser_close"
    CODEX_STATUS = "codex_status"
    CODEX_RUN = "codex_run"
    JOB_START = "job_start"
    JOB_STATUS = "job_status"
    JOB_OUTPUT = "job_output"
    JOB_CANCEL = "job_cancel"
    SYSTEM_LOCK = "system_lock"
    SYSTEM_SLEEP = "system_sleep"


@dataclass(frozen=True, slots=True)
class WorkerAdapters:
    """Worker process가 소유하는 completed adapter facade입니다."""

    shell: ShellTools
    filesystem: FilesystemTools
    processes: ProcessToolService
    computer: ComputerTools
    uia: UiaTools
    browser: BrowserTools
    codex: CodexTools
    jobs: JobTools
    browser_worker: BrowserWorker
    session_power: SessionPowerWorker
    status: Callable[[], JsonPayload]


@final
class CompletedAdapterRouter:
    """Operation enum별 입력 model을 한 번 파싱한 뒤 해당 facade만 호출합니다."""

    def __init__(self, adapters: WorkerAdapters) -> None:
        """수명 소유권이 확정된 facade 묶음을 보관합니다."""
        self._adapters = adapters

    def __call__(  # noqa: C901, PLR0912, PLR0915 - closed exhaustive operation table입니다.
        self, request: IpcRequest
    ) -> JsonPayload:
        """Operation별 strict model로 payload를 파싱하고 facade를 호출합니다."""
        adapters = self._adapters
        payload = request.payload
        correlated = payload | {"operation_id": str(request.request_id)}
        operation = WorkerOperation(request.operation)
        match operation:
            case WorkerOperation.STATUS:
                _ = _EmptyInput.model_validate(payload)
                return adapters.status()
            case WorkerOperation.SHELL_RUN:
                result = adapters.shell.shell_run(ShellRunInput.model_validate(correlated))
            case WorkerOperation.FS_LIST:
                result = adapters.filesystem.fs_list(ListInput.model_validate(payload))
            case WorkerOperation.FS_STAT:
                result = adapters.filesystem.fs_stat(ReadInput.model_validate(payload))
            case WorkerOperation.FS_READ:
                result = adapters.filesystem.fs_read(ReadInput.model_validate(payload))
            case WorkerOperation.FS_WRITE:
                result = adapters.filesystem.fs_write(WriteInput.model_validate(payload))
            case WorkerOperation.FS_MOVE:
                result = adapters.filesystem.fs_move(MoveInput.model_validate(payload))
            case WorkerOperation.FS_COPY:
                result = adapters.filesystem.fs_copy(MoveInput.model_validate(payload))
            case WorkerOperation.FS_DELETE:
                result = adapters.filesystem.fs_delete(DeleteInput.model_validate(payload))
            case WorkerOperation.FS_MKDIR:
                result = adapters.filesystem.fs_mkdir(MkdirInput.model_validate(payload))
            case WorkerOperation.PROCESS_LIST:
                _ = _EmptyInput.model_validate(payload)
                result = adapters.processes.process_list()
            case WorkerOperation.PROCESS_START:
                result = adapters.processes.process_start(ProcessStartInput.model_validate(payload))
            case WorkerOperation.PROCESS_KILL:
                result = adapters.processes.process_kill(ProcessKillInput.model_validate(payload))
            case WorkerOperation.APP_OPEN:
                result = adapters.processes.app_open(AppOpenInput.model_validate(payload))
            case WorkerOperation.COMPUTER_OBSERVE:
                observed = adapters.computer.computer_observe(
                    ComputerObserveInput.model_validate(correlated)
                )
                return observation_to_ipc_payload(observed)
            case WorkerOperation.COMPUTER_CLICK:
                result = adapters.computer.computer_click(
                    ComputerClickInput.model_validate(correlated)
                )
            case WorkerOperation.COMPUTER_MOVE:
                result = adapters.computer.computer_move(
                    ComputerMoveInput.model_validate(correlated)
                )
            case WorkerOperation.COMPUTER_SCROLL:
                result = adapters.computer.computer_scroll(
                    ComputerScrollInput.model_validate(correlated)
                )
            case WorkerOperation.COMPUTER_TYPE:
                result = adapters.computer.computer_type(
                    ComputerTypeInput.model_validate(correlated)
                )
            case WorkerOperation.COMPUTER_HOTKEY:
                result = adapters.computer.computer_hotkey(
                    ComputerHotkeyInput.model_validate(correlated)
                )
            case WorkerOperation.COMPUTER_KEY:
                result = adapters.computer.computer_key(ComputerKeyInput.model_validate(correlated))
            case WorkerOperation.UIA_FIND:
                result = adapters.uia.uia_find(UiaFindInput.model_validate(correlated))
            case WorkerOperation.UIA_ACTION:
                result = adapters.uia.uia_action(UiaActionInput.model_validate(correlated))
            case WorkerOperation.BROWSER_STATUS:
                result = adapters.browser.browser_status(
                    BrowserStatusInput.model_validate(correlated)
                )
            case WorkerOperation.BROWSER_OPEN:
                result = adapters.browser.browser_open(BrowserOpenInput.model_validate(correlated))
            case WorkerOperation.BROWSER_NAVIGATE:
                result = adapters.browser.browser_navigate(
                    BrowserNavigateInput.model_validate(correlated)
                )
            case WorkerOperation.BROWSER_SNAPSHOT:
                result = adapters.browser.browser_snapshot(
                    BrowserSnapshotInput.model_validate(correlated)
                )
            case WorkerOperation.BROWSER_CLICK:
                result = adapters.browser.browser_click(
                    BrowserClickInput.model_validate(correlated)
                )
            case WorkerOperation.BROWSER_TYPE:
                result = adapters.browser.browser_type(BrowserTypeInput.model_validate(correlated))
            case WorkerOperation.BROWSER_EXTRACT:
                result = adapters.browser.browser_extract(
                    BrowserExtractInput.model_validate(correlated)
                )
            case WorkerOperation.BROWSER_CLOSE:
                result = adapters.browser.browser_close(
                    BrowserCloseInput.model_validate(correlated)
                )
            case WorkerOperation.CODEX_STATUS:
                _ = CodexStatusInput.model_validate(correlated)
                result = adapters.codex.codex_status()
            case WorkerOperation.CODEX_RUN:
                result = adapters.codex.codex_run(CodexRunInput.model_validate(correlated))
            case WorkerOperation.JOB_START:
                result = adapters.jobs.job_start(JobStartInput.model_validate(correlated))
            case WorkerOperation.JOB_STATUS:
                result = adapters.jobs.job_status(JobStatusInput.model_validate(payload))
            case WorkerOperation.JOB_OUTPUT:
                result = adapters.jobs.job_output(JobOutputInput.model_validate(payload))
            case WorkerOperation.JOB_CANCEL:
                result = adapters.jobs.job_cancel(JobCancelInput.model_validate(payload))
            case WorkerOperation.SYSTEM_LOCK:
                _ = _EmptyInput.model_validate(payload)
                result = adapters.session_power.system_lock()
            case WorkerOperation.SYSTEM_SLEEP:
                _ = _EmptyInput.model_validate(payload)
                result = adapters.session_power.system_sleep()
            case unreachable:
                assert_never(unreachable)
        return _PAYLOAD.validate_python(to_jsonable_python(result))

    def cancel(self, request_id: UUID) -> bool:
        """Playwright의 exact operation cancellation을 즉시 전달합니다."""
        return self._adapters.browser_worker.cancel(request_id)
