"""비승격 interactive Worker의 session identity와 수명 조합입니다."""

# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false

from __future__ import annotations

import os
import time
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol, override
from uuid import uuid4

import psutil
from pydantic import TypeAdapter

from hermes_windows_bridge.gateway.job_models import JobLimits
from hermes_windows_bridge.gateway.jobs import JobRegistry
from hermes_windows_bridge.ipc.acl import current_process_sid
from hermes_windows_bridge.ipc.protocol import WorkerRegistration
from hermes_windows_bridge.tools.browser import BrowserTools
from hermes_windows_bridge.tools.codex import CodexTools
from hermes_windows_bridge.tools.computer import ComputerTools
from hermes_windows_bridge.tools.filesystem import FilesystemTools
from hermes_windows_bridge.tools.jobs import JobTools
from hermes_windows_bridge.tools.process import ProcessToolService
from hermes_windows_bridge.tools.shell import ShellTools
from hermes_windows_bridge.tools.tailscale_probe import worker_tailscale_connection
from hermes_windows_bridge.tools.uia import UiaTools
from hermes_windows_bridge.worker.adapter_router import (
    CompletedAdapterRouter,
    WorkerAdapters,
    WorkerOperation,
)
from hermes_windows_bridge.worker.browser import BrowserWorker
from hermes_windows_bridge.worker.codex import CodexAdapter
from hermes_windows_bridge.worker.desktop import DesktopWorker
from hermes_windows_bridge.worker.desktop_capture import active_window
from hermes_windows_bridge.worker.desktop_lock import DesktopMutationGate, RemoteInputState
from hermes_windows_bridge.worker.emergency_audit import LocalEmergencyStopAudit
from hermes_windows_bridge.worker.emergency_hotkey import (
    LocalEmergencyHotkey,
    Win32EmergencyHotkey,
)
from hermes_windows_bridge.worker.job_process import RunningJobProcess
from hermes_windows_bridge.worker.operations import WorkerOperationDispatcher
from hermes_windows_bridge.worker.pipe_server import (
    WorkerPipeConfig,
)
from hermes_windows_bridge.worker.processes import ProcessManager
from hermes_windows_bridge.worker.runtime_lifecycle import WorkerRuntime
from hermes_windows_bridge.worker.session_power import SessionPowerWorker
from hermes_windows_bridge.worker.uia_backend import (
    create_uia_worker,
    current_process_is_elevated,
    secure_desktop_active,
)
from hermes_windows_bridge.worker.windows_mcp import (
    WindowsMcpInputBackend,
    load_windows_mcp_executable,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from uuid import UUID

    from hermes_windows_bridge.ipc.protocol import JsonPayload
    from hermes_windows_bridge.models.config import BridgeSettings, PolicySettings
    from hermes_windows_bridge.worker.desktop_input import DesktopInputBackend

_CONFIG_ENV: Final = "HERMES_BRIDGE_CONFIG_FILE"
_POLICY_ENV: Final = "HERMES_BRIDGE_POLICY_FILE"
_EMERGENCY_HOTKEYS: Final = {
    "ctrl+alt+shift+f10": 0x79,
    "ctrl+alt+shift+f11": 0x7A,
}

__all__ = ("WorkerRuntime",)


class SessionProbe(Protocol):
    def __call__(self) -> WorkerSession:
        """단일 identity snapshot을 반환합니다."""
        ...


@dataclass(frozen=True, slots=True)
class WorkerSession:
    """Worker registration과 시작 검증에 쓰는 process session snapshot입니다."""

    session_id: int
    username: str
    sid: str
    elevated: bool
    active: bool


@dataclass(frozen=True, slots=True)
class InvalidWorkerSessionError(PermissionError):
    """SYSTEM/승격/비대화형 Worker 시작을 거부합니다."""

    reason: str

    @override
    def __str__(self) -> str:
        return f"worker session rejected: {self.reason}"


@dataclass(frozen=True, slots=True)
class InvalidEmergencyHotkeyError(ValueError):
    """Worker config requested a hotkey outside the fixed safety allowlist."""

    @override
    def __str__(self) -> str:
        """Avoid echoing untrusted config values into the Worker process output."""
        return "worker emergency hotkey is unsupported"


def validate_worker_session(session: WorkerSession) -> WorkerSession:
    """명명 pipe 생성 전에 active non-elevated user session만 허용합니다."""
    if session.session_id == 0:
        raise InvalidWorkerSessionError(reason="session_zero")
    if session.elevated:
        raise InvalidWorkerSessionError(reason="elevated_token")
    if not session.active:
        raise InvalidWorkerSessionError(reason="session_not_active")
    if not session.username or session.sid in {"S-1-5-18", "S-1-5-19", "S-1-5-20"}:
        raise InvalidWorkerSessionError(reason="service_identity")
    return session


def current_worker_session() -> WorkerSession:
    """현재 process의 WTS 연결 상태, user SID와 elevation을 읽습니다."""
    import win32api  # noqa: PLC0415 - Windows 전용 process ID 경계입니다.
    import win32ts  # noqa: PLC0415 - Windows interactive session 경계입니다.

    session_id = TypeAdapter(int).validate_python(
        win32ts.ProcessIdToSessionId(win32api.GetCurrentProcessId())
    )
    state = TypeAdapter(int).validate_python(
        win32ts.WTSQuerySessionInformation(
            win32ts.WTS_CURRENT_SERVER_HANDLE,
            session_id,
            win32ts.WTSConnectState,
        )
    )
    return WorkerSession(
        session_id=session_id,
        username=psutil.Process().username(),
        sid=current_process_sid(),
        elevated=current_process_is_elevated(),
        active=state == win32ts.WTSActive,
    )


def installed_config_paths(environ: Mapping[str, str] = os.environ) -> tuple[Path, Path]:
    """명시적 override 또는 ProgramData 설치 기본 경로를 반환합니다."""
    program_data = environ.get("ProgramData") or environ.get("PROGRAMDATA")
    if program_data is None:
        raise InvalidWorkerSessionError(reason="program_data_unavailable")
    root = Path(program_data) / "HermesWindowsBridge"
    return (
        Path(environ.get(_CONFIG_ENV, root / "config.yaml")),
        Path(environ.get(_POLICY_ENV, root / "policy.yaml")),
    )


def build_worker_registration(
    session: WorkerSession,
    *,
    registration_id: UUID,
    generation: int,
) -> WorkerRegistration:
    """검증된 session snapshot을 transport 등록 메시지로 변환합니다."""
    accepted = validate_worker_session(session)
    return WorkerRegistration(
        registration_id=registration_id,
        generation=generation,
        session_id=accepted.session_id,
        username=accepted.username,
    )


def build_worker_dispatcher(
    bridge: BridgeSettings,
    policy: PolicySettings,
    session_probe: SessionProbe = current_worker_session,
    mutation_gate: DesktopMutationGate | None = None,
) -> WorkerOperationDispatcher:
    """설정된 completed adapters와 역순 cleanup owner를 조합합니다."""
    session = validate_worker_session(session_probe())
    shell = ShellTools.from_settings(policy)
    filesystem = FilesystemTools.from_settings(bridge=bridge, policy=policy)
    with ExitStack() as stack:
        processes = stack.enter_context(ProcessManager())
        jobs = stack.enter_context(
            JobRegistry(
                bridge.paths.user_data / "jobs",
                process_factory=RunningJobProcess,
                limits=JobLimits(
                    max_concurrent=bridge.jobs.max_concurrent,
                    max_output_bytes=bridge.output.max_output_bytes,
                    retention=timedelta(hours=bridge.jobs.retention_hours),
                ),
            )
        )
        browser_worker = stack.enter_context(
            BrowserWorker(
                profile_dir=bridge.browser.profile_dir,
                headless=bridge.browser.headless,
                max_output_bytes=bridge.output.max_output_bytes,
            )
        )
        active_gate = mutation_gate or DesktopMutationGate(
            RemoteInputState(bridge.paths.user_data / "remote-input.disabled")
        )
        input_backend: DesktopInputBackend | None = None
        windows_mcp_python = load_windows_mcp_executable(bridge.paths.user_data)
        if windows_mcp_python is not None:
            input_backend = stack.enter_context(
                WindowsMcpInputBackend(windows_mcp_python)
            )
        desktop = DesktopWorker(mutation_gate=active_gate, input_backend=input_backend)
        uia_worker = create_uia_worker(active_gate)

        def worker_status() -> JsonPayload:
            live = validate_worker_session(session_probe())
            payload: JsonPayload = {
                "username": live.username,
                "session_id": live.session_id,
                "desktop_unlocked": not secure_desktop_active(),
                "remote_input_enabled": desktop.remote_input_enabled,
                "active_window": {
                    "title": "" if (window := active_window()) is None else window.title,
                    "process": None if window is None else window.process_name,
                },
            }
            if (snapshot := worker_tailscale_connection()) is None:
                return payload
            payload["tailscale"] = {"connected": snapshot.connected, "ip": snapshot.ip}
            return payload

        router = CompletedAdapterRouter(
            WorkerAdapters(
                shell=shell,
                filesystem=filesystem,
                processes=ProcessToolService(processes),
                computer=ComputerTools(desktop),
                uia=UiaTools(uia_worker),
                browser=BrowserTools(browser_worker),
                codex=CodexTools(
                    CodexAdapter(
                        bridge.codex.executable,
                        jobs,
                        records_root=bridge.paths.user_data / "codex-records",
                    )
                ),
                jobs=JobTools(jobs),
                browser_worker=browser_worker,
                session_power=SessionPowerWorker(
                    session=session,
                    expected_session_id=session.session_id,
                ),
                status=worker_status,
            )
        )
        resources = stack.pop_all()
    handlers = {operation.value: router for operation in WorkerOperation}
    return WorkerOperationDispatcher(handlers, resources=(resources,))


def build_worker_runtime(
    bridge: BridgeSettings,
    policy: PolicySettings,
    session: WorkerSession,
) -> WorkerRuntime:
    """검증된 user identity를 registration과 같은 operation owner에 고정합니다."""
    accepted = validate_worker_session(session)
    mutation_gate = DesktopMutationGate(
        RemoteInputState(bridge.paths.user_data / "remote-input.disabled")
    )
    dispatcher = build_worker_dispatcher(
        bridge,
        policy,
        lambda: accepted,
        mutation_gate=mutation_gate,
    )
    config = WorkerPipeConfig(
        pipe_name=bridge.ipc.worker_pipe,
        target_user_sid=accepted.sid,
        registration=build_worker_registration(
            accepted,
            registration_id=uuid4(),
            generation=time.time_ns(),
        ),
        heartbeat_interval_seconds=float(bridge.ipc.heartbeat_seconds),
    )
    emergency_audit = LocalEmergencyStopAudit(bridge.paths.user_data / "worker-audit")

    def activate_local_emergency_stop() -> None:
        """Marker를 먼저 영속해 audit 오류가 입력 재활성화로 이어지지 않게 합니다."""
        mutation_gate.activate_emergency_stop()
        emergency_audit.record_activation()

    virtual_key = emergency_hotkey_virtual_key(bridge.computer.emergency_stop_hotkey)

    return WorkerRuntime(
        config,
        dispatcher,
        emergency_hotkey=LocalEmergencyHotkey(
            mutation_gate,
            backend_factory=lambda: Win32EmergencyHotkey(virtual_key=virtual_key),
            activation=activate_local_emergency_stop,
        ),
    )


def emergency_hotkey_virtual_key(configured: str) -> int:
    """Map the two installer-authorized safety chords to their Win32 virtual keys."""
    try:
        return _EMERGENCY_HOTKEYS[configured]
    except KeyError as error:
        raise InvalidEmergencyHotkeyError from error
