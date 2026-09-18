from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from threading import Event
from typing import TYPE_CHECKING, Never
from uuid import UUID

import pytest

from hermes_windows_bridge.ipc.operation_policy import RebootPayload
from hermes_windows_bridge.ipc.protocol import (
    IpcRequest,
    JsonPayload,
    PeerRole,
    RebootIpcRequest,
    WorkerRegistration,
)
from hermes_windows_bridge.runtime_binding import RuntimeBinding, RuntimeProfile
from hermes_windows_bridge.worker import main as worker_main
from hermes_windows_bridge.worker import runtime as worker_runtime
from hermes_windows_bridge.worker.adapter_router import WorkerOperation
from hermes_windows_bridge.worker.operations import (
    COMPLETED_WORKER_OPERATIONS,
    InvalidWorkerOperationError,
    WorkerOperationDispatcher,
)
from hermes_windows_bridge.worker.pipe_server import (
    StopSignal,
    WorkerPipeConfig,
    WorkerRequestHandler,
)
from hermes_windows_bridge.worker.runtime import (
    InvalidEmergencyHotkeyError,
    InvalidWorkerSessionError,
    WorkerRuntime,
    WorkerSession,
    build_worker_registration,
    installed_config_paths,
    validate_worker_session,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

REQUEST_ID = UUID("018f0000-0000-7000-8000-000000000021")


@dataclass(frozen=True, slots=True)
class RecordingHandler:
    calls: list[int] = field(default_factory=lambda: [0])
    cancelled: Event = field(default_factory=Event)
    closed: Event = field(default_factory=Event)
    entered: Event | None = None
    release: Event | None = None

    def __call__(self, request: IpcRequest) -> JsonPayload:
        self.calls[0] += 1
        if self.entered is not None:
            self.entered.set()
        if self.release is not None:
            assert self.release.wait(1)
        return {"operation": request.operation}

    def cancel(self, request_id: UUID) -> bool:
        if request_id == REQUEST_ID:
            self.cancelled.set()
        return self.cancelled.is_set()

    def close(self) -> None:
        self.closed.set()


def request(operation: str = "status") -> IpcRequest:
    return IpcRequest(
        request_id=REQUEST_ID,
        target=PeerRole.WORKER,
        operation=operation,
        payload={},
        timeout_ms=1_000,
    )


def test_dispatcher_correlates_completed_operation_and_closes_resource() -> None:
    # Given: 완료된 Worker operation 하나와 수명 자원입니다.
    handler = RecordingHandler()
    dispatcher = WorkerOperationDispatcher({"status": handler}, resources=(handler,))

    # When: 요청을 실행하고 dispatcher를 닫습니다.
    response = dispatcher.exchange(request())
    dispatcher.close()

    # Then: 동일 ID 성공 응답과 deterministic cleanup이 관찰됩니다.
    assert response.request_id == REQUEST_ID
    assert response.ok is True
    assert response.payload == {"operation": "status"}
    assert handler.calls == [1]
    assert handler.closed.is_set()


def test_dispatcher_rejects_unknown_and_privileged_operations_without_execution() -> None:
    # Given: 실행 횟수를 기록하는 Worker dispatcher입니다.
    handler = RecordingHandler()
    dispatcher = WorkerOperationDispatcher({"status": handler})

    # When/Then: unknown 및 privileged 요청은 Worker adapter에 도달하지 않습니다.
    unknown = dispatcher.exchange(request("system_reboot"))
    privileged = RebootIpcRequest(
        request_id=REQUEST_ID,
        payload=RebootPayload(delay_seconds=0, reason="maintenance"),
        timeout_ms=1_000,
    )
    with pytest.raises(InvalidWorkerOperationError):
        _ = dispatcher.exchange(privileged)
    assert unknown.ok is False
    assert unknown.error_code == "unsupported_worker_operation"
    assert handler.calls == [0]


def test_dispatcher_cancels_only_correlated_active_request() -> None:
    # Given: exact request ID를 취소할 수 있는 operation handler입니다.
    entered, release = Event(), Event()
    handler = RecordingHandler(entered=entered, release=release)
    dispatcher = WorkerOperationDispatcher({"status": handler})

    # When: 다른 ID와 현재 ID를 차례로 취소합니다.
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(dispatcher.exchange, request())
        assert entered.wait(1)
        stale = dispatcher.cancel(UUID(int=1))
        matched = dispatcher.cancel(REQUEST_ID)
        release.set()
        response = future.result(timeout=1)

    # Then: 현재 ID만 handler에 전달됩니다.
    assert stale is False
    assert matched is True
    assert handler.cancelled.is_set()
    assert response.error_code == "operation_cancelled"


def test_dispatcher_rejects_malformed_payload_with_correlated_error() -> None:
    # Given: strict empty status payload를 요구하는 handler입니다.
    def reject_extra(request: IpcRequest) -> JsonPayload:
        if request.payload:
            raise ValueError
        return {"state": "ok"}

    class StrictHandler:
        def __call__(self, request: IpcRequest) -> JsonPayload:
            return reject_extra(request)

        def cancel(self, request_id: UUID) -> bool:
            del request_id
            return False

    dispatcher = WorkerOperationDispatcher({"status": StrictHandler()})

    # When: unexpected 필드를 포함한 payload를 실행합니다.
    response = dispatcher.exchange(request().model_copy(update={"payload": {"extra": True}}))

    # Then: request ID를 보존한 closed 오류로 반환합니다.
    assert response.request_id == REQUEST_ID
    assert response.ok is False
    assert response.error_code == "invalid_worker_request"


@pytest.mark.parametrize(
    "session",
    [
        WorkerSession(0, "DOMAIN\\alice", "S-1-5-21-1", elevated=False, active=True),
        WorkerSession(2, "DOMAIN\\alice", "S-1-5-21-1", elevated=True, active=True),
        WorkerSession(2, "DOMAIN\\alice", "S-1-5-21-1", elevated=False, active=False),
    ],
)
def test_worker_rejects_system_elevated_and_noninteractive_sessions(
    session: WorkerSession,
) -> None:
    # Given: privilege/session invariant를 위반한 process token입니다.
    # When/Then: pipe나 adapter 생성 전에 실패 폐쇄합니다.
    with pytest.raises(InvalidWorkerSessionError):
        _ = validate_worker_session(session)


def test_completed_worker_operation_registry_matches_closed_router() -> None:
    # Given: Worker allowlist와 concrete exhaustive router enum입니다.
    routed = frozenset(operation.value for operation in WorkerOperation)

    # When/Then: 모든 completed user operation이 정확히 한 번 route됩니다.
    assert routed == COMPLETED_WORKER_OPERATIONS


def test_installed_config_paths_use_program_data_and_explicit_overrides(tmp_path: Path) -> None:
    # Given: 설치 root와 config 전용 override입니다.
    config_override = tmp_path / "custom.yaml"
    environment = {
        "ProgramData": str(tmp_path),
        "HERMES_BRIDGE_CONFIG_FILE": str(config_override),
    }

    # When: Worker 설정 경로를 해석합니다.
    config_path, policy_path = installed_config_paths(environment)

    # Then: override와 명세의 ProgramData 기본값만 사용합니다.
    assert config_path == config_override
    assert policy_path == tmp_path / "HermesWindowsBridge" / "policy.yaml"


def test_runtime_uses_injected_stop_and_closes_dispatcher_resource() -> None:
    # Given: 실제 transport 대신 stop 관찰이 가능한 server seam입니다.
    stop = Event()
    handler = RecordingHandler()
    dispatcher = WorkerOperationDispatcher({"status": handler}, resources=(handler,))
    registration = WorkerRegistration(
        registration_id=REQUEST_ID,
        generation=21,
        session_id=2,
        username="DOMAIN\\alice",
    )
    expected_config = WorkerPipeConfig(
        pipe_name=r"\\.\pipe\HermesWindowsBridgeTest",
        target_user_sid="S-1-5-21-1",
        registration=registration,
    )

    def stop_server(
        config: WorkerPipeConfig,
        handler: WorkerRequestHandler,
        stop: StopSignal,
    ) -> None:
        assert config is expected_config
        assert handler is dispatcher
        assert isinstance(stop, Event)
        stop.set()

    runtime = WorkerRuntime(expected_config, dispatcher, server=stop_server)

    # When: injected stop까지 실행하고 정상 종료합니다.
    runtime.run(stop)
    runtime.close()

    # Then: server가 stop을 관찰하고 owned resource를 회수합니다.
    assert stop.is_set()
    assert handler.closed.is_set()


def test_registration_uses_injected_generation_and_identity() -> None:
    # Given: 가짜 clock 값과 안정적인 registration ID입니다.
    session = WorkerSession(2, "DOMAIN\\alice", "S-1-5-21-1", elevated=False, active=True)

    # When: 등록 메시지를 구성합니다.
    registration = build_worker_registration(
        session,
        registration_id=REQUEST_ID,
        generation=123_456,
    )

    # Then: session ID, username 및 clock 값이 손실 없이 등록됩니다.
    assert registration.registration_id == REQUEST_ID
    assert registration.generation == 123_456
    assert registration.session_id == 2
    assert registration.username == "DOMAIN\\alice"


@pytest.mark.parametrize(
    ("configured", "expected"),
    [("ctrl+alt+shift+f10", 0x79), ("ctrl+alt+shift+f11", 0x7A)],
)
def test_runtime_maps_only_installer_authorized_emergency_hotkeys(
    configured: str, expected: int
) -> None:
    # Given: production F11 or nonce-isolated F10 selected by an installer-bound config.
    # When: Worker runtime derives the Win32 backend key.
    actual = worker_runtime.emergency_hotkey_virtual_key(configured)

    # Then: each selection has a stable independent virtual key.
    assert actual == expected


def test_runtime_rejects_unbounded_emergency_hotkey_config() -> None:
    # Given: a config trying to select an arbitrary chord.
    # When / Then: startup fails closed before a global hotkey can be registered.
    with pytest.raises(InvalidEmergencyHotkeyError):
        _ = worker_runtime.emergency_hotkey_virtual_key("ctrl+alt+shift+f12")


def test_bound_factory_rejects_a_different_interactive_user_before_runtime_build(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Given: a task starts under an active but binding-mismatched interactive SID.
    session = WorkerSession(2, "DOMAIN\\alice", "S-1-5-21-actual", elevated=False, active=True)
    factory = worker_main.InstalledWorkerRuntimeFactory(
        tmp_path / "config.yaml", tmp_path / "policy.yaml", expected_worker_sid="S-1-5-21-bound"
    )
    monkeypatch.setattr(worker_main, "current_worker_session", lambda: session)

    # When / Then: no config or runtime builder is selected for the wrong account.
    with pytest.raises(InvalidWorkerSessionError, match="binding_identity"):
        _ = factory()


def test_bound_factory_revalidates_the_original_binding_before_each_reconnect(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Given: a bound runtime factory whose config reader is stopped after binding refresh.
    binding = RuntimeBinding(
        profile=RuntimeProfile.WORKER,
        context_nonce="0123456789abcdef0123456789abcdef",
        config_path=tmp_path / "config.yaml",
        config_sha256="a" * 64,
        worker_sid="S-1-5-21-1-2-3-4",
        policy_path=tmp_path / "policy.yaml",
        policy_sha256="b" * 64,
    )
    session = WorkerSession(
        2,
        "DOMAIN\\alice",
        binding.worker_sid,
        elevated=False,
        active=True,
    )
    refreshed: list[tuple[RuntimeProfile, Path, str]] = []
    factory = worker_main.InstalledWorkerRuntimeFactory(
        binding.config_path,
        _require_policy_path(binding),
        binding_path=tmp_path / "worker.json",
        binding_sha256="c" * 64,
    )

    def refresh(
        profile: RuntimeProfile, path: Path, digest: str
    ) -> RuntimeBinding:
        refreshed.append((profile, path, digest))
        return binding

    def stop_after_refresh(path: Path, *, environ: Mapping[str, str] | None = None) -> Never:
        del path, environ
        reason = "test_config_boundary"
        raise OSError(reason)

    monkeypatch.setattr(worker_main, "load_runtime_binding", refresh)
    monkeypatch.setattr(worker_main, "load_bridge_settings", stop_after_refresh)
    monkeypatch.setattr(worker_main, "current_worker_session", lambda: session)

    # When: two reconnect factories begin their startup selections.
    for _ in range(2):
        with pytest.raises(OSError, match="test_config_boundary"):
            _ = factory()

    # Then: each reconnect begins by rechecking the original protected binding pair.
    assert refreshed == [
        (RuntimeProfile.WORKER, tmp_path / "worker.json", "c" * 64),
        (RuntimeProfile.WORKER, tmp_path / "worker.json", "c" * 64),
    ]


def _require_policy_path(binding: RuntimeBinding) -> Path:
    """Worker binding fixture의 필수 policy 경로를 type-safe하게 꺼냅니다."""
    if binding.policy_path is None:
        raise AssertionError
    return binding.policy_path
