from __future__ import annotations

from dataclasses import dataclass
from threading import Event, Thread
from time import monotonic
from typing import TYPE_CHECKING, final

import pytest

from hermes_windows_bridge.tools.uia import (
    UiaActionInput,
    UiaFindInput,
    UiaSelectorInput,
    UiaTools,
)
from hermes_windows_bridge.worker import uia_backend
from hermes_windows_bridge.worker.desktop_lock import DesktopMutationGate, RemoteInputState
from hermes_windows_bridge.worker.uia import (
    UiaAction,
    UiaActionResult,
    UiaControl,
    UiaErrorCode,
    UiaExecution,
    UiaOperationError,
    UiaQuery,
    UiaResolvedTarget,
    UiaSecurityProbes,
    UiaTargetIdentity,
    UiaWorker,
)
from hermes_windows_bridge.worker.uia_backend import PywinautoUiaBackend

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True, slots=True)
class FakeTarget:
    identity: UiaTargetIdentity
    control: UiaControl


@final
class SecurityBackend:
    """호출 여부와 typed backend failure를 기록하는 mutable test adapter입니다."""

    def __init__(
        self,
        action_error: UiaErrorCode | None = None,
        *,
        target_count: int = 1,
        available: bool = True,
        cancel_during_resolve: Event | None = None,
    ) -> None:
        self.action_error: UiaErrorCode | None = action_error
        self.target_count = target_count
        self.available = available
        self.cancel_during_resolve = cancel_during_resolve
        self.apply_calls = 0

    def resolve(
        self, query: UiaQuery, limit: int, execution: UiaExecution
    ) -> tuple[UiaResolvedTarget, ...]:
        del query
        targets: list[FakeTarget] = []
        for index in range(self.target_count):
            execution.check()
            if self.cancel_during_resolve is not None:
                self.cancel_during_resolve.set()
                execution.check()
            control = UiaControl(
                path=f"0/{index}",
                title="Same Title",
                automation_id=f"fixture-{index}",
                control_type="Button",
                class_name="Button",
                enabled=True,
                visible=True,
                process_id=42,
            )
            targets.append(FakeTarget(UiaTargetIdentity(42, 100 + index, (index,)), control))
        return tuple(targets[:limit])

    def revalidate(self, target: UiaResolvedTarget, execution: UiaExecution) -> bool:
        del target
        execution.check()
        return self.available

    def apply(
        self,
        target: UiaResolvedTarget,
        action: UiaAction,
        text: str | None,
        execution: UiaExecution,
    ) -> None:
        del target, action, text
        execution.check()
        self.apply_calls += 1
        if self.action_error is not None:
            raise UiaOperationError(code=self.action_error)


def _security(*, secure: bool = False, worker_elevated: bool = False) -> UiaSecurityProbes:
    return UiaSecurityProbes(
        secure_desktop=lambda: secure,
        worker_elevated=lambda: worker_elevated,
        target_elevated=lambda _pid: False,
    )


def _action() -> UiaActionInput:
    return UiaActionInput(
        selector=UiaSelectorInput(
            window_title_contains="Fixture Window",
            automation_id="fixture",
        ),
        action="invoke",
    )


@pytest.mark.security
def test_emergency_stop_blocks_uia_action_before_backend(tmp_path: Path) -> None:
    state = RemoteInputState(tmp_path / "remote-input.disabled")
    state.disable()
    backend = SecurityBackend()
    worker = UiaWorker(backend, DesktopMutationGate(state), _security())

    result = UiaTools(worker).uia_action(_action())

    assert result.ok is False
    assert result.error_code == "emergency_stop"
    assert backend.apply_calls == 0


@pytest.mark.security
def test_ambiguous_selector_is_typed_failure_without_success_claim(tmp_path: Path) -> None:
    backend = SecurityBackend(action_error="ambiguous_selector")
    worker = UiaWorker(
        backend,
        DesktopMutationGate(RemoteInputState(tmp_path / "stop")),
        _security(),
    )

    result = UiaTools(worker).uia_action(_action())

    assert result.ok is False
    assert result.error_code == "ambiguous_selector"
    assert result.controls == ()


@pytest.mark.security
def test_same_title_top_level_windows_never_choose_first_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SameTitleWindow:
        def __init__(self, process_id: int) -> None:
            self.process_id: int = process_id

        def window_text(self) -> str:
            return "Duplicate Fixture"

    class SameTitleDesktop:
        def windows(self, *, title_re: str, visible_only: bool) -> list[SameTitleWindow]:
            assert "Duplicate" in title_re
            assert visible_only is True
            return [SameTitleWindow(101), SameTitleWindow(202)]

    def desktop_factory(*, backend: str) -> SameTitleDesktop:
        assert backend == "uia"
        return SameTitleDesktop()

    monkeypatch.setattr(uia_backend, "Desktop", desktop_factory)

    with pytest.raises(UiaOperationError) as captured:
        _ = PywinautoUiaBackend().target_pid(UiaQuery(window_title_contains="Duplicate"))

    assert captured.value.code == "ambiguous_selector"


@pytest.mark.security
def test_target_swap_between_guard_and_action_is_state_conflict(tmp_path: Path) -> None:
    backend = SecurityBackend(available=False)
    worker = UiaWorker(
        backend,
        DesktopMutationGate(RemoteInputState(tmp_path / "stop")),
        _security(),
    )

    result = UiaTools(worker).uia_action(_action())

    assert result.ok is False
    assert result.error_code == "state_conflict"
    assert backend.apply_calls == 0


@pytest.mark.security
def test_iterative_resolution_cancellation_has_zero_mutation(tmp_path: Path) -> None:
    cancelled = Event()
    backend = SecurityBackend(cancel_during_resolve=cancelled)
    worker = UiaWorker(
        backend,
        DesktopMutationGate(RemoteInputState(tmp_path / "stop")),
        _security(),
    )

    result = worker.action(
        _action().selector.to_query(),
        UiaAction.INVOKE,
        None,
        UiaExecution(deadline=monotonic() + 5, cancelled=cancelled.is_set),
    )

    assert result.error_code == "operation_cancelled"
    assert backend.apply_calls == 0


@pytest.mark.security
def test_queued_action_observes_cancellation_before_mutation(tmp_path: Path) -> None:
    state = RemoteInputState(tmp_path / "stop")
    gate = DesktopMutationGate(state)
    entered = Event()
    release = Event()
    cancelled = Event()

    def hold_mutation_gate() -> None:
        def wait_for_release() -> None:
            _ = release.wait(5)

        gate.run(entered.set, wait_for_release)

    holder = Thread(target=hold_mutation_gate)
    holder.start()
    assert entered.wait(1)
    backend = SecurityBackend()
    worker = UiaWorker(backend, gate, _security())
    captured: list[UiaActionResult] = []
    queued = Thread(
        target=lambda: captured.append(
            worker.action(
                _action().selector.to_query(),
                UiaAction.INVOKE,
                None,
                UiaExecution(deadline=monotonic() + 5, cancelled=cancelled.is_set),
            )
        )
    )
    queued.start()
    cancelled.set()
    release.set()
    holder.join(2)
    queued.join(2)

    assert len(captured) == 1
    assert captured[0].error_code == "operation_cancelled"
    assert backend.apply_calls == 0


@pytest.mark.security
@pytest.mark.parametrize(
    ("security", "expected_code"),
    [
        (_security(secure=True), "secure_desktop_not_automatable"),
        (_security(worker_elevated=True), "worker_must_be_non_elevated"),
    ],
)
def test_secure_desktop_or_elevated_worker_is_rejected(
    tmp_path: Path, security: UiaSecurityProbes, expected_code: UiaErrorCode
) -> None:
    backend = SecurityBackend()
    worker = UiaWorker(
        backend,
        DesktopMutationGate(RemoteInputState(tmp_path / "stop")),
        security,
    )

    result = UiaTools(worker).uia_find(
        UiaFindInput(selector=UiaSelectorInput(control_type="Button"))
    )

    assert result.ok is False
    assert result.error_code == expected_code
    assert backend.apply_calls == 0
