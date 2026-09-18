"""Mock-safe Tailscale Serve transaction contracts for Task 21."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Final, Literal

import pytest
from pydantic import BaseModel, ConfigDict, Field

PROJECT_ROOT: Final = Path(__file__).parents[2]
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None
SERVE_HOST: Final = "bridge.example.ts.net"
type SimulationScenario = Literal[
    "Desired", "EmptyApply", "ApplyReadbackMismatch", "ConcurrentConflict"
]


@dataclass(frozen=True, slots=True)
class ConflictExpectation:
    """각 closed conflict fixture의 무변경 종료 상태입니다."""

    rollback_state: str
    bridge_only: bool


class ServeTransaction(BaseModel):
    """Serve Apply 직전과 실제 시도 여부를 기록합니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    initial_state: str = Field(alias="initialState")
    pre_apply_state: str = Field(alias="preApplyState")
    apply_attempted: bool = Field(alias="applyAttempted")
    would_apply: bool = Field(alias="wouldApply")


class ServeReadBack(BaseModel):
    """Apply 뒤 재읽기한 정확한 bridge-only 상태입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    performed: bool
    state: str
    exact: bool
    bridge_only: bool = Field(alias="bridgeOnly")


class ServeRollback(BaseModel):
    """재읽기 이후에만 허용되는 reset 판단 결과입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    inspected: bool
    eligible: bool
    attempted: bool
    succeeded: bool | None
    state: str


class TailscalePlan(BaseModel):
    """닫힌 simulator가 반환하는 Tailscale transaction 결과입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    mode: Literal["apply"]
    state: Literal["desired", "simulated", "apply-verification-conflict"]
    applied: bool
    atomic: bool | None = None
    external_calls: Literal[0] = Field(alias="externalCalls")
    simulation_scenario: SimulationScenario = Field(alias="simulationScenario")
    transaction: ServeTransaction
    read_back: ServeReadBack = Field(alias="readBack")
    rollback: ServeRollback
    bridge_only: bool = Field(alias="bridgeOnly")
    manual_action_required: bool = Field(alias="manualActionRequired")


class RollbackReceipt(BaseModel):
    """install transaction이 기록한 scoped rollback 결과입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    step: str
    state: str
    external_calls: Literal[0] = Field(alias="externalCalls")


class InstallSimulationPlan(BaseModel):
    """Tailscale transaction을 포함하는 install simulator 응답입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    mode: Literal["apply"]
    state: Literal["failed"]
    applied: Literal[False]
    atomic: bool
    external_calls: Literal[0] = Field(alias="externalCalls")
    tailscale_transaction: TailscalePlan = Field(alias="tailscaleTransaction")
    rollback: list[RollbackReceipt]


def _safe_environment(tmp_path: Path) -> dict[str, str]:
    """실제 사용자 runtime 경로를 pytest fixture로 격리합니다."""

    environment = os.environ.copy()
    environment["ProgramData"] = str(tmp_path / "program-data")
    environment["LOCALAPPDATA"] = str(tmp_path / "local-data")
    return environment


def _run_configure(
    scenario: SimulationScenario, environment: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    """실제 daemon 대신 fixed simulator를 통해 configure 경로를 실행합니다."""

    return subprocess.run(
        [
            POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(PROJECT_ROOT / "scripts" / "configure-tailscale.ps1"),
            "-ServeHost",
            SERVE_HOST,
            "-Apply",
            "-AdapterMode",
            "Simulate",
            "-SimulationScenario",
            scenario,
            "-Json",
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )


def _run_install_simulation(
    scenario: SimulationScenario, failure_step: str, environment: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    """정확한 readback 뒤의 설치 후속 실패 rollback만 실행합니다."""

    return subprocess.run(
        [
            POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(PROJECT_ROOT / "scripts" / "install.ps1"),
            "-Apply",
            "-AdapterMode",
            "Simulate",
            "-ConfigureTailscale",
            "-SimulationScenario",
            scenario,
            "-SimulationFailureStep",
            failure_step,
            "-ServeHost",
            SERVE_HOST,
            "-Json",
            "-ProgramDataRoot",
            environment["ProgramData"],
            "-LocalDataRoot",
            environment["LOCALAPPDATA"],
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )


def test_tailscale_desired_simulation_is_an_exact_noop(tmp_path: Path) -> None:
    # Given: 이미 exact bridge-only Serve 상태인 simulator와 빈 fixture입니다.
    environment = _safe_environment(tmp_path)

    # When: configure Apply 경로를 closed Desired fixture로 실행합니다.
    result = _run_configure("Desired", environment)

    # Then: apply 또는 rollback 없이 재읽기만 성공하고 실제 호출은 없습니다.
    plan = TailscalePlan.model_validate_json(result.stdout)
    assert result.returncode == 0
    assert not plan.applied
    assert plan.state == "desired"
    assert plan.external_calls == 0
    assert not plan.transaction.apply_attempted
    assert plan.read_back.exact
    assert plan.read_back.bridge_only
    assert not plan.rollback.attempted
    assert not plan.manual_action_required
    assert not any(tmp_path.iterdir())


def test_tailscale_empty_simulation_applies_then_reads_back_exactly(tmp_path: Path) -> None:
    # Given: initial Serve 상태가 empty인 simulator와 격리된 fixture입니다.
    environment = _safe_environment(tmp_path)

    # When: configure Apply 경로가 고정 bridge-only argv를 계획하고 실행합니다.
    result = _run_configure("EmptyApply", environment)

    # Then: simulated Apply 뒤 desired 상태가 exact하게 재읽히고 외부 호출은 없습니다.
    plan = TailscalePlan.model_validate_json(result.stdout)
    assert result.returncode == 0
    assert not plan.applied
    assert plan.state == "simulated"
    assert plan.external_calls == 0
    assert plan.transaction.initial_state == "empty"
    assert plan.transaction.apply_attempted
    assert plan.read_back.exact
    assert plan.read_back.bridge_only
    assert not plan.rollback.attempted
    assert not any(tmp_path.iterdir())


def test_install_resets_empty_bridge_only_serve_after_exact_readback(tmp_path: Path) -> None:
    # Given: EmptyApply가 exact readback을 마친 뒤 doctor에서 실패하도록 고정합니다.
    environment = _safe_environment(tmp_path)

    # When: install lifecycle Apply transaction이 후속 실패로 rollback합니다.
    result = _run_install_simulation("EmptyApply", "doctor", environment)

    # Then: inspected exact bridge-only 상태만 scoped reset합니다.
    # simulator fixture와 실제 daemon은 모두 변경하지 않습니다.
    plan = InstallSimulationPlan.model_validate_json(result.stdout)
    transaction = plan.tailscale_transaction
    assert result.returncode == 2
    assert plan.external_calls == 0
    assert transaction.external_calls == 0
    assert transaction.read_back.exact
    assert transaction.read_back.bridge_only
    assert transaction.rollback.inspected
    assert transaction.rollback.eligible
    assert transaction.rollback.attempted
    assert transaction.rollback.succeeded
    assert transaction.rollback.state == "empty"
    assert any(
        receipt.step == "tailscale_serve"
        and receipt.state == "rolled-back-to-empty"
        and receipt.external_calls == 0
        for receipt in plan.rollback
    )
    assert not any(tmp_path.iterdir())


@pytest.mark.parametrize(
    ("scenario", "failure_step", "expected"),
    [
        (
            "ApplyReadbackMismatch",
            "None",
            ConflictExpectation(rollback_state="unverified", bridge_only=True),
        ),
        (
            "ConcurrentConflict",
            "doctor",
            ConflictExpectation(rollback_state="conflict", bridge_only=False),
        ),
    ],
)
def test_tailscale_conflicting_readback_requires_manual_action_without_reset(
    tmp_path: Path,
    scenario: SimulationScenario,
    failure_step: str,
    expected: ConflictExpectation,
) -> None:
    # Given: Apply 뒤 상태가 불일치하거나 concurrent mapping인 고정 simulator입니다.
    environment = _safe_environment(tmp_path)

    # When: install lifecycle가 exact readback을 검증합니다.
    result = _run_install_simulation(scenario, failure_step, environment)

    # Then: reset을 하지 않고 manual action을 남기며 외부 상태는 변하지 않습니다.
    plan = InstallSimulationPlan.model_validate_json(result.stdout)
    transaction = plan.tailscale_transaction
    assert result.returncode == 2
    assert not plan.applied
    assert not plan.atomic
    assert plan.external_calls == 0
    assert transaction.external_calls == 0
    assert transaction.transaction.apply_attempted
    assert not transaction.read_back.exact
    assert transaction.bridge_only is expected.bridge_only
    assert not transaction.rollback.inspected
    assert not transaction.rollback.eligible
    assert not transaction.rollback.attempted
    assert transaction.rollback.state == expected.rollback_state
    assert transaction.manual_action_required
    assert not any(tmp_path.iterdir())
