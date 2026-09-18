"""격리 Windows Sandbox 전용 service deployment harness 계약입니다."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import ClassVar, Final, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

PROJECT_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_ROOT: Final = PROJECT_ROOT / ".omo" / "evidence" / "service-protection-6-sandbox"
HARNESS_PATH: Final = EVIDENCE_ROOT / "run-task6.ps1"
CONFIG_PATH: Final = EVIDENCE_ROOT / "task6-service-qa.wsb"
POWERSHELL_PATH: Final = "powershell.exe"
NONCE = UUID("b67d9582-c0d8-47f0-8c8d-18c8610eefb1")
DEADLINE = "2099-01-01T00:00:00.0000000Z"


class HarnessReceipt(BaseModel):
    """PowerShell harness의 secret-free JSON refusal boundary입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    schema_version: int = Field(alias="schemaVersion")
    state: Literal["refused"]
    reason: str
    nonce: UUID
    deadline_utc: str = Field(alias="deadlineUtc")
    writes: int
    sandbox_launches: int = Field(alias="sandboxLaunches")
    service_operations: int = Field(alias="serviceOperations")


class CleanupReceiptContract(BaseModel):
    """Actual uninstall 후 exact identity cleanup receipt가 지켜야 할 불변식입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    exact_identities: tuple[str, ...] = Field(alias="exactIdentities")
    releases_preserved: bool = Field(alias="releasesPreserved")
    pointer_preserved: bool = Field(alias="pointerPreserved")
    host_packages_preserved: bool = Field(alias="hostPackagesPreserved")
    program_data_preserved: bool = Field(alias="programDataPreserved")


class TailscaleObservationContract(BaseModel):
    """전체 doctor를 fake하지 않는 named Tailscale observation fixture boundary입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    named_check_ids: tuple[Literal["tailscale"], ...] = Field(alias="namedCheckIds")
    external_tailscale_stubbed: Literal[True] = Field(alias="externalTailscaleStubbed")
    production_full_network_passed: Literal[False] = Field(alias="productionFullNetworkPassed")


class DeploymentScenario(BaseModel):
    """실행 전 정적으로 고정한 Task 6 lifecycle evidence manifest입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    schema_version: int = Field(alias="schemaVersion")
    required_environment: tuple[str, ...] = Field(alias="requiredEnvironment")
    fixed_identities: tuple[str, ...] = Field(alias="fixedIdentities")
    gateway_argv: tuple[str, ...] = Field(alias="gatewayArgv")
    privileged_argv: tuple[str, ...] = Field(alias="privilegedArgv")
    artifacts: tuple[str, ...]
    cleanup: CleanupReceiptContract
    tailscale_observation: TailscaleObservationContract = Field(alias="tailscaleObservation")
    doctor_when_tailscale_absent: Literal["unverified"] = Field(
        alias="doctorWhenTailscaleAbsent"
    )


def _run_harness(
    environment: dict[str, str], mode: Literal["ValidateOnly", "Execute"] = "ValidateOnly"
) -> HarnessReceipt:
    """Public validation-only entrypoint을 typed JSON boundary로 실행합니다."""
    result = subprocess.run(
        [
            POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(HARNESS_PATH),
            "-Mode",
            mode,
            "-Nonce",
            str(NONCE),
            "-DeadlineUtc",
            DEADLINE,
            "-ArtifactRoot",
            rf"C:\Task6Evidence\{NONCE}",
            "-BundleRoot",
            rf"C:\Task6Bundle\{NONCE}",
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 64, result.stderr
    receipt = HarnessReceipt.model_validate_json(result.stdout)
    assert receipt.schema_version == 1
    assert receipt.nonce == NONCE
    assert receipt.deadline_utc == DEADLINE
    assert receipt.writes == 0
    assert receipt.sandbox_launches == 0
    assert receipt.service_operations == 0
    return receipt


def test_deployment_harness_artifacts_exist() -> None:
    # Given: Task 6 integration entrypoint와 Windows Sandbox template입니다.
    # When: immutable preparation artifacts의 존재를 확인합니다.
    artifacts = (HARNESS_PATH, CONFIG_PATH)

    # Then: runtime scenario 전에 fail-closed preparation surface가 제공됩니다.
    assert all(artifact.is_file() for artifact in artifacts)


def test_deployment_harness_refuses_host_without_explicit_guest_marker() -> None:
    # Given: Sandbox guest marker를 제공하지 않은 현재 host process입니다.
    environment = os.environ.copy()
    _ = environment.pop("HERMES_TASK6_SANDBOX_GUEST", None)

    # When: validate-only harness entrypoint를 호출합니다.
    receipt = _run_harness(environment)

    # Then: host SCM/ACL/OCI/Tailscale/Sandbox 변경 없이 guest marker failure를 반환합니다.
    assert receipt.reason == "sandbox-guest-marker-missing"


def test_deployment_harness_refuses_guest_marker_with_mismatched_nonce() -> None:
    # Given: guest marker는 있으나 sandbox nonce가 invocation과 다른 fixture입니다.
    environment = os.environ.copy()
    environment.update(
        HERMES_TASK6_SANDBOX_GUEST="hermes-task6-isolated-guest-v1",
        HERMES_TASK6_SANDBOX_NONCE=str(UUID("2b1e6e45-7145-4ff4-8cbb-9d5474604196")),
        HERMES_TASK6_FIXED_IDENTITIES=(
            "HermesWindowsBridgeGateway,HermesWindowsBridgePrivileged,HermesWindowsBridgeWorker"
        ),
        HERMES_TASK6_SCENARIO_PREFIX="HermesTask6Sandbox-",
    )

    # When: same validation-only entrypoint를 호출합니다.
    receipt = _run_harness(environment)

    # Then: caller-provided nonce로 guest authority를 대체하지 않고 fail closed 합니다.
    assert receipt.reason == "sandbox-nonce-mismatch"


def test_deployment_harness_refuses_guest_without_explicit_admin_marker() -> None:
    # Given: nonce와 identity는 정확하지만 explicit administrator marker가 없는 guest fixture입니다.
    environment = os.environ.copy()
    environment.update(
        HERMES_TASK6_SANDBOX_GUEST="hermes-task6-isolated-guest-v1",
        HERMES_TASK6_SANDBOX_NONCE=str(NONCE),
        HERMES_TASK6_FIXED_IDENTITIES=(
            "HermesWindowsBridgeGateway,HermesWindowsBridgePrivileged,HermesWindowsBridgeWorker"
        ),
        HERMES_TASK6_SCENARIO_PREFIX="HermesTask6Sandbox-",
    )
    _ = environment.pop("HERMES_TASK6_SANDBOX_ADMIN", None)

    # When: same validation-only entrypoint를 호출합니다.
    receipt = _run_harness(environment)

    # Then: apparent guest context만으로 SCM mutation 권한을 가정하지 않습니다.
    assert receipt.reason == "sandbox-admin-marker-missing"


def test_deployment_harness_refuses_execute_until_task4_task5_acceptance_is_bound() -> None:
    # Given: guest/admin/identity/nonce가 맞지만 Task 4/5 수락 receipt가 없는 host입니다.
    environment = os.environ.copy()
    environment.update(
        HERMES_TASK6_SANDBOX_GUEST="hermes-task6-isolated-guest-v1",
        HERMES_TASK6_SANDBOX_ADMIN="explicit-admin-required",
        HERMES_TASK6_SANDBOX_NONCE=str(NONCE),
        HERMES_TASK6_FIXED_IDENTITIES=(
            "HermesWindowsBridgeGateway,HermesWindowsBridgePrivileged,HermesWindowsBridgeWorker"
        ),
        HERMES_TASK6_SCENARIO_PREFIX="HermesTask6Sandbox-",
    )

    # When: execution mode를 명시합니다.
    receipt = _run_harness(environment, mode="Execute")

    # Then: Sandbox launch·SCM/ACL/Tailscale/OCI·전원 변경 없이 acceptance gate를 거부합니다.
    assert receipt.reason in {
        "sandbox-administrator-required",
        "task4-task5-acceptance-gate-missing",
    }


def test_deployment_harness_template_disables_network_and_binds_fixed_cleanup_targets() -> None:
    # Given: actual lifecycle 실행 전 배포 Sandbox configuration과 harness source입니다.
    config = CONFIG_PATH.read_text(encoding="utf-8")
    harness = HARNESS_PATH.read_text(encoding="utf-8")

    # When: immutable config와 cleanup contract를 관찰합니다.
    expected_identity = (
        "HermesWindowsBridgeGateway,HermesWindowsBridgePrivileged,HermesWindowsBridgeWorker"
    )

    # Then: host mapping은 read-only이며 guest network와 cleanup target이 고정됩니다.
    assert "<Networking>Disable</Networking>" in config
    assert "<ReadOnly>true</ReadOnly>" in config
    assert "HERMES_TASK6_SANDBOX_GUEST=hermes-task6-isolated-guest-v1" in config
    assert expected_identity in harness
    assert "Get-BridgeTask6ExactCleanupReceipt" in harness
    assert "Install-Task6ProtectedDeployment" not in harness
    assert "Start-Service" not in harness
    assert "Set-Acl" not in harness


def test_deployment_scenario_binds_exact_argv_artifacts_and_unverified_doctor_outcome() -> None:
    # Given: Task 4/5 acceptance 뒤에만 실행될 immutable deployment scenario manifest입니다.
    scenario_path = EVIDENCE_ROOT / "task6-scenario-manifest.json"

    # When: JSON boundary를 Pydantic model로 해석합니다.
    scenario = DeploymentScenario.model_validate_json(scenario_path.read_text(encoding="utf-8"))

    # Then: fixed service argv, evidence path, cleanup, Tailscale-absent outcome이 고정됩니다.
    assert scenario.schema_version == 2
    assert scenario.required_environment == (
        "HERMES_TASK6_SANDBOX_GUEST",
        "HERMES_TASK6_SANDBOX_ADMIN",
        "HERMES_TASK6_SANDBOX_NONCE",
        "HERMES_TASK6_FIXED_IDENTITIES",
        "HERMES_TASK6_SCENARIO_PREFIX",
    )
    assert scenario.fixed_identities == (
        "HermesWindowsBridgeGateway",
        "HermesWindowsBridgePrivileged",
        "HermesWindowsBridgeWorker",
    )
    assert scenario.gateway_argv == (
        "<gatewayHostExecutable>",
        "--profile",
        "gateway",
    )
    assert scenario.privileged_argv == (
        "<privilegedHostExecutable>",
        "--profile",
        "privileged",
    )
    assert scenario.doctor_when_tailscale_absent == "unverified"
    assert "cleanup.json" in scenario.artifacts
    assert "uninstall-readback.json" in scenario.artifacts
    assert scenario.cleanup.exact_identities == scenario.fixed_identities
    assert scenario.cleanup.releases_preserved is True
    assert scenario.cleanup.pointer_preserved is True
    assert scenario.cleanup.host_packages_preserved is True
    assert scenario.cleanup.program_data_preserved is True
    assert scenario.tailscale_observation.named_check_ids == ("tailscale",)
    assert scenario.tailscale_observation.external_tailscale_stubbed is True
    assert scenario.tailscale_observation.production_full_network_passed is False
