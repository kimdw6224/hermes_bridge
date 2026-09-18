"""Adversarial Task 21 lifecycle CLI contracts without live Apply operations."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import ClassVar, Final, Literal

import pytest
from pydantic import BaseModel, ConfigDict, Field

PROJECT_ROOT: Final = Path(__file__).parents[2]
SCRIPTS_ROOT: Final = PROJECT_ROOT / "scripts"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None


class PlannedAction(BaseModel):
    """A non-mutating lifecycle operation emitted by JSON CLI output."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    id: str
    planned: bool


class RegistrationDispatch(BaseModel):
    """A fixed no-op registration adapter dispatch record."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    adapter_mode: Literal["Production", "Simulate"] = Field(alias="adapterMode")
    operation: Literal["Register", "Remove"]
    typed_apis: list[str] = Field(alias="typedApis")
    argv: list[str]
    external_calls: Literal[0] = Field(alias="externalCalls")


class LifecyclePlan(BaseModel):
    """The stable lifecycle response envelope for adversarial scenarios."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    mode: str
    applied: bool
    resume_safe: bool | None = Field(alias="resumeSafe", default=None)
    actions: list[PlannedAction] = Field(default_factory=list)
    state: str | None = None
    failure_reason: str | None = Field(alias="failureReason", default=None)
    dispatch: RegistrationDispatch | None = None


def _environment(tmp_path: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["ProgramData"] = str(tmp_path / "program-data")
    environment["LOCALAPPDATA"] = str(tmp_path / "local-app-data")
    return environment


def _run(
    script_name: str, *arguments: str, environment: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(SCRIPTS_ROOT / script_name),
            *arguments,
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )


@pytest.mark.parametrize("script_name", ["install.ps1", "uninstall.ps1", "rotate-token.ps1"])
def test_lifecycle_rejects_relative_and_root_escape_overrides(
    tmp_path: Path, script_name: str
) -> None:
    # Given: paths that could otherwise escape an isolated root.
    environment = _environment(tmp_path)

    # When: malformed overrides are supplied to the real PowerShell CLI.
    relative = _run(
        script_name,
        "-WhatIf",
        "-Json",
        "-ProgramDataRoot",
        "relative-path",
        environment=environment,
    )
    escape = _run(
        script_name,
        "-WhatIf",
        "-Json",
        "-ProgramDataRoot",
        str(tmp_path / "isolated" / ".." / "escaped"),
        environment=environment,
    )

    # Then: validation fails before any system or fixture mutation.
    assert relative.returncode != 0
    assert escape.returncode != 0
    assert not (tmp_path / "escaped").exists()


def test_uninstall_remove_user_data_requires_explicit_whatif_gate(tmp_path: Path) -> None:
    # Given: a user-data root containing a preservation sentinel.
    environment = _environment(tmp_path)
    sentinel = Path(environment["LOCALAPPDATA"]) / "HermesWindowsBridge" / "keep.txt"
    _ = sentinel.parent.mkdir(parents=True)
    _ = sentinel.write_text("preserve", encoding="utf-8")

    # When: the default and explicitly gated uninstall plans are compared.
    default = _run("uninstall.ps1", "-WhatIf", "-Json", environment=environment)
    explicit = _run(
        "uninstall.ps1", "-WhatIf", "-Json", "-RemoveUserData", environment=environment
    )

    # Then: only explicit consent plans user data removal, while neither path applies it.
    default_plan = LifecyclePlan.model_validate_json(default.stdout)
    explicit_plan = LifecyclePlan.model_validate_json(explicit.stdout)
    assert default.returncode == explicit.returncode == 0
    assert "remove_user_data" not in {action.id for action in default_plan.actions}
    assert "remove_user_data" in {action.id for action in explicit_plan.actions}
    assert not default_plan.applied
    assert not explicit_plan.applied
    assert sentinel.read_text(encoding="utf-8") == "preserve"


def test_rotate_stale_backup_and_remote_marker_whatif_are_resume_safe(tmp_path: Path) -> None:
    # Given: an interrupted backup and an approved emergency marker in temp roots.
    environment = _environment(tmp_path)
    backup = Path(environment["ProgramData"]) / "HermesWindowsBridge" / "backups" / "interrupted"
    marker = Path(environment["LOCALAPPDATA"]) / "HermesWindowsBridge" / "remote-input.disabled"
    _ = backup.mkdir(parents=True)
    _ = (backup / "state.json").write_text(json.dumps({"interrupted": True}), encoding="utf-8")
    _ = marker.parent.mkdir(parents=True)
    _ = marker.write_text("approved", encoding="utf-8")

    # When: rotation and local reset are retried as WhatIf operations.
    rotation = _run("rotate-token.ps1", "-WhatIf", "-Json", environment=environment)
    reset_one = _run("enable-remote-input.ps1", "-WhatIf", "-Json", environment=environment)
    reset_two = _run("enable-remote-input.ps1", "-WhatIf", "-Json", environment=environment)

    # Then: both interrupted-state recovery and repeated reset planning remain non-mutating.
    rotation_plan = LifecyclePlan.model_validate_json(rotation.stdout)
    reset_plan_one = LifecyclePlan.model_validate_json(reset_one.stdout)
    reset_plan_two = LifecyclePlan.model_validate_json(reset_two.stdout)
    assert rotation.returncode == reset_one.returncode == reset_two.returncode == 0
    assert rotation_plan.resume_safe
    assert reset_plan_one == reset_plan_two
    assert not rotation_plan.applied
    assert not reset_plan_one.applied
    assert (backup / "state.json").exists()
    assert marker.exists()


def test_rotate_apply_with_missing_token_fails_closed_before_temp_root_mutation(
    tmp_path: Path,
) -> None:
    # Given: an isolated root with no token, so rotation has no valid replacement source.
    environment = _environment(tmp_path)
    sentinel = tmp_path / "unrelated-state.txt"
    _ = sentinel.write_text("unchanged", encoding="utf-8")
    before = sentinel.read_bytes()

    # When: Apply is explicitly requested without WhatIf through the real CLI.
    result = _run(
        "rotate-token.ps1",
        "-Apply",
        "-Json",
        "-ProgramDataRoot",
        environment["ProgramData"],
        environment=environment,
    )

    # Then: privilege or missing-token validation rejects the request before writes occur.
    plan = LifecyclePlan.model_validate_json(result.stdout)
    assert result.returncode == 2
    assert not plan.applied
    assert plan.state == "blocked"
    assert plan.failure_reason in {"administrator-required", "token-missing"}
    assert sentinel.read_bytes() == before


@pytest.mark.parametrize(
    ("script_name", "arguments", "expected_apis", "expected_argv"),
    [
        (
            "register-gateway-service.ps1",
            ("-ExecutablePath", "python.exe"),
            ("CreateServiceW", "ChangeServiceConfig2W", "DeleteService"),
            ("python.exe", "-I", "-B", "-m", "hermes_windows_bridge.gateway.windows_service"),
        ),
        (
            "register-gateway-service.ps1",
            ("-ExecutablePath", "python.exe", "-Operation", "Remove"),
            ("CreateServiceW", "ChangeServiceConfig2W", "DeleteService"),
            ("python.exe", "-I", "-B", "-m", "hermes_windows_bridge.gateway.windows_service"),
        ),
        (
            "register-privileged-service.ps1",
            ("-ExecutablePath", "python.exe"),
            ("Win32_Service.Create", "ChangeServiceConfig2W", "Win32_Service.Delete"),
            ("python.exe", "-I", "-B", "-m", "hermes_windows_bridge.privileged.main"),
        ),
        (
            "register-worker-task.ps1",
            ("-UserId", "Bridge.User", "-ExecutablePath", "python.exe"),
            (
                "New-ScheduledTaskAction",
                "New-ScheduledTaskTrigger",
                "New-ScheduledTaskPrincipal",
                "Register-ScheduledTask",
            ),
            ("pythonw.exe", "-m", "hermes_windows_bridge.worker.main"),
        ),
    ],
)
def test_registration_simulate_apply_dispatches_fixed_runtime_contract_without_mutation(
    tmp_path: Path,
    script_name: str,
    arguments: tuple[str, ...],
    expected_apis: tuple[str, ...],
    expected_argv: tuple[str, ...],
) -> None:
    # Given: empty pytest roots and no SCM or Task Scheduler handles.
    environment = _environment(tmp_path)

    # When: the explicit no-op adapter records the real CLI Apply dispatch.
    result = _run(
        script_name,
        "-Apply",
        "-Json",
        "-AdapterMode",
        "Simulate",
        *arguments,
        environment=environment,
    )

    # Then: the fixed API/module contract is observable but no external operation occurred.
    plan = LifecyclePlan.model_validate_json(result.stdout)
    assert result.returncode == 0
    assert not plan.applied
    assert plan.state == "simulated"
    assert plan.dispatch is not None
    assert plan.dispatch.operation == ("Remove" if "-Operation" in arguments else "Register")
    assert tuple(plan.dispatch.typed_apis) == expected_apis
    assert tuple(plan.dispatch.argv) == expected_argv
    assert plan.dispatch.external_calls == 0
    assert not any(tmp_path.iterdir())


@pytest.mark.parametrize(
    "arguments",
    [
        ("-Apply", "-WhatIf", "-AdapterMode", "Simulate"),
        ("-Apply", "-AdapterMode", "Invalid"),
        ("-Apply", "-AdapterMode", "Simulate", "-Operation", "Invalid"),
    ],
)
def test_registration_adapter_modes_reject_conflicting_or_malformed_apply_requests(
    tmp_path: Path, arguments: tuple[str, ...]
) -> None:
    # Given: a disposable root and invalid adapter controls.
    environment = _environment(tmp_path)

    # When: the gateway registration CLI receives an unsafe Apply combination.
    result = _run(
        "register-gateway-service.ps1", *arguments, "-Json", environment=environment
    )

    # Then: parameter/preference validation fails before any fixture or external mutation.
    assert result.returncode != 0
    assert not any(tmp_path.iterdir())


def test_registration_production_preflight_fails_closed_before_service_mutation(
    tmp_path: Path,
) -> None:
    # Given: an absent rooted python.exe path, which cannot reach an SCM operation.
    environment = _environment(tmp_path)
    missing_python = tmp_path / "missing-python.exe"

    # When: production Apply reaches only its administrator/runtime preflight.
    result = _run(
        "register-gateway-service.ps1",
        "-Apply",
        "-Json",
        "-AdapterMode",
        "Production",
        "-ExecutablePath",
        str(missing_python),
        environment=environment,
    )

    # Then: release authority rejects before administrator or executable fallback reaches SCM.
    plan = LifecyclePlan.model_validate_json(result.stdout)
    assert result.returncode == 3
    assert not plan.applied
    assert plan.failure_reason == "runtime-entrypoint-unverified"
    assert not any(tmp_path.iterdir())
