"""Task 21 lifecycle PowerShell CLI contracts.

All commands use WhatIf and per-test paths, so the scenarios cannot affect a
real installation, service, scheduled task, Tailscale state, or operator token.
"""

from __future__ import annotations

import hashlib
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
OLD_TOKEN: Final = hashlib.sha256(b"task-21-fixture").hexdigest()
INJECTION_MARKER: Final = "TASK_21_INJECTION_EXECUTED"


class LifecycleAction(BaseModel):
    """A machine-readable planned lifecycle operation."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    id: str
    planned: bool


class InstallPlan(BaseModel):
    """The approved dry-run installation boundary."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    mode: Literal["what-if"]
    applied: bool
    atomic: bool
    resume_safe: bool = Field(alias="resumeSafe")
    actions: list[LifecycleAction]
    backups: list[str]
    tailscale_serve_argv: list[str] = Field(alias="tailscaleServeArgv")
    recommended_grant: str = Field(alias="recommendedGrant")
    final_mcp_url: str = Field(alias="finalMcpUrl")
    hermes_config_snippet: str = Field(alias="hermesConfigSnippet")


class LifecyclePlan(BaseModel):
    """The common non-mutating lifecycle response shape."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    mode: Literal["what-if"]
    applied: bool
    atomic: bool
    resume_safe: bool = Field(alias="resumeSafe")
    actions: list[LifecycleAction]
    backups: list[str]


class RotationPlan(LifecyclePlan):
    """Token rotation output that deliberately exposes no token values."""

    oci_environment_instruction: str = Field(alias="ociEnvironmentInstruction")


class RegistrationPlan(BaseModel):
    """A service/task registration response without performing registration."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    mode: Literal["dry-run", "what-if"]
    applied: bool
    state: Literal["planned", "unchanged", "conflict"]
    account: str
    restart_on_failure: bool = Field(alias="restartOnFailure")
    apply_requires_administrator: bool = Field(alias="applyRequiresAdministrator")
    failure_reason: str | None = Field(alias="failureReason", default=None)


def _run_script(
    script_name: str,
    *arguments: str,
    environment: dict[str, str],
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


def _isolated_environment(tmp_path: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["ProgramData"] = str(tmp_path / f"program-data;{INJECTION_MARKER}")
    environment["LOCALAPPDATA"] = str(tmp_path / "local-app-data")
    return environment


def _tree_digest(root: Path) -> str:
    entries = tuple(
        f"{path.relative_to(root).as_posix()}:{hashlib.sha256(path.read_bytes()).hexdigest()}"
        for path in sorted(root.rglob("*"))
        if path.is_file()
    )
    return hashlib.sha256("\n".join(entries).encode()).hexdigest()


def test_install_whatif_plans_complete_secure_lifecycle_without_mutating_temp_roots(
    tmp_path: Path,
) -> None:
    # Given: stale interrupted backup and hostile path text in isolated runtime roots입니다.
    environment = _isolated_environment(tmp_path)
    stale_backup = tmp_path / "program-data;TASK_21_INJECTION_EXECUTED" / "backups" / "stale"
    _ = stale_backup.mkdir(parents=True)
    _ = (stale_backup / "receipt.json").write_text('{"interrupted":true}', encoding="utf-8")
    before = _tree_digest(tmp_path)

    # When: 선택 기능을 포함한 installer WhatIf를 실제 PowerShell CLI로 실행합니다.
    result = _run_script(
        "install.ps1",
        "-WhatIf",
        "-Json",
        "-ConfigureTailscale",
        "-InstallPlaywright",
        "-ProgramDataRoot",
        environment["ProgramData"],
        "-LocalDataRoot",
        environment["LOCALAPPDATA"],
        environment=environment,
    )

    # Then: 모든 의도된 lifecycle action을 구조적으로 계획하지만 fixture는 바꾸지 않습니다.
    plan = InstallPlan.model_validate_json(result.stdout)
    action_ids = {action.id for action in plan.actions if action.planned}
    assert result.returncode == 0
    assert plan.applied is False
    assert plan.atomic
    assert plan.resume_safe
    assert action_ids == {
        "dependencies",
        "token",
        "token_acl",
        "runtime_access",
        "gateway_service",
        "privileged_helper_service",
        "interactive_worker_task",
        "playwright_chromium",
        "tailscale_serve",
        "tailscale_grant",
        "hermes_config",
        "doctor",
        "backup_resume",
    }
    assert plan.backups
    assert "--accept-app-caps" in plan.tailscale_serve_argv
    assert all("funnel" not in argument.lower() for argument in plan.tailscale_serve_argv)
    assert plan.recommended_grant
    assert plan.final_mcp_url.startswith("https://")
    assert "HERMES_WINDOWS_BRIDGE_TOKEN" in plan.hermes_config_snippet
    assert INJECTION_MARKER not in result.stderr
    assert _tree_digest(tmp_path) == before


def test_uninstall_rotate_and_remote_input_whatif_preserve_temp_state_and_secret(
    tmp_path: Path,
) -> None:
    # Given: a test-only prior token, user data, emergency marker, and backup receipt입니다.
    environment = _isolated_environment(tmp_path)
    program_root = Path(environment["ProgramData"]) / "HermesWindowsBridge"
    local_root = Path(environment["LOCALAPPDATA"]) / "HermesWindowsBridge"
    token_path = program_root / "secrets" / "token"
    _ = token_path.parent.mkdir(parents=True)
    _ = token_path.write_text(OLD_TOKEN, encoding="utf-8")
    _ = (local_root / "browser-profile").mkdir(parents=True)
    marker = local_root / "remote-input.disabled"
    _ = marker.write_text("approved-local-reset-required", encoding="utf-8")
    before = _tree_digest(tmp_path)

    # When: destructive lifecycle operations are dry-run through their real CLI surface.
    uninstall = _run_script(
        "uninstall.ps1",
        "-WhatIf",
        "-Json",
        "-ProgramDataRoot",
        environment["ProgramData"],
        "-LocalDataRoot",
        environment["LOCALAPPDATA"],
        environment=environment,
    )
    rotate = _run_script(
        "rotate-token.ps1",
        "-WhatIf",
        "-Json",
        "-ProgramDataRoot",
        environment["ProgramData"],
        environment=environment,
    )
    remote_input = _run_script(
        "enable-remote-input.ps1",
        "-WhatIf",
        "-Json",
        "-LocalDataRoot",
        environment["LOCALAPPDATA"],
        environment=environment,
    )

    # Then: user data is gated, the OCI variable contract remains exact, and no state leaked.
    uninstall_plan = LifecyclePlan.model_validate_json(uninstall.stdout)
    rotation_plan = RotationPlan.model_validate_json(rotate.stdout)
    remote_input_plan = LifecyclePlan.model_validate_json(remote_input.stdout)
    assert uninstall.returncode == rotate.returncode == remote_input.returncode == 0
    assert all(not plan.applied for plan in (uninstall_plan, rotation_plan, remote_input_plan))
    assert "remove_user_data" not in {action.id for action in uninstall_plan.actions}
    assert "HERMES_WINDOWS_BRIDGE_TOKEN" in rotation_plan.oci_environment_instruction
    assert OLD_TOKEN not in rotate.stdout
    assert _tree_digest(tmp_path) == before


@pytest.mark.parametrize(
    ("script_name", "arguments", "expected_account"),
    [
        (
            "register-gateway-service.ps1",
            ("-ExecutablePath", "python.exe"),
            "NT AUTHORITY\\LocalService",
        ),
        ("register-privileged-service.ps1", ("-ExecutablePath", "python.exe"), "LocalSystem"),
        (
            "register-worker-task.ps1",
            ("-UserId", "Bridge.User", "-ExecutablePath", "python.exe"),
            "Bridge.User",
        ),
    ],
)
def test_registration_apply_is_admin_gated_recovery_ready_and_conflict_fail_closed(
    tmp_path: Path,
    script_name: str,
    arguments: tuple[str, ...],
    expected_account: str,
) -> None:
    # Given: a conflicting manifest whose JSON content would be dangerous only if evaluated.
    environment = _isolated_environment(tmp_path)
    manifest_path = tmp_path / f"{script_name}.json"
    injection_marker = tmp_path / f"{script_name}.injection"
    hostile_account = (
        "untrusted-account;"
        f"[IO.File]::WriteAllText('{injection_marker}', 'unexpected-execution')"
    )
    _ = manifest_path.write_text(json.dumps({"account": hostile_account}), encoding="utf-8")
    before = _tree_digest(tmp_path)

    # When: Apply receives a conflicting JSON definition through the real CLI.
    result = _run_script(
        script_name,
        "-Apply",
        "-Json",
        "-ExistingManifestPath",
        str(manifest_path),
        *arguments,
        environment=environment,
    )

    # Then: conflict validation precedes Apply, treats JSON as data, and leaves no side effect.
    plan = RegistrationPlan.model_validate_json(result.stdout)
    assert result.returncode == 2
    assert plan.state == "conflict"
    assert plan.account == expected_account
    assert plan.restart_on_failure
    assert plan.apply_requires_administrator
    assert plan.failure_reason == "definition-mismatch"
    assert not injection_marker.exists()
    assert _tree_digest(tmp_path) == before
