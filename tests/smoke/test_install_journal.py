"""Installer transaction-journal resume contracts without a production Apply."""

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
INSTALL_SCRIPT: Final = PROJECT_ROOT / "scripts" / "install.ps1"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None


class InstallApplyPlan(BaseModel):
    """Only the stable failed-Apply fields relevant to journal recovery."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    state: Literal["blocked", "failed"]
    failure_reason: str | None = Field(alias="failureReason", default=None)


def _run_install(environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(INSTALL_SCRIPT),
            "-Apply",
            "-AdapterMode",
            "Simulate",
            "-SimulationFailureStep",
            "gateway_service",
            "-Json",
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )


@pytest.mark.parametrize(
    "unsafe_journal",
    [
        {"schemaVersion": 1, "status": "failed"},
        {"schemaVersion": 1, "status": "running"},
        {"schemaVersion": 1, "status": "rolled-back", "rollbackVerified": False},
        {"schemaVersion": 1},
    ],
)
def test_install_verified_rollback_journal_is_resumable_but_unverified_journal_blocks(
    tmp_path: Path,
    unsafe_journal: dict[str, bool | int | str],
) -> None:
    # Given: one journal toggled only between an explicit safe state and an unsafe state.
    environment = os.environ.copy()
    environment["ProgramData"] = str(tmp_path / "program-data")
    environment["LOCALAPPDATA"] = str(tmp_path / "local-data")
    state_path = (
        Path(environment["ProgramData"])
        / "HermesWindowsBridge"
        / "backups"
        / "install-fixture"
        / "state.json"
    )
    _ = state_path.parent.mkdir(parents=True)
    _ = state_path.write_text(
        json.dumps({"schemaVersion": 1, "status": "rolled-back", "rollbackVerified": True}),
        encoding="utf-8",
    )

    # When: the fixed no-op installer retries after each journal state.
    resumed = _run_install(environment)
    _ = state_path.write_text(json.dumps(unsafe_journal), encoding="utf-8")
    unsafe = _run_install(environment)

    # Then: verified rollback reaches the injected failure; all unverified states fail closed.
    resumed_plan = InstallApplyPlan.model_validate_json(resumed.stdout)
    unsafe_plan = InstallApplyPlan.model_validate_json(unsafe.stdout)
    assert resumed.returncode == unsafe.returncode == 2
    assert resumed_plan.state == "failed"
    assert unsafe_plan.state == "blocked"
    assert unsafe_plan.failure_reason == "interrupted-backup-state-requires-operator-review"


def test_install_writes_verified_rollback_status_only_after_rollback_outcomes() -> None:
    # Given: the production script is the only writer for real transaction journals.
    source = INSTALL_SCRIPT.read_text(encoding="utf-8")

    # When: its failure path is inspected without invoking SCM or Task Scheduler.
    rollback_outcomes = source.index("rollback-failed")
    terminal_journal = source.rindex("status = 'rolled-back'; rollbackVerified = $true")

    # Then: a retry-safe terminal state cannot be committed before rollback is evaluated.
    assert "schemaVersion = 1; status = 'failed'" not in source
    assert rollback_outcomes < terminal_journal


def test_install_requires_typed_clean_readback_before_legacy_journal_acknowledgement() -> None:
    # Given: acknowledgement is intentionally restricted to the production installer boundary.
    source = INSTALL_SCRIPT.read_text(encoding="utf-8")

    # When: the legacy failure branch is inspected without elevated service/task mutations.
    acknowledgement = source.index("AcknowledgeLegacyFailedRollback")
    clean_readback = source.index("Get-BridgeLegacyRollbackReadBack")
    safe_write = source.index("legacyFailureAcknowledgedUtc")

    # Then: the explicit switch, clean readback, and auditable safe state remain inseparable.
    assert "BridgeLegacyRollbackAcknowledgementRequiresElevatedProductionApply" in source
    assert "legacy-failed-backup-state-readback-unverified" in source
    assert acknowledgement < clean_readback < safe_write


def test_unreadable_backup_enumeration_fails_closed_without_breaking_what_if() -> None:
    # 비관리자 WhatIf는 제한 ACL 백업을 만나도 변경 없이 검토 필요 상태를 유지해야 합니다.
    source = INSTALL_SCRIPT.read_text(encoding="utf-8")

    enumeration = source.index("Get-ChildItem -LiteralPath $backupRoot -File -Recurse")
    catch = source.index("$unresolvedBackupState = $true", enumeration)

    assert source.rfind("try {", 0, enumeration) < enumeration < catch
