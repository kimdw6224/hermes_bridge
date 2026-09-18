"""Worker task identity and rollback contracts without Task Scheduler mutation."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Final

PROJECT_ROOT: Final = Path(__file__).parents[2]
WORKER_SCRIPT: Final = PROJECT_ROOT / "scripts" / "register-worker-task.ps1"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None


def test_worker_task_accepts_short_principal_when_its_sid_matches_expected_identity() -> None:
    # Given: Task Scheduler normalizes the principal to a short local-account name.
    command = r"""
& {
    $expectedUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $shortUser = $expectedUser.Split('\')[-1]
    . $env:HERMES_TEST_WORKER_PATH -UserId $expectedUser -ExecutablePath python.exe | Out-Null
    $task = [pscustomobject]@{
        Actions = @(
            [pscustomobject]@{
                Execute = 'C:\bridge\pythonw.exe'
                Arguments = '-m hermes_windows_bridge.worker.main'
            }
        )
        Triggers = @(
            [pscustomobject]@{
                CimClass = [pscustomobject]@{ CimClassName = 'MSFT_TaskLogonTrigger' }
                UserId = $expectedUser
            }
        )
        Principal = [pscustomobject]@{
            UserId = $shortUser; LogonType = 'Interactive'; RunLevel = 'Limited'
        }
        Settings = [pscustomobject]@{
            Hidden = $true; RestartCount = 3; RestartInterval = 'PT1M'
        }
    }
    function Get-ScheduledTask { param() $task }
    Get-WorkerTaskDefinitionState -PythonPath 'C:\bridge\pythonw.exe'
}
"""
    environment = os.environ.copy()
    environment["HERMES_TEST_WORKER_PATH"] = str(WORKER_SCRIPT)

    # When: the readback helper sees the normalized principal through a mock only.
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    # Then: matching SID identities are desired, without a Task Scheduler API mutation.
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "desired"


def test_worker_task_remove_accepts_exact_legacy_console_definition() -> None:
    # Given: windowless 전환 전의 정확한 console Worker task 정의입니다.
    command = r"""
& {
    $expectedUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    . $env:HERMES_TEST_WORKER_PATH -UserId $expectedUser -ExecutablePath python.exe | Out-Null
    $task = [pscustomobject]@{
        Actions = @([pscustomobject]@{
            Execute = 'C:\bridge\python.exe'
            Arguments = '-m hermes_windows_bridge.worker.main'
        })
        Triggers = @([pscustomobject]@{
            CimClass = [pscustomobject]@{ CimClassName = 'MSFT_TaskLogonTrigger' }
            UserId = $expectedUser
        })
        Principal = [pscustomobject]@{
            UserId = $expectedUser; LogonType = 'Interactive'; RunLevel = 'Limited'
        }
        Settings = [pscustomobject]@{
            Hidden = $true; RestartCount = 3; RestartInterval = 'PT1M'
        }
    }
    function Get-ScheduledTask { param() $task }
    Get-WorkerTaskDefinitionState -PythonPath 'C:\bridge\pythonw.exe' `
        -LegacyPythonPath 'C:\bridge\python.exe'
}
"""
    environment = os.environ.copy()
    environment["HERMES_TEST_WORKER_PATH"] = str(WORKER_SCRIPT)

    # When: 제거 경로가 legacy executable을 명시해 정확한 정의를 비교합니다.
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    # Then: 다른 보안 필드가 모두 정확할 때만 제거 가능한 상태입니다.
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "desired"


def _run_worker_task_removal_fake(mode: str) -> subprocess.CompletedProcess[str]:
    assert mode in {"stops", "instance_unavailable", "stop_fails"}
    command = rf"""
& {{
    $userId = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    . $env:HERMES_TEST_WORKER_PATH -UserId $userId -ExecutablePath python.exe | Out-Null
    $mode = '{mode}'
    $events = [Collections.Generic.List[string]]::new()
    $script:query = 0; $script:present = $true
    function Stop-ScheduledTask {{
        [CmdletBinding()]
        param($TaskName, $TaskPath)
        $events.Add('stop')
        if ($mode -eq 'stop_fails') {{ throw 'fake-stop-failed' }}
    }}
    function Get-WorkerTaskStopState {{
        param($TaskName)
        $script:query++
        if ($mode -eq 'instance_unavailable' -and $script:query -gt 1) {{
            throw 'fake-state-unavailable'
        }}
        if ($mode -eq 'instance_unavailable') {{
            return [pscustomobject]@{{ runningInstanceCount = 1; state = 4 }}
        }}
        if ($script:query -eq 1) {{
            return [pscustomobject]@{{ runningInstanceCount = 1; state = 4 }}
        }}
        return [pscustomobject]@{{ runningInstanceCount = 0; state = 3 }}
    }}
    function Unregister-ScheduledTask {{
        [CmdletBinding(SupportsShouldProcess=$true)]
        param($TaskName, $TaskPath)
        $events.Add('unregister'); $script:present = $false
    }}
    function Get-ScheduledTask {{
        [CmdletBinding()]
        param($TaskName, $TaskPath)
        if ($script:present) {{ [pscustomobject]@{{}} }}
    }}
    $result = Remove-WorkerTaskAndVerifyAbsent -TaskName 'ExactTask'
    '{{0}}|{{1}}|{{2}}' -f ($events -join ','), $result.removed, $result.failureReason
}}
"""
    return subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={**os.environ, "HERMES_TEST_WORKER_PATH": str(WORKER_SCRIPT)},
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_worker_task_remove_stops_confirmed_instance_before_unregister() -> None:
    # Given: the exact task has one running instance before it becomes Ready.
    result = _run_worker_task_removal_fake("stops")

    # When: the adapter removes that exact desired task.
    # Then: stop precedes unregister and registration becomes absent.
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "stop,unregister|True|"


def test_worker_task_remove_refuses_unregister_when_stop_cannot_be_confirmed() -> None:
    # Given: Task Scheduler reports a running instance, then cannot be read back.
    result = _run_worker_task_removal_fake("instance_unavailable")

    # When: the adapter attempts removal.
    # Then: it fails closed without unregistering the task.
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "stop|False|task-instance-unverified"


def test_worker_task_remove_returns_structured_failure_when_stop_fails() -> None:
    # Given: the exact Task Scheduler stop call fails.
    result = _run_worker_task_removal_fake("stop_fails")

    # When: the adapter attempts removal.
    # Then: it reports the stop failure and leaves registration intact.
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "stop|False|task-stop-failed"


def test_worker_task_post_apply_failure_rolls_back_new_task_and_reports_rollback_failure() -> None:
    # Given: a post-registration readback can find a definition mismatch.
    source = WORKER_SCRIPT.read_text(encoding="utf-8")

    # When: the registration control flow is inspected without invoking it.
    # Then: only a newly-created task is unregistered and absence is checked before failure emits.
    assert "function Remove-WorkerTaskAndVerifyAbsent" in source
    assert "$manifest.rollback.attempted = $true" in source
    assert "post-apply-verification-failed-rollback-failed" in source
    assert "$manifest.receipt.after = if ($removed) { 'absent' } else { 'present' }" in source


def test_worker_task_fails_closed_when_account_sid_cannot_be_resolved() -> None:
    # Given: a principal account name that cannot resolve on the local machine.
    command = r"""
& {
    $expectedUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    . $env:HERMES_TEST_WORKER_PATH -UserId $expectedUser -ExecutablePath python.exe | Out-Null
    $unmappedAccount = '.\__HermesBridgeNeverMapped_0e13e7f2__'
    Test-SameWorkerAccount -ExpectedAccount $expectedUser -ActualAccount $unmappedAccount
}
"""
    environment = os.environ.copy()
    environment["HERMES_TEST_WORKER_PATH"] = str(WORKER_SCRIPT)

    # When: SID translation cannot establish identity equivalence.
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    # Then: the security comparison rejects it rather than falling back to text matching.
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"
