"""Task 6 QA harness의 fixture 경계 회귀를 검증합니다."""

# ruff: noqa: E501

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import ClassVar, Final

import pytest
from pydantic import BaseModel, ConfigDict, Field

PROJECT_ROOT: Final = Path(__file__).resolve().parents[2]
HARNESS_PATH: Final = (
    PROJECT_ROOT
    / ".omo"
    / "evidence"
    / "service-protection-6-sandbox"
    / "task6-guest-lifecycle-v2.ps1"
)
PREFLIGHT_PATH: Final = (
    PROJECT_ROOT
    / ".omo"
    / "evidence"
    / "service-protection-6-sandbox"
    / "task6-guest-preflight.ps1"
)
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
EVALUATION_UUID: Final = "00000000-0000-0000-0000-000000000001"
MISMATCHED_EVALUATION_UUID: Final = "00000000-0000-0000-0000-000000000002"
assert POWERSHELL_PATH is not None


class UninstallDispatch(BaseModel):
    """제어된 process boundary가 기록한 uninstall 호출입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    name: str
    file: str
    work: str


class DoctorDispatch(BaseModel):
    """제어된 process boundary가 기록한 doctor 호출입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    arguments: tuple[str, ...]


class SafeLifecycleFailure(BaseModel):
    """검증된 EvaluationVm lifecycle 실패 receipt의 공개 계약입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_name=True,
    )

    schema_version: int = Field(
        validation_alias="schemaVersion",
        serialization_alias="schemaVersion",
    )
    state: str
    reason: str
    nonce: str
    execution_stage: str = Field(
        validation_alias="executionStage",
        serialization_alias="executionStage",
    )
    error_identifier: str = Field(
        validation_alias="errorIdentifier",
        serialization_alias="errorIdentifier",
    )
    exception_type: str = Field(
        validation_alias="exceptionType",
        serialization_alias="exceptionType",
    )
    hresult: int
    receipt_persisted: bool = Field(
        validation_alias="receiptPersisted",
        serialization_alias="receiptPersisted",
    )


def test_uninstall_dispatch_uses_original_source_checkout() -> None:
    """업그레이드 fixture가 아닌 설치 Worker의 원본 checkout으로 제거를 실행합니다."""
    source_root = r"C:\HermesTask6\nonce\source"
    upgrade_root = r"C:\HermesTask6\nonce\upgrade-fixture"
    command = r"""
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_HARNESS,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -ne 0) { throw 'HarnessParseFailed' }
$dispatch = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Extent.Text -match '(?s)^\$uninstall\s*=\s*Invoke-Task6Process'
}, $true)
if ($null -eq $dispatch) { throw 'UninstallDispatchMissing' }
function Invoke-Task6Process {
    param($Name, $File, $Work, $ChildPath, $ArgumentList)
    $global:captured = [pscustomobject]@{
        name = $Name
        file = $File
        work = $Work
    }
    return [pscustomobject]@{
        receipt = [pscustomobject]@{ exitCode = 0 }
        stdout = 'controlled-result'
    }
}
$sourceRoot = $env:HERMES_QA_SOURCE_ROOT
$upgradeRoot = $env:HERMES_QA_UPGRADE_ROOT
$childPath = 'controlled-child-path'
& ([scriptblock]::Create($dispatch.Extent.Text))
$global:captured | ConvertTo-Json -Compress
"""
    environment = os.environ.copy()
    environment.update(
        HERMES_QA_HARNESS=str(HARNESS_PATH),
        HERMES_QA_SOURCE_ROOT=source_root,
        HERMES_QA_UPGRADE_ROOT=upgrade_root,
    )

    # Given: 실제 AST에서 추출한 uninstall dispatch와 제어된 process boundary입니다.
    # When: dispatch를 실행합니다.
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    # Then: installed Worker가 가리키는 원본 checkout에서 uninstall이 실행됩니다.
    assert result.returncode == 0, result.stderr
    dispatch = UninstallDispatch.model_validate_json(result.stdout)
    assert dispatch.name == "uninstall"
    assert dispatch.file == rf"{source_root}\scripts\uninstall.ps1"
    assert dispatch.work == source_root
    assert upgrade_root not in result.stdout


def test_doctor_dispatch_supplies_task6_serve_host() -> None:
    """보호된 Gateway doctor는 fixture의 정확한 Serve host로 bearer probe를 구성합니다."""
    upgrade_root = r"C:\HermesTask6\nonce\upgrade-fixture"
    release_root = r"C:\Program Files\HermesWindowsBridge\releases\a"
    serve_host = "task6-sandbox.ts.net"
    command = r"""
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_HARNESS,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -ne 0) { throw 'HarnessParseFailed' }
$dispatch = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Extent.Text -match '(?s)^\$doctor\s*=\s*Invoke-Task6Process'
}, $true)
if ($null -eq $dispatch) { throw 'DoctorDispatchMissing' }
function Invoke-Task6Process {
    param($Name, $File, $Work, $ChildPath, $ArgumentList)
    $global:captured = [pscustomobject]@{ arguments = @($ArgumentList) }
    return [pscustomobject]@{
        receipt = [pscustomobject]@{ exitCode = 0 }
        stdout = 'controlled-result'
    }
}
function Get-Task6HostInstallArguments { param($Contracts) return @() }
$upgradeRoot = $env:HERMES_QA_UPGRADE_ROOT
$childPath = 'controlled-child-path'
$task6ServeHost = $env:HERMES_QA_SERVE_HOST
$upgrade = [pscustomobject]@{ releaseRoot = $env:HERMES_QA_RELEASE_ROOT }
$upgradeHosts = $null
$doctorArguments = @('-Json','-Security','-ServiceReleaseRoot',$upgrade.releaseRoot,'-ServeHost',$task6ServeHost)
& ([scriptblock]::Create($dispatch.Extent.Text))
$global:captured | ConvertTo-Json -Compress
"""
    environment = os.environ.copy()
    environment.update(
        HERMES_QA_HARNESS=str(HARNESS_PATH),
        HERMES_QA_UPGRADE_ROOT=upgrade_root,
        HERMES_QA_RELEASE_ROOT=release_root,
        HERMES_QA_SERVE_HOST=serve_host,
    )

    # Given: 실제 AST에서 추출한 doctor dispatch와 제어된 process boundary입니다.
    # When: dispatch를 실행합니다.
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    # Then: doctor가 capability-보호 Gateway의 정확한 Serve host를 probe로 전달합니다.
    assert result.returncode == 0, result.stderr
    dispatch = DoctorDispatch.model_validate_json(result.stdout)
    assert dispatch.arguments == (
        "-Json",
        "-Security",
        "-ServiceReleaseRoot",
        release_root,
        "-ServeHost",
        serve_host,
    )


@pytest.mark.parametrize(
    ("current_state", "current_executable", "expected_output"),
    [
        ("Running", r"C:\source\.venv\Scripts\pythonw.exe", "passed"),
        ("Ready", r"C:\source\.venv\Scripts\pythonw.exe", "Task6UpgradeWorkerNotRunning"),
        ("Running", r"C:\source\.venv\Scripts\python.exe", "Task6UpgradeWorkerDefinitionInvalid"),
    ],
)
def test_lifecycle_worker_readback_requires_windowless_running_definition(
    current_state: str,
    current_executable: str,
    expected_output: str,
) -> None:
    """실행 상태는 현재 관측하고, baseline에는 windowless 등록 정의만 비교합니다."""
    command = r"""
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_HARNESS,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -ne 0) { throw 'HarnessParseFailed' }
foreach ($name in 'Get-Task6WorkerDefinition', 'Assert-Task6RegisteredReadback') {
    $definition = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true) | Select-Object -First 1
    if ($null -eq $definition) { throw ('FunctionMissing:' + $name) }
    . ([scriptblock]::Create($definition.Extent.Text))
}
function New-Worker([string]$state, [string]$executable, [int]$lastTaskResult) {
    return [pscustomobject]@{
        userId = 'EVAL\HermesEvalQA'; principalSid = 'S-1-5-21-100'; runLevel = 'Limited'
        logonType = 'InteractiveToken'; state = $state; lastTaskResult = $lastTaskResult
        actions = @([pscustomobject]@{
            execute = $executable; arguments = '-m hermes_windows_bridge.worker.main'
        })
        triggers = @([pscustomobject]@{
            userId = 'EVAL\HermesEvalQA'; sid = 'S-1-5-21-100'
            className = 'MSFT_TaskLogonTrigger'
        })
    }
}
$services = @(
    [pscustomobject]@{
        name = 'HermesWindowsBridgeGateway'
        pathName = ('"C:\Program Files\HermesWindowsBridge\releases\a\venv\Scripts\python.exe" ' +
            '-I -B -m hermes_windows_bridge.gateway.windows_service')
        startName = 'NT AUTHORITY\LocalService'; state = 'Running'; startMode = 'Auto'
    },
    [pscustomobject]@{
        name = 'HermesWindowsBridgePrivileged'
        pathName = ('"C:\Program Files\HermesWindowsBridge\releases\a\venv\Scripts\python.exe" ' +
            '-I -B -m hermes_windows_bridge.privileged.main')
        startName = 'LocalSystem'; state = 'Running'; startMode = 'Auto'
    }
)
$current = New-Worker $env:HERMES_QA_CURRENT_STATE $env:HERMES_QA_CURRENT_EXECUTABLE 0
$baseline = New-Worker 'Ready' 'C:\source\.venv\Scripts\pythonw.exe' 267009
$readback = [pscustomobject]@{
    services = $services; currentUser = [pscustomobject]@{ sid = 'S-1-5-21-100' }
    worker = $current
}
try {
    Assert-Task6RegisteredReadback -Readback $readback `
        -ReleaseRoot 'C:\Program Files\HermesWindowsBridge\releases\a' `
        -WorkerPython 'C:\source\.venv\Scripts\pythonw.exe' `
        -WorkerBaseline $baseline -Stage 'Upgrade'
    'passed'
} catch {
    $_.Exception.Message
}
"""
    environment = os.environ.copy()
    environment.update(
        HERMES_QA_HARNESS=str(HARNESS_PATH),
        HERMES_QA_CURRENT_STATE=current_state,
        HERMES_QA_CURRENT_EXECUTABLE=current_executable,
    )

    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected_output


@pytest.mark.parametrize(
    ("bad_child", "expected_output"),
    [("false", "passed"), ("true", "Task6HostReadbackHostChildDefinitionInvalid")],
)
def test_host_readback_requires_exact_scm_host_and_live_child_chain(
    bad_child: str, expected_output: str
) -> None:
    """host QA mode는 SCM argv와 실행 중인 host→Python child 계보를 함께 고정합니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_HARNESS, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) { throw 'HarnessParseFailed' }
foreach ($name in 'Get-Task6WorkerDefinition', 'Assert-Task6RegisteredReadback') {
    $definition = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $true) | Select-Object -First 1
    if ($null -eq $definition) { throw ('FunctionMissing:' + $name) }
    . ([scriptblock]::Create($definition.Extent.Text))
}
$release = 'C:\Program Files\HermesWindowsBridge\releases\a'
$python = Join-Path $release 'venv\Scripts\python.exe'
$contracts = @{
    gateway = [pscustomobject]@{ hostExecutable = 'C:\Program Files\HermesWindowsBridge\hosts\gateway\HermesBridge.ServiceHost.exe' }
    privileged = [pscustomobject]@{ hostExecutable = 'C:\Program Files\HermesWindowsBridge\hosts\privileged\HermesBridge.ServiceHost.exe' }
}
function New-ServiceReadback([string]$name, [string]$profile, [string]$account, [int]$servicePid) {
    $hostExecutable = [string]$contracts[$profile].hostExecutable
    $childExecutable = if ($env:HERMES_QA_BAD_CHILD -ceq 'true' -and $profile -ceq 'gateway') { 'C:\wrong\python.exe' } else { $python }
    return [pscustomobject]@{
        name = $name; pathName = ('"{0}" --profile {1}' -f $hostExecutable, $profile)
        startName = $account; state = 'Running'; startMode = 'Auto'; processId = $servicePid
        hostProcess = [pscustomobject]@{ processId = $servicePid; executablePath = $hostExecutable; commandLine = ('"{0}" --profile {1}' -f $hostExecutable, $profile) }
        childProcesses = @([pscustomobject]@{ processId = $servicePid + 100; parentProcessId = $servicePid; executablePath = $childExecutable; commandLine = ('"{0}" -I -B -m hermes_windows_bridge.service_child --profile {1}' -f $python, $profile) })
    }
}
$worker = [pscustomobject]@{
    userId = 'EVAL\HermesEvalQA'; principalSid = 'S-1-5-21-100'; runLevel = 'Limited'; logonType = 'InteractiveToken'; state = 'Running'; lastTaskResult = 0
    actions = @([pscustomobject]@{ execute = 'C:\source\.venv\Scripts\pythonw.exe'; arguments = '-m hermes_windows_bridge.worker.main' })
    triggers = @([pscustomobject]@{ userId = 'EVAL\HermesEvalQA'; sid = 'S-1-5-21-100'; className = 'MSFT_TaskLogonTrigger' })
}
$gatewayReadback = New-ServiceReadback 'HermesWindowsBridgeGateway' 'gateway' 'NT AUTHORITY\LocalService' 4100
$privilegedReadback = New-ServiceReadback 'HermesWindowsBridgePrivileged' 'privileged' 'LocalSystem' 4200
$readback = [pscustomobject]@{
    services = @($gatewayReadback, $privilegedReadback)
    currentUser = [pscustomobject]@{ sid = 'S-1-5-21-100' }; worker = $worker
}
try {
    Assert-Task6RegisteredReadback -Readback $readback -ReleaseRoot $release `
        -WorkerPython 'C:\source\.venv\Scripts\pythonw.exe' -WorkerBaseline $null `
        -Stage 'HostReadback' -HostContracts $contracts
    'passed'
} catch { $_.Exception.Message }
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={**os.environ, "HERMES_QA_HARNESS": str(HARNESS_PATH), "HERMES_QA_BAD_CHILD": bad_child},
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected_output


@pytest.mark.parametrize(
    ("host_qa_mode", "expected_output"),
    [("true", "True"), ("false", "False"), ('"true"', "Task6HostQaModeInvalid")],
)
def test_host_qa_mode_is_explicitly_typed_in_immutable_binding(
    tmp_path: Path, host_qa_mode: str, expected_output: str
) -> None:
    """기존 binding의 implicit legacy 동작은 보존하고 host QA는 Boolean true만 허용합니다."""
    binding = tmp_path / "task6-input-binding.json"
    _ = binding.write_text('{"hostQaMode":' + host_qa_mode + "}", encoding="utf-8")
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_HARNESS, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) { throw 'HarnessParseFailed' }
$definition = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-Task6HostQaMode'
}, $true) | Select-Object -First 1
if ($null -eq $definition) { throw 'HostQaModeFunctionMissing' }
. ([scriptblock]::Create($definition.Extent.Text))
try { [string](Get-Task6HostQaMode -Binding (Get-Content -LiteralPath $env:HERMES_QA_BINDING -Raw | ConvertFrom-Json)) }
catch { $_.Exception.Message }
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={**os.environ, "HERMES_QA_HARNESS": str(HARNESS_PATH), "HERMES_QA_BINDING": str(binding)},
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected_output


@pytest.mark.parametrize(
    ("script_path", "environment_kind", "expected_uuid", "observed_uuid", "expected_output"),
    [
        (PREFLIGHT_PATH, "Sandbox", "", "", "passed"),
        (HARNESS_PATH, "Sandbox", "", "", "passed"),
        (
            PREFLIGHT_PATH,
            "EvaluationVm",
            "",
            EVALUATION_UUID,
            "Task6EvaluationVmIdentityRequired",
        ),
        (
            HARNESS_PATH,
            "EvaluationVm",
            "",
            EVALUATION_UUID,
            "Task6EvaluationVmIdentityRequired",
        ),
        (
            PREFLIGHT_PATH,
            "EvaluationVm",
            EVALUATION_UUID,
            MISMATCHED_EVALUATION_UUID,
            "Task6EvaluationVmIdentityMismatch",
        ),
        (
            HARNESS_PATH,
            "EvaluationVm",
            EVALUATION_UUID,
            MISMATCHED_EVALUATION_UUID,
            "Task6EvaluationVmIdentityMismatch",
        ),
        (PREFLIGHT_PATH, "EvaluationVm", EVALUATION_UUID, EVALUATION_UUID, "passed"),
        (HARNESS_PATH, "EvaluationVm", EVALUATION_UUID, EVALUATION_UUID, "passed"),
    ],
)
def test_guest_environment_guard_preserves_sandbox_and_requires_evaluation_identity(
    script_path: Path,
    environment_kind: str,
    expected_uuid: str,
    observed_uuid: str,
    expected_output: str,
) -> None:
    """두 guest 진입점은 Sandbox 기본 계약과 평가 VM의 실측 UUID gate를 동일하게 적용합니다."""
    command = r"""
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_GUEST_SCRIPT,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -ne 0) { throw 'GuestScriptParseFailed' }
foreach ($name in 'Assert-Task6EvaluationVmRoots', 'Assert-Task6GuestBoundary') {
    $definition = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true) | Select-Object -First 1
    if ($null -eq $definition) { throw ('GuestBoundaryFunctionMissing:' + $name) }
    . ([scriptblock]::Create($definition.Extent.Text))
}
function Test-Task6Admin { return $true }
function Test-Task6Administrator { return $true }
function Get-CimInstance {
    return [pscustomobject]@{
        Vendor = 'Microsoft Corporation'; Name = 'Virtual Machine'
        UUID = $env:HERMES_QA_OBSERVED_UUID
    }
}
$Nonce = [guid]'00000000-0000-0000-0000-000000000099'
$identities = 'HermesWindowsBridgeGateway,HermesWindowsBridgePrivileged,HermesWindowsBridgeWorker'
$fixedIdentities = $identities
$EnvironmentKind = $env:HERMES_QA_ENVIRONMENT_KIND
$evaluationBase = Join-Path 'C:\HermesTask6' $Nonce.Guid
$InputRoot = if ($EnvironmentKind -ceq 'EvaluationVm') {
    Join-Path $evaluationBase 'input'
} else {
    ''
}
$OutputRoot = if ($EnvironmentKind -ceq 'EvaluationVm') {
    Join-Path $evaluationBase 'output'
} else {
    ''
}
$GuestRoot = if ($EnvironmentKind -ceq 'EvaluationVm') {
    Join-Path $evaluationBase 'work'
} else {
    ''
}
$task6InputRoot = $InputRoot
$task6OutputRoot = $OutputRoot
$task6GuestRoot = $GuestRoot
$ExpectedGuestUuid = if ([string]::IsNullOrWhiteSpace($env:HERMES_QA_EXPECTED_UUID)) {
    [guid]::Empty
} else {
    [guid]$env:HERMES_QA_EXPECTED_UUID
}
$HostDirectVmBinding = if ($EnvironmentKind -ceq 'EvaluationVm') {
    'host-direct-exact-vm-bound'
} else {
    ''
}
$InteractiveTokenClassification = if ($EnvironmentKind -ceq 'EvaluationVm') {
    'verified'
} else {
    ''
}
if ($EnvironmentKind -ceq 'Sandbox') {
    $env:HERMES_TASK6_SANDBOX_GUEST = 'hermes-task6-isolated-guest-v1'
    $env:HERMES_TASK6_SANDBOX_NONCE = $Nonce.Guid
    $env:HERMES_TASK6_FIXED_IDENTITIES = $identities
    $env:HERMES_TASK6_SCENARIO_PREFIX = 'HermesTask6Sandbox-'
} else {
    Remove-Item Env:HERMES_TASK6_SANDBOX_GUEST,Env:HERMES_TASK6_SANDBOX_NONCE `
        -ErrorAction SilentlyContinue
    Remove-Item Env:HERMES_TASK6_FIXED_IDENTITIES,Env:HERMES_TASK6_SCENARIO_PREFIX `
        -ErrorAction SilentlyContinue
}
try { Assert-Task6GuestBoundary; 'passed' } catch { $_.Exception.Message }
"""
    environment = os.environ.copy()
    environment.update(
        HERMES_QA_GUEST_SCRIPT=str(script_path),
        HERMES_QA_ENVIRONMENT_KIND=environment_kind,
        HERMES_QA_EXPECTED_UUID=expected_uuid,
        HERMES_QA_OBSERVED_UUID=observed_uuid,
    )

    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected_output


@pytest.mark.parametrize("script_path", [PREFLIGHT_PATH, HARNESS_PATH])
def test_evaluation_vm_bad_roots_do_not_create_or_follow_supplied_output_root(
    script_path: Path,
    tmp_path: Path,
) -> None:
    """EvaluationVm gate 실패는 caller 제공 output root를 만들거나 receipt로 쓰지 않습니다."""
    outside_output = tmp_path / "outside-output"
    result = subprocess.run(
        [
            POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(script_path),
            "-Nonce",
            "00000000-0000-0000-0000-000000000099",
            "-DeadlineUtc",
            "2099-01-01T00:00:00.0000000Z",
            "-EnvironmentKind",
            "EvaluationVm",
            "-OutputRoot",
            str(outside_output),
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 2
    assert not outside_output.exists()
    assert "evaluation-vm-guard-rejected" in result.stdout


@pytest.mark.parametrize("script_path", [PREFLIGHT_PATH, HARNESS_PATH])
def test_evaluation_vm_expired_deadline_does_not_create_output_root(
    script_path: Path,
    tmp_path: Path,
) -> None:
    """만료된 EvaluationVm 입력은 guest 경계나 출력 디렉터리를 건드리지 않고 거부합니다."""
    outside_output = tmp_path / "expired-output"
    result = subprocess.run(
        [
            POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(script_path),
            "-Nonce",
            "00000000-0000-0000-0000-000000000099",
            "-DeadlineUtc",
            "2000-01-01T00:00:00.0000000Z",
            "-EnvironmentKind",
            "EvaluationVm",
            "-OutputRoot",
            str(outside_output),
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 2
    assert not outside_output.exists()
    assert '"exceptionType":"TimeoutException"' in result.stdout
    assert "evaluation-vm-guard-rejected" in result.stdout


@pytest.mark.parametrize(
    ("guard_verified", "roots_valid", "execution_stage"),
    [
        ("true", "true", "upgrade_dispatch"),
        ("true", "true", "upgrade_wait"),
        ("true", "false", "upgrade_dispatch"),
        ("false", "true", "upgrade_dispatch"),
    ],
)
def test_evaluation_vm_lifecycle_failure_saves_only_post_guard_safe_receipt(
    guard_verified: str,
    roots_valid: str,
    execution_stage: str,
) -> None:
    """EvaluationVm 실패는 검증 뒤에만 raw 예외 없이 결과 receipt를 남깁니다."""
    command = r"""
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_HARNESS,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -ne 0) { throw 'HarnessParseFailed' }
$catch = @($ast.FindAll({
    param($node)
    $node.GetType().Name -ceq 'CatchClauseAst' -and
        $node.Body.Extent.Text -match 'evaluation-vm-execution-failed'
}, $true)) | Select-Object -First 1
if ($null -eq $catch) { throw 'LifecycleCatchMissing' }
$EnvironmentKind = 'EvaluationVm'
$Nonce = [guid]'00000000-0000-0000-0000-000000000099'
$task6OutputRoot = $env:TEMP
$script:Task6EvaluationGuardVerified = [bool]::Parse($env:HERMES_QA_GUARD_VERIFIED)
$script:Task6ExecutionStage = $env:HERMES_QA_EXECUTION_STAGE
function Save-Task6Json {
    param($Name, $Value)
    'SAVE:' + $Name + ':' + ($Value | ConvertTo-Json -Compress)
}
function Assert-Task6EvaluationVmRoots {
    if ($env:HERMES_QA_ROOTS_VALID -cne 'true') { throw 'revalidation_rejected' }
}
$wrapper = (
    'try { throw [InvalidOperationException]::new(''sentinel-not-for-receipt'') } catch ' +
    $catch.Body.Extent.Text
)
& ([scriptblock]::Create($wrapper))
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={
            **os.environ,
            "HERMES_QA_HARNESS": str(HARNESS_PATH),
            "HERMES_QA_GUARD_VERIFIED": guard_verified,
            "HERMES_QA_ROOTS_VALID": roots_valid,
            "HERMES_QA_EXECUTION_STAGE": execution_stage,
        },
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 2
    lines = result.stdout.splitlines()
    saved = [line for line in lines if line.startswith("SAVE:")]
    expected_save = guard_verified == "true" and roots_valid == "true"
    assert bool(saved) is expected_save
    assert "sentinel-not-for-receipt" not in result.stdout
    expected_failure = SafeLifecycleFailure(
        schema_version=1,
        state="failed",
        reason=(
            "evaluation-vm-execution-failed"
            if guard_verified == "true"
            else "evaluation-vm-guard-rejected"
        ),
        nonce="00000000-0000-0000-0000-000000000099",
        execution_stage=execution_stage,
        error_identifier="unclassified",
        exception_type="InvalidOperationException",
        hresult=-2146233079,
        receipt_persisted=expected_save,
    )
    assert SafeLifecycleFailure.model_validate_json(lines[-1]) == expected_failure
    if expected_save:
        assert len(saved) == 1
        assert saved[0].startswith("SAVE:task6-result.json:")
        saved_receipt = SafeLifecycleFailure.model_validate_json(saved[0].split(":", 2)[2])
        assert saved_receipt == expected_failure
    elif guard_verified == "true":
        assert "Task6FailureReceiptNotPersisted" in result.stdout


def test_upgrade_process_wait_stage_is_recorded_by_actual_ast_function(
    tmp_path: Path,
) -> None:
    """upgrade child가 시작된 뒤 실패하면 dispatch가 아닌 wait stage를 기록합니다."""
    command = r"""
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_HARNESS,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -ne 0) { throw 'HarnessParseFailed' }
$definition = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Invoke-Task6Process'
}, $true)
if ($null -eq $definition) { throw 'Task6ProcessFunctionMissing' }
. ([scriptblock]::Create($definition.Extent.Text))
$task6OutputRoot = $env:HERMES_QA_OUTPUT_ROOT
$script:Task6Deadline = [DateTime]::UtcNow.AddSeconds(30)
$script:Task6ExecutionStage = 'upgrade_dispatch'
$env:HERMES_TASK6_TAILSCALE_LOG = Join-Path $task6OutputRoot 'tailscale.jsonl'
function Save-Task6Json { param($Name, $Value) }
Invoke-Task6Process -Name 'upgrade' -File 'powershell.exe' `
    -ArgumentList @('-NoProfile','-NonInteractive','-Command','exit 0') `
    -Work $env:TEMP -ChildPath $env:Path -WaitStage 'upgrade_wait' | Out-Null
[string]$script:Task6ExecutionStage
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={
            **os.environ,
            "HERMES_QA_HARNESS": str(HARNESS_PATH),
            "HERMES_QA_OUTPUT_ROOT": str(tmp_path),
        },
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "upgrade_wait"


@pytest.mark.parametrize("script_path", [PREFLIGHT_PATH, HARNESS_PATH])
def test_evaluation_vm_guard_rejects_existing_reparse_endpoint(script_path: Path) -> None:
    """고정 nonce root여도 existing input/output/work endpoint junction은 guard에서 거부합니다."""
    command = r"""
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_GUEST_SCRIPT,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -ne 0) { throw 'GuestScriptParseFailed' }
foreach ($name in 'Assert-Task6EvaluationVmRoots', 'Assert-Task6GuestBoundary') {
    $definition = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true) | Select-Object -First 1
    if ($null -eq $definition) { throw ('GuestBoundaryFunctionMissing:' + $name) }
    . ([scriptblock]::Create($definition.Extent.Text))
}
function Test-Task6Admin { return $true }
function Test-Task6Administrator { return $true }
function Get-CimInstance {
    return [pscustomobject]@{
        Vendor = 'Microsoft Corporation'; Name = 'Virtual Machine'; UUID = $env:HERMES_QA_UUID
    }
}
function Test-Path { return $true }
function Get-Item {
    return [pscustomobject]@{ Attributes = [IO.FileAttributes]::ReparsePoint }
}
$Nonce = [guid]'00000000-0000-0000-0000-000000000099'
$identities = 'HermesWindowsBridgeGateway,HermesWindowsBridgePrivileged,HermesWindowsBridgeWorker'
$fixedIdentities = $identities
$EnvironmentKind = 'EvaluationVm'
$evaluationBase = Join-Path 'C:\\HermesTask6' $Nonce.Guid
$InputRoot = Join-Path $evaluationBase 'input'
$OutputRoot = Join-Path $evaluationBase 'output'
$GuestRoot = Join-Path $evaluationBase 'work'
$task6InputRoot = $InputRoot; $task6OutputRoot = $OutputRoot; $task6GuestRoot = $GuestRoot
$ExpectedGuestUuid = [guid]$env:HERMES_QA_UUID
$HostDirectVmBinding = 'host-direct-exact-vm-bound'
$InteractiveTokenClassification = 'verified'
try { Assert-Task6GuestBoundary; 'passed' } catch { $_.Exception.Message }
"""
    environment = os.environ.copy()
    environment.update(HERMES_QA_GUEST_SCRIPT=str(script_path), HERMES_QA_UUID=EVALUATION_UUID)

    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "Task6EvaluationVmPathReparsePoint"


@pytest.mark.parametrize(
    ("expected_code", "candidate_event", "require_no_candidate", "host_process_id", "expected_output"),
    [
        (1001, "false", "true", 40, "1001:0:True"),
        (1004, "false", "true", 40, "Task6SyntheticObservedScmExitMissing"),
        (1001, "true", "true", 40, "Task6SyntheticCandidatePythonExecuted"),
        (1001, "true", "false", 40, "1001:1:True"),
        (1001, "false", "true", 0, "Task6ObservedHostProcessMissing"),
    ],
)
def test_scm_start_failure_evidence_uses_observed_cim_exit_and_process_events(
    expected_code: int,
    candidate_event: str,
    require_no_candidate: str,
    host_process_id: int,
    expected_output: str,
) -> None:
    """실제 lifecycle 함수가 Start-Service·CIM·observer 경계를 함께 판정합니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_HARNESS, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) { throw 'HarnessParseFailed' }
foreach ($name in 'Get-Task6ServiceScmSnapshot', 'Get-Task6StoppedServiceEvidence',
    'Get-Task6ObservedHostChildProcessEvents', 'Assert-Task6ScmFailureEvidence', 'Invoke-Task6ScmStartFailure') {
    $definition = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $true) | Select-Object -First 1
    if ($null -eq $definition) { throw ('FunctionMissing:' + $name) }
    . ([scriptblock]::Create($definition.Extent.Text))
}
$script:Task6Deadline = [DateTime]::UtcNow.AddSeconds(5)
function Start-Task6ScmObserver { param($CandidatePython) return [pscustomobject]@{ candidatePython = $CandidatePython } }
function Stop-Task6ScmObserver {
    param($Observer)
    $candidateEvents = if ($env:HERMES_QA_CANDIDATE_EVENT -ceq 'true') {
        @([pscustomobject]@{ observedUtc = '2099-01-01T00:00:00.0000000Z'; processId = 99; parentProcessId = 40; processName = 'python.exe' })
    } else { @() }
    return [pscustomobject]@{
        armedUtc = '2099-01-01T00:00:00.0000000Z'; stoppedUtc = '2099-01-01T00:00:01.0000000Z'
        pythonProcessStartEvents = $candidateEvents; serviceEvents = @()
    }
}
function Start-Service { param($Name) throw [InvalidOperationException]::new('controlled SCM rejection') }
function Get-CimInstance {
    param($ClassName, $Filter)
    if ($ClassName -cne 'Win32_Service' -or $Filter -cne "Name='HermesWindowsBridgeGateway'") {
        throw 'UnexpectedCimQuery'
    }
    return [pscustomobject]@{
        Name = 'HermesWindowsBridgeGateway'; State = 'Stopped'; ProcessId = [int]$env:HERMES_QA_HOST_PROCESS_ID
        ExitCode = 1066; ServiceSpecificExitCode = 1001
    }
}
function Start-Sleep { param($Seconds) throw 'UnexpectedSleep' }
try {
    $result = Invoke-Task6ScmStartFailure -Name 'Synthetic' -ServiceName 'HermesWindowsBridgeGateway' `
        -CandidatePython 'C:\candidate\python.exe' -ExpectedServiceSpecificExitCode ([int]$env:HERMES_QA_EXPECTED_CODE) `
        -RequireNoCandidatePython ([bool]::Parse($env:HERMES_QA_REQUIRE_NO_CANDIDATE))
    $snapshot = @($result.serviceSnapshots | Select-Object -First 1)
    '{0}:{1}:{2}' -f $snapshot.serviceSpecificExitCode,
        $result.candidatePythonProcessEvents.Count, $result.startRequestFailed
} catch { $_.Exception.Message }
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={
            **os.environ,
            "HERMES_QA_HARNESS": str(HARNESS_PATH),
            "HERMES_QA_EXPECTED_CODE": str(expected_code),
            "HERMES_QA_CANDIDATE_EVENT": candidate_event,
            "HERMES_QA_REQUIRE_NO_CANDIDATE": require_no_candidate,
            "HERMES_QA_HOST_PROCESS_ID": str(host_process_id),
        },
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected_output


@pytest.mark.parametrize(
    ("pointer_drift", "expected_output"),
    [
        (
            "false",
            (
                '{"stoppedBothProfiles":true,"stoppedWithExpectedExit":true,'
                '"stopGraceExpired":true,"terminatedJob":true,"orphanSamplesEmpty":true,'
                '"registrationReadbackExact":true,"pointerReadbackExact":true}'
            ),
        ),
        ("true", "Task6UncooperativeStopRegistrationDrift"),
    ],
)
def test_uncooperative_stop_records_scm_exit_job_kill_and_orphan_readback(
    tmp_path: Path, pointer_drift: str, expected_output: str
) -> None:
    """두 service STOP 뒤 1066/1007·Job kill·orphan과 exact registration/pointer readback을 판정합니다."""
    _ = (tmp_path / "active-release.json").write_text('{"releaseRoot":"before"}', encoding="utf-8")
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_HARNESS, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) { throw 'HarnessParseFailed' }
$definition = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Invoke-Task6ScmUncooperativeStopScenario'
}, $true) | Select-Object -First 1
if ($null -eq $definition) { throw 'UncooperativeStopScenarioMissing' }
. ([scriptblock]::Create($definition.Extent.Text))
$registrationDefinition = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Get-Task6RegistrationDefinition'
}, $true) | Select-Object -First 1
if ($null -eq $registrationDefinition) { throw 'RegistrationDefinitionMissing' }
. ([scriptblock]::Create($registrationDefinition.Extent.Text))
$script:Task6Deadline = [DateTime]::UtcNow.AddSeconds(5)
$script:programRoot = $env:HERMES_QA_PROGRAM_ROOT
$script:stopRequests = [Collections.Generic.List[string]]::new()
$script:serviceStates = @{
    HermesWindowsBridgeGateway = 'Running'
    HermesWindowsBridgePrivileged = 'Running'
}
function Stop-Service {
    param($Name, [switch]$Force, $ErrorAction)
    [void]$script:stopRequests.Add($Name)
    $script:serviceStates[$Name] = 'Stopped'
    if ($Name -ceq 'HermesWindowsBridgePrivileged' -and $env:HERMES_QA_POINTER_DRIFT -ceq 'true') {
        [IO.File]::WriteAllText((Join-Path $script:programRoot 'active-release.json'), '{"releaseRoot":"drifted"}')
    }
}
function Start-Task6ScmObserver { param($CandidatePython) return [pscustomobject]@{} }
function Stop-Task6ScmObserver {
    param($Observer)
    return [pscustomobject]@{ serviceEvents = @(
        $script:serviceStates.Keys | ForEach-Object {
            [pscustomobject]@{
                serviceName = $_; state = $script:serviceStates[$_]; processId = 0
                exitCode = if ($script:serviceStates[$_] -ceq 'Stopped') { 1066 } else { 0 }
                serviceSpecificExitCode = if ($script:serviceStates[$_] -ceq 'Stopped') { 1007 } else { 0 }
            }
        }
    ) }
}
function Get-Task6StoppedServiceEvidence {
    param($ServiceNames)
    return @($ServiceNames | ForEach-Object {
        [pscustomobject]@{
            serviceName = $_; state = $script:serviceStates[$_]; processId = 0
            exitCode = if ($script:serviceStates[$_] -ceq 'Stopped') { 1066 } else { 0 }
            serviceSpecificExitCode = if ($script:serviceStates[$_] -ceq 'Stopped') { 1007 } else { 0 }
        }
    })
}
function Assert-Task6NoCandidatePython {
    param($ReleaseRoot, $Stage)
    $runningCandidates = @($script:serviceStates.Values | Where-Object { $_ -ceq 'Running' })
    $processIds = if ($runningCandidates.Count -gt 0) { @(1..$runningCandidates.Count) } else { @() }
    return @([pscustomobject]@{ sample = 1; processIds = $processIds })
}
function Get-Task6Readback {
    return [pscustomobject]@{
        services = @(
            [pscustomobject]@{ name = 'HermesWindowsBridgeGateway' },
            [pscustomobject]@{ name = 'HermesWindowsBridgePrivileged' }
        )
        worker = [pscustomobject]@{ id = 'fixture-worker' }
    }
}
function Get-Task6WorkerDefinition { param($Worker) return [ordered]@{ id = [string]$Worker.id } }
function Assert-Task6RegisteredReadback { param($Readback, $ReleaseRoot, $WorkerPython, $WorkerBaseline, $Stage, $HostContracts) }
function Start-Sleep { param($Seconds) }
function Get-FileHash {
    param($LiteralPath, $Algorithm)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [IO.File]::ReadAllBytes($LiteralPath)
        return [pscustomobject]@{ Hash = ([BitConverter]::ToString($hasher.ComputeHash($bytes))).Replace('-', '') }
    } finally { $hasher.Dispose() }
}
try {
        $receipt = Invoke-Task6ScmUncooperativeStopScenario `
        -HostContracts @{} -ReleaseRoot 'C:\fixture\release' `
        -WorkerPython 'C:\fixture\pythonw.exe' -WorkerBaseline ([pscustomobject]@{ id = 'baseline' })
    [ordered]@{
    stoppedBothProfiles = ((@($script:stopRequests | Sort-Object) -join '|') -ceq 'HermesWindowsBridgeGateway|HermesWindowsBridgePrivileged')
    stoppedWithExpectedExit = @($receipt.serviceSnapshots | Where-Object {
        $_.state -ceq 'Stopped' -and [int]$_.exitCode -eq 1066 -and
        [int]$_.serviceSpecificExitCode -eq 1007
    }).Count -gt 0
    stopGraceExpired = [bool]$receipt.stopGraceExpired
    terminatedJob = [bool]$receipt.terminatedJob
    orphanSamplesEmpty = @($receipt.orphanSamples | Where-Object {
        @($_.processIds).Count -ne 0
    }).Count -eq 0
    registrationReadbackExact = [bool]$receipt.registrationReadback.exactBeforeAfter
    pointerReadbackExact = [bool]$receipt.registrationReadback.activeReleasePointerSha256.exactBeforeAfter
} | ConvertTo-Json -Compress
} catch { $_.Exception.Message }
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={
            **os.environ,
            "HERMES_QA_HARNESS": str(HARNESS_PATH),
            "HERMES_QA_PROGRAM_ROOT": str(tmp_path),
            "HERMES_QA_POINTER_DRIFT": pointer_drift,
        },
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected_output
