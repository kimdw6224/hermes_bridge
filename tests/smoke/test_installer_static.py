"""Task 12 설치 골격의 안전 계약을 검증합니다."""

from __future__ import annotations

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


class InstallPlan(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    mode: str
    applied: bool
    atomic: bool
    resume_safe: bool = Field(alias="resumeSafe")
    administrator_required_for_install: bool = Field(alias="administratorRequiredForInstall")
    runtime_directories: list[str] = Field(alias="runtimeDirectories")
    prerequisites: list[Prerequisite]


class Prerequisite(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    id: str
    present: bool
    required: bool
    status: Literal["pass", "warn", "fail"]


class RegistrationAdapterFailure(BaseModel):
    """A redacted registration child-process failure."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    reason: str
    diagnostic: str


class SimulatedInstallFailure(BaseModel):
    """No-external-call failure injection receipt."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    applied: bool
    state: Literal["failed"]
    failed_step: Literal["dependencies"] = Field(alias="failedStep")
    adapter_mode: Literal["Simulate"] = Field(alias="adapterMode")
    external_calls: Literal[0] = Field(alias="externalCalls")


def _run_install(
    *arguments: str,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(SCRIPTS_ROOT / "install.ps1"),
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
    environment["ProgramData"] = str(tmp_path / "program-data")
    environment["LOCALAPPDATA"] = str(tmp_path / "local-app-data")
    return environment


def test_install_whatif_is_read_only_and_reports_elevation_contract(tmp_path: Path) -> None:
    # Given: 실제 설치 승인을 뜻하지 않는 WhatIf 호출입니다.
    # When: 설치 골격을 실행합니다.
    result = _run_install("-WhatIf", "-Json", environment=_isolated_environment(tmp_path))

    # Then: 성공한 계획이며 관리자 요건과 무변경 상태를 구조적으로 보고합니다.
    plan = InstallPlan.model_validate_json(result.stdout)
    assert result.returncode == 0
    assert plan.mode == "what-if"
    assert plan.applied is False
    assert plan.administrator_required_for_install is True
    assert plan.atomic is True
    assert plan.resume_safe is True


def test_install_plan_reports_required_checks_and_optional_warnings(tmp_path: Path) -> None:
    # Given: 현재 호스트의 Task 12 WhatIf 계획입니다.
    # When: prerequisite 결과를 구조적으로 해석합니다.
    plan = InstallPlan.model_validate_json(
        _run_install("-WhatIf", "-Json", environment=_isolated_environment(tmp_path)).stdout
    )
    checks = {check.id: check for check in plan.prerequisites}

    # Then: 필수 도구와 선택 도구를 빠짐없이 구분합니다.
    assert set(checks) == {"python", "uv", "dependencies", "tailscale", "playwright", "codex"}
    required_ids = ("python", "uv", "dependencies", "tailscale")
    optional_ids = ("playwright", "codex")
    assert all(checks[check_id].required for check_id in required_ids)
    assert all(not checks[check_id].required for check_id in optional_ids)
    assert all(
        check.status == ("pass" if check.present else "fail" if check.required else "warn")
        for check in checks.values()
    )


def test_simulated_apply_failure_has_no_external_calls(tmp_path: Path) -> None:
    # Given: 첫 단계에서 실패하도록 고정한 simulated apply입니다.
    result = _run_install(
        "-Apply",
        "-AdapterMode",
        "Simulate",
        "-SimulationFailureStep",
        "dependencies",
        "-Json",
        environment=_isolated_environment(tmp_path),
    )

    # Then: 서비스, ACL, 파일을 건드리지 않는 fail-closed receipt를 반환합니다.
    assert result.returncode == 2, result.stderr
    receipt = SimulatedInstallFailure.model_validate_json(result.stdout)
    assert receipt.applied is False
    assert receipt.state == "failed"
    assert receipt.failed_step == "dependencies"
    assert receipt.adapter_mode == "Simulate"
    assert receipt.external_calls == 0


def test_installer_treats_environment_path_as_data() -> None:
    # Given: 출력 주입처럼 보이는 ProgramData 경로입니다.
    environment = os.environ.copy()
    environment["ProgramData"] = r"C:\ProgramData; Write-Output PROMPT_INJECTION_EXECUTED"

    # When: JSON WhatIf 계획을 만듭니다.
    result = _run_install("-WhatIf", "-Json", environment=environment)

    # Then: 값은 JSON 문자열일 뿐 별도 출력이나 실행이 아닙니다.
    plan = InstallPlan.model_validate_json(result.stdout)
    assert result.returncode == 0
    assert "PROMPT_INJECTION_EXECUTED" in plan.runtime_directories[0]
    containing_paths = [
        path for path in plan.runtime_directories if "PROMPT_INJECTION_EXECUTED" in path
    ]
    assert result.stdout.count("PROMPT_INJECTION_EXECUTED") == len(containing_paths)
    assert result.stderr == ""


def test_install_scripts_use_typed_dry_run_plans_without_shell_evaluation() -> None:
    # Given: Task 12가 소유한 설치 및 등록 스크립트입니다.
    script_paths = (
        SCRIPTS_ROOT / "install.ps1",
        SCRIPTS_ROOT / "register-gateway-service.ps1",
        SCRIPTS_ROOT / "register-privileged-service.ps1",
        SCRIPTS_ROOT / "register-worker-task.ps1",
    )

    # When: 정적 실행 표면을 읽습니다.
    sources = tuple(path.read_text(encoding="utf-8") for path in script_paths)

    # Then: eval 계열이나 Tailscale 상태 변경 명령 없이 argv 계획만 둡니다.
    forbidden = ("Invoke-Expression", "tailscale up", "tailscale set", "tailscale serve --bg")
    assert all(token not in source for source in sources for token in forbidden)
    assert all("argv" in source for source in sources[1:])
    assert "SupportsShouldProcess" in sources[0]
    assert all("mode = 'dry-run'" in source for source in sources[1:])


def test_gateway_registration_requests_start_access_for_restart_failure_actions() -> None:
    # Given: gateway는 SCM이 처리하는 재시작 failure action을 고정 등록합니다.
    source = (SCRIPTS_ROOT / "register-gateway-service.ps1").read_text(encoding="utf-8")

    # When: CreateServiceW가 반환하는 handle의 권한 계약을 읽습니다.
    # Then: SC_ACTION_RESTART를 설정할 때 필요한 SERVICE_START도 함께 요청합니다.
    assert "SERVICE_START = 0x0010" in source
    assert (
        "SERVICE_QUERY_CONFIG|SERVICE_CHANGE_CONFIG|SERVICE_START|SERVICE_STOP|DELETE" in source
    )


def test_registration_adapter_redacts_and_preserves_child_stderr_diagnostics() -> None:
    # Given: child registration failures can otherwise lose their only useful diagnostic.
    source = (SCRIPTS_ROOT / "lifecycle-common.ps1").read_text(encoding="utf-8")

    # When: the adapter converts a nonzero child result to its stable failure contract.
    # Then: stderr is bounded and secret-shaped values are redacted without losing the code.
    assert "Get-BridgeRegistrationAdapterFailure" in source
    expected_contract = (
        "BridgeRegistrationAdapterFailed[$ScriptName;exit=$($adapterResult.exitCode);"
        "reason=$($failure.reason);stderr=$($failure.diagnostic)]"
    )
    assert expected_contract in source
    assert "'$1=[REDACTED]'" in source
    assert "[\\r\\n\\t:;]+" in source


def test_registration_adapter_preserves_structured_failure_and_redacts_stderr() -> None:
    # Given: a failed child can emit a reason with secret-shaped stderr.
    command = """
& {
    $ErrorActionPreference = "Stop"
    . $env:HERMES_TEST_COMMON_PATH
    $failureArguments = @{
        ExitCode = 3
        StandardOutput = $env:HERMES_TEST_CHILD_OUTPUT
        StandardError = $env:HERMES_TEST_CHILD_ERROR
    }
    Get-BridgeRegistrationAdapterFailure @failureArguments |
        ConvertTo-Json -Compress
}
"""
    environment = os.environ.copy()
    environment["HERMES_TEST_COMMON_PATH"] = str(SCRIPTS_ROOT / "lifecycle-common.ps1")
    environment["HERMES_TEST_CHILD_OUTPUT"] = '{"failureReason":"runtime-entrypoint-unverified"}'
    environment["HERMES_TEST_CHILD_ERROR"] = "CreateServiceW token=do-not-expose"

    # When: the same failure-normalization seam used by the adapter runs in PowerShell.
    result = subprocess.run(
        [
            POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    # Then: the stable reason remains actionable while the secret-shaped value never leaks.
    assert result.returncode == 0, result.stderr
    failure = RegistrationAdapterFailure.model_validate_json(result.stdout)
    assert failure == RegistrationAdapterFailure(
        reason="runtime-entrypoint-unverified",
        diagnostic="CreateServiceW token=[REDACTED]",
    )


@pytest.mark.parametrize(
    "script_name",
    [
        "install.ps1",
        "register-gateway-service.ps1",
        "register-privileged-service.ps1",
        "register-worker-task.ps1",
    ],
)
def test_installer_powershell_ast_has_no_parse_errors(script_name: str) -> None:
    # Given: 실행 전 검증할 PowerShell 파일입니다.
    script_path = SCRIPTS_ROOT / script_name
    command = (
        "& { param([string]$Path) $tokens=$null; $errors=$null; "
        "[void][System.Management.Automation.Language.Parser]::ParseFile("
        "$Path,[ref]$tokens,[ref]$errors); if($errors.Count){exit 1} }"
    )

    # When: PowerShell 자체 parser로 AST를 생성합니다.
    result = subprocess.run(
        [
            POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
            "-Path",
            str(script_path),
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    # Then: syntax error가 없습니다.
    assert result.returncode == 0, result.stderr
