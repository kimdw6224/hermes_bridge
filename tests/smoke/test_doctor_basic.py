"""읽기 전용 Bridge doctor의 기본 진단 표면을 검증합니다."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import ClassVar, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

PROJECT_ROOT: Final = Path(__file__).parents[2]
DOCTOR_PATH: Final = PROJECT_ROOT / "scripts" / "doctor.ps1"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None


class DoctorCheck(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    id: str
    status: Literal["pass", "warn", "fail"]
    critical: bool


class DoctorReport(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    schema_version: int = Field(alias="schemaVersion")
    read_only: bool = Field(alias="readOnly")
    max_external_command_seconds: int = Field(alias="maxExternalCommandSeconds")
    healthy: bool
    checks: list[DoctorCheck]


class TransportPolicyCall(BaseModel):
    """Security doctor의 transport probe 입력 경계입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    port: int
    serve_host: str = Field(alias="serveHost")
    capability: str
    token_path: str = Field(alias="tokenPath")


class InstallationContextPair(BaseModel):
    """Host-child seam에 전달된 설치 컨텍스트 쌍입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    path: str
    sha256: str


class ProtectedRuntimeHostChildProbe(BaseModel):
    """보호 런타임의 host-child 전달 관찰 결과입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    status: Literal["pass"]
    context: InstallationContextPair


def _run_doctor() -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(DOCTOR_PATH),
            "-Json",
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_doctor_json_reports_all_basic_prerequisites() -> None:
    # Given: 설치 여부와 무관한 현재 Windows 호스트입니다.
    # When: machine-readable 기본 진단을 실행합니다.
    result = _run_doctor()

    # Then: exit 상태와 독립적으로 모든 기본 check가 typed JSON에 존재합니다.
    report = DoctorReport.model_validate_json(result.stdout)
    check_ids = {check.id for check in report.checks}
    assert report.schema_version == 1
    assert report.read_only is True
    assert check_ids == {
        "tailscale",
        "gateway_service",
        "privileged_helper_service",
        "backend_listener",
        "bearer_auth",
        "interactive_worker",
        "playwright",
        "codex",
        "token_acl",
    }
    assert result.returncode == (0 if report.healthy else 1)


def test_doctor_json_has_bounded_structured_results() -> None:
    # Given: 실제 시스템 상태를 읽은 doctor 결과입니다.
    # When: JSON report를 검사합니다.
    result = _run_doctor()
    report = DoctorReport.model_validate_json(result.stdout)

    # Then: 각 check는 유한 시간과 명시적 상태를 제공합니다.
    assert report.max_external_command_seconds == 5
    assert all(check.status in {"pass", "warn", "fail"} for check in report.checks)
    assert all(isinstance(check.critical, bool) for check in report.checks)


def test_doctor_source_contains_only_read_only_tailscale_queries() -> None:
    # Given: Tailscale 상태를 확인하는 doctor source입니다.
    # When: 명령 문자열을 읽습니다.
    source = DOCTOR_PATH.read_text(encoding="utf-8")

    # Then: status만 허용하고 구성 변경 동사는 포함하지 않습니다.
    assert "status --json" in source
    assert "serve status --json" in source
    assert "tailscale up" not in source
    assert "tailscale set" not in source
    assert "serve reset" not in source


def test_security_doctor_forwards_explicit_serve_host_to_transport_policy() -> None:
    # Given: environment 값 없이 explicit ServeHost만 제공한 Security doctor 호출 경계입니다.
    doctor_path = str(DOCTOR_PATH).replace("'", "''")
    expected_path = r"C:\fixture\probe-input"
    command = f"""
$tokens = $null; $errors = $null
$scriptPath = '{doctor_path}'
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $scriptPath, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) {{ throw 'doctor_parse_failed' }}
$transportCalls = @($ast.FindAll({{
    param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -ceq 'Get-TransportPolicyCheck'
}}, $true))
if ($transportCalls.Count -ne 1) {{ throw 'transport_policy_call_missing' }}
$env:HERMES_BRIDGE_TAILSCALE_SERVE_HOST = $null
$gatewayPort = 8765
$ServeHost = 'explicit.fixture.ts.net'
$doctorTransportServeHost = [string]$ServeHost
$Capability = 'hermes.local/windows-control'
$tokenPath = '{expected_path}'
$script:observed = $null
function Get-TransportPolicyCheck {{
    param([int]$Port, [string]$ServeHost, [string]$Capability, [string]$TokenPath)
    $script:observed = [ordered]@{{
        port = $Port; serveHost = $ServeHost; capability = $Capability; tokenPath = $TokenPath
    }}
}}
. ([scriptblock]::Create($transportCalls[0].Extent.Text))
if ($null -eq $script:observed) {{ throw 'transport_policy_call_not_executed' }}
$script:observed | ConvertTo-Json -Compress
"""

    # When: source에서 추출한 실제 호출만 probe stub으로 실행합니다.
    result = subprocess.run(
        [
            POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    # Then: environment 값이 없어도 explicit ServeHost가 transport probe에 그대로 전달됩니다.
    assert result.returncode == 0, result.stderr
    transport_call = TransportPolicyCall.model_validate_json(result.stdout)
    assert transport_call.port == 8765
    assert transport_call.serve_host == "explicit.fixture.ts.net"
    assert transport_call.capability == "hermes.local/windows-control"
    assert transport_call.token_path == expected_path


def test_protected_runtime_forwards_context_to_host_child_sensor() -> None:
    """컨텍스트 모드가 검증된 쌍을 host-child 경계까지 유지합니다."""
    doctor_path = str(DOCTOR_PATH).replace("'", "''")
    command = f"""
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    '{doctor_path}', [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) {{ throw 'doctor_parse_failed' }}
foreach ($name in @('New-CheckResult', 'Get-ProtectedServiceRuntimeCheck')) {{
    $definition = $ast.Find({{
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }}, $true)
    if ($null -eq $definition) {{ throw "doctor_function_missing:$name" }}
    . ([scriptblock]::Create($definition.Extent.Text))
}}
function Resolve-BridgeServiceReleaseSelection {{
    [pscustomobject]@{{
        releaseRoot = 'C:\\fixture\\release'
        gatewayServiceHostRoot = 'C:\\fixture\\hosts\\gateway'
        privilegedServiceHostRoot = 'C:\\fixture\\hosts\\privileged'
    }}
}}
function Get-BridgeServicePairInspection {{
    [pscustomobject]@{{ previousState = 'safe-pair' }}
}}
$script:observedContext = $null
function Get-ProtectedServiceHostChildCheck {{
    param($Id, $Release, $GatewayServiceName, $PrivilegedServiceName, $InstallationContext)
    $script:observedContext = [ordered]@{{
        path = [string]$InstallationContext.contextPath
        sha256 = [string]$InstallationContext.contextSha256
    }}
    $null
}}
$context = [pscustomobject]@{{
    contextPath = 'C:\\fixture\\installation-context.json'
    contextSha256 = ('a' * 64)
}}
$result = Get-ProtectedServiceRuntimeCheck -Id 'protected_service_runtime' `
    -ProgramRoot 'C:\\fixture\\program' -ServiceReleaseRoot 'C:\\fixture\\release' `
    -GatewayServiceHostRoot 'C:\\fixture\\hosts\\gateway' `
    -PrivilegedServiceHostRoot 'C:\\fixture\\hosts\\privileged' `
    -InstallationContext $context
$observation = [pscustomobject]@{{ status = $result.status; context = $script:observedContext }}
$observation | ConvertTo-Json -Compress
"""

    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    observation = ProtectedRuntimeHostChildProbe.model_validate_json(result.stdout)
    assert observation.status == "pass"
    assert observation.context.path == r"C:\fixture\installation-context.json"
    assert observation.context.sha256 == "a" * 64


def test_protected_host_child_uses_context_binding_argv_only_for_schema_two() -> None:
    """Schema-2 child identity에 검증된 runtime-binding 쌍만 정확히 추가합니다."""
    source = DOCTOR_PATH.read_text(encoding="utf-8")
    start = source.index("function Get-ProtectedServiceHostChildCheck")
    end = source.index("function Initialize-BridgeDoctorServiceSecurityApi", start)
    host_child_source = source[start:end]

    assert "-InstallationContext $InstallationContext" in source
    assert (
        "-InstallationContextPath $ContextPath -InstallationContextSha256 $ContextSha256"
        in host_child_source
    )
    assert "$usesRuntimeBinding = ([int]$contract.schemaVersion -eq 2)" in host_child_source
    assert ' --runtime-binding "{0}" --runtime-binding-sha256 {1}' in host_child_source
