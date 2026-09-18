"""격리 installation context가 adapter 고정 이름과 binding을 강제하는 회귀 검사입니다."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import ClassVar, Final

import pytest
from pydantic import BaseModel, ConfigDict

ROOT: Final = Path(__file__).parents[2]
POWERSHELL: Final = shutil.which("powershell.exe")
assert POWERSHELL is not None
NONCE: Final = "0123456789abcdef0123456789abcdef"
CONTEXT_SHA256: Final = "a" * 64
BINDING_SHA256: Final = "b" * 64


class AdapterReceipt(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    target: str


class AdapterPlan(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    name: str
    argv: tuple[str, ...]
    receipt: AdapterReceipt


class WorkerArgumentReceipt(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    encoded: str
    state: str


class UninstallPlanReceipt(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    mode: str
    state: str


def _write_context_contract(script_root: Path) -> Path:
    context_path = script_root / "context.json"
    _ = context_path.write_text("{}", encoding="utf-8")
    _ = (script_root / "installation-context.ps1").write_text(
        f"""
param([switch]$LibraryMode)
function Get-BridgeInstallationContext {{
    param([string]$Path, [string]$Sha256)
    if ($Sha256 -cne '{CONTEXT_SHA256}') {{ throw 'context-hash-mismatch' }}
    [pscustomobject]@{{
        schemaVersion=1; nonce='{NONCE}'; prefix='HermesWindowsBridgeEval-{NONCE}'; port=50123
        contextPath=$Path; contextSha256=$Sha256
        programRoot='C:\\Program Files\\HermesWindowsBridgeEval-{NONCE}'
        programDataRoot='C:\\ProgramData\\HermesWindowsBridgeEval-{NONCE}'
        localDataRoot='C:\\Users\\worker\\AppData\\Local\\HermesWindowsBridgeEval-{NONCE}'
        bindingsDirectory='C:\\Program Files\\HermesWindowsBridgeEval-{NONCE}\\bindings'
        gatewayServiceName='HermesWindowsBridgeEval-{NONCE}-Gateway'
        privilegedServiceName='HermesWindowsBridgeEval-{NONCE}-Privileged'
        workerTaskName='HermesWindowsBridgeEval-{NONCE}-Worker'
    }}
}}
function Get-BridgeInstallationContextBinding {{
    param($Context, [string]$Profile)
    [pscustomobject]@{{
        path=(Join-Path $Context.bindingsDirectory ($Profile + '.json'))
        sha256='{BINDING_SHA256}'; profile=$Profile; contextNonce=$Context.nonce
        workerSid='S-1-5-21-1-2-3-4'
    }}
}}
""",
        encoding="utf-8",
    )
    return context_path


@pytest.mark.parametrize(
    ("script_name", "profile", "service_name"),
    [
        (
            "register-gateway-service.ps1",
            "gateway",
            f"HermesWindowsBridgeEval-{NONCE}-Gateway",
        ),
        (
            "register-privileged-service.ps1",
            "privileged",
            f"HermesWindowsBridgeEval-{NONCE}-Privileged",
        ),
    ],
)
def test_service_adapter_resolves_context_binding_after_resolver_returns(
    script_name: str,
    profile: str,
    service_name: str,
    tmp_path: Path,
) -> None:
    # Given: schema-2 Host contract and a valid context binding under an isolated script root.
    script_root = tmp_path / "scripts"
    _ = script_root.mkdir()
    _ = shutil.copy2(ROOT / "scripts" / script_name, script_root / script_name)
    _ = shutil.copy2(ROOT / "scripts" / "service-object-security.ps1", script_root)
    context_path = _write_context_contract(script_root)
    host_root = tmp_path / "host"
    release_root = tmp_path / "release"
    _ = host_root.mkdir()
    _ = release_root.mkdir()
    host_executable = host_root / "HermesBridge.ServiceHost.exe"
    _ = (script_root / "service-host.ps1").write_text(
        f"""
param([switch]$LibraryMode, [string]$Profile)
function Get-BridgeServiceHostContract {{
    param($HostRoot, $Profile, $ReleaseRoot, $InstallationContextPath, $InstallationContextSha256)
    [pscustomobject]@{{
        verified=$true; schemaVersion=2; state='verified'; profile=$Profile
        contextNonce='{NONCE}'; serviceName='{service_name}'
        runtimeBindingPath=(
            'C:\\Program Files\\HermesWindowsBridgeEval-{NONCE}\\bindings\\{profile}.json'
        )
        runtimeBindingSha256='{BINDING_SHA256}'
        hostRoot=[IO.Path]::GetFullPath($HostRoot); hostDigest='{'a' * 64}'
        hostExecutable=(Join-Path $HostRoot 'HermesBridge.ServiceHost.exe')
        argv=@((Join-Path $HostRoot 'HermesBridge.ServiceHost.exe'),'--profile',$Profile)
        releaseRoot=[IO.Path]::GetFullPath($ReleaseRoot); manifestSha256='{'c' * 64}'
        releaseExecutable=(Join-Path $ReleaseRoot 'python.exe')
    }}
}}
""",
        encoding="utf-8",
    )

    # When: a dry-run adapter receives the verified context pair.
    result = subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(script_root / script_name),
            "-InstallationContextPath",
            str(context_path),
            "-InstallationContextSha256",
            CONTEXT_SHA256,
            "-ServiceHostRoot",
            str(host_root),
            "-RuntimeReleaseRoot",
            str(release_root),
            "-Json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    # Then: the later script-scope binding lookup emits only the derived nonce
    # service and fixed Host argv.
    plan = AdapterPlan.model_validate_json(result.stdout)
    assert result.returncode == 0, result.stderr
    assert plan.name == service_name
    assert plan.receipt.target == service_name
    assert plan.argv == (str(host_executable), "--profile", profile)


def test_worker_adapter_derives_nonce_task_and_hash_bound_action(tmp_path: Path) -> None:
    # Given: a context contract whose Worker SID is the invoking interactive identity.
    script_root = tmp_path / "scripts"
    _ = script_root.mkdir()
    _ = shutil.copy2(ROOT / "scripts" / "register-worker-task.ps1", script_root)
    context_path = _write_context_contract(script_root)
    source = (script_root / "installation-context.ps1").read_text(encoding="utf-8")
    sid_contract = "([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"
    _ = (script_root / "installation-context.ps1").write_text(
        source.replace("workerSid='S-1-5-21-1-2-3-4'", f"workerSid={sid_contract}"),
        encoding="utf-8",
    )
    command = (
        "$user=[Security.Principal.WindowsIdentity]::GetCurrent().Name; "
        f"& '{script_root / 'register-worker-task.ps1'}' -UserId $user "
        f"-InstallationContextPath '{context_path}' "
        f"-InstallationContextSha256 '{CONTEXT_SHA256}' -Json"
    )

    # When: the adapter constructs its dry-run scheduled-task definition.
    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    # Then: the exact nonce task and protected binding pair are part of the fixed module action.
    plan = AdapterPlan.model_validate_json(result.stdout)
    assert result.returncode == 0, result.stderr
    assert plan.name == f"HermesWindowsBridgeEval-{NONCE}-Worker"
    assert plan.argv[1:3] == ("-m", "hermes_windows_bridge.worker.main")
    assert plan.argv[-4:] == (
        "--runtime-binding",
        f"C:\\Program Files\\HermesWindowsBridgeEval-{NONCE}\\bindings\\worker.json",
        "--runtime-binding-sha256",
        BINDING_SHA256,
    )


def test_context_service_adapter_never_falls_back_to_production_simulation(tmp_path: Path) -> None:
    # Given: a complete context pair and Host contract that would otherwise permit a dry-run plan.
    script_root = tmp_path / "scripts"
    _ = script_root.mkdir()
    _ = shutil.copy2(ROOT / "scripts" / "register-gateway-service.ps1", script_root)
    _ = shutil.copy2(ROOT / "scripts" / "service-object-security.ps1", script_root)
    context_path = _write_context_contract(script_root)
    host_root = tmp_path / "host"
    release_root = tmp_path / "release"
    _ = host_root.mkdir()
    _ = release_root.mkdir()
    _ = (script_root / "service-host.ps1").write_text(
        f"""
param([switch]$LibraryMode, [string]$Profile)
function Get-BridgeServiceHostContract {{
    param($HostRoot, $Profile, $ReleaseRoot, $InstallationContextPath, $InstallationContextSha256)
    $executable=Join-Path $HostRoot 'HermesBridge.ServiceHost.exe'
    [pscustomobject]@{{
        verified=$true; schemaVersion=2; state='verified'; profile=$Profile
        contextNonce='{NONCE}'; serviceName='HermesWindowsBridgeEval-{NONCE}-Gateway'
        runtimeBindingPath=(
            'C:\\Program Files\\HermesWindowsBridgeEval-{NONCE}\\bindings\\gateway.json'
        )
        runtimeBindingSha256='{BINDING_SHA256}'
        hostRoot=[IO.Path]::GetFullPath($HostRoot)
        hostDigest='{'a' * 64}'
        hostExecutable=$executable
        argv=@($executable,'--profile',$Profile)
        releaseRoot=[IO.Path]::GetFullPath($ReleaseRoot); manifestSha256='{'c' * 64}'
        releaseExecutable=(Join-Path $ReleaseRoot 'python.exe')
    }}
}}
""",
        encoding="utf-8",
    )

    # When: the caller tries to combine context mode with a simulated adapter.
    result = subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(script_root / "register-gateway-service.ps1"),
            "-Apply",
            "-AdapterMode",
            "Simulate",
            "-InstallationContextPath",
            str(context_path),
            "-InstallationContextSha256",
            CONTEXT_SHA256,
            "-ServiceHostRoot",
            str(host_root),
            "-RuntimeReleaseRoot",
            str(release_root),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    # Then: a supplied context cannot silently become a production-style simulated adapter call.
    assert result.returncode != 0
    assert "BridgeContextSimulationForbidden" in result.stderr


def test_context_uninstall_passes_validated_context_to_release_selection() -> None:
    # Given: nonce uninstall validates schema-2 Host contracts during release selection.
    source = (ROOT / "scripts" / "uninstall.ps1").read_text(encoding="utf-8")

    # When: the actual uninstall transaction builds its release selection.
    selection_call = (
        "Resolve-BridgeServiceReleaseSelection -ProgramRoot $serviceProgramRoot "
        "-InstallationContext $installationContext"
    )

    # Then: the validated nonce context reaches the selection's internal Host-contract checks.
    assert selection_call in source


def test_uninstall_preserves_context_pair_across_runtime_library_import(
    tmp_path: Path,
) -> None:
    # Given: LibraryMode imports a runtime contract whose same-named parameters
    # would reset a caller's context pair when dot-sourced.
    script_root = tmp_path / "scripts"
    _ = script_root.mkdir()
    _ = shutil.copy2(ROOT / "scripts" / "uninstall.ps1", script_root)
    context_path = script_root / "installation-context.json"
    _ = context_path.write_text("{}", encoding="utf-8")
    program_data_root = tmp_path / "program-data"
    local_data_root = tmp_path / "local-data"
    _ = program_data_root.mkdir()
    _ = local_data_root.mkdir()
    _ = (script_root / "lifecycle-common.ps1").write_text(
        """
function Resolve-BridgeLocalRoot { param([string]$Path) [IO.Path]::GetFullPath($Path) }
function Assert-BridgePathUnderRoot { param([string]$Root, [string]$Path) $Path }
function Test-BridgeAdministrator { $false }
function Test-BridgeRegistrationAdapterContract { $true }
function Get-Service { param() $null }
function Get-Command { param() $null }
""",
        encoding="utf-8",
    )
    _ = (script_root / "service-runtime.ps1").write_text(
        """
param(
    [string]$InstallationContextPath = '',
    [string]$InstallationContextSha256 = '',
    [switch]$LibraryMode
)
function Get-BridgeRuntimeAccessMarkerPath {
    param([string]$RuntimeRoot)
    Join-Path $RuntimeRoot 'marker.json'
}
function Read-BridgeRuntimeAccessMarker { param([string]$RuntimeRoot) $null }
""",
        encoding="utf-8",
    )
    _ = (script_root / "service-runtime-transaction.ps1").write_text(
        "",
        encoding="utf-8",
    )
    _ = (script_root / "installation-context.ps1").write_text(
        f"""
param([switch]$LibraryMode)
function Get-BridgeInstallationContext {{
    param([string]$Path, [string]$Sha256)
    if ($Path -cne '{context_path}') {{ throw 'context-path-lost' }}
    if ($Sha256 -cne '{CONTEXT_SHA256}') {{ throw 'context-hash-lost' }}
    [pscustomobject]@{{
        schemaVersion=1; nonce='{NONCE}'; contextPath=$Path; contextSha256=$Sha256
        programDataRoot='{program_data_root}'; localDataRoot='{local_data_root}'
        programRoot='{tmp_path / 'program-files'}'; bindingsDirectory='{tmp_path / 'bindings'}'
        gatewayServiceName='HermesWindowsBridgeEval-{NONCE}-Gateway'
        privilegedServiceName='HermesWindowsBridgeEval-{NONCE}-Privileged'
        workerTaskName='HermesWindowsBridgeEval-{NONCE}-Worker'
    }}
}}
""",
        encoding="utf-8",
    )

    # When: read-only uninstall loads that colliding runtime library first.
    result = subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(script_root / "uninstall.ps1"),
            "-InstallationContextPath",
            str(context_path),
            "-InstallationContextSha256",
            CONTEXT_SHA256,
            "-Json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    # Then: the original pair reaches the context resolver after the import.
    assert result.returncode == 0, result.stderr
    receipt = UninstallPlanReceipt.model_validate_json(result.stdout)
    assert receipt.mode == "read-only"
    assert receipt.state == "planned"


def test_worker_task_argument_round_trip_quotes_binding_path_with_spaces() -> None:
    # Given: a binding path beneath the isolated Program Files root.
    command = rf"""
& {{
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $workerScript = '{ROOT / "scripts" / "register-worker-task.ps1"}'
    . $workerScript -UserId $user -ExecutablePath python.exe | Out-Null
    $bindingPath = 'C:\Program Files\HermesWindowsBridgeEval-{NONCE}\bindings\worker.json'
    $argv = @(
        '-m', 'hermes_windows_bridge.worker.main',
        '--runtime-binding', $bindingPath,
        '--runtime-binding-sha256', '{BINDING_SHA256}'
    )
    $encoded = ConvertTo-WorkerTaskArgumentText -Arguments $argv
    $task = [pscustomobject]@{{
        Actions = @([pscustomobject]@{{ Execute='C:\bridge\pythonw.exe'; Arguments=$encoded }})
        Triggers = @([pscustomobject]@{{
            CimClass=[pscustomobject]@{{ CimClassName='MSFT_TaskLogonTrigger' }}; UserId=$user
        }})
        Principal = [pscustomobject]@{{
            UserId=$user; LogonType='InteractiveToken'; RunLevel='Limited'
        }}
        Settings = [pscustomobject]@{{ Hidden=$true; RestartCount=3; RestartInterval='PT1M' }}
    }}
    function Get-ScheduledTask {{ param() $task }}
    $state = Get-WorkerTaskDefinitionState -PythonPath 'C:\bridge\pythonw.exe' `
        -ExpectedUserId $user -TaskName 'HermesWindowsBridgeEval-{NONCE}-Worker' `
        -ExpectedArguments $argv
    [pscustomobject]@{{ encoded=$encoded; state=$state }} | ConvertTo-Json -Compress
}}
"""

    # When: creation and readback both use the Windows argument encoder.
    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    # Then: the parsed receipt retains one quoted binding path and exact readback is desired.
    assert result.returncode == 0, result.stderr
    receipt = WorkerArgumentReceipt.model_validate_json(result.stdout)
    assert receipt.encoded == (
        "-m hermes_windows_bridge.worker.main --runtime-binding "
        f'"C:\\Program Files\\HermesWindowsBridgeEval-{NONCE}\\bindings\\worker.json" '
        f"--runtime-binding-sha256 {BINDING_SHA256}"
    )
    assert receipt.state == "desired"

