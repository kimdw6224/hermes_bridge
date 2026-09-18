"""Evaluation-VM guest security-check harness contracts."""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from threading import Event, Thread
from typing import TYPE_CHECKING, Final, TypedDict, final
from unittest.mock import patch
from uuid import UUID, uuid4

import pytest
from pydantic import TypeAdapter

from hermes_windows_bridge.gateway import helper_runtime
from hermes_windows_bridge.gateway.helper_runtime import GatewayHelperWatcher
from hermes_windows_bridge.gateway.worker_runtime import GatewayWorkerWatcher
from hermes_windows_bridge.ipc.acl import (
    PipeAcl,
    build_privileged_pipe_acl,
    current_process_sid,
)
from hermes_windows_bridge.ipc.named_pipe import PipeEndpoint, create_server_pipe
from hermes_windows_bridge.ipc.protocol import (
    HelperRegistration,
    IpcRequest,
    IpcResponse,
    WorkerRegistration,
)
from hermes_windows_bridge.privileged.ipc_server import HelperRegistry
from hermes_windows_bridge.privileged.pipe_session import HelperRuntimeConfig
from hermes_windows_bridge.privileged.runtime import PrivilegedHelperRuntime
from hermes_windows_bridge.worker import pipe_server as worker_pipe_server
from hermes_windows_bridge.worker.ipc_client import WorkerRegistry
from hermes_windows_bridge.worker.pipe_server import WorkerPipeConfig, serve_worker_pipe

if TYPE_CHECKING:
    from hermes_windows_bridge.ipc.named_pipe import NamedPipeServer, PeerIdentity
    from hermes_windows_bridge.privileged.operations import RebootRequest, ShutdownRequest

PROJECT_ROOT: Final = Path(__file__).resolve().parents[2]
SCRIPT_PATH: Final = (
    PROJECT_ROOT
    / ".omo"
    / "evidence"
    / "service-protection-eval-vm-20260908"
    / "security"
    / "guest-security-checks.ps1"
)
CLIENT_PIPE_ACL_PROBE_PATH: Final = (
    PROJECT_ROOT
    / ".omo"
    / "evidence"
    / "service-protection-eval-vm-20260908"
    / "security"
    / "client_pipe_acl_probe.py"
)
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None
NONCE: Final = UUID("8fb55a28-69e7-41f2-b449-df8148645bc0")


class PlannedReceipt(TypedDict):
    schemaVersion: int
    nonce: str
    outcome: str
    executionStage: str
    writes: bool


class PipeFixtureReport(TypedDict):
    openSucceeded: bool
    waitResult: str
    daclReadSucceeded: bool
    metadataOpenConsumesConnection: bool
    cleanupSucceeded: bool
    fixedBridgePipesAccessed: bool


class MetadataRecoveryReport(TypedDict):
    openSucceeded: bool
    waitResult: str
    errorCode: int
    fixedBridgePipesAccessed: bool


class ClientPipeAclProbeReport(TypedDict):
    opened: bool
    daclRead: bool
    exactTemplate: bool


PLANNED_RECEIPT_ADAPTER: Final = TypeAdapter(PlannedReceipt)
PIPE_FIXTURE_REPORT_ADAPTER: Final = TypeAdapter(PipeFixtureReport)
METADATA_RECOVERY_REPORT_ADAPTER: Final = TypeAdapter(MetadataRecoveryReport)
CLIENT_PIPE_ACL_PROBE_REPORT_ADAPTER: Final = TypeAdapter(ClientPipeAclProbeReport)


@final
class _MetadataRecoveryDispatcher:
    """Handshake 뒤에는 이 회귀가 operation을 보내지 않으므로 typed no-op만 제공합니다."""

    def exchange(self, request: IpcRequest) -> IpcResponse:
        return IpcResponse(request_id=request.request_id, ok=True, payload={})

    def cancel(self, request_id: UUID) -> bool:
        del request_id
        return False


@final
class _NoopPowerActionExecutor:
    """Recovery fixture는 handshake만 검사하므로 Windows power API를 호출하지 않습니다."""

    def reboot(self, request: RebootRequest) -> None:
        del request

    def shutdown(self, request: ShutdownRequest) -> None:
        del request


def test_client_pipe_acl_probe_artifact_exists() -> None:
    """평가 전용 client-handle probe는 guest harness와 분리된 artifact여야 합니다."""
    assert CLIENT_PIPE_ACL_PROBE_PATH.is_file()


def _accept_fixture_peer(peer: PeerIdentity) -> None:
    """Worker-ACL fixture는 LocalService SID 검증이 아닌 disconnect recovery만 검증합니다."""
    del peer


def _run_client_pipe_acl_probe(
    pipe_name: str,
    expected_target_sid: str,
) -> ClientPipeAclProbeReport:
    """별도 Python process에서 client READ_CONTROL handle만 열어 typed 결과만 받습니다."""
    command = f"""
import json
import sys

sys.path.insert(0, {str(CLIENT_PIPE_ACL_PROBE_PATH.parent)!r})
from client_pipe_acl_probe import probe_client_pipe_acl
from hermes_windows_bridge.ipc.acl import build_worker_pipe_acl

result = probe_client_pipe_acl(sys.argv[1], build_worker_pipe_acl(sys.argv[2]))
print(json.dumps({{
    "opened": result.opened,
    "daclRead": result.dacl_read,
    "exactTemplate": result.exact_template,
}}, separators=(",", ":")))
"""
    result = subprocess.run(
        [sys.executable, "-c", command, pipe_name, expected_target_sid],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    return CLIENT_PIPE_ACL_PROBE_REPORT_ADAPTER.validate_json(result.stdout)


def _run_helper_client_pipe_acl_probe(
    pipe_name: str,
    expected_gateway_sid: str,
) -> ClientPipeAclProbeReport:
    """Test-only expanded Helper template을 같은 client-handle probe로 검증합니다."""
    command = f"""
import json
import sys

sys.path.insert(0, {str(CLIENT_PIPE_ACL_PROBE_PATH.parent)!r})
from client_pipe_acl_probe import probe_client_pipe_acl
from hermes_windows_bridge.ipc.acl import PipeAcl, build_privileged_pipe_acl

expected = PipeAcl((*build_privileged_pipe_acl().allowed_sids, sys.argv[2]))
result = probe_client_pipe_acl(sys.argv[1], expected)
print(json.dumps({{
    "opened": result.opened,
    "daclRead": result.dacl_read,
    "exactTemplate": result.exact_template,
}}, separators=(",", ":")))
"""
    result = subprocess.run(
        [sys.executable, "-c", command, pipe_name, expected_gateway_sid],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    return CLIENT_PIPE_ACL_PROBE_REPORT_ADAPTER.validate_json(result.stdout)


def _gateway_recovery_probe_from_script() -> str:
    """Guest PowerShell이 실제 subprocess에 전달할 SDK recovery body를 추출합니다."""
    source = SCRIPT_PATH.read_text(encoding="utf-8-sig")
    marker = "$gatewayRecoveryProbe = @'\n"
    start = source.index(marker) + len(marker)
    end = source.index("\n'@", start)
    return source[start:end]


def _reserve_loopback_port() -> int:
    """고유 local Gateway fixture에 넘길 포트를 한 번 예약합니다."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        address = TypeAdapter(tuple[str, int]).validate_python(listener.getsockname())
        return address[1]


def _wait_for_loopback_server(process: subprocess.Popen[str], port: int) -> None:
    """bounded connect로 fixture server가 실제 listen한 뒤 child를 시작합니다."""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            message = "gateway_fixture_exited_before_listen"
            raise AssertionError(message)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    message = "gateway_fixture_did_not_listen"
    raise AssertionError(message)


def _serve_worker_for_metadata_recovery(
    pipe_name: str,
    sid: str,
    stop: Event,
    ready: Event,
) -> None:
    """실제 Worker accept loop를 고유 fixture로 한정합니다."""

    def create_signaled_pipe(
        endpoint: PipeEndpoint,
        *,
        pipe_name: str | None = None,
        target_user_sid: str | None = None,
        expected_peer_sid: str | None = None,
    ) -> NamedPipeServer:
        del endpoint
        server = create_server_pipe(
            PipeEndpoint.WORKER,
            pipe_name=pipe_name,
            target_user_sid=target_user_sid,
            expected_peer_sid=expected_peer_sid,
        )
        ready.set()
        return server

    with patch.object(worker_pipe_server, "create_server_pipe", create_signaled_pipe):
        serve_worker_pipe(
            WorkerPipeConfig(
                pipe_name=pipe_name,
                target_user_sid=sid,
                registration=WorkerRegistration(
                    registration_id=uuid4(),
                    generation=1,
                    session_id=1,
                    username="TEST\\worker",
                ),
                expected_gateway_sid=sid,
                heartbeat_interval_seconds=0.05,
            ),
            _MetadataRecoveryDispatcher(),
            stop,
        )


def _serve_helper_for_metadata_recovery(
    pipe_name: str,
    sid: str,
    stop: Event,
    ready: Event,
) -> None:
    """실제 PrivilegedHelperRuntime loop를 nonce Helper fixture pipe seam으로 구동합니다."""

    def create_signaled_pipe(endpoint: PipeEndpoint) -> NamedPipeServer:
        del endpoint
        server = create_server_pipe(
            PipeEndpoint.PRIVILEGED_HELPER,
            pipe_name=pipe_name,
            expected_peer_sid=sid,
        )
        ready.set()
        return server

    runtime = PrivilegedHelperRuntime(
        executor=_NoopPowerActionExecutor(),
        config=HelperRuntimeConfig(
            registration=HelperRegistration(registration_id=uuid4(), generation=1),
            heartbeat_interval_seconds=0.05,
        ),
        pipe_factory=create_signaled_pipe,
        peer_session_id=lambda _: 0,
    )
    with patch.object(
        PrivilegedHelperRuntime,
        "_validate_gateway_peer",
        staticmethod(_accept_fixture_peer),
    ):
        runtime.run_pipe_loop(stop_requested=stop.is_set)


def test_guest_security_checks_default_is_planned_and_has_no_mutation_commands() -> None:
    """기본 호출은 guest filesystem·service·pipe에 접근하지 않는 계획만 반환합니다."""
    result = subprocess.run(
        [
            POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(SCRIPT_PATH),
            "-Nonce",
            str(NONCE),
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=15,
    )

    receipt = PLANNED_RECEIPT_ADAPTER.validate_json(result.stdout)
    assert result.returncode == 0, result.stderr
    assert receipt == {
        "schemaVersion": 1,
        "nonce": str(NONCE),
        "outcome": "planned",
        "executionStage": "dry_run",
        "writes": False,
    }
    assert str(NONCE) in result.stdout
    assert "C:\\HermesTask6" not in result.stdout


def test_guest_security_checks_probes_write_access_only_with_explorer_impersonation() -> None:
    """실제 access probe는 write-open만 하며 임의 명령·서비스 조작을 포함하지 않습니다."""
    source = SCRIPT_PATH.read_text(encoding="utf-8-sig")

    assert "GENERIC_WRITE = 0x40000000" in source
    assert "OPEN_EXISTING = 3" in source
    assert "DuplicateTokenEx" in source
    assert "ImpersonateLoggedOnUser" in source
    assert "RevertToSelf" in source
    assert "RevertSucceeded" in source
    assert "PipeMetadataResult" in source
    assert "ConnectionConsumed" in source
    assert "FixtureRemoved" in source
    assert "ExpectedTokenProbeSha256" in source
    assert "TokenProbeText" not in source
    assert source.index("if (-not $file.RevertSucceeded)") < source.index(
        "$directory = [HermesEval.SecurityAccessProbe]::Probe"
    )
    assert "Set-Acl" not in source
    assert "Remove-Item -LiteralPath $releaseRoot -Recurse -Force" in source


def test_guest_security_checks_receipt_exposes_only_fixed_result_categories() -> None:
    """실패 receipt에는 raw path·SDDL·예외 메시지를 넣지 않는 allowlist를 고정합니다."""
    source = SCRIPT_PATH.read_text(encoding="utf-8-sig")

    assert "$script:AllowedFailureReasons" in source
    assert "access_probe_unverified" in source
    assert "immutable_write_not_denied" in source
    assert "pipe_metadata_probe_unverified" in source
    assert "Exception.Message" not in source
    assert "Get-Acl" not in source


def test_guest_security_checks_requires_a_hash_bound_live_pipe_probe() -> None:
    """live DACL 성공은 nonce-root의 hash-bound client probe와 recovery 없이는 성립하지 않습니다."""
    source = SCRIPT_PATH.read_text(encoding="utf-8-sig")

    assert "PipeAclProbePath" in source
    assert "ExpectedPipeAclProbeSha256" in source
    assert "Test-LivePipeDaclAndRecovery" in source
    assert "registration_cleanup" in source


def test_live_pipe_stage_keeps_cleanup_before_tamper() -> None:
    """등록 cleanup 실패 시 실행 중 fixture를 삭제하지 않고 성공 순서를 고정합니다."""
    source = SCRIPT_PATH.read_text(encoding="utf-8-sig")

    live_stage = source.index("$live = Test-LivePipeDaclAndRecovery -Registration $registration")
    registration_cleanup = source.index(
        "$receipt.cleanup.registrationsRemoved = Remove-TemporarySecurityComponents $registration",
        live_stage,
    )
    tamper_stage = source.index("$contract = Test-IsolatedFixtureTamperContract")
    assert live_stage < registration_cleanup < tamper_stage
    finally_guard = source.index(
        "if ($null -ne $fixture -and $receipt.cleanup.registrationsRemoved)"
    )
    assert finally_guard > tamper_stage


def test_live_pipe_stage_requires_two_exact_dacls_and_two_online_status_samples(
    tmp_path: Path,
) -> None:
    """hash-bound probe와 MCP status 두 sample이 모두 true일 때만 recovery를 통과합니다."""
    probe_path = tmp_path / "client_pipe_acl_probe.py"
    _ = probe_path.write_text("# hash-bound fixture\n", encoding="utf-8")
    probe_hash = hashlib.sha256(probe_path.read_bytes()).hexdigest()
    command = f"""
$scriptPath = '{SCRIPT_PATH}'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) {{ throw 'parse_failed' }}
$names = @('Fail-SecurityCheck', 'Assert-AdapterApplied', 'Test-LivePipeDaclAndRecovery')
$definitions = @($ast.FindAll({{
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $names
}}, $true))
if ($definitions.Count -ne 3) {{ throw 'live_pipe_functions_missing' }}
foreach ($definition in $definitions) {{ . ([scriptblock]::Create($definition.Extent.Text)) }}
$script:AllowedFailureReasons = @('live_pipe_dacl_unverified', 'gateway_recovery_unverified')
$script:VerifiedOutputRoot = '{tmp_path}'
$ExpectedPipeAclProbeSha256 = '{probe_hash}'
$PipeAclProbePath = '{probe_path}'
function Import-VerifiedRegistrationAdapter {{ param($ScriptRoot) }}
$script:childCalls = 0
function Invoke-BridgeChildProcess {{
    param($FilePath, $ArgumentList, $WorkingDirectory, $TimeoutSeconds)
    $script:childCalls++
    if ($script:childCalls -le 2) {{
        return [pscustomobject]@{{
            exitCode = 0
            stdout = '{{"opened":true,"daclRead":true,"exactTemplate":true}}'
        }}
    }}
    return [pscustomobject]@{{ exitCode = 0; stdout = '{{"gatewayRecoveryVerified":true}}' }}
}}
function Invoke-BridgeRegistrationAdapter {{
    param(
        $ScriptRoot, $ScriptName, $ArgumentList, $AdapterMode, $Operation,
        $ExpectedName, $ExpectedAccount, $ExpectedArgv
    )
    return [pscustomobject]@{{
        state = 'applied'
        applied = $true
        readBack = [pscustomobject]@{{ exact = $true; state = 'desired' }}
    }}
}}
function Start-Service {{ param($Name) }}
function Get-Service {{
    param($Name)
    $service = [pscustomobject]@{{}}
    $service | Add-Member -MemberType ScriptMethod -Name WaitForStatus -Value {{
        param($Status, $Timeout)
    }}
    $service | Add-Member -MemberType ScriptMethod -Name Dispose -Value {{ }}
    return $service
}}
function Get-RemainingSeconds {{ return 60 }}
$registration = [pscustomobject]@{{
    sourceRoot = '{tmp_path}'
    manifestPath = 'C:\\fixture\\release-manifest.json'
    releaseRoot = 'C:\\fixture\\release'
    serviceExecutable = '{POWERSHELL_PATH}'
    workerExecutable = 'C:\\fixture\\pythonw.exe'
    workerUserId = 'TEST\\worker'
    workerSid = 'S-1-5-21-1-2-3-4'
    gatewayRegistered = $false
}}
$result = Test-LivePipeDaclAndRecovery -Registration $registration
$summary = [ordered]@{{
    dacl = [bool]$result.livePipeDaclVerified
    recovery = [bool]$result.gatewayRecoveryVerified
    childCalls = [int]$script:childCalls
    gatewayOwned = [bool]$registration.gatewayRegistered
}}
$summary | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "dacl": True,
        "recovery": True,
        "childCalls": 3,
        "gatewayOwned": True,
    }


@pytest.mark.integration
def test_gateway_recovery_probe_reads_production_sse_in_a_child_subprocess(
    tmp_path: Path,
) -> None:
    """json_response=False production MCP 응답은 guest child가 SDK로만 안전하게 판정합니다."""
    port = _reserve_loopback_port()
    program_data = tmp_path / "ProgramData"
    runtime = program_data / "HermesWindowsBridge"
    runtime.mkdir(parents=True)
    token_file = runtime / "token"
    _ = token_file.write_text("fixture-gateway-token", encoding="utf-8")
    config = {
        "paths": {
            "program_data": str(runtime),
            "user_data": str(runtime),
            "token_file": str(token_file),
        },
        "server": {
            "port": port,
            "allowed_hosts": ["127.0.0.1"],
            "allowed_origins": ["http://localhost"],
        },
        "tailscale": {"require_app_capability": False},
    }
    _ = (runtime / "config.yaml").write_text(json.dumps(config), encoding="utf-8")
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("HERMES_BRIDGE_")
    }
    environment["ProgramData"] = str(program_data)
    gateway_command = f"""
from threading import Thread
from time import sleep
from uuid import UUID

import uvicorn

from hermes_windows_bridge.gateway.main import GatewayRegistries, build_gateway_server
from hermes_windows_bridge.gateway.origin_host import GatewayTransportPolicy
from hermes_windows_bridge.ipc.protocol import (
    Heartbeat,
    HelperHeartbeat,
    HelperRegistration,
    IpcResponse,
    WorkerRegistration,
)
from hermes_windows_bridge.privileged.ipc_server import HelperRegistry
from hermes_windows_bridge.worker.ipc_client import WorkerRegistry


class Endpoint:
    def exchange(self, request):
        return IpcResponse(
            request_id=request.request_id,
            ok=True,
            payload={{
                'username': 'TEST\\\\worker',
                'session_id': 1,
                'desktop_unlocked': True,
                'remote_input_enabled': True,
                'active_window': {{'title': 'fixture', 'process': 'fixture.exe'}},
            }},
        )

    def cancel(self, request_id, reason):
        return False


endpoint = Endpoint()
workers = WorkerRegistry()
worker_registration = WorkerRegistration(
    registration_id=UUID('00000000-0000-4000-8000-000000000001'),
    generation=1,
    session_id=1,
    username='TEST\\\\worker',
)
workers.register(worker_registration, endpoint)
helpers = HelperRegistry()
helper_registration = HelperRegistration(
    registration_id=UUID('00000000-0000-4000-8000-000000000002'),
    generation=1,
)
helpers.register_transport(helper_registration, endpoint)


def heartbeat_loop():
    sequence = 0
    while True:
        workers.heartbeat(
            Heartbeat(
                registration_id=worker_registration.registration_id,
                sequence=sequence,
                session_id=worker_registration.session_id,
                username=worker_registration.username,
            )
        )
        helpers.heartbeat(
            HelperHeartbeat(
                registration_id=helper_registration.registration_id,
                sequence=sequence,
            )
        )
        sequence += 1
        sleep(5)


Thread(target=heartbeat_loop, daemon=True).start()
server = build_gateway_server(
    'fixture-gateway-token',
    registries=GatewayRegistries(workers, helpers),
)
app = server.streamable_http_app(
    streamable_http_path='/mcp',
    json_response=False,
    host='127.0.0.1',
    transport_security=GatewayTransportPolicy(
        allowed_hosts=('127.0.0.1',),
        allowed_origins=('http://localhost',),
    ).sdk_settings(),
)
uvicorn.run(app, host='127.0.0.1', port={port}, log_level='error')
"""
    process = subprocess.Popen(
        [sys.executable, "-I", "-B", "-c", gateway_command],
        cwd=PROJECT_ROOT,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        _wait_for_loopback_server(process, port)
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", _gateway_recovery_probe_from_script()],
            cwd=PROJECT_ROOT,
            env=environment,
            check=False,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            text=True,
            timeout=30,
        )
    finally:
        process.terminate()
        _ = process.wait(timeout=5)

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"gatewayRecoveryVerified": True}


def test_guest_security_checks_uses_the_verified_registration_adapter_and_owned_context() -> None:
    """임시 registration은 공통 검증 adapter를 쓰고 caller finally가 소유합니다."""
    source = SCRIPT_PATH.read_text(encoding="utf-8-sig")

    assert "function Invoke-EvalRegistrationAdapter" not in source
    assert "Invoke-BridgeRegistrationAdapter" in source
    context_index = source.index(
        "$registration = New-TemporaryRegistrationContext -Fixture $fixture"
    )
    assert context_index < source.index(
        "Register-TemporarySecurityComponents -Registration $registration"
    )
    assert "Remove-TemporarySecurityComponents $registration" in source
    assert "$receipt.cleanup.registrationsRemoved" in source


def test_verified_registration_adapter_is_imported_into_the_registration_scope(
) -> None:
    """공통 adapter는 helper-local scope가 아니라 Register caller scope에 정의되어야 합니다."""
    command = f"""
$scriptPath = '{SCRIPT_PATH}'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) {{ throw 'parse_failed' }}
$definition = @($ast.FindAll({{
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Import-VerifiedRegistrationAdapter'
}}, $true))
if ($definition.Count -ne 1) {{ throw 'import_function_missing' }}
. ([scriptblock]::Create($definition[0].Extent.Text))
function Fail-SecurityCheck {{ throw 'unexpected_failure' }}
. Import-VerifiedRegistrationAdapter -ScriptRoot '{PROJECT_ROOT / 'scripts'}'
$adapter = Get-Command Invoke-BridgeRegistrationAdapter `
    -CommandType Function -ErrorAction SilentlyContinue
if ($null -eq $adapter) {{
    throw 'adapter_not_exported'
}}
'adapter_available'
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "adapter_available"


def test_pristine_contract_flag_is_set_only_after_baseline_verification() -> None:
    """Build 성공만으로 pristine contract 검증 성공을 receipt에 기록하지 않습니다."""
    source = SCRIPT_PATH.read_text(encoding="utf-8-sig")

    assert source.index("$contract = Test-IsolatedFixtureTamperContract") < source.index(
        "$receipt.pristineLaunchContractVerified = $contract.pristineLaunchContractVerified"
    )


def test_safe_receipt_persists_its_success_flag(tmp_path: Path) -> None:
    """성공 write의 디스크 receipt도 persisted=true여야 host가 완료를 신뢰할 수 있습니다."""
    command = f"""
$scriptPath = '{SCRIPT_PATH}'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) {{ throw 'parse_failed' }}
$definition = @($ast.FindAll({{
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Write-SafeReceipt'
}}, $true))
if ($definition.Count -ne 1) {{ throw 'receipt_function_missing' }}
. ([scriptblock]::Create($definition[0].Extent.Text))
$script:VerifiedOutputRoot = '{tmp_path}'
$script:ReceiptPersisted = $false
$receipt = [ordered]@{{ receiptPersisted = $false; outcome = 'passed' }}
$returned = Write-SafeReceipt $receipt
$diskPath = Join-Path $script:VerifiedOutputRoot 'security-result.json'
$disk = Get-Content -LiteralPath $diskPath -Raw | ConvertFrom-Json
[ordered]@{{
    returned = [bool]$returned
    memory = [bool]$receipt.receiptPersisted
    disk = [bool]$disk.receiptPersisted
}} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "returned": True,
        "memory": True,
        "disk": True,
    }


def test_fixture_cleanup_rejects_outside_source_before_delete() -> None:
    """Fixture source가 verified nonce root 밖이면 Remove-Item에 도달하지 않습니다."""
    command = f"""
$scriptPath = '{SCRIPT_PATH}'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) {{ throw 'parse_failed' }}
$definition = @($ast.FindAll({{
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Remove-IsolatedFixture'
}}, $true))
if ($definition.Count -ne 1) {{ throw 'cleanup_function_missing' }}
. ([scriptblock]::Create($definition[0].Extent.Text))
function Remove-Item {{ throw 'unexpected_delete' }}
$script:VerifiedOutputRoot = 'C:\\HermesTask6\\{NONCE}'
$fixture = [pscustomobject]@{{
    sourceRoot = 'C:\\Users\\DW\\unowned-source'
    releaseRoot = 'C:\\Program Files\\HermesWindowsBridge\\releases\\{'a' * 64}'
    stagingRoot = 'C:\\Program Files\\HermesWindowsBridge\\staging\\owned-fixture'
}}
$removed = Remove-IsolatedFixture $fixture
[ordered]@{{ removed = [bool]$removed; mutationAttempted = $false }} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"removed": False, "mutationAttempted": False}


def test_bound_fixture_copy_selects_complete_build_inputs_and_excludes_extra(
    tmp_path: Path,
) -> None:
    """Binding-listed build inputs만 선택하고 unbound extra는 fixture input이 아닙니다."""
    input_root = tmp_path / "input"
    source_root = tmp_path / "source"
    input_root.mkdir()
    source_root.mkdir()
    bound_files = {
        "pyproject.toml": "[project]\nname = 'fixture'\n",
        "uv.lock": "version = 1\n",
        ".python-version": "3.14\n",
        "scripts/build.ps1": "# bound script\n",
        "src/bridge.py": "# bound module\n",
    }
    inventory: list[dict[str, str | int]] = []
    for relative_path, content in bound_files.items():
        source_path = source_root / relative_path
        _ = source_path.parent.mkdir(parents=True, exist_ok=True)
        _ = source_path.write_text(content, encoding="utf-8")
        digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
        inventory.append(
            {"relativePath": relative_path, "sha256": digest, "size": source_path.stat().st_size}
        )
    unbound_extra = source_root / "scripts" / "unbound-extra.ps1"
    _ = unbound_extra.write_text("# never copied\n", encoding="utf-8")
    _ = (input_root / "task6-input-binding.json").write_text(
        json.dumps({"inputFiles": inventory}), encoding="utf-8"
    )
    binding_hash = hashlib.sha256(
        (input_root / "task6-input-binding.json").read_bytes()
    ).hexdigest()
    command = f"""
$scriptPath = '{SCRIPT_PATH}'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) {{ throw 'parse_failed' }}
$names = @(
    'Fail-SecurityCheck',
    'Assert-ExistingRegularDirectory',
    'Assert-FixtureSourceMatchesInput'
)
$definitions = @($ast.FindAll({{
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -in $names
}}, $true))
if ($definitions.Count -ne 3) {{ throw 'fixture_source_functions_missing' }}
$script:AllowedFailureReasons = @('tamper_fixture_unverified')
$script:FailureReason = $null
foreach ($definition in $definitions) {{ . ([scriptblock]::Create($definition.Extent.Text)) }}
$ExpectedInputRoot = '{input_root}'
$ExpectedInputBindingSha256 = '{binding_hash}'
$FixtureSourceRoot = '{source_root}'
$selected = Assert-FixtureSourceMatchesInput
$paths = @($selected.verifiedFiles | ForEach-Object {{ [string]$_.relativePath }} | Sort-Object)
$paths | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == sorted(bound_files)
    source = SCRIPT_PATH.read_text(encoding="utf-8-sig")
    assert "foreach ($file in @($Source.verifiedFiles))" in source
    assert "Copy-Item -LiteralPath $Source.sourceRoot" not in source


def test_unique_pipe_metadata_open_consumes_connection_and_fixture_is_disposed() -> None:
    """고유 fixture에서 metadata-only pipe open의 연결 소비를 실제 PS5로 고정합니다."""
    command = f"""
$scriptPath = '{SCRIPT_PATH}'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) {{ throw 'parse_failed' }}
$definitions = @($ast.FindAll({{
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -in @('Initialize-EvalSecurityNative', 'Test-PipeMetadataOpenSafety')
}}, $true))
if ($definitions.Count -ne 2) {{ throw 'fixture_functions_missing' }}
foreach ($definition in $definitions) {{ . ([scriptblock]::Create($definition.Extent.Text)) }}
$Nonce = [guid]'{NONCE}'
$script:AllowedFailureReasons = @('pipe_metadata_probe_unverified')
$script:FailureReason = $null
$probe = Test-PipeMetadataOpenSafety
[ordered]@{{
    openSucceeded = [bool]$probe.openSucceeded
    waitResult = [string]$probe.waitResult
    daclReadSucceeded = [bool]$probe.daclReadSucceeded
    metadataOpenConsumesConnection = [bool]$probe.connectionConsumed
    cleanupSucceeded = [bool]$probe.cleanupSucceeded
    fixedBridgePipesAccessed = $false
}} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=15,
    )

    report = PIPE_FIXTURE_REPORT_ADAPTER.validate_python(json.loads(result.stdout))
    assert result.returncode == 0, result.stderr
    assert report == {
        "openSucceeded": True,
        "waitResult": "connected",
        "daclReadSucceeded": True,
        "metadataOpenConsumesConnection": True,
        "cleanupSucceeded": True,
        "fixedBridgePipesAccessed": False,
    }


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "win32", reason="Windows named pipe required")
def test_client_pipe_acl_probe_rejects_a_mismatching_exact_template() -> None:
    """실제 client READ_CONTROL DACL이 다른 template이면 raw descriptor 없이 거부됩니다."""
    target_sid = current_process_sid()
    pipe_name = rf"\\.\pipe\HermesWindowsBridgeEvalAclMismatch-{uuid4()}"

    with create_server_pipe(
        PipeEndpoint.WORKER,
        pipe_name=pipe_name,
        target_user_sid=target_sid,
        expected_peer_sid=target_sid,
    ):
        report = _run_client_pipe_acl_probe(pipe_name, "S-1-5-21-1-2-3-4")

    assert report == {
        "opened": True,
        "daclRead": True,
        "exactTemplate": False,
    }


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "win32", reason="Windows named pipe required")
def test_metadata_only_open_on_worker_pipe_recovers_to_normal_handshake() -> None:
    """Metadata-only open으로 끊긴 실제 Worker accept loop가 다음 handshake를 받습니다."""
    context = multiprocessing.get_context("spawn")
    stop = context.Event()
    ready = context.Event()
    metadata_name = f"HermesWindowsBridgeEvalMetadataRecovery-{uuid4()}"
    pipe_name = rf"\\.\pipe\{metadata_name}"
    sid = current_process_sid()
    process = context.Process(
        target=_serve_worker_for_metadata_recovery,
        args=(pipe_name, sid, stop, ready),
    )
    registry = WorkerRegistry()
    watcher = GatewayWorkerWatcher(pipe_name, registry, connect_timeout_ms=200)
    watcher_thread = Thread(target=watcher.run, daemon=True)
    watcher_started = False
    process.start()
    try:
        assert ready.wait(3), process.exitcode
        probe_report = _run_client_pipe_acl_probe(pipe_name, sid)
        assert probe_report == {
            "opened": True,
            "daclRead": True,
            "exactTemplate": True,
        }
        watcher_thread.start()
        watcher_started = True
        assert watcher.wait_for_connections(1, timeout_seconds=3)
        assert watcher.wait_for_heartbeats(1, timeout_seconds=1)
    finally:
        watcher.close()
        stop.set()
        process.join(3)
        if process.is_alive():
            process.terminate()
            process.join(2)
        if watcher_started:
            watcher_thread.join(2)

    assert process.exitcode == 0


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "win32", reason="Windows named pipe required")
def test_metadata_only_open_on_helper_pipe_recovers_to_normal_handshake(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Metadata-only open 뒤 Helper fixture가 다음 Gateway handshake를 수용합니다."""
    context = multiprocessing.get_context("spawn")
    stop = context.Event()
    ready = context.Event()
    metadata_name = f"HermesWindowsBridgeEvalHelperMetadataRecovery-{uuid4()}"
    pipe_name = rf"\\.\pipe\{metadata_name}"
    sid = current_process_sid()
    # Test process는 LocalService가 아니므로 fixture DACL에만 current-user ACE를 추가합니다.
    # 이 expanded template은 fixed production Helper ACL의 security proof가 아닙니다.
    fixture_acl = PipeAcl((*build_privileged_pipe_acl().allowed_sids, sid))
    monkeypatch.setattr(helper_runtime, "build_privileged_pipe_acl", lambda: fixture_acl)
    process = context.Process(
        target=_serve_helper_for_metadata_recovery,
        args=(pipe_name, sid, stop, ready),
    )
    registry = HelperRegistry()
    watcher = GatewayHelperWatcher(pipe_name, registry, connect_timeout_ms=200)
    watcher_thread = Thread(target=watcher.run, daemon=True)
    watcher_started = False
    process.start()
    try:
        assert ready.wait(3), process.exitcode
        probe_report = _run_helper_client_pipe_acl_probe(pipe_name, sid)
        assert probe_report == {
            "opened": True,
            "daclRead": True,
            "exactTemplate": True,
        }
        watcher_thread.start()
        watcher_started = True
        assert watcher.wait_for_connections(1, timeout_seconds=3)
        assert watcher.wait_for_heartbeats(1, timeout_seconds=1)
    finally:
        watcher.close()
        stop.set()
        process.join(3)
        if process.is_alive():
            process.terminate()
            process.join(2)
        if watcher_started:
            watcher_thread.join(2)

    assert process.exitcode == 0
