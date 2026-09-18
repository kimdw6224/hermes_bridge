"""Windows 시작 구성의 권한 경계를 검증합니다."""

from __future__ import annotations

import ast
import shutil
import subprocess
import sys
from pathlib import Path
from typing import ClassVar, Final

import pytest
from pydantic import BaseModel, ConfigDict

from hermes_windows_bridge.gateway.windows_service import GATEWAY_SERVICE
from hermes_windows_bridge.privileged import ipc_server, operations
from hermes_windows_bridge.privileged.operations import (
    PrivilegedOperation,
    parse_privileged_operation,
    supported_operations,
)
from hermes_windows_bridge.privileged.windows_service import PRIVILEGED_SERVICE
from hermes_windows_bridge.worker.main import build_worker_task_manifest

PROJECT_ROOT: Final = Path(__file__).parents[2]
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None


class DryRunManifest(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    mode: str
    installed: bool
    state: str
    account: str
    argv: list[str]


def _run_script(script_name: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(PROJECT_ROOT / "scripts" / script_name),
            *arguments,
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


class TestServiceAccounts:
    def test_gateway_localservice_helper_localsystem_worker_user(self) -> None:
        # Given: 세 구성 요소의 설치 전 manifest입니다.
        worker = build_worker_task_manifest(user_id="CONTOSO\\alice")

        # When: 각 실행 주체를 조회합니다.
        accounts = (GATEWAY_SERVICE.account, PRIVILEGED_SERVICE.account, worker.user_id)

        # Then: 서비스와 대화형 워커의 권한이 분리됩니다.
        assert accounts == (
            "NT AUTHORITY\\LocalService",
            "LocalSystem",
            "CONTOSO\\alice",
        )
        assert worker.logon_type == "InteractiveToken"
        assert worker.run_level == "Limited"

    @pytest.mark.parametrize(
        ("script_name", "arguments", "expected_account"),
        [
            ("register-gateway-service.ps1", (), "NT AUTHORITY\\LocalService"),
            ("register-privileged-service.ps1", (), "LocalSystem"),
            (
                "register-worker-task.ps1",
                ("-UserId", "CONTOSO\\alice"),
                "CONTOSO\\alice",
            ),
        ],
    )
    def test_registration_script_emits_dry_run_manifest(
        self,
        script_name: str,
        arguments: tuple[str, ...],
        expected_account: str,
    ) -> None:
        # Given: 실제 등록 권한이 없는 dry-run 호출입니다.
        result = _run_script(script_name, *arguments)

        # When: 구조화된 출력 manifest를 해석합니다.
        manifest = DryRunManifest.model_validate_json(result.stdout)

        # Then: 설치 성공을 가장하지 않고 의도한 계정만 선언합니다.
        assert result.returncode == 0
        assert manifest.mode == "dry-run"
        assert manifest.installed is False
        assert manifest.account == expected_account
        assert manifest.argv


class TestNoPrivilegedShell:
    def test_no_admin_shell_rpc_or_tool(self) -> None:
        # Given: 권한 helper가 소유한 Python 모듈입니다.
        module_paths = tuple((PROJECT_ROOT / "src/hermes_windows_bridge/privileged").glob("*.py"))

        # When: 외부에 노출되는 함수와 클래스 이름을 AST로 읽습니다.
        symbols: set[str] = set()
        listener_calls: set[str] = set()
        network_imports: set[str] = set()
        for path in module_paths:
            module = ast.parse(path.read_text(encoding="utf-8"))
            symbols.update(
                node.name.casefold()
                for node in ast.walk(module)
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
                and not node.name.startswith("_")
            )
            listener_calls.update(
                node.func.attr.casefold()
                for node in ast.walk(module)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            )
            listener_calls.update(
                node.func.id.casefold()
                for node in ast.walk(module)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            )
            network_imports.update(
                alias.name.casefold()
                for node in ast.walk(module)
                if isinstance(node, ast.Import)
                for alias in node.names
            )

        # Then: generic privileged 실행 표면이나 network listener construction이 없습니다.
        prohibited = {
            name
            for name in symbols
            if "shell" in name
            or "command" in name
            or "elevated" in name
            or "run_as_system" in name
        }
        assert prohibited == set()
        assert listener_calls.isdisjoint({"bind", "listen", "serve", "start_server"})
        assert "socket" not in network_imports

    @pytest.mark.parametrize(
        "operation",
        [
            "run_as_system",
            "shell",
            "execute_command",
            "raw_command",
            "admin_shell",
            "system_shell",
            "elevated",
        ],
    )
    def test_unknown_privileged_operation_is_rejected(self, operation: str) -> None:
        # Given: allowlist에 없는 generic 명령 요청입니다.
        payload = f'{{"operation":"{operation}","argv":["whoami"]}}'

        # When/Then: typed boundary가 요청을 거부합니다.
        with pytest.raises(ValueError, match="privileged operation"):
            _ = parse_privileged_operation(payload)

    def test_typed_allowlist_contains_exactly_reboot_and_shutdown(self) -> None:
        # Given: helper가 외부에 제공하는 operation registry입니다.
        expected = frozenset({"reboot", "shutdown"})

        # When: 지원 operation을 조회합니다.
        actual = supported_operations()

        # Then: generic 실행을 포함한 제3 operation이 추가되지 않았습니다.
        assert actual == expected

    @pytest.mark.parametrize("operation", ["reboot", "shutdown"])
    def test_each_allowlisted_variant_rejects_hostile_extra_field(
        self, operation: PrivilegedOperation
    ) -> None:
        # Given: 정상 operation에 임의 명령 필드를 섞은 요청입니다.
        payload = (
            f'{{"operation":"{operation}","delay_seconds":0,'
            '"reason":"maintenance","raw_command":"whoami"}'
        )

        # When/Then: 각 Pydantic variant가 extra field를 거부합니다.
        with pytest.raises(ValueError, match="privileged operation"):
            _ = parse_privileged_operation(payload)

    def test_helper_exports_no_generic_execution_surface(self) -> None:
        # Given: helper package가 명시적으로 공개한 symbol입니다.
        module_exports = (
            (ipc_server, ipc_server.__all__),
            (operations, operations.__all__),
        )
        exported = {name for _, names in module_exports for name in names}

        # When: export가 실제 존재하는지 확인하고 정규화합니다.
        assert all(hasattr(module, name) for module, names in module_exports for name in names)

        # Then: 명세의 forbidden surface 이름이 없습니다.
        forbidden = ("runassystem", "shell", "executecommand", "rawcommand", "elevated")
        normalized = {name.replace("_", "") for name in exported}
        assert all(token not in name for token in forbidden for name in normalized)

    def test_helper_manifest_observably_disables_network_listener(self) -> None:
        # Given: helper의 공개 service manifest입니다.
        manifest = PRIVILEGED_SERVICE

        # When/Then: helper는 named-pipe 경계 외 network listener를 소유하지 않습니다.
        assert manifest.network_listener is False

    @pytest.mark.parametrize("operation", ["reboot", "shutdown"])
    def test_typed_privileged_allowlist_accepts_only_named_operations(
        self, operation: PrivilegedOperation
    ) -> None:
        # Given: 명세가 허용한 typed operation입니다.
        payload = f'{{"operation":"{operation}","delay_seconds":30,"reason":"maintenance"}}'

        # When: helper 경계에서 파싱합니다.
        parsed = parse_privileged_operation(payload)

        # Then: argv나 raw command 없이 typed operation만 남습니다.
        assert parsed.operation == operation
        assert not hasattr(parsed, "argv")
        assert not hasattr(parsed, "command")


class TestRegistrationInputSafety:
    def test_prompt_injection_username_is_rejected_without_execution(self) -> None:
        # Given: PowerShell 구문을 섞은 신뢰할 수 없는 사용자명입니다.
        marker = "PROMPT_INJECTION_EXECUTED"
        result = _run_script(
            "register-worker-task.ps1",
            "-UserId",
            f"alice; Write-Output {marker}",
        )

        # When/Then: 입력은 실행되지 않고 validation error로 끝납니다.
        assert result.returncode != 0
        assert marker not in result.stdout

    def test_existing_conflicting_manifest_is_reported_as_stale_state(
        self, tmp_path: Path
    ) -> None:
        # Given: 요청과 계정이 다른 기존 manifest입니다.
        manifest_path = tmp_path / "worker.json"
        _ = manifest_path.write_text('{"account":"CONTOSO\\\\bob"}', encoding="utf-8")

        # When: 기존 상태를 검사하는 dry-run을 실행합니다.
        result = _run_script(
            "register-worker-task.ps1",
            "-UserId",
            "CONTOSO\\alice",
            "-ExistingManifestPath",
            str(manifest_path),
        )

        # Then: 설치 성공을 가장하지 않고 충돌을 보고합니다.
        assert result.returncode == 2
        output = DryRunManifest.model_validate_json(result.stdout)
        assert output.installed is False
        assert output.state == "conflict"


def test_worker_manifest_rejects_malformed_account() -> None:
    # Given: account가 아닌 빈 문자열입니다.
    malformed_account = "   "

    # When/Then: trust boundary가 manifest 생성을 거부합니다.
    with pytest.raises(ValueError, match="user account"):
        _ = build_worker_task_manifest(user_id=malformed_account)


def test_service_entrypoints_are_argv_not_shell_strings() -> None:
    # Given: 두 서비스의 실행 manifest입니다.
    manifests = (GATEWAY_SERVICE, PRIVILEGED_SERVICE)

    # When/Then: 실행 표면은 현재 Python, isolated options, argv tuple로 고정됩니다.
    assert all(manifest.argv[0] == sys.executable for manifest in manifests)
    assert all(manifest.argv[1:3] == ("-I", "-B") for manifest in manifests)
    assert all(isinstance(manifest.argv, tuple) for manifest in manifests)
