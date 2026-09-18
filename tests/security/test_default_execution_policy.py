"""기본 실행 정책을 보존하는 PowerShell 자식 실행 계약입니다."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

PROJECT_ROOT: Final = Path(__file__).parents[2]
ACTIVE_SCRIPT_PATHS: Final = (
    "scripts/lifecycle-common.ps1",
    "scripts/service-runtime-transaction.ps1",
    "scripts/install.ps1",
    "scripts/rotate-token.ps1",
    "scripts/recover-service-switch.ps1",
)
TEST_LAUNCHER_PATHS: Final = (
    "tests/smoke/test_doctor_basic.py",
    "tests/smoke/test_doctor_pipe_acl.py",
    "tests/smoke/test_install_journal.py",
    "tests/smoke/test_installer_static.py",
    "tests/smoke/test_lifecycle_adversarial.py",
    "tests/smoke/test_scripts.py",
    "tests/smoke/test_tailscale_lifecycle.py",
    "tests/security/test_emergency_stop.py",
    "tests/security/test_public_exposure.py",
    "tests/security/test_runtime_access_contract.py",
    "tests/security/test_secret_acl.py",
    "tests/security/test_service_host_packaging.py",
    "tests/security/test_service_host_registration.py",
    "tests/security/test_service_host_transaction.py",
    "tests/security/test_service_runtime_build.py",
    "tests/security/test_service_runtime_contract.py",
    "tests/security/test_service_runtime_doctor.py",
    "tests/security/test_service_runtime_launch.py",
    "tests/security/test_service_runtime_transaction.py",
    "tests/integration/test_eval_registration_arguments.py",
    "tests/integration/test_eval_security_launcher.py",
    "tests/integration/test_service_runtime_deployment.py",
    "tests/integration/test_tailscale_script.py",
)
POLICY_OVERRIDE_ARGUMENT_PAIR: Final = re.compile(
    r"[\"']-ExecutionPolicy[\"']\s*,\s*[\"']Bypass[\"']"
)


def test_active_powershell_children_do_not_override_execution_policy() -> None:
    """활성 PowerShell 자식 실행 인자 배열에 정책 우회 쌍이 없음을 확인합니다."""

    for relative_path in ACTIVE_SCRIPT_PATHS:
        source = (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")
        assert "-NoProfile" in source, relative_path
        assert "-NonInteractive" in source, relative_path
        assert "-File" in source, relative_path
        assert POLICY_OVERRIDE_ARGUMENT_PAIR.search(source) is None, relative_path


def test_actual_test_launchers_do_not_override_execution_policy() -> None:
    """실행되는 테스트 자식 인자 배열에 정책 우회 쌍이 없음을 확인합니다."""

    for relative_path in TEST_LAUNCHER_PATHS:
        source = (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")
        assert POLICY_OVERRIDE_ARGUMENT_PAIR.search(source) is None, relative_path
