"""Task 1 프로젝트 레이아웃 계약을 검증합니다."""

from pathlib import Path
from typing import Final

PROJECT_ROOT: Final = Path(__file__).parents[2]
REQUIRED_PATHS: Final = (
    Path("pyproject.toml"),
    Path("uv.lock"),
    Path("README.md"),
    Path("LICENSE"),
    Path(".gitignore"),
    Path(".env.example"),
    Path("config/config.example.yaml"),
    Path("config/policy.example.yaml"),
    Path("scripts/install.ps1"),
    Path("scripts/uninstall.ps1"),
    Path("scripts/register-gateway-service.ps1"),
    Path("scripts/register-privileged-service.ps1"),
    Path("scripts/register-worker-task.ps1"),
    Path("scripts/configure-tailscale.ps1"),
    Path("scripts/rotate-token.ps1"),
    Path("scripts/enable-remote-input.ps1"),
    Path("scripts/doctor.ps1"),
    Path("scripts/dev-run.ps1"),
    Path("src/hermes_windows_bridge/__init__.py"),
    Path("src/hermes_windows_bridge/__main__.py"),
    Path("src/hermes_windows_bridge/config.py"),
    Path("src/hermes_windows_bridge/logging_setup.py"),
    Path("src/hermes_windows_bridge/gateway/__init__.py"),
    Path("src/hermes_windows_bridge/gateway/main.py"),
    Path("src/hermes_windows_bridge/gateway/windows_service.py"),
    Path("src/hermes_windows_bridge/gateway/mcp_server.py"),
    Path("src/hermes_windows_bridge/gateway/auth.py"),
    Path("src/hermes_windows_bridge/gateway/origin_host.py"),
    Path("src/hermes_windows_bridge/gateway/tailscale_identity.py"),
    Path("src/hermes_windows_bridge/gateway/policy.py"),
    Path("src/hermes_windows_bridge/gateway/dispatcher.py"),
    Path("src/hermes_windows_bridge/gateway/idempotency.py"),
    Path("src/hermes_windows_bridge/gateway/jobs.py"),
    Path("src/hermes_windows_bridge/gateway/audit.py"),
    Path("src/hermes_windows_bridge/worker/__init__.py"),
    Path("src/hermes_windows_bridge/worker/main.py"),
    Path("src/hermes_windows_bridge/worker/ipc_client.py"),
    Path("src/hermes_windows_bridge/worker/desktop.py"),
    Path("src/hermes_windows_bridge/worker/desktop_lock.py"),
    Path("src/hermes_windows_bridge/worker/uia.py"),
    Path("src/hermes_windows_bridge/worker/shell.py"),
    Path("src/hermes_windows_bridge/worker/filesystem.py"),
    Path("src/hermes_windows_bridge/worker/path_safety.py"),
    Path("src/hermes_windows_bridge/worker/processes.py"),
    Path("src/hermes_windows_bridge/worker/browser.py"),
    Path("src/hermes_windows_bridge/worker/codex.py"),
    Path("src/hermes_windows_bridge/worker/job_object.py"),
    Path("src/hermes_windows_bridge/privileged/__init__.py"),
    Path("src/hermes_windows_bridge/privileged/main.py"),
    Path("src/hermes_windows_bridge/privileged/windows_service.py"),
    Path("src/hermes_windows_bridge/privileged/ipc_server.py"),
    Path("src/hermes_windows_bridge/privileged/operations.py"),
    Path("src/hermes_windows_bridge/ipc/__init__.py"),
    Path("src/hermes_windows_bridge/ipc/protocol.py"),
    Path("src/hermes_windows_bridge/ipc/named_pipe.py"),
    Path("src/hermes_windows_bridge/ipc/acl.py"),
    Path("src/hermes_windows_bridge/ipc/framing.py"),
    Path("src/hermes_windows_bridge/tools/__init__.py"),
    Path("src/hermes_windows_bridge/tools/status.py"),
    Path("src/hermes_windows_bridge/tools/shell.py"),
    Path("src/hermes_windows_bridge/tools/filesystem.py"),
    Path("src/hermes_windows_bridge/tools/process.py"),
    Path("src/hermes_windows_bridge/tools/computer.py"),
    Path("src/hermes_windows_bridge/tools/browser.py"),
    Path("src/hermes_windows_bridge/tools/codex.py"),
    Path("src/hermes_windows_bridge/tools/jobs.py"),
    Path("src/hermes_windows_bridge/tools/system.py"),
    Path("src/hermes_windows_bridge/models/__init__.py"),
    Path("src/hermes_windows_bridge/models/common.py"),
    Path("src/hermes_windows_bridge/models/tool_results.py"),
    Path("src/hermes_windows_bridge/models/operation.py"),
    Path("src/hermes_windows_bridge/models/policy.py"),
    Path("tests/unit"),
    Path("tests/integration"),
    Path("tests/security"),
    Path("tests/smoke"),
)


def test_required_paths_exist_when_project_is_scaffolded() -> None:
    # Given: 명세와 Task 1이 요구하는 저장소 경로 목록입니다.
    required_paths = tuple(PROJECT_ROOT / path for path in REQUIRED_PATHS)

    # When: 현재 워크스페이스에서 누락 경로를 찾습니다.
    missing_paths = tuple(
        str(path.relative_to(PROJECT_ROOT)) for path in required_paths if not path.exists()
    )

    # Then: 모든 스캐폴드 경로가 존재해야 합니다.
    assert missing_paths == ()
