# ruff: noqa: S604 - `shell`은 subprocess 옵션이 아니라 검증된 도구 schema field입니다.

from __future__ import annotations

import getpass
import socket
import subprocess
import sys
from pathlib import Path
from typing import Literal
from uuid import UUID

import psutil
import pytest

from hermes_windows_bridge.tools.shell import ShellRunInput, ShellTools
from hermes_windows_bridge.worker.shell import (
    GitBashNotInstalledError,
    ShellWorker,
    inspect_command,
)


@pytest.fixture
def shell_tools() -> ShellTools:
    return ShellTools(ShellWorker(max_output_bytes=4_096))


@pytest.mark.integration
class TestShellRun:
    def test_powershell_hostname_runs_as_current_user(self, shell_tools: ShellTools) -> None:
        # Given: 현재 non-elevated 대화형 Worker와 PowerShell hostname 요청입니다.
        request = ShellRunInput(
            operation_id=UUID("00000000-0000-4000-8000-000000000009"),
            command="hostname",
            cwd=Path.home(),
            shell="powershell",
            timeout_s=10,
        )

        # When: 실제 Worker shell adapter를 호출합니다.
        result = shell_tools.shell_run(request)

        # Then: 실제 hostname과 현재 사용자 identity가 성공 결과에 남습니다.
        assert result.exit_code == 0
        assert result.stdout.strip().casefold() == socket.gethostname().casefold()
        assert result.execution_user.casefold().endswith(getpass.getuser().casefold())
        assert result.is_elevated is False
        assert result.timed_out is False

    @pytest.mark.parametrize(
        ("shell", "command", "expected"),
        [
            ("powershell", "Write-Output '한글'", "한글"),
            ("cmd", "echo 한글", "한글"),
            ("git-bash", "printf '한글'", "한글"),
        ],
    )
    def test_supported_shell_argv_executes_literal_command(
        self,
        shell_tools: ShellTools,
        shell: Literal["powershell", "cmd", "git-bash"],
        command: str,
        expected: str,
    ) -> None:
        # Given: 지원 shell별 harmless command입니다.
        request = ShellRunInput(
            operation_id=UUID("00000000-0000-4000-8000-000000000019"),
            command=command,
            cwd=Path.cwd(),
            shell=shell,
        )

        # When: 명시적 argv adapter로 실행합니다.
        try:
            result = shell_tools.shell_run(request)
        except GitBashNotInstalledError:
            if shell == "git-bash":
                pytest.skip("Git Bash is not installed")
            raise

        # Then: command 결과만 반환되고 launcher는 성공합니다.
        assert result.exit_code == 0
        assert result.stdout.strip() == expected

    def test_cwd_is_per_request_and_does_not_become_stale(
        self,
        shell_tools: ShellTools,
        tmp_path: Path,
    ) -> None:
        # Given: 서로 다른 두 cwd 요청입니다.
        first = tmp_path / "first"
        second = tmp_path / "second"
        first.mkdir()
        second.mkdir()

        # When: 같은 Worker에서 순서대로 현재 위치를 조회합니다.
        first_result = shell_tools.shell_run(
            ShellRunInput(
                operation_id=UUID("00000000-0000-4000-8000-000000000029"),
                command="cd",
                cwd=first,
                shell="cmd",
            )
        )
        second_result = shell_tools.shell_run(
            ShellRunInput(
                operation_id=UUID("00000000-0000-4000-8000-000000000039"),
                command="cd",
                cwd=second,
                shell="cmd",
            )
        )

        # Then: 프로세스별 cwd가 섞이지 않습니다.
        assert Path(first_result.stdout.strip()).samefile(first)
        assert Path(second_result.stdout.strip()).samefile(second)

    def test_output_is_bounded_with_byte_metadata(self) -> None:
        # Given: 반환 상한보다 큰 ASCII stdout을 만드는 Worker입니다.
        tools = ShellTools(ShellWorker(max_output_bytes=32))

        # When: 1,000 bytes를 출력합니다.
        result = tools.shell_run(
            ShellRunInput(
                operation_id=UUID("00000000-0000-4000-8000-000000000049"),
                command='[Console]::Out.Write("x" * 1000)',
                cwd=Path.cwd(),
                shell="powershell",
            )
        )

        # Then: 반환 bytes는 제한되고 실제 관찰 bytes와 truncation이 분리됩니다.
        assert len(result.stdout.encode("utf-8")) <= 32
        assert result.stdout_bytes == 1_000
        assert result.stderr_bytes == 0
        assert result.truncated is True

    @pytest.mark.parametrize("stream", ["stdout", "stderr"])
    @pytest.mark.parametrize(("limit", "expected"), [(1, ""), (2, ""), (3, "한")])
    def test_multibyte_output_truncates_at_valid_utf8_boundary(
        self, stream: str, limit: int, expected: str
    ) -> None:
        # Given: UTF-8에서 3-byte인 한글 출력입니다.
        target = "Out" if stream == "stdout" else "Error"
        command = f"[Console]::{target}.Write('한글')"

        # When: 실제 pipe에서 multibyte output을 수집합니다.
        result = ShellTools(ShellWorker(max_output_bytes=limit)).shell_run(
            ShellRunInput(
                operation_id=UUID("00000000-0000-4000-8000-000000000050"),
                command=command,
                cwd=Path.cwd(),
                shell="powershell",
            )
        )

        # Then: 불완전 codepoint나 replacement expansion을 반환하지 않습니다.
        returned = result.stdout if stream == "stdout" else result.stderr
        assert returned == expected
        assert len(returned.encode("utf-8")) <= limit
        assert result.truncated is True

    def test_timeout_kills_child_tree_and_worker_can_run_again(
        self,
        shell_tools: ShellTools,
    ) -> None:
        # Given: child PowerShell을 만들고 기다리는 command입니다.
        command = (
            "$p=Start-Process powershell.exe -ArgumentList "
            "'-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30' -PassThru; "
            "[Console]::Out.WriteLine($p.Id); [Console]::Out.Flush(); Wait-Process -Id $p.Id"
        )

        # When: 1초 timeout으로 실행한 뒤 새 요청을 실행합니다.
        timed_out = shell_tools.shell_run(
            ShellRunInput(
                operation_id=UUID("00000000-0000-4000-8000-000000000059"),
                command=command,
                cwd=Path.cwd(),
                shell="powershell",
                timeout_s=1,
            )
        )
        child_pid = int(timed_out.stdout.strip())
        resumed = shell_tools.shell_run(
            ShellRunInput(
                operation_id=UUID("00000000-0000-4000-8000-000000000069"),
                command="exit 0",
                cwd=Path.cwd(),
                shell="powershell",
                timeout_s=10,
            )
        )

        # Then: timeout이 명시되고 descendant가 남지 않으며 Worker가 재사용됩니다.
        assert timed_out.timed_out is True
        assert resumed.exit_code == 0
        assert not psutil.pid_exists(child_pid)

    def test_misleading_success_text_does_not_override_exit_code(
        self,
        shell_tools: ShellTools,
    ) -> None:
        # Given: 성공 문구를 출력하지만 실패 exit code를 내는 command입니다.
        request = ShellRunInput(
            operation_id=UUID("00000000-0000-4000-8000-000000000079"),
            command='Write-Output "success"; exit 7',
            cwd=Path.cwd(),
            shell="powershell",
        )

        # When: 실제 프로세스 결과를 수집합니다.
        result = shell_tools.shell_run(request)

        # Then: 출력 문구와 무관하게 OS exit code를 보존합니다.
        assert result.stdout.strip() == "success"
        assert result.exit_code == 7


def test_shell_run_does_not_change_parent_working_directory(
    shell_tools: ShellTools,
    tmp_path: Path,
) -> None:
    # Given: 부모 process cwd와 다른 요청 cwd입니다.
    original = Path.cwd()

    # When: child shell을 임시 경로에서 실행합니다.
    _ = shell_tools.shell_run(
        ShellRunInput(
            operation_id=UUID("00000000-0000-4000-8000-000000000089"),
            command="cd",
            cwd=tmp_path,
            shell="cmd",
        )
    )

    # Then: 호출 process와 worktree의 상태는 변경되지 않습니다.
    assert Path.cwd() == original
    assert tuple(tmp_path.iterdir()) == ()


def test_obvious_accidents_produce_heuristic_warnings() -> None:
    command = "Clear-Disk -Number 0; Remove-Partition -DiskNumber 0 -PartitionNumber 1"
    warnings = inspect_command(command)
    assert {warning.code for warning in warnings} == {"clear_disk", "remove_partition"}


def test_inspection_does_not_claim_encoded_commands_are_safe() -> None:
    warnings = inspect_command("powershell -EncodedCommand RwBlAHQALQBEAGEAdABlAA==")
    assert {warning.code for warning in warnings} == {"opaque_encoded_command"}


def test_gateway_main_import_does_not_load_shell_worker() -> None:
    code = (
        "import sys; import hermes_windows_bridge.gateway.main; "
        "print('hermes_windows_bridge.worker.shell' in sys.modules)"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code], check=True, capture_output=True, text=True
    )
    assert completed.stdout.strip() == "False"
