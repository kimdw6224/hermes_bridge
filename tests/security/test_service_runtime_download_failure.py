"""Execution tests for protected-runtime download failures."""

from __future__ import annotations

import shutil
import socket
import subprocess
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Final, final, override

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from collections.abc import Generator

PROJECT_ROOT: Final = Path(__file__).parents[2]
RUNTIME_SCRIPT: Final = PROJECT_ROOT / "scripts" / "service-runtime.ps1"
BUILD_SCRIPT: Final = PROJECT_ROOT / "scripts" / "service-runtime-build.ps1"
POWERSHELL: Final = shutil.which("powershell.exe")
assert POWERSHELL is not None


class FailureReceipt(BaseModel):
    """Bounded non-success result emitted by the test boundary."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    state: str
    exception_type: str = Field(validation_alias="exceptionType")
    destination_exists: bool = Field(validation_alias="destinationExists")
    manifest_exists: bool = Field(validation_alias="manifestExists")


class CallerFailureReceipt(BaseModel):
    """Observed caller state after the real post-download statement tail aborts."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    state: str
    archive_validation_reached: bool = Field(validation_alias="archiveValidationReached")
    release_exists: bool = Field(validation_alias="releaseExists")
    manifest_exists: bool = Field(validation_alias="manifestExists")


@final
class DelayedBodyHandler(BaseHTTPRequestHandler):
    """Serve headers immediately while withholding the response body."""

    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", "32")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        time.sleep(5)

    @override
    def log_message(self, format: str, *args: str) -> None:
        del format, args


@final
class DripBodyHandler(BaseHTTPRequestHandler):
    """Continuously complete small reads beyond the absolute deadline."""

    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", "300")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        try:
            for _ in range(300):
                _ = self.wfile.write(b"x")
                self.wfile.flush()
                time.sleep(0.01)
        except (BrokenPipeError, ConnectionResetError):
            return

    @override
    def log_message(self, format: str, *args: str) -> None:
        del format, args


@contextmanager
def _delayed_server() -> Generator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), DelayedBodyHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/archive"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@contextmanager
def _drip_server() -> Generator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), DripBodyHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/archive"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _unused_loopback_url() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return f"http://127.0.0.1:{listener.getsockname()[1]}/archive"


def _invoke_download(
    url: str,
    root: Path,
    timeout_seconds: int,
) -> subprocess.CompletedProcess[str]:
    destination = root / "python.tar.gz"
    manifest = root / "release-manifest.json"
    command = " ".join(
        (
            f". '{RUNTIME_SCRIPT}' -LibraryMode; . '{BUILD_SCRIPT}';",
            "try {",
            f"Save-BridgeBoundedDownload -Url '{url}' -Destination '{destination}'",
            f"-TimeoutSeconds {timeout_seconds} -MaximumBytes 1048576;",
            "[pscustomobject]@{state='built';exceptionType='';",
            f"destinationExists=(Test-Path -LiteralPath '{destination}');",
            f"manifestExists=(Test-Path -LiteralPath '{manifest}')}}",
            "|ConvertTo-Json -Compress; exit 0",
            "} catch {",
            "[pscustomobject]@{state='failed';exceptionType=$_.Exception.GetType().FullName;",
            f"destinationExists=(Test-Path -LiteralPath '{destination}');",
            f"manifestExists=(Test-Path -LiteralPath '{manifest}')}}",
            "|ConvertTo-Json -Compress; exit 2",
            "}",
        )
    )
    return subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def _assert_failed_without_manifest(result: subprocess.CompletedProcess[str]) -> FailureReceipt:
    assert result.returncode == 2, result.stderr
    receipt = FailureReceipt.model_validate_json(result.stdout)
    assert receipt.state == "failed"
    assert receipt.exception_type
    assert receipt.manifest_exists is False
    assert "built" not in result.stderr.lower()
    return receipt


def _invoke_caller_tail_after_forced_download_failure(
    root: Path,
) -> subprocess.CompletedProcess[str]:
    release = root / "release"
    manifest = release / "release-manifest.json"
    command = " ".join(
        (
            f". '{RUNTIME_SCRIPT}' -LibraryMode; . '{BUILD_SCRIPT}';",
            (
                f"$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::"
                f"ParseFile('{BUILD_SCRIPT}',[ref]$tokens,[ref]$errors);"
            ),
            (
                "$function=$ast.Find({param($node) $node -is "
                "[Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq "
                "'Invoke-BridgeProtectedReleaseBuild'},$true);"
            ),
            (
                "$try=$function.Find({param($node) $node -is "
                "[Management.Automation.Language.TryStatementAst] -and $node.Extent.Text -match "
                "'Save-BridgeBoundedDownload'},$true);"
            ),
            (
                "$statements=@($try.Body.Statements);$start=[Array]::FindIndex($statements,"
                "[Predicate[object]]{param($statement) $statement.Extent.Text -match "
                "'^\\s*Save-BridgeBoundedDownload'});"
            ),
            (
                "$tail=[scriptblock]::Create((($statements[$start..($statements.Count-1)]|"
                "ForEach-Object {$_.Extent.Text}) -join [Environment]::NewLine));"
            ),
            "$archiveValidationReached=$false;",
            (
                "function Save-BridgeBoundedDownload { throw "
                "[Net.Http.HttpRequestException]::new('forced-transport-failure') };"
            ),
            (
                "function Test-BridgePythonArchive { "
                "$script:archiveValidationReached=$true; return $true };"
            ),
            "$script:BridgePythonArchiveUrl='http://127.0.0.1:1/archive';",
            "$archivePath=Join-Path $env:TEMP 'forced-download.archive';$stagingRoot=$env:TEMP;",
            f"$releaseRoot='{release}';",
            "try { & $tail; $state='built' } catch { $state='failed' };",
            "[pscustomobject]@{state=$state;archiveValidationReached=$archiveValidationReached;",
            f"releaseExists=(Test-Path -LiteralPath '{release}');",
            f"manifestExists=(Test-Path -LiteralPath '{manifest}')}}|ConvertTo-Json -Compress;",
            "if ($state -eq 'failed') { exit 2 } else { exit 0 }",
        )
    )
    return subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_transport_failure_cannot_create_built_release_receipt(tmp_path: Path) -> None:
    result = _invoke_download(_unused_loopback_url(), tmp_path, timeout_seconds=2)

    receipt = _assert_failed_without_manifest(result)

    assert receipt.destination_exists is False


def test_body_timeout_is_bounded_and_cannot_create_built_release_receipt(
    tmp_path: Path,
) -> None:
    with _delayed_server() as url:
        started = time.monotonic()
        result = _invoke_download(url, tmp_path, timeout_seconds=1)
        elapsed = time.monotonic() - started

    receipt = _assert_failed_without_manifest(result)

    assert elapsed < 5
    assert receipt.destination_exists is True
    assert (tmp_path / "python.tar.gz").stat().st_size == 0


def test_completed_small_reads_cannot_extend_the_absolute_deadline(
    tmp_path: Path,
) -> None:
    with _drip_server() as url:
        started = time.monotonic()
        result = _invoke_download(url, tmp_path, timeout_seconds=1)
        elapsed = time.monotonic() - started

    receipt = _assert_failed_without_manifest(result)

    assert elapsed < 3
    assert receipt.destination_exists is True
    assert (tmp_path / "python.tar.gz").stat().st_size > 0


def test_build_caller_stops_before_archive_validation_and_publish(
    tmp_path: Path,
) -> None:
    result = _invoke_caller_tail_after_forced_download_failure(tmp_path)

    assert result.returncode == 2, result.stderr
    receipt = CallerFailureReceipt.model_validate_json(result.stdout)
    assert receipt.state == "failed"
    assert receipt.archive_validation_reached is False
    assert receipt.release_exists is False
    assert receipt.manifest_exists is False
