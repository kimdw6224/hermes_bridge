from __future__ import annotations

import json
import os
import shutil
import subprocess
from contextlib import contextmanager
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, Thread
from typing import TYPE_CHECKING, override
from uuid import UUID

import anyio
import psutil
import pytest
from pydantic import ValidationError

from hermes_windows_bridge.gateway.audit import AuditRecorder
from hermes_windows_bridge.gateway.dispatcher import DispatcherServices, GatewayDispatcher
from hermes_windows_bridge.gateway.idempotency import IdempotencyStore
from hermes_windows_bridge.gateway.mcp_server import create_gateway_server
from hermes_windows_bridge.gateway.policy import ApprovalManager
from hermes_windows_bridge.privileged.ipc_server import HelperRegistry
from hermes_windows_bridge.tools.browser import (
    BrowserClickInput,
    BrowserEvaluateInput,
    BrowserExtractInput,
    BrowserOpenInput,
    BrowserSnapshotInput,
    BrowserTools,
    register_browser_tools,
)
from hermes_windows_bridge.worker.browser import BrowserWorker
from hermes_windows_bridge.worker.browser_safety import (
    BrowserProfileGuard,
    BrowserWorkerError,
    redact_browser_json,
)
from hermes_windows_bridge.worker.ipc_client import WorkerRegistry

if TYPE_CHECKING:
    from collections.abc import Generator

_COOKIE_VALUE = "cookie-value-never-return"
_LOCAL_VALUE = "local-value-never-return"
_SESSION_VALUE = "session-value-never-return"
_OPERATION_ID = UUID("018f0000-0000-7000-8000-000000000116")
_PLAYWRIGHT_BROWSERS_PATH = str(Path(os.environ["LOCALAPPDATA"]) / "ms-playwright")
_SECRET_PAGE = f"""<!doctype html>
<html><head><title>Secret fixture</title></head><body>
  <h1>Secret fixture</h1><div id="leak"></div>
  <script>
    localStorage.setItem('access_token', '{_LOCAL_VALUE}');
    sessionStorage.setItem('session_secret', '{_SESSION_VALUE}');
    document.querySelector('#leak').textContent =
      '{_COOKIE_VALUE} {_LOCAL_VALUE} {_SESSION_VALUE}';
  </script>
</body></html>""".encode()


def _secret_handler(sink_hit: Event) -> type[BaseHTTPRequestHandler]:
    class SecretHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path.startswith("/sink"):
                sink_hit.set()
                self.send_response(204)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", f"session={_COOKIE_VALUE}; HttpOnly; SameSite=Strict")
            self.send_header("Content-Length", str(len(_SECRET_PAGE)))
            self.end_headers()
            _ = self.wfile.write(_SECRET_PAGE)

        @override
        def log_message(self, format: str, *args: str | int) -> None:
            del format, args

    return SecretHandler


@contextmanager
def _secret_page() -> Generator[tuple[str, Event]]:
    sink_hit = Event()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _secret_handler(sink_hit))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/", sink_hit
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@contextmanager
def _browser_tools(tmp_path: Path) -> Generator[BrowserTools]:
    with pytest.MonkeyPatch.context() as monkeypatch, TemporaryDirectory(dir=tmp_path) as directory:
        monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", _PLAYWRIGHT_BROWSERS_PATH)
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        profile = Path(directory) / "HermesWindowsBridge" / "browser-profile"
        worker = BrowserWorker(profile_dir=profile, headless=True, max_output_bytes=200_000)
        try:
            with worker as _:
                yield BrowserTools(worker)
        finally:
            if profile.parent.exists():
                shutil.rmtree(profile.parent)


def _remove_test_profile(profile: Path) -> None:
    if profile.is_junction():
        profile.rmdir()
    if profile.parent.exists():
        shutil.rmtree(profile.parent)


@pytest.mark.security
def test_profile_guard_blocks_junction_swap_and_releases_handles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    local_app_data = tmp_path / "local"
    profile = local_app_data / "HermesWindowsBridge" / "browser-profile"
    outside = tmp_path / "outside"
    profile.mkdir(parents=True)
    outside.mkdir()
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", _PLAYWRIGHT_BROWSERS_PATH)
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))

    try:
        worker = BrowserWorker(profile_dir=profile, headless=True, max_output_bytes=200_000)
        try:
            try:
                profile.rmdir()
            except OSError:
                removed = False
            else:
                removed = True
            swap = subprocess.run(
                (os.environ["COMSPEC"], "/c", "mklink", "/J", str(profile), str(outside)),
                check=False,
                capture_output=True,
            )
            opened = worker.open("about:blank", _OPERATION_ID)
        finally:
            with worker as _:
                pass

        assert removed is False
        assert swap.returncode != 0
        assert profile.is_junction() is False
        assert opened.running is True
    finally:
        _remove_test_profile(profile)
        shutil.rmtree(outside)


@pytest.mark.security
def test_profile_guard_handle_count_is_stable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = tmp_path / "HermesWindowsBridge" / "browser-profile"
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    process = psutil.Process()
    baseline_handles = process.num_handles()

    try:
        for _ in range(20):
            with BrowserProfileGuard(profile):
                pass
        final_handles = process.num_handles()
    finally:
        _remove_test_profile(profile)

    assert final_handles <= baseline_handles


@pytest.mark.security
def test_snapshot_and_extract_redact_cookie_and_storage_values(
    tmp_path: Path,
) -> None:
    # Given: cookie/localStorage/sessionStorage 값이 DOM에도 복사된 로컬 페이지입니다.
    # When: semantic snapshot과 DOM text를 반환합니다.
    with _secret_page() as (url, _), _browser_tools(tmp_path) as tools:
        _ = tools.browser_open(BrowserOpenInput(operation_id=_OPERATION_ID, url=url))
        snapshot = tools.browser_snapshot(BrowserSnapshotInput(operation_id=_OPERATION_ID))
        extracted = tools.browser_extract(
            BrowserExtractInput(operation_id=_OPERATION_ID, selector="#leak")
        )

    # Then: 세 저장소의 비밀 원문은 모두 반환 경계를 통과하지 못합니다.
    combined = snapshot.content + extracted.content
    assert _COOKIE_VALUE not in combined
    assert _LOCAL_VALUE not in combined
    assert _SESSION_VALUE not in combined
    assert "[REDACTED]" in combined


@pytest.mark.security
@pytest.mark.parametrize(
    "expression",
    [
        "document.cookie",
        "JSON.stringify(localStorage)",
        "sessionStorage.getItem('session_secret')",
        "fetch('/sink?x=' + window['local' + 'Storage'].getItem('access_token'))",
        "(0, eval)(\"fetch('/sink?x=eval')\")",
        "Function(\"return fetch('/sink?x=function')\")()",
        "window['con'+'structor']['constructor'](\"fetch('/sink?x=ctor')\")()",
    ],
)
def test_evaluate_rejects_arbitrary_javascript_without_network_sink(
    expression: str, tmp_path: Path
) -> None:
    # Given: 실제 loopback sink와 저장소 비밀이 있는 전용 브라우저입니다.
    with _secret_page() as ((url, sink_hit)), _browser_tools(tmp_path) as tools:
        _ = tools.browser_open(BrowserOpenInput(operation_id=_OPERATION_ID, url=url))

        # When / Then: 난독화 형태도 실행 전에 거부되고 sink 요청이 없습니다.
        with pytest.raises(BrowserWorkerError, match="unsafe_evaluation"):
            _ = tools.browser_evaluate(BrowserEvaluateInput(expression=expression))
        assert sink_hit.wait(timeout=0.2) is False


@pytest.mark.security
def test_evaluate_allows_only_predefined_read_only_query(tmp_path: Path) -> None:
    # Given: 안전한 title 조회가 정의된 전용 브라우저입니다.
    with _secret_page() as (url, _), _browser_tools(tmp_path) as tools:
        _ = tools.browser_open(BrowserOpenInput(operation_id=_OPERATION_ID, url=url))
        result = tools.browser_evaluate(BrowserEvaluateInput(expression="document.title"))

    assert result.value == "Secret fixture"


@pytest.mark.security
@pytest.mark.parametrize(
    "key",
    ["apiKey", "api_key", "API-KEY", "accessKey", "privateKey", "clientSecret"],
)
def test_recursive_redaction_normalizes_common_secret_key_forms(key: str) -> None:
    # Given: 여러 표기법의 secret key가 재귀 JSON에 있습니다.
    result = redact_browser_json({"outer": [{key: "computed-value"}], "visible": "ok"}, frozenset())

    encoded = json.dumps(result)
    assert "computed-value" not in encoded
    assert "[REDACTED]" in encoded
    assert "ok" in encoded


@pytest.mark.security
def test_registered_browser_tools_have_closed_open_world_schemas() -> None:
    # Given: 실제 Gateway dispatcher와 공식 MCPServer 등록 표면입니다.
    dispatcher = GatewayDispatcher(
        DispatcherServices(
            workers=WorkerRegistry(),
            helpers=HelperRegistry(),
            idempotency=IdempotencyStore(ttl=timedelta(minutes=1)),
            approvals=ApprovalManager(),
            audit=AuditRecorder(),
        )
    )
    server = create_gateway_server("test-token")
    register_browser_tools(server, dispatcher)

    # When: 공식 SDK schema를 열거합니다.
    registered = anyio.run(server.list_tools)

    # Then: 여덟 도구 모두 closed input이며 open-world로 표시됩니다.
    assert {tool.name for tool in registered} == {
        "browser_status",
        "browser_open",
        "browser_navigate",
        "browser_snapshot",
        "browser_click",
        "browser_type",
        "browser_extract",
        "browser_close",
    }
    assert all(tool.input_schema.get("additionalProperties") is False for tool in registered)
    assert all(
        tool.annotations is not None and tool.annotations.open_world_hint for tool in registered
    )


@pytest.mark.security
def test_script_url_is_rejected_at_input_boundary() -> None:
    # Given: page context에서 실행될 수 있는 javascript URL입니다.
    # When / Then: Pydantic 경계가 browser dispatch 전에 거부합니다.
    with pytest.raises(ValidationError):
        _ = BrowserOpenInput(operation_id=_OPERATION_ID, url="javascript:alert(1)")


@pytest.mark.security
def test_nul_selector_is_rejected_at_input_boundary() -> None:
    # Given: IPC/Playwright 문자열을 자를 수 있는 NUL selector입니다.
    # When / Then: Pydantic 경계가 browser dispatch 전에 거부합니다.
    with pytest.raises(ValidationError):
        _ = BrowserClickInput(operation_id=_OPERATION_ID, selector="#safe\0#other")
