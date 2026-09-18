"""Loopback-only MCP gateway process entry point."""

from __future__ import annotations

import os
import threading
import time
from copy import deepcopy
from dataclasses import dataclass
from datetime import timedelta
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Final, override

import anyio
import uvicorn
from anyio import to_thread
from uvicorn.config import LOGGING_CONFIG

from hermes_windows_bridge.config import InvalidConfigurationError, load_startup_settings
from hermes_windows_bridge.gateway.audit import AuditJsonlStore, AuditRecorder
from hermes_windows_bridge.gateway.dispatcher import DispatcherServices, GatewayDispatcher
from hermes_windows_bridge.gateway.helper_runtime import GatewayHelperWatcher
from hermes_windows_bridge.gateway.idempotency import IdempotencyStore
from hermes_windows_bridge.gateway.mcp_server import create_gateway_server
from hermes_windows_bridge.gateway.origin_host import GatewayTransportPolicy
from hermes_windows_bridge.gateway.policy import ApprovalManager
from hermes_windows_bridge.gateway.tailscale_identity import (
    DEFAULT_APP_CAPABILITY,
    AppCapabilityPolicy,
    app_capability_verified,
)
from hermes_windows_bridge.gateway.worker_runtime import GatewayWorkerWatcher
from hermes_windows_bridge.ipc.named_pipe import PRIVILEGED_PIPE_NAME, WORKER_PIPE_NAME
from hermes_windows_bridge.privileged.ipc_server import HelperRegistry
from hermes_windows_bridge.runtime_binding import (
    RuntimeBinding,
    RuntimeProfile,
    load_installed_worker_sid,
)
from hermes_windows_bridge.tools.browser import register_browser_tools
from hermes_windows_bridge.tools.codex import register_codex_tools
from hermes_windows_bridge.tools.computer import register_computer_tool
from hermes_windows_bridge.tools.fs_process_mcp import (
    register_filesystem_tools,
    register_process_tools,
)
from hermes_windows_bridge.tools.jobs import register_job_tools
from hermes_windows_bridge.tools.shell import register_shell_tool
from hermes_windows_bridge.tools.status import StatusCollector, register_status_tool
from hermes_windows_bridge.tools.system import register_system_tools
from hermes_windows_bridge.worker.ipc_client import WorkerRegistry

if TYPE_CHECKING:
    from collections.abc import Callable

    from mcp.server.mcpserver import MCPServer

    from hermes_windows_bridge.gateway.mcp_server import GatewayMCPServer
    from hermes_windows_bridge.models.config import StartupSettings


LOOPBACK_HOST: Final = "127.0.0.1"
DEFAULT_PORT: Final = 8765
_TOKEN_ENV: Final = "HERMES_BRIDGE_TOKEN"  # noqa: S105 - 환경 변수 이름이며 자격 증명이 아닙니다.
_HOSTS_ENV: Final = "HERMES_BRIDGE_ALLOWED_HOSTS"
_ORIGINS_ENV: Final = "HERMES_BRIDGE_ALLOWED_ORIGINS"
_TAILSCALE_SERVE_HOST_ENV: Final = "HERMES_BRIDGE_TAILSCALE_SERVE_HOST"
_TAILSCALE_APP_CAPABILITY_ENV: Final = "HERMES_BRIDGE_TAILSCALE_APP_CAPABILITY"
_AUDIT_SENSITIVE_ARTIFACT_RETENTION: Final = timedelta(hours=24)


@dataclass(frozen=True, slots=True)
class GatewayEnvironmentError(Exception):
    """Raised when required process configuration is absent or malformed."""

    variable: str

    @override
    def __str__(self) -> str:
        """Return only the missing variable name, never an environment value."""
        return f"required gateway environment variable is missing: {self.variable}"


@dataclass(frozen=True, slots=True)
class GatewayRegistries:
    """Production server와 IPC watcher가 공유하는 peer registries입니다."""

    workers: WorkerRegistry
    helpers: HelperRegistry


def _required_environment(variable: str) -> str:
    value = os.environ.get(variable)
    if not value:
        raise GatewayEnvironmentError(variable=variable)
    return value


def build_gateway_server(
    token: str,
    *,
    app_capability_policy: AppCapabilityPolicy | None = None,
    registries: GatewayRegistries | None = None,
    audit_root: Path | None = None,
) -> MCPServer[None]:
    """Offline peer를 typed failure로 유지한 production MCP 구성을 만듭니다."""
    peers = registries or GatewayRegistries(WorkerRegistry(), HelperRegistry())
    approvals = ApprovalManager()
    dispatcher = GatewayDispatcher(
        DispatcherServices(
            workers=peers.workers,
            helpers=peers.helpers,
            idempotency=IdempotencyStore(ttl=timedelta(minutes=30)),
            approvals=approvals,
            audit=_gateway_audit_recorder(audit_root),
        )
    )
    collector = StatusCollector(
        dispatcher=dispatcher,
        helpers=peers.helpers,
        workers=peers.workers,
        app_capability_verified=app_capability_verified,
    )

    def register_tools(server: GatewayMCPServer) -> None:
        register_status_tool(server, collector)
        register_shell_tool(server, dispatcher)
        register_filesystem_tools(server, dispatcher)
        register_process_tools(server, dispatcher)
        register_computer_tool(server, dispatcher)
        register_browser_tools(server, dispatcher)
        register_codex_tools(server, dispatcher)
        register_job_tools(server, dispatcher)
        register_system_tools(server, dispatcher, approvals)

    return create_gateway_server(
        token,
        register_tools=register_tools,
        app_capability_policy=app_capability_policy,
    )


def _gateway_audit_recorder(audit_root: Path | None) -> AuditRecorder:
    """운영 root가 주어질 때만 redacted JSONL audit store를 조립합니다."""
    if audit_root is None:
        return AuditRecorder()
    return AuditRecorder(
        store=AuditJsonlStore(
            audit_root,
            retention=_AUDIT_SENSITIVE_ARTIFACT_RETENTION,
        )
    )


def load_app_capability_policy() -> AppCapabilityPolicy | None:
    """명시적인 Serve hostname이 있을 때만 App Capability 검증을 활성화합니다."""
    serve_host = os.environ.get(_TAILSCALE_SERVE_HOST_ENV, "").strip()
    if not serve_host:
        return None
    capability = os.environ.get(_TAILSCALE_APP_CAPABILITY_ENV, DEFAULT_APP_CAPABILITY).strip()
    return AppCapabilityPolicy(capability=capability, serve_host=serve_host)


def _configured_app_capability_policy(
    settings: StartupSettings,
    config_file: Path,
) -> AppCapabilityPolicy | None:
    """설치 구성에서 Tailscale App Capability 정책을 안전하게 만듭니다."""
    if not settings.bridge.tailscale.require_app_capability:
        return None
    server_settings = settings.bridge.server
    serve_hosts = tuple(host for host in server_settings.allowed_hosts if host.endswith(".ts.net"))
    capability = settings.bridge.tailscale.app_capability
    if len(serve_hosts) != 1 or capability is None:
        raise InvalidConfigurationError(config_file)
    return AppCapabilityPolicy(capability=capability, serve_host=serve_hosts[0])


async def _serve(
    server: MCPServer[None],
    policy: GatewayTransportPolicy,
    port: int,
    on_ready: Callable[[], None] | None = None,
    stop_requested: Callable[[], bool] | None = None,
) -> None:
    """Run the SDK HTTP application and report readiness after its listener starts."""
    app = server.streamable_http_app(
        host=LOOPBACK_HOST,
        streamable_http_path="/mcp",
        json_response=False,
        transport_security=policy.sdk_settings(),
    )
    # stdout은 서비스 호스트의 READY 전용 채널이므로 접속 로그는 stderr로 보냅니다.
    log_config = deepcopy(LOGGING_CONFIG)
    log_config["handlers"]["access"]["stream"] = "ext://sys.stderr"
    config = uvicorn.Config(
        app,
        host=LOOPBACK_HOST,
        port=port,
        log_level=server.settings.log_level.lower(),
        proxy_headers=False,
        log_config=log_config,
    )
    uvicorn_server = uvicorn.Server(config)
    finished = threading.Event()

    async def serve() -> None:
        try:
            await uvicorn_server.serve()
        finally:
            _ = finished.set()

    async with anyio.create_task_group() as task_group:
        _ = task_group.start_soon(serve)
        started = await to_thread.run_sync(
            _wait_for_uvicorn_start,
            uvicorn_server,
            finished,
            abandon_on_cancel=True,
        )
        if started and on_ready is not None:
            on_ready()
        if stop_requested is not None:
            should_stop = await to_thread.run_sync(
                _wait_for_stop_or_finish,
                stop_requested,
                finished,
                abandon_on_cancel=True,
            )
            if should_stop:
                uvicorn_server.should_exit = True
        _ = await to_thread.run_sync(finished.wait, abandon_on_cancel=True)


def _wait_for_uvicorn_start(server: uvicorn.Server, finished: threading.Event) -> bool:
    """Listener가 시작되거나 server task가 끝날 때까지 bounded polling합니다."""
    while not server.started and not finished.is_set():
        time.sleep(0.01)
    return server.started


def _wait_for_stop_or_finish(stop_requested: Callable[[], bool], finished: threading.Event) -> bool:
    """Parent stop 또는 server 종료 중 먼저 관찰한 상태를 반환합니다."""
    while not stop_requested() and not finished.is_set():
        time.sleep(0.01)
    return stop_requested()


async def run_gateway_server(
    *,
    environment: bool = False,
    on_ready: Callable[[], None] | None = None,
    stop_requested: Callable[[], bool] | None = None,
    binding: RuntimeBinding | None = None,
) -> None:
    """보안 설정, MCP server, Worker reconnect watcher를 한 수명으로 실행합니다."""
    port = DEFAULT_PORT
    audit_root: Path | None = None
    worker_pipe_name = WORKER_PIPE_NAME
    privileged_pipe_name = PRIVILEGED_PIPE_NAME
    if binding is not None:
        if binding.profile is not RuntimeProfile.GATEWAY:
            raise GatewayEnvironmentError(variable="runtime_binding_profile")
        settings = load_startup_settings(binding.config_path, environ={})
        audit_root = settings.bridge.paths.gateway_logs
        token = settings.bearer_token.get_secret_value()
        server_settings = settings.bridge.server
        port = server_settings.port
        policy = GatewayTransportPolicy(
            allowed_hosts=server_settings.allowed_hosts,
            allowed_origins=server_settings.allowed_origins,
        )
        capability_policy = _configured_app_capability_policy(settings, binding.config_path)
        worker_pipe_name = settings.bridge.ipc.worker_pipe
        privileged_pipe_name = settings.bridge.ipc.privileged_pipe
    elif environment:
        token = _required_environment(_TOKEN_ENV)
        hosts = _required_environment(_HOSTS_ENV)
        origins = _required_environment(_ORIGINS_ENV)
        policy = GatewayTransportPolicy.from_csv(hosts=hosts, origins=origins)
        capability_policy = load_app_capability_policy()
    else:
        config_file = (
            Path(_required_environment("ProgramData")) / "HermesWindowsBridge" / "config.yaml"
        )
        settings = load_startup_settings(config_file)
        audit_root = settings.bridge.paths.gateway_logs
        token = settings.bearer_token.get_secret_value()
        server_settings = settings.bridge.server
        port = server_settings.port
        policy = GatewayTransportPolicy(
            allowed_hosts=server_settings.allowed_hosts,
            allowed_origins=server_settings.allowed_origins,
        )
        capability_policy = _configured_app_capability_policy(settings, config_file)
        worker_pipe_name = settings.bridge.ipc.worker_pipe
        privileged_pipe_name = settings.bridge.ipc.privileged_pipe
    registries = GatewayRegistries(WorkerRegistry(), HelperRegistry())
    server = build_gateway_server(
        token,
        app_capability_policy=capability_policy,
        registries=registries,
        audit_root=audit_root,
    )
    expected_worker_sid = (
        binding.worker_sid
        if binding is not None
        else None
        if environment
        else load_installed_worker_sid()
    )
    worker_watcher = GatewayWorkerWatcher(
        worker_pipe_name, registries.workers, expected_worker_sid=expected_worker_sid
    )
    helper_watcher = GatewayHelperWatcher(privileged_pipe_name, registries.helpers)
    async with anyio.create_task_group() as task_group:
        _ = task_group.start_soon(to_thread.run_sync, worker_watcher.run)
        _ = task_group.start_soon(to_thread.run_sync, helper_watcher.run)
        try:
            await _serve(server, policy, port, on_ready, stop_requested)
        finally:
            worker_watcher.close()
            helper_watcher.close()
            task_group.cancel_scope.cancel()


def main() -> None:
    """Load security configuration and run the Gateway HTTP server."""
    try:
        anyio.run(partial(run_gateway_server, environment=True))
    except KeyboardInterrupt:
        return


if __name__ == "__main__":
    main()
