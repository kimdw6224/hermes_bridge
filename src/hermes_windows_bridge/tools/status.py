"""부분 실패를 격리하는 Windows Bridge status 도구입니다."""

from __future__ import annotations

import platform
import socket
import subprocess
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, ClassVar, Final, Protocol, final
from uuid import uuid4

import psutil
from anyio import fail_after, to_thread
from mcp.types import CallToolResult, TextContent, ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from hermes_windows_bridge import __version__
from hermes_windows_bridge.gateway.dispatcher import DispatchCall
from hermes_windows_bridge.models.policy import StrictFrozenModel
from hermes_windows_bridge.models.tool_results import (
    ActiveWindowStatus,
    InteractiveWorkerStatus,
    PipeAclState,
    PipeAclStatus,
    PrivilegedHelperStatus,
    ResourceStatus,
    StatusResult,
    StatusSensor,
    StatusWarning,
    TailscaleStatus,
)
from hermes_windows_bridge.privileged.ipc_server import HelperRegistry, HelperUnavailableError
from hermes_windows_bridge.tools.tailscale_probe import TailscaleConnectionSnapshot

if TYPE_CHECKING:
    from collections.abc import Callable

    from hermes_windows_bridge.gateway.mcp_server import GatewayMCPServer
    from hermes_windows_bridge.worker.ipc_client import WorkerRegistry

_BYTES_PER_GIB: Final = 1024**3
_DEFAULT_SENSOR_TIMEOUT_S: Final = 0.4
_WORKER_TIMEOUT_MS: Final = 350


class _StatusDispatchOutcome(Protocol):
    @property
    def result(self) -> CallToolResult: ...


class _StatusDispatcher(Protocol):
    async def dispatch(self, call: DispatchCall) -> _StatusDispatchOutcome: ...


class StatusSystemInfo(StrictFrozenModel):
    """빠른 로컬 OS 센서 결과입니다."""

    hostname: Annotated[str, Field(min_length=1, max_length=255)]
    windows_version: Annotated[str, Field(min_length=1, max_length=512)]


class _WorkerPayload(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)
    username: Annotated[str, Field(min_length=1, max_length=256)]
    session_id: Annotated[int, Field(ge=0)]
    desktop_unlocked: bool
    remote_input_enabled: bool
    active_window: ActiveWindowStatus
    tailscale: TailscaleConnectionSnapshot | None = None


@dataclass(frozen=True, slots=True)
class _SensorSuccess[ValueT]:
    value: ValueT


type _WorkerValue = tuple[
    InteractiveWorkerStatus, ActiveWindowStatus, TailscaleConnectionSnapshot | None
]
type _SensorResult[ValueT] = _SensorSuccess[ValueT] | StatusWarning


def _probe_system() -> StatusSystemInfo:
    return StatusSystemInfo(hostname=socket.gethostname(), windows_version=platform.platform())


def _probe_resources() -> ResourceStatus:
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage(str(Path.cwd().anchor or Path.cwd()))
    return ResourceStatus(
        cpu_percent=float(psutil.cpu_percent(interval=0.1)),
        ram_used_gb=round(float(memory.used) / _BYTES_PER_GIB, 1),
        ram_total_gb=round(float(memory.total) / _BYTES_PER_GIB, 1),
        disk_free_gb=round(float(disk.free) / _BYTES_PER_GIB, 1),
    )


@final
class StatusCollector:
    """각 센서를 제한 시간 내 수집하고 실패를 typed 경고로 바꿉니다."""

    def __init__(  # noqa: PLR0913 - 독립 센서를 테스트 가능한 좁은 seam으로 주입합니다.
        self,
        *,
        dispatcher: _StatusDispatcher,
        helpers: HelperRegistry,
        workers: WorkerRegistry | None = None,
        app_capability_verified: Callable[[], bool],
        system_probe: Callable[[], StatusSystemInfo] = _probe_system,
        tailscale_probe: Callable[[], TailscaleStatus] | None = None,
        resource_probe: Callable[[], ResourceStatus] = _probe_resources,
        sensor_timeout_s: float = _DEFAULT_SENSOR_TIMEOUT_S,
        started_at: float | None = None,
    ) -> None:
        """의존 센서와 단일 센서 제한 시간을 고정합니다."""
        self._dispatcher = dispatcher
        self._helpers = helpers
        self._workers = workers
        self._system_probe = system_probe
        self._app_capability_verified = app_capability_verified
        self._tailscale_probe = tailscale_probe
        self._resource_probe = resource_probe
        self._sensor_timeout_s = sensor_timeout_s
        self._started_at = time.monotonic() if started_at is None else started_at

    async def collect(self) -> StatusResult:
        """독립 실패가 있어도 완전한 status shape를 반환합니다."""
        system = await self._bounded("system", self._system_probe)
        tailscale = await self._legacy_tailscale()
        resources = await self._bounded("resources", self._resource_probe)
        worker = await self._worker()
        capability_verified = self._app_capability_verified()
        worker_tailscale_failed = isinstance(worker, _SensorSuccess) and worker.value[2] is None
        warnings = [
            result
            for result in (
                system,
                tailscale,
                resources,
                worker,
                StatusWarning(sensor="tailscale", code="sensor_failed")
                if tailscale is None and worker_tailscale_failed
                else None,
            )
            if isinstance(result, StatusWarning)
        ]
        system_value = system.value if isinstance(system, _SensorSuccess) else None
        tailscale_value = self._tailscale_status(
            worker, tailscale, capability_verified=capability_verified
        )
        resources_value = (
            resources.value
            if isinstance(resources, _SensorSuccess)
            else ResourceStatus.unavailable()
        )
        worker_value = (
            worker.value
            if isinstance(worker, _SensorSuccess)
            else (InteractiveWorkerStatus.offline(), ActiveWindowStatus.unavailable())
        )
        return StatusResult(
            hostname=system_value.hostname if system_value is not None else None,
            bridge_version=__version__,
            gateway_uptime_s=max(0.0, time.monotonic() - self._started_at),
            windows_version=system_value.windows_version if system_value is not None else None,
            tailscale=tailscale_value,
            interactive_worker=worker_value[0],
            privileged_helper=PrivilegedHelperStatus(online=self._helper_online()),
            resources=resources_value,
            active_window=worker_value[1],
            pipe_acl=PipeAclStatus(
                worker=self._worker_pipe_acl_state(),
                privileged=self._helper_pipe_acl_state(),
            ),
            warnings=tuple(warnings),
        )

    async def _bounded[ValueT](
        self, sensor: StatusSensor, probe: Callable[[], ValueT]
    ) -> _SensorResult[ValueT]:
        try:
            with fail_after(self._sensor_timeout_s):
                value = await to_thread.run_sync(probe, abandon_on_cancel=True)
        except TimeoutError:
            return StatusWarning(sensor=sensor, code="sensor_timeout")
        except OSError, RuntimeError, ValueError, psutil.Error, subprocess.SubprocessError:
            return StatusWarning(sensor=sensor, code="sensor_failed")
        return _SensorSuccess(value)

    async def _worker(self) -> _SensorResult[_WorkerValue]:
        try:
            with fail_after(self._sensor_timeout_s):
                outcome = await self._dispatcher.dispatch(
                    DispatchCall(
                        operation_id=uuid4(),
                        tool_name="status",
                        payload={},
                        requested_at=datetime.now(UTC),
                        timeout_ms=min(
                            _WORKER_TIMEOUT_MS,
                            max(1, int(self._sensor_timeout_s * 1_000)),
                        ),
                    )
                )
        except TimeoutError:
            return StatusWarning(sensor="interactive_worker", code="sensor_timeout")
        except OSError, RuntimeError, ValueError:
            return StatusWarning(sensor="interactive_worker", code="sensor_failed")
        if outcome.result.is_error is True:
            return StatusWarning(sensor="interactive_worker", code="worker_unavailable")
        content = outcome.result.content
        if len(content) != 1 or not isinstance(content[0], TextContent):
            return StatusWarning(sensor="interactive_worker", code="invalid_worker_response")
        try:
            payload = _WorkerPayload.model_validate_json(content[0].text)
        except ValidationError:
            return StatusWarning(sensor="interactive_worker", code="invalid_worker_response")
        return _SensorSuccess(
            (
                InteractiveWorkerStatus(
                    online=True,
                    username=payload.username,
                    session_id=payload.session_id,
                    desktop_unlocked=payload.desktop_unlocked,
                    remote_input_enabled=payload.remote_input_enabled,
                ),
                ActiveWindowStatus(
                    title=payload.active_window.title,
                    process=payload.active_window.process,
                ),
                payload.tailscale,
            )
        )

    async def _legacy_tailscale(self) -> _SensorResult[TailscaleStatus] | None:
        if self._tailscale_probe is None:
            return None
        return await self._bounded("tailscale", self._tailscale_probe)

    @staticmethod
    def _tailscale_status(
        worker: _SensorResult[_WorkerValue],
        legacy: _SensorResult[TailscaleStatus] | None,
        *,
        capability_verified: bool,
    ) -> TailscaleStatus:
        if isinstance(legacy, _SensorSuccess):
            return legacy.value.model_copy(update={"app_capability_verified": capability_verified})
        if not isinstance(worker, _SensorSuccess) or worker.value[2] is None:
            return TailscaleStatus.disconnected(app_capability_verified=capability_verified)
        snapshot = worker.value[2]
        return TailscaleStatus(
            connected=snapshot.connected,
            ip=snapshot.ip,
            app_capability_verified=capability_verified,
        )

    def _helper_online(self) -> bool:
        try:
            _ = self._helpers.current()
        except HelperUnavailableError, OSError, RuntimeError, ValueError:
            return False
        return True

    def _worker_pipe_acl_state(self) -> PipeAclState:
        """Legacy collector와 status probe 실패는 opaque unverified로 고정합니다."""
        workers = self._workers
        if workers is None:
            return "unverified"
        try:
            state = workers.pipe_acl_state()
        except OSError, RuntimeError, ValueError:
            return "unverified"
        return _parse_pipe_acl_state(state)

    def _helper_pipe_acl_state(self) -> PipeAclState:
        """Helper DACL 재검증 실패는 online 여부와 무관하게 fail closed합니다."""
        try:
            state = self._helpers.pipe_acl_state()
        except OSError, RuntimeError, ValueError:
            return "unverified"
        return _parse_pipe_acl_state(state)


def _parse_pipe_acl_state(state: str) -> PipeAclState:
    """registry가 반환하는 opaque state를 공개 strict enum 값으로 제한합니다."""
    match state:
        case "verified":
            return "verified"
        case "mismatch":
            return "mismatch"
        case "unverified":
            return "unverified"
        case "offline":
            return "offline"
        case _:
            return "unverified"


def register_status_tool(server: GatewayMCPServer, collector: StatusCollector) -> None:
    """Gateway MCP 공개 API에 읽기 전용 status를 등록합니다."""

    async def status() -> CallToolResult:
        result = await collector.collect()
        return CallToolResult(
            content=[TextContent(text=result.model_dump_json())],
            structured_content=result.model_dump(mode="json"),
        )

    server.add_closed_tool(
        status,
        input_model=StrictFrozenModel,
        name="status",
        description="Return a typed Windows Bridge health overview.",
        annotations=ToolAnnotations(
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
        structured_output=False,
    )
