"""MCP 경계로 반환하는 엄격한 도구 결과 모델입니다."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from hermes_windows_bridge.models.policy import StrictFrozenModel

type StatusSensor = Literal["system", "tailscale", "interactive_worker", "resources"]
type PipeAclState = Literal["verified", "mismatch", "unverified", "offline"]
type StatusWarningCode = Literal[
    "sensor_failed", "sensor_timeout", "worker_unavailable", "invalid_worker_response"
]


class StatusWarning(StrictFrozenModel):
    """신뢰하지 않는 오류 원문을 제외한 센서별 실패 표시입니다."""

    sensor: StatusSensor
    code: StatusWarningCode


class TailscaleStatus(StrictFrozenModel):
    """Tailscale 연결과 요청별 App Capability 검증 상태입니다."""

    connected: bool
    ip: Annotated[str, Field(min_length=2, max_length=45)] | None
    app_capability_verified: bool

    @classmethod
    def disconnected(cls, *, app_capability_verified: bool) -> TailscaleStatus:
        """Tailscale이 없거나 센서를 읽지 못한 안전한 기본값입니다."""
        return cls(
            connected=False,
            ip=None,
            app_capability_verified=app_capability_verified,
        )


class InteractiveWorkerStatus(StrictFrozenModel):
    """로그인 사용자 Worker의 가용성과 데스크톱 상태입니다."""

    online: bool
    username: Annotated[str, Field(min_length=1, max_length=256)] | None
    session_id: Annotated[int, Field(ge=0)] | None
    desktop_unlocked: bool | None
    remote_input_enabled: bool | None

    @classmethod
    def offline(cls) -> InteractiveWorkerStatus:
        """Stale 또는 연결되지 않은 Worker의 명시적 상태입니다."""
        return cls(
            online=False,
            username=None,
            session_id=None,
            desktop_unlocked=None,
            remote_input_enabled=None,
        )


class PrivilegedHelperStatus(StrictFrozenModel):
    """제한된 Privileged Helper 연결 상태입니다."""

    online: bool


class PipeAclStatus(StrictFrozenModel):
    """현재 Gateway-owned IPC client handle의 불투명 ACL 관찰 상태입니다."""

    worker: PipeAclState = "unverified"
    privileged: PipeAclState = "unverified"


class ResourceStatus(StrictFrozenModel):
    """현재 PC 리소스 사용량이며 실패한 값은 null입니다."""

    cpu_percent: Annotated[float, Field(ge=0.0)] | None
    ram_used_gb: Annotated[float, Field(ge=0.0)] | None
    ram_total_gb: Annotated[float, Field(gt=0.0)] | None
    disk_free_gb: Annotated[float, Field(ge=0.0)] | None

    @classmethod
    def unavailable(cls) -> ResourceStatus:
        """센서 실패 시 다른 status 필드를 보존하는 기본값입니다."""
        return cls(cpu_percent=None, ram_used_gb=None, ram_total_gb=None, disk_free_gb=None)


class ActiveWindowStatus(StrictFrozenModel):
    """Interactive Worker가 관찰한 foreground 창입니다."""

    title: Annotated[str, Field(max_length=512)] | None
    process: Annotated[str, Field(max_length=260)] | None

    @classmethod
    def unavailable(cls) -> ActiveWindowStatus:
        """Worker offline 또는 관찰 실패 상태입니다."""
        return cls(title=None, process=None)


class StatusResult(StrictFrozenModel):
    """부분 실패를 포함해 항상 직렬화 가능한 status 결과입니다."""

    hostname: Annotated[str, Field(min_length=1, max_length=255)] | None
    bridge_version: Annotated[str, Field(min_length=1, max_length=64)]
    gateway_uptime_s: Annotated[float, Field(ge=0.0)]
    windows_version: Annotated[str, Field(min_length=1, max_length=512)] | None
    tailscale: TailscaleStatus
    interactive_worker: InteractiveWorkerStatus
    privileged_helper: PrivilegedHelperStatus
    resources: ResourceStatus
    active_window: ActiveWindowStatus
    pipe_acl: PipeAclStatus = PipeAclStatus()
    warnings: tuple[StatusWarning, ...] = ()
