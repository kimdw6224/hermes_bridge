"""Interactive Worker가 읽는 최소 Tailscale 연결 snapshot입니다."""

from __future__ import annotations

import ipaddress
import shutil
import subprocess
from typing import Annotated, ClassVar, Final

from pydantic import BaseModel, ConfigDict, Field, field_validator

_IPV4_VERSION: Final = 4
_TAILSCALE_TIMEOUT_S: Final = 0.2
_TAILSCALE_EXECUTABLE: Final = r"C:\Program Files\Tailscale\tailscale.exe"


class TailscaleConnectionSnapshot(BaseModel):
    """권한 정보 없이 Worker가 관찰한 Tailscale 연결 상태입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)
    connected: bool
    ip: Annotated[str, Field(min_length=2, max_length=45)] | None

    @field_validator("ip")
    @classmethod
    def require_ip_address(cls, value: str | None) -> str | None:
        """Worker가 전달하는 주소를 public status 전에 엄격히 검증합니다."""
        if value is not None:
            _ = ipaddress.ip_address(value)
        return value


class _TailscaleSelf(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore", frozen=True)
    online: bool = Field(default=False, alias="Online")


class _TailscaleOutput(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore", frozen=True)
    backend_state: str = Field(default="", alias="BackendState")
    tailscale_ips: tuple[str, ...] = Field(default=(), alias="TailscaleIPs")
    self_node: _TailscaleSelf = Field(default_factory=_TailscaleSelf, alias="Self")


def probe_tailscale_connection() -> TailscaleConnectionSnapshot:
    """Bounded native CLI로 연결 정보만 읽고 caller가 실패를 분리하게 합니다."""
    executable = shutil.which("tailscale") or _TAILSCALE_EXECUTABLE
    completed = subprocess.run(  # noqa: S603 - PATH 또는 Windows 표준 설치 경로의 CLI만 실행합니다.
        [executable, "status", "--json"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=_TAILSCALE_TIMEOUT_S,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    status = _TailscaleOutput.model_validate_json(completed.stdout)
    ipv4 = next(
        (
            value
            for value in status.tailscale_ips
            if ipaddress.ip_address(value).version == _IPV4_VERSION
        ),
        None,
    )
    connected = status.backend_state == "Running" and status.self_node.online
    return TailscaleConnectionSnapshot(connected=connected, ip=ipv4 if connected else None)


def worker_tailscale_connection() -> TailscaleConnectionSnapshot | None:
    """Worker health와 독립적으로 Tailscale CLI 실패를 optional snapshot으로 축소합니다."""
    try:
        return probe_tailscale_connection()
    except OSError, RuntimeError, ValueError, subprocess.SubprocessError:
        return None
