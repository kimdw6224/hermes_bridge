"""동결된 Hermes Windows Bridge 구성 모델입니다."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PureWindowsPath
from typing import TYPE_CHECKING, ClassVar, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationInfo, field_validator

if TYPE_CHECKING:
    from collections.abc import Mapping

ENVIRONMENT_VARIABLE_PATTERN: Final = re.compile(
    r"%(?P<windows>[^%]+)%|\$\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|\$(?P<posix>[A-Za-z_][A-Za-z0-9_]*)"
)


@dataclass(frozen=True, slots=True)
class EnvironmentContext:
    """한 번의 구성 로드에만 적용되는 환경 변수 스냅샷입니다."""

    environ: Mapping[str, str]


class FrozenSettings(BaseModel):
    """외부 구성 파싱에 공통으로 적용되는 Pydantic 규칙입니다."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid", frozen=True, validate_default=True
    )


def _environment_from(info: ValidationInfo) -> Mapping[str, str]:
    context = info.context
    if isinstance(context, EnvironmentContext):
        return context.environ
    return os.environ


def _expand_windows_path(value: str, environment: Mapping[str, str]) -> Path:
    normalized_environment = {key.casefold(): item for key, item in environment.items()}

    def replace(match: re.Match[str]) -> str:
        variable = next(group for group in match.groups() if group is not None)
        replacement = normalized_environment.get(variable.casefold())
        if replacement is None:
            message = f"unresolved environment variable: {variable}"
            raise ValueError(message)
        return replacement

    expanded = ENVIRONMENT_VARIABLE_PATTERN.sub(replace, value)
    windows_path = PureWindowsPath(expanded)
    if not windows_path.is_absolute() or ".." in windows_path.parts:
        message = "runtime paths must be absolute and traversal-free"
        raise ValueError(message)
    return Path(expanded)


class RuntimePaths(FrozenSettings):
    """Machine-wide 및 사용자별 Windows 런타임 위치입니다."""

    program_data: Path = Path(r"%ProgramData%\HermesWindowsBridge")
    user_data: Path = Path(r"%LOCALAPPDATA%\HermesWindowsBridge")
    token_file: Path = Path(r"%ProgramData%\HermesWindowsBridge\secrets\token")

    @field_validator("program_data", "user_data", "token_file", mode="after")
    @classmethod
    def expand_environment_paths(cls, value: Path, info: ValidationInfo) -> Path:
        """경로를 요청별 환경 스냅샷으로 확장합니다."""
        return _expand_windows_path(str(value), _environment_from(info))

    @property
    def gateway_logs(self) -> Path:
        """Gateway 로그와 감사 이벤트의 기본 위치를 반환합니다."""
        return self.program_data / "logs"

    @property
    def jobs(self) -> Path:
        """Job 메타데이터의 기본 위치를 반환합니다."""
        return self.program_data / "jobs"

    @property
    def secrets(self) -> Path:
        """Gateway 전용 비밀 파일 디렉터리를 반환합니다."""
        return self.program_data / "secrets"

    @property
    def browser_profile(self) -> Path:
        """기본 browser profile 위치를 반환합니다."""
        return self.user_data / "browser-profile"

    @property
    def worker_logs(self) -> Path:
        """선택적 Worker 진단 로그 위치를 반환합니다."""
        return self.user_data / "logs"


class ServerSettings(FrozenSettings):
    """Loopback MCP endpoint 및 Host/Origin 허용 목록입니다."""

    host: Literal["127.0.0.1", "::1"] = "127.0.0.1"
    port: int = Field(default=8765, ge=1, le=65535, strict=True)
    mcp_path: str = "/mcp"
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost")
    allowed_origins: tuple[str, ...] = ()

    @field_validator("mcp_path")
    @classmethod
    def require_absolute_mcp_path(cls, value: str) -> str:
        """MCP endpoint가 상대 경로로 해석되지 않게 합니다."""
        if not value.startswith("/") or value.startswith("//"):
            message = "mcp_path must be an absolute single-slash path"
            raise ValueError(message)
        return value


class IpcSettings(FrozenSettings):
    """두 최소 권한 named pipe의 연결 기본값입니다."""

    worker_pipe: str = r"\\.\pipe\HermesWindowsBridgeWorker"
    privileged_pipe: str = r"\\.\pipe\HermesWindowsBridgePrivileged"
    protocol_version: int = Field(default=1, ge=1, strict=True)
    heartbeat_seconds: int = Field(default=5, ge=1, strict=True)
    offline_after_seconds: int = Field(default=15, ge=1, strict=True)


class TailscaleSettings(FrozenSettings):
    """선택적 Tailscale 애플리케이션 권한 검증 설정입니다."""

    require_app_capability: bool = True
    app_capability: str | None = "hermes.local/windows-control"


class BrowserSettings(FrozenSettings):
    """대상 사용자 브라우저 자동화와 profile 위치입니다."""

    enabled: bool = True
    profile_dir: Path = Path(r"%LOCALAPPDATA%\HermesWindowsBridge\browser-profile")
    headless: bool = False

    @field_validator("profile_dir", mode="after")
    @classmethod
    def expand_profile_dir(cls, value: Path, info: ValidationInfo) -> Path:
        """Profile 경로를 환경 스냅샷으로 확장합니다."""
        return _expand_windows_path(str(value), _environment_from(info))


class CodexSettings(FrozenSettings):
    """로컬 Codex adapter의 명시적 실행 설정입니다."""

    enabled: bool = True
    executable: str = "codex"
    record_git_preflight: bool = True


class ComputerSettings(FrozenSettings):
    """직렬화된 사용자 입력과 비상 중지 설정입니다."""

    enabled: bool = True
    serialize_input: bool = True
    emergency_stop_hotkey: str = "ctrl+alt+shift+f11"
    emergency_stop_persistent: bool = True


class WindowsMcpSettings(FrozenSettings):
    """일반 사용자 Worker가 소유하는 Windows-MCP 실행 설정입니다."""

    python_executable: Path

    @field_validator("python_executable")
    @classmethod
    def require_absolute_mcp_python(cls, value: Path) -> Path:
        """PATH 검색으로 다른 실행 파일을 선택하지 않도록 명시적 경로만 받습니다."""
        if not value.is_absolute():
            raise InvalidWindowsMcpPathError
        return value


class InvalidWindowsMcpPathError(ValueError):
    """Windows-MCP Python 경로가 절대 경로가 아닙니다."""


class JobSettings(FrozenSettings):
    """동시 작업 수와 Windows Job Object 사용 한도입니다."""

    max_concurrent: int = Field(default=4, ge=1, strict=True)
    retention_hours: int = Field(default=24, ge=1, strict=True)
    use_windows_job_objects: bool = True


class IdempotencySettings(FrozenSettings):
    """Bridge request replay 방지 저장소의 전역 보존 설정입니다."""

    enabled: bool = True
    ttl_minutes: int = Field(default=30, ge=1, strict=True)


class OutputSettings(FrozenSettings):
    """응답과 인라인 파일 전송의 크기 한도입니다."""

    max_output_bytes: int = Field(default=200_000, ge=1, strict=True)
    max_inline_read_bytes: int = Field(default=1_000_000, ge=1, strict=True)
    max_inline_write_bytes: int = Field(default=1_000_000, ge=1, strict=True)


class LoggingSettings(FrozenSettings):
    """원문 출력과 스크린샷을 보관하지 않는 로그 설정입니다."""

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    retain_raw_command_output: bool = False
    retain_screenshots: bool = False


class BridgeSettings(FrozenSettings):
    """Gateway 시작에 필요한 비밀값을 제외한 모든 Bridge 구성입니다."""

    server: ServerSettings = Field(default_factory=ServerSettings)
    ipc: IpcSettings = Field(default_factory=IpcSettings)
    tailscale: TailscaleSettings = Field(default_factory=TailscaleSettings)
    paths: RuntimePaths = Field(default_factory=RuntimePaths)
    browser: BrowserSettings = Field(default_factory=BrowserSettings)
    codex: CodexSettings = Field(default_factory=CodexSettings)
    computer: ComputerSettings = Field(default_factory=ComputerSettings)
    jobs: JobSettings = Field(default_factory=JobSettings)
    idempotency: IdempotencySettings = Field(default_factory=IdempotencySettings)
    output: OutputSettings = Field(default_factory=OutputSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)


class TrustMode(StrEnum):
    """정책 경계가 인식하는 명시적 신뢰 상태입니다."""

    UNTRUSTED = "untrusted"
    TRUSTED_USER_CONTROL = "trusted_user_control"


class AuditPolicy(FrozenSettings):
    """비밀값과 대용량 원문을 보관하지 않는 감사 정책입니다."""

    enabled: bool = True
    store_raw_stdout: bool = False
    store_screenshots: bool = False
    redact_secrets: bool = True


class ApprovalPolicy(FrozenSettings):
    """모델 외부의 단발성 승인 요구 사항입니다."""

    method: Literal["elicitation_then_local"] = "elicitation_then_local"
    timeout_seconds: int = Field(default=300, ge=1, strict=True)
    required_for: tuple[str, ...] = ()
    bulk_delete_threshold: int = Field(default=100, ge=1, strict=True)


class ShellPolicy(FrozenSettings):
    """사용자 수준 shell 실행의 안전 한도입니다."""

    user_level_only: bool = True
    inspect_commands_for_accident_prevention: bool = True
    max_sync_seconds: int = Field(default=110, ge=1, strict=True)
    max_output_bytes: int = Field(default=200_000, ge=1, strict=True)


class FilesystemPolicy(FrozenSettings):
    """Windows path 처리와 인라인 I/O의 보수적 기본값입니다."""

    resolve_reparse_points: bool = True
    additional_allowed_roots: tuple[Path, ...] = ()
    deny_device_paths: bool = True
    allow_unc: bool = False
    allow_alternate_data_streams: bool = False
    max_inline_read_bytes: int = Field(default=1_000_000, ge=1, strict=True)
    max_inline_write_bytes: int = Field(default=1_000_000, ge=1, strict=True)

    @field_validator("additional_allowed_roots", mode="after")
    @classmethod
    def expand_additional_roots(
        cls, values: tuple[Path, ...], info: ValidationInfo,
    ) -> tuple[Path, ...]:
        """추가 작업 경로도 기존 런타임 경로와 같은 절대 경로 경계에서 파싱합니다."""
        return tuple(_expand_windows_path(str(value), _environment_from(info)) for value in values)


class ComputerPolicy(FrozenSettings):
    """원격 컴퓨터 입력의 직렬화 및 로컬 중지 조건입니다."""

    serialize_input: bool = True
    emergency_stop_requires_local_reset: bool = True


class PolicyIdempotencySettings(FrozenSettings):
    """Policy dispatch가 Bridge replay 설정을 사용하도록 요구하는 값입니다."""

    enabled: bool = True
    ttl_minutes: int = Field(default=30, ge=1, strict=True)


class PolicySettings(FrozenSettings):
    """Dispatch 전에 파싱되는 최소 권한 정책입니다."""

    mode: TrustMode = TrustMode.UNTRUSTED
    audit: AuditPolicy = Field(default_factory=AuditPolicy)
    approval: ApprovalPolicy = Field(default_factory=ApprovalPolicy)
    hard_deny: tuple[str, ...] = ()
    shell: ShellPolicy = Field(default_factory=ShellPolicy)
    filesystem: FilesystemPolicy = Field(default_factory=FilesystemPolicy)
    computer: ComputerPolicy = Field(default_factory=ComputerPolicy)
    idempotency: PolicyIdempotencySettings = Field(default_factory=PolicyIdempotencySettings)


@dataclass(frozen=True, slots=True)
class StartupSettings:
    """비밀 표현을 자동 마스킹하는 시작 전용 설정 묶음입니다."""

    bridge: BridgeSettings
    bearer_token: SecretStr
