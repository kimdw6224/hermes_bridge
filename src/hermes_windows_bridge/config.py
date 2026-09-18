"""YAML 구성 로딩과 비밀 파일 경계입니다."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, ClassVar, final, override

import yaml
from pydantic import SecretStr, ValidationError

from hermes_windows_bridge.models.config import (
    ApprovalPolicy,
    AuditPolicy,
    BridgeSettings,
    BrowserSettings,
    CodexSettings,
    ComputerPolicy,
    ComputerSettings,
    EnvironmentContext,
    FilesystemPolicy,
    FrozenSettings,
    IdempotencySettings,
    IpcSettings,
    JobSettings,
    LoggingSettings,
    OutputSettings,
    PolicyIdempotencySettings,
    PolicySettings,
    RuntimePaths,
    ServerSettings,
    ShellPolicy,
    StartupSettings,
    TailscaleSettings,
    TrustMode,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

__all__ = [
    "ApprovalPolicy",
    "AuditPolicy",
    "BridgeSettings",
    "BrowserSettings",
    "CodexSettings",
    "ComputerPolicy",
    "ComputerSettings",
    "ConfigurationFileError",
    "ConfigurationFileNotFoundError",
    "EmptyTokenError",
    "FilesystemPolicy",
    "IdempotencySettings",
    "InvalidConfigurationError",
    "IpcSettings",
    "JobSettings",
    "LoggingSettings",
    "MissingTokenFileError",
    "OutputSettings",
    "PolicyIdempotencySettings",
    "PolicySettings",
    "RuntimePaths",
    "ServerSettings",
    "ShellPolicy",
    "StartupSettings",
    "TailscaleSettings",
    "TokenFileError",
    "TrustMode",
    "load_bridge_settings",
    "load_policy_settings",
    "load_startup_settings",
]


class ConfigurationFileError(Exception):
    """안전한 파일 위치만 담는 구성 파싱 오류의 기반 클래스입니다."""

    config_file: Path
    description: ClassVar[str]

    def __init__(self, config_file: Path) -> None:
        """원문 구성 값을 보관하지 않고 파일 위치를 초기화합니다."""
        super().__init__()
        self.config_file = config_file

    @override
    def __str__(self) -> str:
        """비밀값 없는 오류 메시지를 반환합니다."""
        return f"{self.description}: {self.config_file}"


@final
class ConfigurationFileNotFoundError(ConfigurationFileError):
    """구성 파일이 없을 때 발생합니다."""

    description: ClassVar[str] = "configuration file was not found"


@final
class InvalidConfigurationError(ConfigurationFileError):
    """구성 텍스트가 안전한 모델로 파싱되지 않을 때 발생합니다."""

    description: ClassVar[str] = "configuration file is invalid"


class TokenFileError(Exception):
    """토큰 원문을 보관하지 않는 비밀 파일 오류의 기반 클래스입니다."""

    token_file: Path
    description: ClassVar[str]

    def __init__(self, token_file: Path) -> None:
        """비밀값 대신 파일 위치를 초기화합니다."""
        super().__init__()
        self.token_file = token_file

    @override
    def __str__(self) -> str:
        """비밀값 없는 오류 메시지를 반환합니다."""
        return f"{self.description}: {self.token_file}"


@final
class MissingTokenFileError(TokenFileError):
    """토큰 파일이 없을 때 자동 생성을 막습니다."""

    description: ClassVar[str] = "gateway token file was not found"


@final
class EmptyTokenError(TokenFileError):
    """빈 토큰 파일을 시작 오류로 처리합니다."""

    description: ClassVar[str] = "gateway token file is empty"


def _load_model[T: FrozenSettings](
    config_file: Path, model_type: type[T], environ: Mapping[str, str] | None
) -> T:
    try:
        contents = config_file.read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise ConfigurationFileNotFoundError(config_file=config_file) from error
    except UnicodeDecodeError as error:
        raise InvalidConfigurationError(config_file=config_file) from error
    try:
        environment = os.environ if environ is None else environ
        return model_type.model_validate(
            yaml.safe_load(contents), context=EnvironmentContext(environ=environment)
        )
    except (ValidationError, yaml.YAMLError, ValueError) as error:
        raise InvalidConfigurationError(config_file=config_file) from error


def load_bridge_settings(
    config_file: Path, *, environ: Mapping[str, str] | None = None
) -> BridgeSettings:
    """비밀을 읽지 않고 Bridge 구성을 동결 모델로 파싱합니다."""
    return _load_model(config_file, BridgeSettings, environ)


def load_policy_settings(policy_file: Path) -> PolicySettings:
    """정책 파일을 untrusted 기본값을 가진 동결 모델로 파싱합니다."""
    return _load_model(policy_file, PolicySettings, None)


def load_startup_settings(
    config_file: Path, *, environ: Mapping[str, str] | None = None
) -> StartupSettings:
    """Gateway 기동 직전에 토큰 파일을 읽되 누락 시 즉시 실패합니다."""
    bridge = load_bridge_settings(config_file, environ=environ)
    try:
        token = bridge.paths.token_file.read_text(encoding="utf-8").strip()
    except FileNotFoundError as error:
        raise MissingTokenFileError(token_file=bridge.paths.token_file) from error
    if not token:
        raise EmptyTokenError(token_file=bridge.paths.token_file)
    return StartupSettings(bridge=bridge, bearer_token=SecretStr(token))
