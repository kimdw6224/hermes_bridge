"""구성 파일 경계와 비밀값 처리를 검증합니다."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from hermes_windows_bridge.config import (
    InvalidConfigurationError,
    MissingTokenFileError,
    TrustMode,
    load_bridge_settings,
    load_policy_settings,
    load_startup_settings,
)
from hermes_windows_bridge.models.config import ComputerSettings, WindowsMcpSettings


class TestConfigParsing:
    def test_windows_mcp_requires_explicit_absolute_python(self, tmp_path: Path) -> None:
        executable = tmp_path / "python.exe"
        assert WindowsMcpSettings(python_executable=executable).python_executable == executable
        with pytest.raises(ValidationError):
            _ = WindowsMcpSettings(python_executable=Path("python.exe"))

    def test_computer_default_hotkey_matches_approved_f11_contract(self) -> None:
        # Given: runtime이 등록하는 승인된 로컬 비상 정지 키입니다.

        # When: computer 설정을 별도 override 없이 생성합니다.
        settings = ComputerSettings()

        # Then: 사용자에게 노출되는 기본값도 Ctrl+Alt+Shift+F11입니다.
        assert settings.emergency_stop_hotkey == "ctrl+alt+shift+f11"

    def test_example_config_parses(self) -> None:
        # Given: spec shape의 browser profile 및 bridge idempotency를 포함한 예시 구성입니다.
        environment = {
            "ProgramData": r"C:\\ProgramData",
            "LOCALAPPDATA": r"C:\\Users\\BridgeUser\\AppData\\Local",
        }

        # When: 예시 구성을 타입 경계에서 읽습니다.
        settings = load_bridge_settings(Path("config/config.example.yaml"), environ=environment)

        # Then: browser profile과 bridge 요청 재실행 설정이 독립적으로 보존됩니다.
        assert settings.browser.profile_dir == Path(
            r"C:\\Users\\BridgeUser\\AppData\\Local\\HermesWindowsBridge\\browser-profile"
        )
        assert settings.idempotency.enabled
        assert settings.idempotency.ttl_minutes == 30
        assert settings.computer.emergency_stop_hotkey == "ctrl+alt+shift+f11"

    def test_example_config_parses_when_windows_environment_is_available(self) -> None:
        # Given: 저장소의 비밀값 없는 예시 구성과 명시적인 Windows 환경입니다.
        config_path = Path("config/config.example.yaml")
        environment = {
            "ProgramData": r"C:\\ProgramData",
            "LOCALAPPDATA": r"C:\\Users\\BridgeUser\\AppData\\Local",
        }

        # When: 예시 구성을 타입 경계에서 읽습니다.
        settings = load_bridge_settings(config_path, environ=environment)

        # Then: 경로와 네트워크 기본값이 Windows 런타임 규약과 일치합니다.
        assert settings.paths.program_data == Path(r"C:\\ProgramData\\HermesWindowsBridge")
        assert settings.paths.browser_profile == Path(
            r"C:\\Users\\BridgeUser\\AppData\\Local\\HermesWindowsBridge\\browser-profile"
        )
        assert settings.server.host == "127.0.0.1"

    def test_expands_environment_when_explicit_environment_is_supplied(
        self, tmp_path: Path
    ) -> None:
        # Given: 환경 변수로 구성된 경로를 포함한 최소 구성 파일입니다.
        config_path = tmp_path / "config.yaml"
        config_text = """paths:
  program_data: '%BRIDGE_ROOT%\\program-data'
  user_data: '%BRIDGE_ROOT%\\user-data'
  token_file: '%BRIDGE_ROOT%\\program-data\\secrets\\token'
"""
        _ = config_path.write_text(config_text, encoding="utf-8")
        environment = {"BRIDGE_ROOT": str(tmp_path / "runtime")}

        # When: 호출별 환경 스냅샷으로 구성을 읽습니다.
        settings = load_bridge_settings(config_path, environ=environment)

        # Then: 경로가 확장되어 저장되고 기본 파생 경로도 같은 루트를 사용합니다.
        assert settings.paths.program_data == tmp_path / "runtime" / "program-data"
        assert settings.paths.token_file == (
            tmp_path / "runtime" / "program-data" / "secrets" / "token"
        )

    def test_reloads_environment_when_environment_changes(self, tmp_path: Path) -> None:
        # Given: 같은 구성 텍스트와 서로 다른 두 환경 스냅샷입니다.
        config_path = tmp_path / "config.yaml"
        config_text = """paths:
  program_data: '%ROOT%\\data'
  user_data: '%ROOT%\\user-data'
  token_file: '%ROOT%\\data\\secrets\\token'
"""
        _ = config_path.write_text(config_text, encoding="utf-8")

        # When: 캐시 없이 두 번 읽습니다.
        first = load_bridge_settings(config_path, environ={"ROOT": str(tmp_path / "one")})
        second = load_bridge_settings(config_path, environ={"ROOT": str(tmp_path / "two")})

        # Then: 새 로드는 새 환경 값만 반영합니다.
        assert first.paths.program_data == tmp_path / "one" / "data"
        assert second.paths.program_data == tmp_path / "two" / "data"

    def test_rejects_malformed_yaml_and_python_object_tags(self, tmp_path: Path) -> None:
        # Given: 명령으로 해석될 수 있는 Python YAML 태그가 포함된 구성입니다.
        config_path = tmp_path / "unsafe.yaml"
        _ = config_path.write_text(
            "server: !!python/object/apply:os.system ['whoami']",
            encoding="utf-8",
        )

        # When: 안전한 구성 로더로 읽습니다.
        with pytest.raises(InvalidConfigurationError):
            _ = load_bridge_settings(config_path)

        # Then: 안전하지 않은 YAML은 설정 객체로 전달되지 않습니다.

    def test_rejects_wrong_port_type(self, tmp_path: Path) -> None:
        # Given: 문자열로 기록된 port를 가진 구성입니다.
        config_path = tmp_path / "invalid-port.yaml"
        _ = config_path.write_text(
            "server:\n  port: '8765'\n",
            encoding="utf-8",
        )

        # When: 타입 안전 구성 경계에서 읽습니다.
        with pytest.raises(InvalidConfigurationError):
            _ = load_bridge_settings(config_path)

        # Then: port coercion 없이 하나의 typed 오류로 실패합니다.

    def test_rejects_unresolved_path_environment(self, tmp_path: Path) -> None:
        # Given: 해석할 수 없는 환경 변수를 가진 구성입니다.
        config_path = tmp_path / "invalid-path.yaml"
        _ = config_path.write_text(
            "paths:\n  program_data: '%MISSING_ROOT%\\\\data'\n",
            encoding="utf-8",
        )

        # When: 환경 스냅샷에 없는 변수를 확장하려고 합니다.
        with pytest.raises(InvalidConfigurationError):
            _ = load_bridge_settings(config_path, environ={"LOCALAPPDATA": r"C:\\LocalAppData"})

        # Then: 경로를 추측하지 않고 하나의 typed 오류로 실패합니다.


class TestSecrets:
    def test_missing_token_is_typed_startup_error(self, tmp_path: Path) -> None:
        # Given: 존재하지 않는 토큰 파일을 가리키는 구성입니다.
        config_path = tmp_path / "config.yaml"
        missing_token = tmp_path / "missing-token"
        _ = config_path.write_text(
            f"paths:\n  token_file: '{missing_token.as_posix()}'\n",
            encoding="utf-8",
        )

        # When: 시작용 설정을 로드합니다.
        with pytest.raises(MissingTokenFileError) as raised:
            _ = load_startup_settings(config_path)

        # Then: 자동 생성 없이 파일 위치만 가진 타입 오류를 반환합니다.
        assert raised.value.token_file == missing_token
        assert not missing_token.exists()

    def test_token_is_redacted_when_startup_settings_are_represented(self, tmp_path: Path) -> None:
        # Given: 실제 토큰을 저장한 임시 비밀 파일과 구성입니다.
        marker = "never-log-this-token"
        token_path = tmp_path / "token"
        _ = token_path.write_text(f"{marker}\n", encoding="utf-8")
        config_path = tmp_path / "config.yaml"
        _ = config_path.write_text(
            f"paths:\n  token_file: '{token_path.as_posix()}'\n",
            encoding="utf-8",
        )

        # When: 시작용 설정을 구성합니다.
        startup_settings = load_startup_settings(config_path)

        # Then: Pydantic 비밀값 표현에는 원문 토큰이 없습니다.
        assert marker not in repr(startup_settings)
        assert startup_settings.bearer_token.get_secret_value() == marker


class TestPolicyParsing:
    def test_policy_idempotency_remains_distinct_from_bridge_request_retention(
        self, tmp_path: Path
    ) -> None:
        # Given: 서로 다른 idempotency 값을 가진 bridge와 dispatch policy 구성입니다.
        bridge_file = tmp_path / "bridge.yaml"
        policy_file = tmp_path / "policy.yaml"
        _ = bridge_file.write_text(
            "idempotency:\n  enabled: false\n  ttl_minutes: 13\n",
            encoding="utf-8",
        )
        _ = policy_file.write_text(
            "idempotency:\n  enabled: true\n  ttl_minutes: 29\n",
            encoding="utf-8",
        )

        # When: 두 구성 경계를 독립적으로 읽습니다.
        bridge = load_bridge_settings(bridge_file)
        policy = load_policy_settings(policy_file)

        # Then: bridge replay retention과 policy dispatch 요구가 섞이지 않습니다.
        assert not bridge.idempotency.enabled
        assert bridge.idempotency.ttl_minutes == 13
        assert policy.idempotency.enabled
        assert policy.idempotency.ttl_minutes == 29

    def test_example_policy_defaults_to_untrusted_mode(self) -> None:
        # Given: 저장소의 정책 예시입니다.
        policy_path = Path("config/policy.example.yaml")

        # When: 정책 경계를 읽습니다.
        policy = load_policy_settings(policy_path)

        # Then: 초기 trust 상태는 허용 대신 untrusted입니다.
        assert policy.mode is TrustMode.UNTRUSTED
