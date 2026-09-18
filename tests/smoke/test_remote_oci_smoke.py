"""Task 25 remote-smoke scenarios with a non-mutating default path."""

from __future__ import annotations

import json
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from hermes_windows_bridge.gateway.policy import registered_tool_names
from tests.conftest import (
    FORBIDDEN_REMOTE_MUTATION_TOKENS,
    LOOPBACK_ADDRESSES,
    REMOTE_PREFLIGHT_COMMAND,
    SSH_TIMEOUT_SECONDS,
    CommandState,
    SmokeCliInput,
    SmokeConfigurationError,
    SmokeOptions,
    build_ssh_argv,
    cleanup_owned_artifacts,
    execute_bounded,
    parse_smoke_options,
    public_listener_addresses,
    smoke_options_from_pytest,
)


def test_preflight_defaults_to_no_operational_mutation() -> None:
    options = parse_smoke_options(
        SmokeCliInput()
    )
    assert options == SmokeOptions()
    assert all(token not in REMOTE_PREFLIGHT_COMMAND for token in FORBIDDEN_REMOTE_MUTATION_TOKENS)


@pytest.mark.parametrize("host", ["bad host", "user@host", "host;shutdown", "-oProxyCommand=x"])
def test_untrusted_ssh_host_is_rejected(host: str) -> None:
    with pytest.raises(SmokeConfigurationError, match="invalid OCI host"):
        _ = parse_smoke_options(SmokeCliInput(oci_host=host))


def test_invalid_user_and_missing_identity_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(SmokeConfigurationError, match="invalid OCI user"):
        _ = parse_smoke_options(
            SmokeCliInput(oci_host="host", oci_user="user;id")
        )
    with pytest.raises(SmokeConfigurationError, match="SSH identity"):
        _ = parse_smoke_options(
            SmokeCliInput(oci_host="host", ssh_identity=str(tmp_path / "missing"))
        )


def test_mutation_flags_fail_closed_without_required_approvals(tmp_path: Path) -> None:
    identity = tmp_path / "identity"
    _ = identity.write_text("fixture", encoding="utf-8")
    cases = (
        SmokeCliInput(local_apply=True),
        SmokeCliInput(oci_host="host", ssh_identity=str(identity), local_apply=True),
        SmokeCliInput(
            oci_host="host", ssh_identity=str(identity), remote_config_mutation=True
        ),
        SmokeCliInput(
            oci_host="host", serve_host="bridge.example.ts.net", reboot_smoke=True
        ),
    )
    for raw in cases:
        with pytest.raises(SmokeConfigurationError):
            _ = parse_smoke_options(raw)


def test_ssh_argv_is_structured_and_contains_only_fixed_remote_command(tmp_path: Path) -> None:
    identity = tmp_path / "identity"
    _ = identity.write_text("fixture", encoding="utf-8")
    options = parse_smoke_options(
        SmokeCliInput(
            oci_host="host.example", oci_user="bridge_user", ssh_identity=str(identity)
        )
    )
    argv = build_ssh_argv(options)
    assert argv[-2:] == ("bridge_user@host.example", REMOTE_PREFLIGHT_COMMAND)
    assert argv[1:5] == ("-i", str(identity.resolve()), "-o", "IdentitiesOnly=yes")
    assert not any(token in argv for token in ("shell=True", "cmd.exe", "powershell.exe"))


def test_ssh_failure_is_redacted_and_never_reported_as_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_ssh(
        _args: list[str], *, check: bool, capture_output: bool, timeout: int
    ) -> subprocess.CompletedProcess[bytes]:
        assert not check
        assert capture_output
        assert timeout > 0
        return subprocess.CompletedProcess(
            args=["ssh"], returncode=255, stdout=b"TOKEN=top-secret", stderr=b"Bearer abc123"
        )

    monkeypatch.setattr(subprocess, "run", fail_ssh)
    receipt = execute_bounded(("ssh", "host", REMOTE_PREFLIGHT_COMMAND), SSH_TIMEOUT_SECONDS)
    assert receipt.state is CommandState.FAILED
    assert receipt.return_code == 255
    assert receipt.stdout == "TOKEN=[REDACTED]"
    assert receipt.stderr == "Bearer [REDACTED]"


def test_timeout_is_reported_as_cancelled(monkeypatch: pytest.MonkeyPatch) -> None:
    def time_out(
        _args: list[str], *, check: bool, capture_output: bool, timeout: int
    ) -> subprocess.CompletedProcess[bytes]:
        assert not check
        assert capture_output
        assert timeout > 0
        raise subprocess.TimeoutExpired(cmd=["ssh"], timeout=1, output=b"TOKEN=secret")

    monkeypatch.setattr(subprocess, "run", time_out)
    receipt = execute_bounded(("ssh", "host", REMOTE_PREFLIGHT_COMMAND), 1)
    assert receipt.state is CommandState.TIMED_OUT
    assert receipt.cancelled
    assert receipt.return_code is None
    assert "secret" not in receipt.stdout


def test_utf8_remote_output_is_decoded_independently_of_windows_locale(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def utf8_output(
        _args: list[str], *, check: bool, capture_output: bool, timeout: int
    ) -> subprocess.CompletedProcess[bytes]:
        assert not check
        assert capture_output
        assert timeout > 0
        return subprocess.CompletedProcess(
            args=["ssh"], returncode=0, stdout="Hermes 준비됨".encode(), stderr=b""
        )

    monkeypatch.setattr(subprocess, "run", utf8_output)
    receipt = execute_bounded(("ssh", "host", REMOTE_PREFLIGHT_COMMAND), 1)
    assert receipt.state is CommandState.SUCCEEDED
    assert receipt.stdout == "Hermes 준비됨"


def test_cleanup_receipts_cover_only_owned_fixture_artifacts(tmp_path: Path) -> None:
    artifacts = (tmp_path / "process.pid", tmp_path / "browser-fixture.html")
    for artifact in artifacts:
        _ = artifact.write_text("fixture", encoding="utf-8")
    receipts = cleanup_owned_artifacts(artifacts, tmp_path)
    assert all(receipt.existed and receipt.removed for receipt in receipts)
    assert not any(artifact.exists() for artifact in artifacts)
    with pytest.raises(SmokeConfigurationError, match="escapes fixture root"):
        _ = cleanup_owned_artifacts((tmp_path.parent / "unowned",), tmp_path)


def test_local_security_surface_has_no_public_listener_or_generic_privileged_tool() -> None:
    public = public_listener_addresses(8765) - LOOPBACK_ADDRESSES
    assert public == frozenset()
    assert registered_tool_names().isdisjoint(
        {"admin_shell", "system_shell", "run_as_system", "approval_grant"}
    )


def test_remote_read_only_preflight_when_host_is_supplied(pytestconfig: pytest.Config) -> None:
    options = smoke_options_from_pytest(pytestconfig)
    if options.oci_host is None:
        assert not options.local_apply
        assert not options.remote_config_mutation
        assert not options.reboot_smoke
        return
    receipt = execute_bounded(build_ssh_argv(options), SSH_TIMEOUT_SECONDS)
    _ = sys.stdout.write(
        json.dumps({"state": receipt.state, "stdout": receipt.stdout}, ensure_ascii=True) + "\n"
    )
    assert receipt.state is CommandState.SUCCEEDED, receipt.stderr
    assert "kernel=Linux" in receipt.stdout
    assert "config_access=" in receipt.stdout
