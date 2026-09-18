"""Pytest CLI gates and typed support for the Task 25 remote-smoke harness."""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from enum import StrEnum, unique
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol, override

if TYPE_CHECKING:
    import pytest

SSH_TIMEOUT_SECONDS: Final = 20
LOOPBACK_ADDRESSES: Final = frozenset({"127.0.0.1", "::1"})
HOST_PATTERN: Final = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$"
)
USER_PATTERN: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,31}$")
SECRET_PATTERNS: Final = (
    re.compile(r"(?i)(Bearer\s+)[^\s\"']+"),
    re.compile(r"(?i)((?:TOKEN|PASSWORD|SECRET|API_KEY)\s*[=:]\s*)[^\s\"']+"),
    re.compile(
        r"-----BEGIN [^-]+ PRIVATE KEY-----.*?-----END [^-]+ PRIVATE KEY-----", re.DOTALL
    ),
)
REMOTE_PREFLIGHT_COMMAND: Final = (
    "set -eu; "
    "printf 'remote_user='; id -un; "
    "printf 'kernel='; uname -s; "
    "printf 'remote_host='; hostname; "
    "hermes_bin=$(command -v hermes || true); "
    'if test -z "$hermes_bin" && test -x "$HOME/.local/bin/hermes"; then '
    'hermes_bin="$HOME/.local/bin/hermes"; fi; '
    "printf 'hermes_available='; "
    'if test -n "$hermes_bin"; then printf \'yes\\n\'; '
    '"$hermes_bin" --version 2>/dev/null || true; '
    "else printf 'no\\n'; fi; "
    "printf 'gateway_state='; systemctl --user is-active hermes-gateway 2>/dev/null || true; "
    'if test -r "$HOME/.hermes/config.yaml"; then '
    "printf 'config_access=readable\\n'; "
    'stat -c \'config_mode=%a\\n\' "$HOME/.hermes/config.yaml"; '
    "else printf 'config_access=unavailable\\n'; fi"
)
FORBIDDEN_REMOTE_MUTATION_TOKENS: Final = (
    "sudo ",
    "tailscale up",
    "tailscale serve",
    "systemctl restart",
    "systemctl reload",
    "rm ",
    "mv ",
    "cp ",
)


class PytestOptionReader(Protocol):
    def getoption(self, name: str) -> str | bool | None: ...


@unique
class CommandState(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


@dataclass(frozen=True, slots=True)
class SmokeCliInput:
    oci_host: str | None = None
    oci_user: str | None = None
    ssh_identity: str | None = None
    serve_host: str | None = None
    local_apply: bool = False
    remote_config_mutation: bool = False
    remote_backup_confirmed: bool = False
    reboot_smoke: bool = False


@dataclass(frozen=True, slots=True)
class SmokeOptions:
    oci_host: str | None = None
    oci_user: str | None = None
    ssh_identity: Path | None = None
    serve_host: str | None = None
    local_apply: bool = False
    remote_config_mutation: bool = False
    reboot_smoke: bool = False


@dataclass(frozen=True, slots=True)
class CommandReceipt:
    state: CommandState
    return_code: int | None
    stdout: str
    stderr: str
    cancelled: bool


@dataclass(frozen=True, slots=True)
class CleanupReceipt:
    path: str
    existed: bool
    removed: bool


@dataclass(frozen=True, slots=True)
class SmokeConfigurationError(Exception):
    reason: str

    @override
    def __str__(self) -> str:
        return self.reason


def redact_secret(value: str) -> str:
    redacted = value
    for pattern in SECRET_PATTERNS:
        replacement = r"\1[REDACTED]" if pattern.groups else "[REDACTED]"
        redacted = pattern.sub(replacement, redacted)
    return redacted


def decode_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def parse_smoke_options(raw: SmokeCliInput) -> SmokeOptions:
    if raw.oci_host is not None and HOST_PATTERN.fullmatch(raw.oci_host) is None:
        raise SmokeConfigurationError(reason="invalid OCI host")
    if raw.oci_user is not None and USER_PATTERN.fullmatch(raw.oci_user) is None:
        raise SmokeConfigurationError(reason="invalid OCI user")
    if raw.serve_host is not None and HOST_PATTERN.fullmatch(raw.serve_host) is None:
        raise SmokeConfigurationError(reason="invalid Serve host")
    identity = Path(raw.ssh_identity).resolve() if raw.ssh_identity is not None else None
    if identity is not None and (not identity.is_absolute() or not identity.is_file()):
        raise SmokeConfigurationError(reason="SSH identity must be an existing file")
    any_live_flag = raw.local_apply or raw.remote_config_mutation or raw.reboot_smoke
    if any_live_flag and raw.oci_host is None:
        raise SmokeConfigurationError(reason="live flags require --oci-host")
    if raw.local_apply and raw.serve_host is None:
        raise SmokeConfigurationError(reason="local Apply requires --serve-host")
    if raw.remote_config_mutation and not raw.remote_backup_confirmed:
        raise SmokeConfigurationError(reason="remote mutation requires confirmed backup")
    if raw.reboot_smoke and not (raw.local_apply and raw.remote_config_mutation):
        raise SmokeConfigurationError(reason="reboot requires both operational approval flags")
    return SmokeOptions(
        oci_host=raw.oci_host,
        oci_user=raw.oci_user,
        ssh_identity=identity,
        serve_host=raw.serve_host,
        local_apply=raw.local_apply,
        remote_config_mutation=raw.remote_config_mutation,
        reboot_smoke=raw.reboot_smoke,
    )


def smoke_options_from_pytest(config: PytestOptionReader) -> SmokeOptions:
    def optional_text(name: str) -> str | None:
        value = config.getoption(name)
        return value if isinstance(value, str) and value else None

    return parse_smoke_options(
        SmokeCliInput(
            oci_host=optional_text("--oci-host"),
            oci_user=optional_text("--oci-user"),
            ssh_identity=optional_text("--ssh-identity"),
            serve_host=optional_text("--serve-host"),
            local_apply=config.getoption("--allow-local-apply") is True,
            remote_config_mutation=config.getoption("--allow-remote-config-mutation") is True,
            remote_backup_confirmed=config.getoption("--remote-config-backup-confirmed") is True,
            reboot_smoke=config.getoption("--allow-reboot-smoke") is True,
        )
    )


def build_ssh_argv(options: SmokeOptions) -> tuple[str, ...]:
    ssh_path = shutil.which("ssh")
    if ssh_path is None or options.oci_host is None:
        raise SmokeConfigurationError(reason="SSH and --oci-host are required")
    target = (
        f"{options.oci_user}@{options.oci_host}"
        if options.oci_user is not None
        else options.oci_host
    )
    identity_args = (
        ()
        if options.ssh_identity is None
        else ("-i", str(options.ssh_identity), "-o", "IdentitiesOnly=yes")
    )
    return (
        ssh_path,
        *identity_args,
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ServerAliveInterval=5",
        "-o",
        "ServerAliveCountMax=1",
        target,
        REMOTE_PREFLIGHT_COMMAND,
    )


def execute_bounded(argv: tuple[str, ...], timeout_seconds: int) -> CommandReceipt:
    try:
        result = subprocess.run(
            list(argv), check=False, capture_output=True, timeout=timeout_seconds
        )
    except subprocess.TimeoutExpired as error:
        return CommandReceipt(
            state=CommandState.TIMED_OUT,
            return_code=None,
            stdout=redact_secret(decode_output(error.stdout)),
            stderr=redact_secret(decode_output(error.stderr)),
            cancelled=True,
        )
    state = CommandState.SUCCEEDED if result.returncode == 0 else CommandState.FAILED
    return CommandReceipt(
        state=state,
        return_code=result.returncode,
        stdout=redact_secret(decode_output(result.stdout)),
        stderr=redact_secret(decode_output(result.stderr)),
        cancelled=False,
    )


def cleanup_owned_artifacts(artifacts: tuple[Path, ...], root: Path) -> tuple[CleanupReceipt, ...]:
    safe_root = root.resolve()
    receipts: list[CleanupReceipt] = []
    for artifact in artifacts:
        candidate = artifact.resolve()
        if not candidate.is_relative_to(safe_root):
            raise SmokeConfigurationError(reason="cleanup artifact escapes fixture root")
        existed = candidate.is_file()
        candidate.unlink(missing_ok=True)
        receipts.append(CleanupReceipt(str(candidate), existed, existed))
    return tuple(receipts)


def public_listener_addresses(port: int) -> frozenset[str]:
    powershell_path = shutil.which("powershell.exe")
    if powershell_path is None:
        raise SmokeConfigurationError(reason="PowerShell is required for listener preflight")
    command = (
        f"@(Get-NetTCPConnection -State Listen -LocalPort {port} "
        "-ErrorAction SilentlyContinue).LocalAddress"
    )
    receipt = execute_bounded((powershell_path, "-NoProfile", "-Command", command), 10)
    if receipt.state is not CommandState.SUCCEEDED:
        raise SmokeConfigurationError(reason="listener preflight failed")
    return frozenset(line.strip() for line in receipt.stdout.splitlines() if line.strip())


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("hermes-remote-smoke")
    group.addoption("--oci-host", default=None, help="Validated OCI SSH host or alias")
    group.addoption("--oci-user", default=None, help="Validated OCI SSH user override")
    group.addoption("--ssh-identity", default=None, help="Existing SSH private-key path")
    group.addoption("--serve-host", default=None, help="Validated private Tailscale Serve host")
    group.addoption("--allow-local-apply", action="store_true", default=False)
    group.addoption("--allow-remote-config-mutation", action="store_true", default=False)
    group.addoption("--remote-config-backup-confirmed", action="store_true", default=False)
    group.addoption("--allow-reboot-smoke", action="store_true", default=False)
