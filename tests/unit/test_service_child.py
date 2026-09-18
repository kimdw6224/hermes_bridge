"""Service child process start and stop contracts."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import os
import sys
import threading
from io import StringIO
from pathlib import Path
from typing import TYPE_CHECKING, final

import anyio
import pytest
from anyio import to_thread

from hermes_windows_bridge import service_child
from hermes_windows_bridge.runtime_binding import RuntimeBinding, RuntimeProfile
from hermes_windows_bridge.service_child import (
    ServiceChildDependencies,
    ServiceChildUsageError,
    ServiceProfile,
    parse_profile,
    parse_service_child_args,
    run_service_child,
)

if TYPE_CHECKING:
    from collections.abc import Callable


class TestProfileParsing:
    def test_accepts_only_fixed_host_argv(self) -> None:
        assert parse_profile(("--profile", "gateway")) is ServiceProfile.GATEWAY
        assert parse_profile(("--profile", "privileged")) is ServiceProfile.PRIVILEGED

    @pytest.mark.parametrize(
        "argv",
        [
            (),
            ("--profile", "worker"),
            ("gateway",),
            ("--profile", "gateway", "--extra"),
        ],
    )
    def test_rejects_non_fixed_or_unknown_argv(self, argv: tuple[str, ...]) -> None:
        with pytest.raises(ServiceChildUsageError):
            _ = parse_profile(argv)

    def test_accepts_complete_binding_pair_after_fixed_profile(self) -> None:
        # Given: the schema-2 host's fixed profile plus its binding/hash pair.
        digest = "a" * 64

        # When: the child parses its full startup command.
        profile, binding = parse_service_child_args(
            (
                "--profile",
                "gateway",
                "--runtime-binding",
                "C:\\binding.json",
                "--runtime-binding-sha256",
                digest,
            )
        )

        # Then: profile remains fixed and the pair is preserved for protected verification.
        assert profile is ServiceProfile.GATEWAY
        assert binding == (Path("C:\\binding.json"), digest)


@final
class _BlockingHelperRuntime:
    def __init__(self) -> None:
        self.ready = threading.Event()
        self.stop_requested = threading.Event()
        self.finished = threading.Event()

    def request_stop(self) -> None:
        self.stop_requested.set()

    def run_pipe_loop(
        self,
        stop_requested: Callable[[], bool],
        on_ready: Callable[[], None] | None = None,
    ) -> None:
        assert on_ready is not None
        on_ready()
        self.ready.set()
        assert self.stop_requested.wait(1)
        assert stop_requested()
        self.finished.set()


async def _gateway_must_not_run(
    announce_ready: Callable[[], None],
    stop_requested: Callable[[], bool],
) -> None:
    del announce_ready, stop_requested
    message = "gateway profile must not run"
    raise AssertionError(message)


def test_helper_requests_runtime_stop_after_parent_stop_line() -> None:
    runtime = _BlockingHelperRuntime()
    ready: list[str] = []

    async def scenario() -> None:
        async def read_stop() -> bytes:
            _ = await to_thread.run_sync(runtime.ready.wait)
            return b"STOP\n"

        await run_service_child(
            ServiceProfile.PRIVILEGED,
            dependencies=ServiceChildDependencies(
                read_line=read_stop,
                announce_ready=lambda: ready.append("ready"),
                gateway_runner=_gateway_must_not_run,
                helper_runtime=lambda: runtime,
            ),
        )

    anyio.run(scenario)

    assert runtime.ready.is_set()
    assert runtime.stop_requested.is_set()
    assert runtime.finished.is_set()
    assert ready == ["ready"]


def test_eof_before_helper_ready_does_not_announce_ready() -> None:
    runtime = _BlockingHelperRuntime()
    ready: list[str] = []

    async def read_eof() -> bytes:
        return b""

    async def scenario() -> None:
        await run_service_child(
            ServiceProfile.PRIVILEGED,
            dependencies=ServiceChildDependencies(
                read_line=read_eof,
                announce_ready=lambda: ready.append("ready"),
                gateway_runner=_gateway_must_not_run,
                helper_runtime=lambda: runtime,
            ),
        )

    anyio.run(scenario)

    assert runtime.ready.is_set() is False
    assert ready == []


def test_ready_writer_emits_exact_lf_frame(monkeypatch: pytest.MonkeyPatch) -> None:
    read_end, write_end = os.pipe()
    output = StringIO()
    try:
        monkeypatch.setattr(sys, "stdout", output)
        monkeypatch.setattr(sys.stdout, "fileno", lambda: write_end)

        service_child._write_ready()
    finally:
        os.close(write_end)

    try:
        assert os.read(read_end, 8) == b"READY 1\n"
    finally:
        os.close(read_end)


@pytest.mark.parametrize(
    "binding",
    [
        None,
        RuntimeBinding(
            profile=RuntimeProfile.GATEWAY,
            context_nonce="0123456789abcdef0123456789abcdef",
            config_path=Path(r"C:\\config.yaml"),
            config_sha256="a" * 64,
            worker_sid="S-1-5-21-1-2-3-4",
        ),
    ],
)
def test_main_runs_legacy_and_bound_profiles_through_anyio_runner(
    monkeypatch: pytest.MonkeyPatch, binding: RuntimeBinding | None
) -> None:
    # Given: a CLI profile whose binding load and coroutine runner are both test seams.
    observed: list[RuntimeBinding | None] = []

    async def fake_run(profile: ServiceProfile, *, binding: RuntimeBinding | None = None) -> None:
        assert profile is ServiceProfile.GATEWAY
        observed.append(binding)

    monkeypatch.setattr(service_child, "run_service_child", fake_run)
    if binding is not None:
        def load_binding(
            profile: RuntimeProfile, path: Path, digest: str
        ) -> RuntimeBinding:
            del profile, path, digest
            return binding

        monkeypatch.setattr(service_child, "load_runtime_binding", load_binding)
        argv = (
            "--profile",
            "gateway",
            "--runtime-binding",
            r"C:\\binding.json",
            "--runtime-binding-sha256",
            "a" * 64,
        )
    else:
        argv = ("--profile", "gateway")

    # When: the real anyio entrypoint invokes the fully bound coroutine callable.
    service_child.main(argv)

    # Then: both legacy and schema-2 invocations reach the coroutine without TypeError.
    assert observed == [binding]
