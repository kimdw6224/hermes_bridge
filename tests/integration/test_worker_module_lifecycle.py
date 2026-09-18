from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from threading import Event
from time import monotonic
from uuid import uuid4

import psutil
import pytest
import pywintypes

from hermes_windows_bridge.ipc.named_pipe import connect_named_pipe_client


@pytest.mark.integration
def test_worker_module_stays_alive_on_real_same_user_pipe_until_process_stop(
    tmp_path: Path,
) -> None:
    # Given: machine state를 바꾸지 않는 temp config와 고유 named pipe입니다.
    local_data = tmp_path / "LocalAppData"
    user_data = local_data / "HermesWindowsBridge"
    program_data = tmp_path / "ProgramData" / "HermesWindowsBridge"
    pipe_name = rf"\\.\pipe\HermesWindowsBridgeTest-{uuid4()}"
    config_path, policy_path = tmp_path / "config.yaml", tmp_path / "policy.yaml"
    config = {
        "ipc": {"worker_pipe": pipe_name, "heartbeat_seconds": 1},
        "paths": {
            "program_data": str(program_data),
            "user_data": str(user_data),
            "token_file": str(program_data / "secrets" / "token"),
        },
        "browser": {"profile_dir": str(user_data / "browser-profile"), "headless": True},
    }
    program_data.mkdir(parents=True)
    user_data.mkdir(parents=True)
    _ = config_path.write_text(json.dumps(config), encoding="utf-8")
    _ = policy_path.write_text("{}", encoding="utf-8")
    environment = os.environ | {
        "ProgramData": str(tmp_path / "ProgramData"),
        "LOCALAPPDATA": str(local_data),
        "HERMES_BRIDGE_CONFIG_FILE": str(config_path),
        "HERMES_BRIDGE_POLICY_FILE": str(policy_path),
    }
    before_children = {child.pid for child in psutil.Process().children(recursive=True)}

    # When: test-only F24 backend으로 실제 module entrypoint를 호출합니다.
    bootstrap = (
        "from hermes_windows_bridge.worker import runtime; "
        "from hermes_windows_bridge.worker.emergency_hotkey import "
        "LocalEmergencyHotkey, Win32EmergencyHotkey; "
        "runtime.LocalEmergencyHotkey = lambda gate, *, backend_factory, activation: "
        "LocalEmergencyHotkey("
        "gate, backend_factory=lambda: Win32EmergencyHotkey(virtual_key=135), "
        "activation=activation); "
        "from hermes_windows_bridge.worker.main import main; main()"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", bootstrap],
        cwd=Path(__file__).parents[2],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    try:
        deadline = monotonic() + 5
        while True:
            try:
                client = connect_named_pipe_client(pipe_name, timeout_ms=250)
                break
            except pywintypes.error:
                if process.poll() is not None or monotonic() >= deadline:
                    _, stderr = process.communicate(timeout=1)
                    pytest.fail(f"worker did not open pipe: {stderr[-1_000:]}")
                _ = Event().wait(0.02)
        with client:
            assert process.poll() is None
    finally:
        process.terminate()
        _, stderr = process.communicate(timeout=5)
        assert process.returncode not in {None, 0}, stderr[-1_000:]

    # Then: OS stop 뒤 worker process와 descendant가 남지 않습니다.
    assert not psutil.pid_exists(process.pid)
    after_children = {child.pid for child in psutil.Process().children(recursive=True)}
    assert after_children == before_children
