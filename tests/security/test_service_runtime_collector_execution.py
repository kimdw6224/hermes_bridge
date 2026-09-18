"""Execution tests for the embedded protected-service closure collector."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import ClassVar, Final

import pytest
from pydantic import BaseModel, ConfigDict, Field

PROJECT_ROOT: Final = Path(__file__).parents[2]
CLOSURE_SCRIPT: Final = PROJECT_ROOT / "scripts" / "service-runtime-closure.ps1"
PYTHON: Final = sys.executable


class ModuleOrigin(BaseModel):
    """A required module observed by the Python collector."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    name: str
    path: str


class ProbePayload(BaseModel):
    """The runtime facts emitted by a complete probe execution."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    enable_user_site: bool = Field(validation_alias="enableUserSite")
    sys_path: list[str] = Field(validation_alias="sysPath")
    module_files: list[str] = Field(validation_alias="moduleFiles")
    loaded_dlls: list[str] = Field(validation_alias="loadedDlls")
    module_origins: list[ModuleOrigin] = Field(validation_alias="moduleOrigins")
    base_executable: str = Field(validation_alias="baseExecutable")
    service_executable: str = Field(validation_alias="serviceExecutable")


class CollectorResult(BaseModel):
    """Isolated embedded probe execution result."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    ok: bool
    error: str | None = None
    payload: ProbePayload | None = None


def _probe_source() -> str:
    source = CLOSURE_SCRIPT.read_text(encoding="utf-8")
    match = re.search(
        r"\$script:BridgeClosureProbeCode = @'\r?\n(?P<probe>.*?)\r?\n'@\.Trim\(\)",
        source,
        flags=re.DOTALL,
    )
    assert match is not None
    return match.group("probe")


def _execute_probe(scenario: str) -> CollectorResult:
    probe = _probe_source()
    harness = r"""
import contextlib, ctypes, ctypes.wintypes as w, io, json, os, sys

scenario = sys.argv[1]
probe = sys.stdin.read()
redirector_service = "C:\\release\\venv\\Scripts\\python.exe"
redirector_base = "C:\\release\\python\\python.exe"
foreign_image = "C:\\release\\foreign\\python.exe"
if scenario in {"venv_redirector", "service_only_loader", "foreign_process_image"}:
    sys.executable = redirector_service
    sys._base_executable = redirector_base
service = os.path.realpath(sys.executable)
base = os.path.realpath(sys._base_executable)
paths = [
    base,
    "C:\\release\\python\\alpha.pyd",
    "C:\\release\\python\\odd.extension",
]
process_image = base
if scenario == "venv_redirector":
    paths = [
        redirector_base,
        "C:\\release\\python\\alpha.pyd",
        "C:\\release\\python\\odd.extension",
    ]
    process_image = redirector_base
elif scenario == "service_only_loader":
    paths[0] = service
    process_image = service
elif scenario == "foreign_process_image":
    paths[0] = foreign_image
    process_image = foreign_image
snapshot_calls = 0
active_paths = paths[:]

class ImportedModule:
    def __init__(self, path): self.__file__ = path

class Importer:
    def import_module(self, name):
        module = ImportedModule("C:\\release\\modules\\" + name + ".plugin")
        sys.modules[name] = module
        return module

class Map:
    def __init__(self, addr, path): self.addr = addr; self.path = path

class Process:
    def memory_maps(self, grouped=False):
        del grouped
        if scenario == "uncovered_image": return [Map("0x2000", "C:\\release\\uncovered.dll")]
        return [Map("0x1000", paths[1])]

class Psutil:
    def Process(self): return Process()

def enum_modules(process, modules, size, needed):
    del process
    global active_paths, snapshot_calls
    snapshot_calls += 1
    capacity = size // ctypes.sizeof(w.HMODULE)
    if scenario == "exhausted" or (scenario == "growth" and snapshot_calls == 1):
        needed._obj.value = (capacity + 1) * ctypes.sizeof(w.HMODULE)
        return 1
    active_paths = paths[:] if scenario != "missing_service" else paths[1:]
    if scenario == "unstable" and snapshot_calls >= 2:
        active_paths = [service, "C:\\release\\python\\changed.pyd"]
    needed._obj.value = len(active_paths) * ctypes.sizeof(w.HMODULE)
    for index in range(len(active_paths)): modules[index] = index + 1
    return 1

def module_name(handle, buffer, capacity):
    del capacity
    value = process_image if not handle else active_paths[int(handle) - 1]
    buffer.value = value
    return len(value)

def virtual_query(address, info_pointer, size):
    del address, size
    if scenario == "query_partial": return 0
    info = info_pointer._obj
    info.AllocationBase = 2 if scenario != "uncovered_image" else 99
    info.State = 0x1000
    info.Type = 0x1000000
    return ctypes.sizeof(info)

class Kernel:
    GetCurrentProcess = staticmethod(lambda: 1)
    GetModuleFileNameW = staticmethod(module_name)
    VirtualQuery = staticmethod(virtual_query)

class Psapi:
    EnumProcessModules = staticmethod(enum_modules)

original_windll = ctypes.WinDLL
ctypes.WinDLL = lambda name, use_last_error=True: Kernel() if name == "kernel32" else Psapi()
try:
    rewritten = probe.replace(
        "import ctypes,ctypes.wintypes as w,importlib,json,os,re,site,sys,psutil",
        (
            "import ctypes,ctypes.wintypes as w,json,os,re,site,sys\n"
            "importlib=Importer()\npsutil=Psutil()"
        ),
        1,
    )
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        exec(rewritten, {"Importer": Importer, "Psutil": Psutil})
    print(json.dumps({"ok": True, "payload": json.loads(output.getvalue())}, separators=(",", ":")))
except Exception as error:
    print(json.dumps({"ok": False, "error": str(error)}, separators=(",", ":")))
finally:
    ctypes.WinDLL = original_windll
"""
    result = subprocess.run(
        [PYTHON, "-c", harness, scenario],
        cwd=PROJECT_ROOT,
        input=probe,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        check=False,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    return CollectorResult.model_validate_json(result.stdout)


def test_embedded_collector_emits_module_origins_and_arbitrary_extensions() -> None:
    """A stable observation records required imports and every module filename."""
    result = _execute_probe("happy")

    assert result.ok
    assert result.payload is not None
    assert "C:\\release\\modules\\ctypes.plugin" in result.payload.module_files
    assert "C:\\release\\python\\odd.extension" in result.payload.loaded_dlls
    assert "ctypes" in {origin.name for origin in result.payload.module_origins}


@pytest.mark.parametrize(
    ("scenario", "expected_error"),
    [
        ("missing_service", "module-closure-unverified"),
        ("uncovered_image", "module-closure-unverified"),
        ("query_partial", "module-closure-unverified"),
        ("unstable", "module-closure-unverified"),
        ("exhausted", "module-enumeration-unstable"),
    ],
)
def test_embedded_collector_fails_closed_for_incomplete_native_observation(
    scenario: str,
    expected_error: str,
) -> None:
    """Incomplete module data cannot produce a receipt payload."""
    result = _execute_probe(scenario)

    assert not result.ok
    assert result.error == expected_error
    assert result.payload is None


def test_embedded_collector_retries_needed_capacity_growth() -> None:
    """A larger required byte count causes bounded re-enumeration."""
    result = _execute_probe("growth")

    assert result.ok
    assert result.payload is not None
    assert "C:\\release\\python\\alpha.pyd" in result.payload.loaded_dlls


def test_embedded_collector_accepts_exact_base_image_for_venv_redirector() -> None:
    """A venv service redirector can bind to its exact protected base image."""
    result = _execute_probe("venv_redirector")

    assert result.ok
    assert result.payload is not None
    assert result.payload.service_executable == "C:\\release\\venv\\Scripts\\python.exe"
    assert result.payload.base_executable == "C:\\release\\python\\python.exe"


@pytest.mark.parametrize("scenario", ["service_only_loader", "foreign_process_image"])
def test_embedded_collector_rejects_non_base_process_images(scenario: str) -> None:
    """A service redirector or arbitrary third image cannot substitute for the base image."""
    result = _execute_probe(scenario)

    assert not result.ok
    assert result.error == "module-closure-unverified"
    assert result.payload is None
