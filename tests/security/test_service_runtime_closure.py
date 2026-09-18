"""Durable protected-service closure receipt tests."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Final, TypedDict

import pytest

PROJECT_ROOT: Final = Path(__file__).parents[2]
SCRIPT_PATH: Final = PROJECT_ROOT / "scripts" / "service-runtime.ps1"
CLOSURE_SCRIPT_PATH: Final = PROJECT_ROOT / "scripts" / "service-runtime-closure.ps1"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
REQUIRED_MODULES: Final = (
    "hermes_windows_bridge.gateway.windows_service",
    "hermes_windows_bridge.gateway.main",
    "hermes_windows_bridge.privileged.main",
    "servicemanager",
    "win32api",
    "win32con",
    "win32event",
    "win32file",
    "win32pipe",
    "win32security",
    "win32service",
    "win32serviceutil",
    "win32ts",
    "pywintypes",
    "ctypes",
)
assert POWERSHELL_PATH is not None


def test_probe_uses_stable_loader_snapshot_and_address_coverage() -> None:
    source = CLOSURE_SCRIPT_PATH.read_text(encoding="utf-8")

    assert "EnumProcessModules" in source
    assert "GetModuleFileNameW" in source
    assert "VirtualQuery" in source
    assert "memory_maps(grouped=False)" in source
    assert "module_snapshots_stable" in source
    assert "uncovered_units" in source
    assert "process_image_count != 1" in source
    assert "capacity>8192" in source
    assert "needed.value<=ctypes.sizeof(modules)" in source
    assert "info.Type==0x1000000" in source
    assert "allocation not in module_map" in source
    assert "before=module_snapshot()" in source
    assert "after=module_snapshot()" in source
    assert "VSMB-" not in source
    assert "os.path.realpath(item.path)" not in source
    assert "os.path.realpath(path.value)" not in source
    assert "if not item.path: continue" not in source
    assert "path.lower().endswith" not in source
    assert "needed.value%ctypes.sizeof(w.HMODULE)" in source
    assert "module-enumeration-duplicate" in source


class ModuleOrigin(TypedDict):
    name: str
    path: str


class Probe(TypedDict):
    enableUserSite: bool | int
    sysPath: list[str]
    moduleFiles: list[str]
    loadedDlls: list[str]
    moduleOrigins: list[ModuleOrigin]
    baseExecutable: str
    serviceExecutable: str


def _run_library(expression: str) -> subprocess.CompletedProcess[str]:
    command = f". '{SCRIPT_PATH}' -LibraryMode; {expression}"
    return subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _run_isolated_library(
    runtime_script: Path, closure_script: Path, expression: str
) -> subprocess.CompletedProcess[str]:
    command = (
        f". '{runtime_script}' -LibraryMode; . '{closure_script}'; {expression}"
    )
    return subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _make_probe(release: Path) -> tuple[Probe, Path, Path]:
    base = release / "python" / "python.exe"
    service = release / "venv" / "Scripts" / "python.exe"
    modules = release / "venv" / "Lib" / "site-packages"
    dll = release / "python" / "runtime.dll"
    for path in (base, service, dll):
        path.parent.mkdir(parents=True, exist_ok=True)
        _ = path.write_bytes(path.name.encode())
    origins: list[ModuleOrigin] = []
    module_files: list[str] = []
    for index, name in enumerate(REQUIRED_MODULES):
        path = modules / f"module-{index}.pyd"
        path.parent.mkdir(parents=True, exist_ok=True)
        _ = path.write_bytes(name.encode())
        origins.append({"name": name, "path": str(path)})
        module_files.append(str(path))
    return (
        {
            "enableUserSite": False,
            "sysPath": [str(modules)],
            "moduleFiles": module_files,
            "loadedDlls": [str(dll)],
            "moduleOrigins": origins,
            "baseExecutable": str(base),
            "serviceExecutable": str(service),
        },
        base,
        service,
    )


def test_probe_rejects_boolean_coercion_empty_arrays_and_missing_required_module(
    tmp_path: Path,
) -> None:
    probe, base, service = _make_probe(tmp_path)
    valid_json = json.dumps(probe, separators=(",", ":"))
    valid_expression = " ".join(
        (
            "$p=ConvertFrom-BridgeClosureProbe",
            f"-ReleaseRoot '{tmp_path}' -BaseExecutable '{base}'",
            f"-ServiceExecutable '{service}' -ProbeJson '{valid_json}'; $null -ne $p",
        )
    )
    valid = _run_library(valid_expression)
    assert valid.returncode == 0, valid.stderr
    assert valid.stdout.strip() == "True"

    mutations: tuple[Probe, ...] = (
        {**probe, "enableUserSite": 0},
        {**probe, "sysPath": []},
        {**probe, "loadedDlls": []},
        {**probe, "moduleOrigins": probe["moduleOrigins"][:-1]},
    )
    for mutated in mutations:
        mutated_json = json.dumps(mutated, separators=(",", ":"))
        expression = " ".join(
            (
                "$p=ConvertFrom-BridgeClosureProbe",
                f"-ReleaseRoot '{tmp_path}' -BaseExecutable '{base}'",
                f"-ServiceExecutable '{service}' -ProbeJson '{mutated_json}'; $null -eq $p",
            )
        )
        result = _run_library(expression)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "True"


def test_receipt_binds_manifest_inventory_and_module_bytes(tmp_path: Path) -> None:
    probe, base, service = _make_probe(tmp_path)
    provenance = tmp_path / "build-provenance.json"
    _ = provenance.write_text("{}", encoding="utf-8")
    digest = "a" * 64
    probe_json = json.dumps(probe, separators=(",", ":"))
    expression = " ".join(
        (
            "function Get-BridgePathAcl {",
            "$a=[Security.AccessControl.FileSecurity]::new();",
            "$a.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)');return $a};",
            f"$seed=[pscustomobject]@{{releaseId='{digest}';sourceDigest='{digest}';",
            f"lockDigest='{'b' * 64}';",
            f"baseExecutable='{base}';serviceExecutable='{service}'}};",
            f"$r=New-BridgeServiceClosureReceipt -ReleaseRoot '{tmp_path}' ",
            f"-ManifestSeed $seed -ProbeJson '{probe_json}';",
            f"$rp=Join-Path '{tmp_path}' 'closure-receipt.json';",
            "[IO.File]::WriteAllText($rp,($r|ConvertTo-Json -Depth 8),",
            "[Text.UTF8Encoding]::new($false));",
            "$m=[pscustomobject]@{schemaVersion=2;releaseId=$seed.releaseId;sourceDigest=$seed.sourceDigest;lockDigest=$seed.lockDigest;",
            "baseExecutable=$seed.baseExecutable;serviceExecutable=$seed.serviceExecutable;closureReceipt='closure-receipt.json';",
            "closureReceiptSha256=Get-BridgeFileSha256 -Path $rp};",
            f"$before=Test-BridgeServiceClosureReceipt -ReleaseRoot '{tmp_path}' -Manifest $m;",
            f"[IO.File]::AppendAllText('{probe['moduleFiles'][0]}','tampered');",
            f"$after=Test-BridgeServiceClosureReceipt -ReleaseRoot '{tmp_path}' -Manifest $m;",
            "[pscustomobject]@{before=$before;after=$after}|ConvertTo-Json -Compress",
        )
    )
    result = _run_library(expression)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"before": True, "after": False}
    assert _sha256(tmp_path / "closure-receipt.json")


def test_isolated_host_package_verifies_receipt_without_build_helper(tmp_path: Path) -> None:
    host_package = tmp_path / "host-package"
    host_package.mkdir()
    runtime_script = host_package / SCRIPT_PATH.name
    closure_script = host_package / CLOSURE_SCRIPT_PATH.name
    build_helper = host_package / "service-runtime-build.ps1"
    _ = shutil.copy2(SCRIPT_PATH, runtime_script)
    _ = shutil.copy2(CLOSURE_SCRIPT_PATH, closure_script)

    release = tmp_path / "release"
    probe, base, service = _make_probe(release)
    _ = (release / "build-provenance.json").write_text("{}", encoding="utf-8")
    digest = "a" * 64
    probe_json = json.dumps(probe, separators=(",", ":"))
    expression = " ".join(
        (
            "function Get-BridgePathAcl {",
            "$a=[Security.AccessControl.FileSecurity]::new();",
            "$a.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)');return $a};",
            f"$seed=[pscustomobject]@{{releaseId='{digest}';sourceDigest='{digest}';",
            f"lockDigest='{'b' * 64}';baseExecutable='{base}';serviceExecutable='{service}'}};",
            f"$r=New-BridgeServiceClosureReceipt -ReleaseRoot '{release}' ",
            f"-ManifestSeed $seed -ProbeJson '{probe_json}';",
            f"$rp=Join-Path '{release}' 'closure-receipt.json';",
            "[IO.File]::WriteAllText($rp,($r|ConvertTo-Json -Depth 8),",
            "[Text.UTF8Encoding]::new($false));",
            "$m=[pscustomobject]@{schemaVersion=2;releaseId=$seed.releaseId;sourceDigest=$seed.sourceDigest;lockDigest=$seed.lockDigest;",
            "baseExecutable=$seed.baseExecutable;serviceExecutable=$seed.serviceExecutable;closureReceipt='closure-receipt.json';",
            "closureReceiptSha256=Get-BridgeFileSha256 -Path $rp};",
            f"$before=Test-BridgeServiceClosureReceipt -ReleaseRoot '{release}' -Manifest $m;",
            f"[IO.File]::AppendAllText('{probe['moduleFiles'][0]}','tampered');",
            f"$after=Test-BridgeServiceClosureReceipt -ReleaseRoot '{release}' -Manifest $m;",
            f"$buildHelperExists=Test-Path -LiteralPath '{build_helper}';",
            "[pscustomobject]@{psMajor=$PSVersionTable.PSVersion.Major;",
            "buildHelperExists=$buildHelperExists;before=$before;after=$after}",
            "|ConvertTo-Json -Compress",
        )
    )
    result = _run_isolated_library(runtime_script, closure_script, expression)

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "psMajor": 5,
        "buildHelperExists": False,
        "before": True,
        "after": False,
    }


def test_receipt_accepts_only_trusted_windows_dll_updates(tmp_path: Path) -> None:
    probe, base, service = _make_probe(tmp_path)
    windows_dll = Path(os.environ["WINDIR"]) / "System32" / "kernel32.dll"
    probe["loadedDlls"].append(str(windows_dll))
    probe_json = json.dumps(probe, separators=(",", ":"))
    expression = " ".join(
        (
            (
                "Import-Module (Join-Path $PSHOME "
                "'Modules/Microsoft.PowerShell.Security/Microsoft.PowerShell.Security.psd1');"
            ),
            "function Get-BridgePathAcl {",
            "$a=[Security.AccessControl.FileSecurity]::new();",
            "$a.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)');return $a};",
            f"$seed=[pscustomobject]@{{releaseId='{'a' * 64}';sourceDigest='{'a' * 64}';",
            f"lockDigest='{'b' * 64}';baseExecutable='{base}';serviceExecutable='{service}'}};",
            (
                f"$r=New-BridgeServiceClosureReceipt -ReleaseRoot '{tmp_path}' "
                f"-ManifestSeed $seed -ProbeJson '{probe_json}';"
            ),
            f"$external=@($r.loadedDlls|Where-Object path -eq '{windows_dll}')[0];",
            "$external.sha256='0'*64;$external.size=1;",
            f"$rp=Join-Path '{tmp_path}' 'closure-receipt.json';",
            (
                "[IO.File]::WriteAllText($rp,($r|ConvertTo-Json -Depth 8),"
                "[Text.UTF8Encoding]::new($false));"
            ),
            (
                "$m=[pscustomobject]@{schemaVersion=2;releaseId=$seed.releaseId;"
                "sourceDigest=$seed.sourceDigest;lockDigest=$seed.lockDigest;"
            ),
            (
                "baseExecutable=$seed.baseExecutable;serviceExecutable=$seed.serviceExecutable;"
                "closureReceipt='closure-receipt.json';"
            ),
            "closureReceiptSha256=Get-BridgeFileSha256 -Path $rp};",
            f"$updated=Test-BridgeServiceClosureReceipt -ReleaseRoot '{tmp_path}' -Manifest $m;",
            "function Get-AuthenticodeSignature { return [pscustomobject]@{Status='NotSigned';",
            "SignerCertificate=$null} };",
            f"$unsigned=Test-BridgeServiceClosureReceipt -ReleaseRoot '{tmp_path}' -Manifest $m;",
            (
                "function Get-AuthenticodeSignature { return [pscustomobject]@{Status='Valid';"
                "SignerCertificate=[pscustomobject]@{Subject='CN=Other, O=Other'}} };"
            ),
            f"$other=Test-BridgeServiceClosureReceipt -ReleaseRoot '{tmp_path}' -Manifest $m;",
            ("[pscustomobject]@{updated=$updated;unsigned=$unsigned;other=$other}"
            "|ConvertTo-Json -Compress"),
        )
    )
    result = _run_library(expression)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"updated": True, "unsigned": False, "other": False}


@pytest.mark.parametrize(
    ("sddl", "guard"),
    [
        ("O:BUG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)", "file"),
        ("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x2;;;BU)", "file"),
        ("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x2;;;BU)", "ancestor"),
        ("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)", "reparse"),
        ("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)", "internal"),
    ],
)
def test_windows_dll_exception_rejects_untrusted_paths(
    tmp_path: Path, sddl: str, guard: str
) -> None:
    windows_dll = Path(os.environ["WINDIR"]) / "System32" / "kernel32.dll"
    release = windows_dll.parent if guard == "internal" else tmp_path
    expression = " ".join(
        (
            (
                "function Get-AuthenticodeSignature { return [pscustomobject]@{Status='Valid';"
                "SignerCertificate=[pscustomobject]@{"
                "Subject='CN=Windows, O=Microsoft Corporation'}} };"
            ),
            "function Get-BridgePathAcl { param($Path)",
            "$a=[Security.AccessControl.FileSecurity]::new();",
            (
                f"$bad=if ('{guard}' -eq 'ancestor') {{ $Path -eq '{windows_dll.parent}' }} "
                f"else {{ $Path -eq '{windows_dll}' }};"
            ),
            f"$s=if ($bad) {{'{sddl}'}} else {{'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'}};",
            "$a.SetSecurityDescriptorSddlForm($s);return $a };",
            "function Test-BridgePathReparseFree { return $false };" if guard == "reparse" else "",
            f"Test-BridgeClosureTrustedExternalDll -ReleaseRoot '{release}' -Path '{windows_dll}'",
        )
    )
    result = _run_library(expression)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"
