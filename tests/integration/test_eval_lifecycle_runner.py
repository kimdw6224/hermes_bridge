"""정상 평가 VM lifecycle runner의 무변경·경계 계약을 검증합니다."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Final, TypedDict

import pytest
from pydantic import TypeAdapter

PROJECT_ROOT: Final = Path(__file__).resolve().parents[2]
RUNNER_PATH: Final = (
    PROJECT_ROOT
    / ".omo"
    / "evidence"
    / "service-protection-eval-vm-20260908"
    / "lifecycle"
    / "run-eval-lifecycle.ps1"
)
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None
CORE_POWERSHELL_PATH: Final = shutil.which("pwsh.exe")
ATTRIB_PATH: Final = Path(os.environ["SYSTEMROOT"]) / "System32" / "attrib.exe"
PREPARED_BUNDLE_ROOT: Final = (
    PROJECT_ROOT
    / ".omo"
    / "evidence"
    / "service-protection-eval-vm-20260908"
    / "lifecycle"
    / "bundles"
    / "4cdcbd12-a7e3-4b57-bf30-41b45d2dbb5f"
)
CANONICAL_LIFECYCLE_PATH: Final = (
    PROJECT_ROOT
    / ".omo"
    / "evidence"
    / "service-protection-6-sandbox"
    / "task6-guest-lifecycle-v2.ps1"
)
REFRESH_PATH: Final = (
    PROJECT_ROOT
    / ".omo"
    / "evidence"
    / "service-protection-6-sandbox"
    / "refresh-task6-input.ps1"
)
EVAL_BUNDLE_PRODUCER_PATH: Final = (
    PROJECT_ROOT
    / ".omo"
    / "evidence"
    / "service-protection-eval-vm-20260908"
    / "lifecycle"
    / "prepare-eval-bundle.ps1"
)
LEGACY_SOURCE_INPUTS_PATH: Final = (
    PROJECT_ROOT
    / ".omo"
    / "evidence"
    / "service-protection-eval-vm-20260908"
    / "lifecycle"
    / "source-inputs-4cdcbd12-a7e3-4b57-bf30-41b45d2dbb5f.json"
)


class DryRunReport(TypedDict):
    action: str
    applyRequired: bool
    credentialPrompted: bool
    vmConnectionCreated: bool
    guestMutation: bool
    vcLicenseAcceptanceRequired: bool


class RunnerFailureReport(TypedDict):
    failureKind: str
    executionStage: str
    errorIdentifier: str
    exceptionType: str | None
    credentialPrompted: bool
    vmConnectionCreated: bool


class GuestJobTimeoutReport(TypedDict):
    error: str
    stopped: bool
    removed: bool
    jobCleared: bool


class CopyReceipt(TypedDict):
    source: str
    destination: str


class HostInputInventoryEntry(TypedDict):
    relativePath: str
    sha256: str
    size: int


class RefreshBinding(TypedDict):
    hostQaMode: bool
    inputFiles: list[HostInputInventoryEntry]


class HostQaBundlePlan(TypedDict):
    """Host QA producer plan이 공개하는 immutable binding 요약입니다."""

    state: str
    hostQaMode: bool
    hostBuildInputSha256: str
    files: list[HostInputInventoryEntry]


class SourceInputsReceipt(TypedDict):
    """Producer가 source set equality에 사용하는 task-only receipt입니다."""

    schemaVersion: int
    sourceRoot: str
    files: list[HostInputInventoryEntry]


class GuestIdentityFixtureReport(TypedDict):
    outcome: str
    exceptionType: str | None
    hresult: int | None
    fullyQualifiedErrorId: str | None
    uuidMatch: bool | None


DRY_RUN_REPORT_ADAPTER: Final = TypeAdapter(DryRunReport)
RUNNER_FAILURE_REPORT_ADAPTER: Final = TypeAdapter(RunnerFailureReport)
GUEST_JOB_TIMEOUT_REPORT_ADAPTER: Final = TypeAdapter(GuestJobTimeoutReport)
COPY_RECEIPTS_ADAPTER: Final = TypeAdapter(list[CopyReceipt])
HOST_INPUT_INVENTORY_ADAPTER: Final = TypeAdapter(list[HostInputInventoryEntry])
REFRESH_BINDING_ADAPTER: Final = TypeAdapter(RefreshBinding)
HOST_QA_BUNDLE_PLAN_ADAPTER: Final = TypeAdapter(HostQaBundlePlan)
SOURCE_INPUTS_RECEIPT_ADAPTER: Final = TypeAdapter(SourceInputsReceipt)
GUEST_IDENTITY_FIXTURE_REPORT_ADAPTER: Final = TypeAdapter(GuestIdentityFixtureReport)


def _powershell_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Windows PowerShell 5가 inbox utility module만 발견하도록 test env를 고정합니다."""
    environment = os.environ.copy()
    environment["PSModulePath"] = r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
    if extra is not None:
        environment.update(extra)
    return environment


def test_eval_bundle_producer_plans_current_host_qa_binding(tmp_path: Path) -> None:
    """Host QA plan은 current source·canonical guest와 host build inputs를 하나로 bind합니다."""
    legacy_receipt = SOURCE_INPUTS_RECEIPT_ADAPTER.validate_json(
        LEGACY_SOURCE_INPUTS_PATH.read_text(encoding="utf-8")
    )
    legacy_paths = {
        entry["relativePath"]
        for entry in legacy_receipt["files"]
        if not entry["relativePath"].startswith("src/")
    }
    current_python_paths = {
        path.relative_to(PROJECT_ROOT).as_posix()
        for path in (PROJECT_ROOT / "src").rglob("*.py")
        if not {"__pycache__", ".pytest_cache", ".ruff_cache"}.intersection(
            path.relative_to(PROJECT_ROOT).parts
        )
    }
    host_paths = {
        path.relative_to(PROJECT_ROOT).as_posix()
        for path in (PROJECT_ROOT / "service-host").rglob("*")
        if (
            (path.is_file() and path.suffix in {".cs", ".csproj"})
            or (
                path.is_file()
                and path.name
                in {
                    "global.json",
                    "Directory.Build.props",
                    "Directory.Build.targets",
                    "NuGet.config",
                }
            )
        )
        and not {"bin", "obj"}.intersection(path.relative_to(PROJECT_ROOT).parts)
    }
    relative_paths = sorted(
        legacy_paths
        | current_python_paths
        | host_paths
        | {"scripts/service-object-security.ps1"}
    )
    receipt_files = [
        {
            "relativePath": relative_path,
            "sha256": hashlib.sha256((PROJECT_ROOT / relative_path).read_bytes()).hexdigest(),
            "size": (PROJECT_ROOT / relative_path).stat().st_size,
        }
        for relative_path in relative_paths
    ]
    expected_source_inputs = tmp_path / "current-source-inputs.json"
    _ = expected_source_inputs.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "sourceRoot": str(PROJECT_ROOT),
                "files": receipt_files,
            }
        ),
        encoding="utf-8",
    )
    uv_path = shutil.which("uv.exe")
    assert uv_path is not None
    uv_file = Path(uv_path)
    result = subprocess.run(
        [
            POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(EVAL_BUNDLE_PRODUCER_PATH),
            "-Mode",
            "Plan",
            "-Nonce",
            str(uuid.uuid4()),
            "-DeadlineUtc",
            "2099-01-01T00:00:00.0000000Z",
            "-SourceRoot",
            str(PROJECT_ROOT),
            "-ExpectedSourceInputsPath",
            str(expected_source_inputs),
            "-TrustedUvPath",
            str(uv_file),
            "-ExpectedUvSha256",
            hashlib.sha256(uv_file.read_bytes()).hexdigest(),
            "-HostQaMode",
        ],
        cwd=PROJECT_ROOT,
        env=_powershell_environment(),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    plan = HOST_QA_BUNDLE_PLAN_ADAPTER.validate_json(result.stdout)
    planned_by_path = {entry["relativePath"]: entry for entry in plan["files"]}
    assert plan["state"] == "planned"
    assert plan["hostQaMode"] is True
    assert len(plan["hostBuildInputSha256"]) == 64
    assert all(character in "0123456789abcdef" for character in plan["hostBuildInputSha256"])
    assert host_paths <= planned_by_path.keys()
    assert all(
        planned_by_path[path]["sha256"]
        == hashlib.sha256((PROJECT_ROOT / path).read_bytes()).hexdigest()
        for path in host_paths
    )


def test_runner_default_is_side_effect_free_dry_run() -> None:
    """기본 호출은 credential·VM 연결·guest write 없이 계획만 반환합니다."""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-File", str(RUNNER_PATH)],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    report = DRY_RUN_REPORT_ADAPTER.validate_json(result.stdout)
    assert report == {
        "action": "dry_run",
        "applyRequired": True,
        "credentialPrompted": False,
        "vmConnectionCreated": False,
        "guestMutation": False,
        "vcLicenseAcceptanceRequired": True,
    }


def test_runner_pins_current_canonical_lifecycle() -> None:
    with CANONICAL_LIFECYCLE_PATH.open("rb") as lifecycle_stream:
        canonical_hash = hashlib.file_digest(lifecycle_stream, "sha256").hexdigest().upper()

    runner_source = RUNNER_PATH.read_text(encoding="utf-8-sig")

    assert f"$lifecycleSha256 = '{canonical_hash}'" in runner_source


def test_runner_host_qa_mode_is_explicit_boolean_opt_in() -> None:
    """legacy binding은 host mode가 아니며 문자열·다른 대소문자는 fail closed합니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_RUNNER, [ref]$tokens, [ref]$errors
)
if ($errors.Count) { throw 'RunnerParseFailed' }
$function = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Get-RunnerHostQaMode'
}, $true) | Select-Object -First 1
if ($null -eq $function) { throw 'HostQaModeHelperMissing' }
. ([scriptblock]::Create($function.Extent.Text))
$fixtures = @(
    [pscustomobject]@{ name = 'legacy'; binding = [pscustomobject]@{} },
    [pscustomobject]@{ name = 'false'; binding = [pscustomobject]@{ hostQaMode = $false } },
    [pscustomobject]@{ name = 'true'; binding = [pscustomobject]@{ hostQaMode = $true } },
    [pscustomobject]@{ name = 'string'; binding = [pscustomobject]@{ hostQaMode = 'true' } },
    [pscustomobject]@{ name = 'wrongCase'; binding = [pscustomobject]@{ HostQaMode = $true } }
)
@($fixtures | ForEach-Object {
    $fixture = $_
    try {
        $value = Get-RunnerHostQaMode -Binding $fixture.binding
        [ordered]@{ name = $fixture.name; value = $value; error = $null }
    } catch {
        [ordered]@{ name = $fixture.name; value = $null; error = $_.Exception.Message }
    }
}) | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=_powershell_environment({"HERMES_QA_RUNNER": str(RUNNER_PATH)}),
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [
        {"name": "legacy", "value": False, "error": None},
        {"name": "false", "value": False, "error": None},
        {"name": "true", "value": True, "error": None},
        {"name": "string", "value": None, "error": "EvalBundleHostQaModeInvalid"},
        {"name": "wrongCase", "value": None, "error": "EvalBundleHostQaModeInvalid"},
    ]


def test_runner_sdk_version_gate_accepts_only_exact_10_0_400() -> None:
    """SDK readiness는 10.0.400만 수용하고 preview·인접 버전은 거부합니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_RUNNER, [ref]$tokens, [ref]$errors
)
if ($errors.Count) { throw 'RunnerParseFailed' }
$function = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Test-RunnerExactSdkVersion'
}, $true) | Select-Object -First 1
if ($null -eq $function) { throw 'SdkVersionHelperMissing' }
. ([scriptblock]::Create($function.Extent.Text))
[ordered]@{
    exact = Test-RunnerExactSdkVersion `
        -Output @('10.0.400 [C:\\Program Files\\dotnet\\sdk]') `
        -ExpectedVersion '10.0.400'
    preview = Test-RunnerExactSdkVersion `
        -Output @('10.0.400-preview.1 [C:\\Program Files\\dotnet\\sdk]') `
        -ExpectedVersion '10.0.400'
    adjacent = Test-RunnerExactSdkVersion `
        -Output @('10.0.401 [C:\\Program Files\\dotnet\\sdk]') `
        -ExpectedVersion '10.0.400'
    duplicate = Test-RunnerExactSdkVersion `
        -Output @('10.0.400 [a]', '10.0.400 [b]') `
        -ExpectedVersion '10.0.400'
} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=_powershell_environment({"HERMES_QA_RUNNER": str(RUNNER_PATH)}),
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "exact": True,
        "preview": False,
        "adjacent": False,
        "duplicate": False,
    }


def test_runner_guest_sdk_helper_text_defines_and_loads_both_functions() -> None:
    """guest로 전달하는 helper text는 함수 정의 두 개로 파싱·dot-source되어야 합니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_RUNNER, [ref]$tokens, [ref]$errors
)
if ($errors.Count) { throw 'RunnerParseFailed' }
foreach ($name in @(
    'Test-RunnerExactSdkVersion',
    'Get-RunnerGuestDotnetSdkState',
    'Get-RunnerGuestDotnetSdkHelperText'
)) {
    $function = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true) | Select-Object -First 1
    if ($null -eq $function) { throw ('FunctionMissing:' + $name) }
    . ([scriptblock]::Create($function.Extent.Text))
}
$helperText = Get-RunnerGuestDotnetSdkHelperText
$helperTokens = $null; $helperErrors = $null
$helperAst = [System.Management.Automation.Language.Parser]::ParseInput(
    $helperText, [ref]$helperTokens, [ref]$helperErrors
)
. ([scriptblock]::Create($helperText))
[ordered]@{
    parserErrors = $helperErrors.Count
        definitions = @($helperAst.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
    }, $true) | ForEach-Object { $_.Name } | Sort-Object)
    loaded = @(
        (Get-Command -Name 'Test-RunnerExactSdkVersion' -CommandType Function).Name,
        (Get-Command -Name 'Get-RunnerGuestDotnetSdkState' -CommandType Function).Name
    )
} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=_powershell_environment({"HERMES_QA_RUNNER": str(RUNNER_PATH)}),
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "parserErrors": 0,
        "definitions": [
            "Get-RunnerGuestDotnetSdkState",
            "Test-RunnerExactSdkVersion",
        ],
        "loaded": [
            "Test-RunnerExactSdkVersion",
            "Get-RunnerGuestDotnetSdkState",
        ],
    }


def test_runner_canonical_child_inherits_verified_guest_dotnet_path(tmp_path: Path) -> None:
    """새 PowerShell child도 guest의 Program Files dotnet PATH를 상속받아야 합니다."""
    dotnet_directory = tmp_path / "dotnet"
    dotnet_directory.mkdir()
    _ = (dotnet_directory / "dotnet.exe").write_bytes(b"fixture")
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_RUNNER, [ref]$tokens, [ref]$errors
)
if ($errors.Count) { throw 'RunnerParseFailed' }
$node = @($ast.FindAll({
    param($candidate)
    ($candidate -is [System.Management.Automation.Language.ScriptBlockAst]) -and
        $candidate.Extent.Text -match 'guest_dotnet_path_not_ready' -and
        $candidate.Extent.Text -match 'Start-Process -FilePath'
}, $true) | Sort-Object { $_.Extent.Text.Length } | Select-Object -First 1)[0]
if ($null -eq $node) { throw 'CanonicalChildDotnetPathBlockMissing' }
$childStart = [scriptblock]::Create([string]$node.EndBlock.Extent.Text)
$script:runnerCanonicalChild = $null
$global:inheritedPath = $null
function Start-Process {
    param($FilePath, $ArgumentList, [switch]$PassThru, $WindowStyle)
    $global:inheritedPath = $env:PATH
    return [pscustomobject]@{ id = 1 }
}
& $childStart 'C:\\fixture\\input' @() 'task6-guest-preflight.ps1' $env:HERMES_QA_DOTNET | Out-Null
$pathPrefix = $env:HERMES_QA_DOTNET + ';'
$pathComparison = [StringComparison]::OrdinalIgnoreCase
[ordered]@{
    childStored = ($null -ne $script:runnerCanonicalChild)
    pathStartsWithDotnet = $global:inheritedPath.StartsWith($pathPrefix, $pathComparison)
} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(RUNNER_PATH),
                "HERMES_QA_DOTNET": str(dotnet_directory),
            }
        ),
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "childStored": True,
        "pathStartsWithDotnet": True,
    }


def test_runner_sdk_media_guard_requires_valid_microsoft_signature(tmp_path: Path) -> None:
    """host SDK media는 hash 이후 Microsoft Authenticode 서명이 아니면 거부합니다."""
    package = tmp_path / "dotnet-sdk-10.0.400-win-x64.exe"
    _ = package.write_bytes(b"sdk-media")
    package_hash = hashlib.sha256(package.read_bytes()).hexdigest().upper()
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_RUNNER, [ref]$tokens, [ref]$errors
)
if ($errors.Count) { throw 'RunnerParseFailed' }
foreach ($name in @('Assert-RunnerMicrosoftSignedFile')) {
    $function = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true) | Select-Object -First 1
    if ($null -eq $function) { throw ('FunctionMissing:' + $name) }
    . ([scriptblock]::Create($function.Extent.Text))
}
function Assert-RunnerNoReparsePath { param($Path) }
function Assert-RunnerHash { param($Path, $Expected, $Failure) }
function Get-AuthenticodeSignature {
    [pscustomobject]@{ Status = 'NotSigned'; SignerCertificate = $null }
}
try {
    Assert-RunnerMicrosoftSignedFile `
        -Path $env:HERMES_QA_SDK `
        -ExpectedSha256 $env:HERMES_QA_SDK_HASH `
        -HashFailure 'dotnet_sdk_hash_mismatch' `
        -SignatureFailure 'dotnet_sdk_signature_invalid'
    'passed'
} catch {
    $_.Exception.Message
}
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(RUNNER_PATH),
                "HERMES_QA_SDK": str(package),
                "HERMES_QA_SDK_HASH": package_hash,
            }
        ),
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "dotnet_sdk_signature_invalid"


def test_runner_rejects_apply_without_explicit_vc_terms_before_credentials() -> None:
    """Apply만으로는 VC 약관 수락·인증창·VM 연결을 진행할 수 없습니다."""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-File", str(RUNNER_PATH), "-Apply"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 2
    report = RUNNER_FAILURE_REPORT_ADAPTER.validate_json(result.stdout)
    assert report["failureKind"] == "vc_license_acceptance_required"
    assert report["executionStage"] == "host_guard"
    assert report["errorIdentifier"] == "unclassified"
    assert report["credentialPrompted"] is False
    assert report["vmConnectionCreated"] is False


def test_runner_core_apply_rejects_before_credentials() -> None:
    """Core host는 deadline을 해석하거나 credential을 요청하기 전에 fail closed합니다."""
    if CORE_POWERSHELL_PATH is None:
        pytest.skip("PowerShell Core is unavailable")

    result = subprocess.run(
        [
            CORE_POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(RUNNER_PATH),
            "-Apply",
            "-AcceptVcRuntimeLicense",
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 2, result.stderr
    report = RUNNER_FAILURE_REPORT_ADAPTER.validate_json(result.stdout)
    assert report["failureKind"] == "runner_guard_or_execution_failed"
    assert report["exceptionType"] == "SecurityException"
    assert report["credentialPrompted"] is False
    assert report["vmConnectionCreated"] is False


def test_runner_guard_functions_reject_noncanonical_inventory_before_connection() -> None:
    """재현 가능한 manifest guard는 traversal inventory를 session 생성 전에 거부합니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_RUNNER,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count) { throw 'RunnerParseFailed' }
$function = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Assert-EvalBundleInventory'
}, $true) | Select-Object -First 1
if ($null -eq $function) { throw 'InventoryGuardMissing' }
. ([scriptblock]::Create($function.Extent.Text))
$BundleRoot = $env:TEMP
$binding = [pscustomobject]@{
    schemaVersion = 1; nonce = '00000000-0000-0000-0000-000000000001'
    deadlineUtc = '2099-01-01T00:00:00.0000000Z'; uvSha256 = ('A' * 64)
    productHashes = @{}
    inputFiles = @([pscustomobject]@{ relativePath = '..\\secret'; sha256 = ('A' * 64); size = 0 })
}
try {
    Assert-EvalBundleInventory -Binding $binding -BundleRoot $BundleRoot
    'passed'
} catch {
    $_.Exception.Message
}
"""
    environment = _powershell_environment({"HERMES_QA_RUNNER": str(RUNNER_PATH)})
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "EvalBundleRelativePathInvalid"


def test_runner_inventory_guard_accepts_prepared_optional_python_version(tmp_path: Path) -> None:
    """실제 inventory guard는 producer optional .python-version을 포함한 bundle을 허용합니다."""
    payloads = {
        ".python-version": "3.14.3",
        "service-host/global.json": '{"sdk":{"version":"10.0.400"}}',
        "service-host/HermesBridge.ServiceHost/HermesBridge.ServiceHost.csproj": "<Project />",
        "service-host/HermesBridge.ServiceHost/Program.cs": "internal static class Program {}",
        "task6-guest-preflight.ps1": "preflight",
        "task6-guest-lifecycle-v2.ps1": "lifecycle",
        "uv.exe": "uv",
    }
    for relative_path, content in payloads.items():
        target = tmp_path / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        _ = target.write_text(content, encoding="utf-8")
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_RUNNER,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count) { throw 'RunnerParseFailed' }
$function = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Assert-EvalBundleInventory'
}, $true) | Select-Object -First 1
if ($null -eq $function) { throw 'InventoryGuardMissing' }
foreach ($name in 'Get-RunnerHash', 'Assert-RunnerNoReparsePath', 'Get-RunnerHostQaMode') {
    $dependency = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true) | Select-Object -First 1
    . ([scriptblock]::Create($dependency.Extent.Text))
}
. ([scriptblock]::Create($function.Extent.Text))
function Assert-RunnerHash { param($Path, $Expected, $Failure) }
$preflightSha256 = ('A' * 64); $lifecycleSha256 = ('B' * 64)
$names = @(
    '.python-version',
    'service-host/HermesBridge.ServiceHost/HermesBridge.ServiceHost.csproj',
    'service-host/HermesBridge.ServiceHost/Program.cs',
    'service-host/global.json',
    'task6-guest-lifecycle-v2.ps1',
    'task6-guest-preflight.ps1',
    'uv.exe'
)
$entries = @($names | ForEach-Object {
    $item = Get-Item -LiteralPath (Join-Path $env:HERMES_QA_ROOT $_)
    [pscustomobject]@{
        relativePath = $_
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
        size = $item.Length
    }
})
$uvEntry = @($entries | Where-Object { $_.relativePath -ceq 'uv.exe' })[0]
$fixtureJson = [ordered]@{
    schemaVersion = 1; nonce = '00000000-0000-0000-0000-000000000001'
    deadlineUtc = '2099-01-01T00:00:00.0000000Z'
    productHashes = [pscustomobject]@{ source = ('C' * 64) }
    uvSha256 = $uvEntry.sha256; inputFiles = $entries
} | ConvertTo-Json -Depth 4 -Compress
$fixture = $fixtureJson | ConvertFrom-Json
try {
    Assert-EvalBundleInventory -Binding $fixture -BundleRoot $env:HERMES_QA_ROOT
    'passed'
} catch {
    $_.Exception.Message
}
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=_powershell_environment(
            {"HERMES_QA_RUNNER": str(RUNNER_PATH), "HERMES_QA_ROOT": str(tmp_path)}
        ),
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "passed", result.stderr


def test_refresh_host_qa_mode_snapshots_only_dotnet_source_inputs(tmp_path: Path) -> None:
    """host QA opt-in bundle은 .NET source와 build config만 immutable inventory에 넣습니다."""
    source_root = tmp_path / "source"
    host_root = source_root / "service-host"
    project_root = host_root / "HermesBridge.ServiceHost"
    project_root.mkdir(parents=True)
    _ = (host_root / "global.json").write_text(
        '{"sdk":{"version":"10.0.400"}}', encoding="utf-8"
    )
    _ = (project_root / "HermesBridge.ServiceHost.csproj").write_text(
        "<Project />", encoding="utf-8"
    )
    _ = (project_root / "Program.cs").write_text(
        "internal static class Program {}", encoding="utf-8"
    )
    generated_root = project_root / "obj"
    generated_root.mkdir()
    _ = (generated_root / "Generated.cs").write_text("generated", encoding="utf-8")
    destination = tmp_path / "input"
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_REFRESH, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) { throw 'RefreshParseFailed' }
$definition = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Copy-Task6HostBuildInputs'
}, $true) | Select-Object -First 1
if ($null -eq $definition) { throw 'HostBuildCopyFunctionMissing' }
. ([scriptblock]::Create($definition.Extent.Text))
$hostInputs = @(Copy-Task6HostBuildInputs `
    -SourceRoot $env:HERMES_QA_SOURCE `
    -DestinationRoot $env:HERMES_QA_DESTINATION)
$hostInputs | ConvertTo-Json -Depth 4 -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=_powershell_environment(
            {
                "HERMES_QA_REFRESH": str(REFRESH_PATH),
                "HERMES_QA_SOURCE": str(source_root),
                "HERMES_QA_DESTINATION": str(destination),
            }
        ),
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    inventory = HOST_INPUT_INVENTORY_ADAPTER.validate_json(result.stdout)
    assert [entry["relativePath"] for entry in inventory] == [
        "service-host/global.json",
        "service-host/HermesBridge.ServiceHost/HermesBridge.ServiceHost.csproj",
        "service-host/HermesBridge.ServiceHost/Program.cs",
    ]
    assert not (destination / "service-host" / "HermesBridge.ServiceHost" / "obj").exists()
    refresh_source = REFRESH_PATH.read_text(encoding="utf-8-sig")
    assert "[switch]$HostQaMode" in refresh_source
    assert "hostQaMode = [bool]$HostQaMode" in refresh_source


def test_refresh_producer_excludes_cache_artifacts_and_sorts_manifest() -> None:
    """실제 producer는 cache artifact를 넣지 않고 Ordinal 순서의 binding만 만듭니다."""
    trusted_uv = shutil.which("uv.exe")
    assert trusted_uv is not None
    nonce = uuid.uuid4()
    evidence_root = REFRESH_PATH.parent
    input_root = evidence_root / f"input-{nonce}"
    output_root = evidence_root / f"output-{nonce}"
    wsb_path = evidence_root / f"task6-attempt-{nonce}.wsb"
    try:
        result = subprocess.run(
            [
                POWERSHELL_PATH,
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(REFRESH_PATH),
                "-Nonce",
                str(nonce),
                "-DeadlineUtc",
                "2099-01-01T00:00:00Z",
                "-TrustedUvPath",
                trusted_uv,
            ],
            cwd=PROJECT_ROOT,
            env=_powershell_environment(),
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0, result.stderr
        binding = REFRESH_BINDING_ADAPTER.validate_json(result.stdout)
        paths = [entry["relativePath"] for entry in binding["inputFiles"]]
        assert binding["hostQaMode"] is False
        assert paths == sorted(paths)
        assert not any("__pycache__" in path or path.endswith(".pyc") for path in paths)
        assert (input_root / "task6-input-binding.json").is_file()
    finally:
        if input_root.exists():
            _ = subprocess.run(
                [str(ATTRIB_PATH), "-R", str(input_root), "/S", "/D"],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            shutil.rmtree(input_root)
        if output_root.exists():
            shutil.rmtree(output_root)
        if wsb_path.exists():
            wsb_path.unlink()


@pytest.mark.parametrize(
    ("deadline", "expected"),
    [
        ("2099-01-01T00:00:00.0000000Z", "passed"),
        ("2000-01-01T00:00:00.0000000Z", "EvalBundleDeadlineExpired"),
    ],
)
def test_runner_desktop_inventory_guard_checks_prepared_bundle_deadline(
    deadline: str, expected: str
) -> None:
    """과거 실행 번들은 보존하고 메모리 fixture의 만료 여부만 분리해 검증합니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_RUNNER,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count) { throw 'RunnerParseFailed' }
foreach ($name in @(
    'Get-RunnerHash',
    'Assert-RunnerNoReparsePath',
    'Assert-RunnerHash',
    'Get-RunnerHostQaMode',
    'Assert-EvalBundleInventory'
)) {
    $function = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true) | Select-Object -First 1
    if ($null -eq $function) { throw ('FunctionMissing:' + $name) }
    . ([scriptblock]::Create($function.Extent.Text))
}
$preflightSha256 = 'BAA291EB1ADD5FF7F4ED2C5D27258904CE4B005F053D0CE18B3D23F0B9601110'
$lifecycleSha256 = 'AE0729C7A83F4EBEEF8DCDD296E9E629D71901FEB58C9292BE57CF54F71D6E84'
$bindingPath = Join-Path $env:HERMES_QA_BUNDLE 'task6-input-binding.json'
$binding = Get-Content -LiteralPath $bindingPath -Raw | ConvertFrom-Json
$binding.deadlineUtc = $env:HERMES_QA_TEST_DEADLINE
try {
    Assert-EvalBundleInventory -Binding $binding -BundleRoot $env:HERMES_QA_BUNDLE
    'passed'
} catch [TimeoutException] {
    $_.Exception.Message
}
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(RUNNER_PATH),
                "HERMES_QA_BUNDLE": str(PREPARED_BUNDLE_ROOT),
                "HERMES_QA_TEST_DEADLINE": deadline,
            }
        ),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected, result.stderr


def test_runner_reparse_guard_rejects_binding_like_endpoint_before_hash() -> None:
    """binding과 같은 leaf reparse endpoint는 hash seam에 닿기 전에 거부합니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_RUNNER,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count) { throw 'RunnerParseFailed' }
$function = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Assert-RunnerNoReparsePath'
}, $true) | Select-Object -First 1
if ($null -eq $function) { throw 'NoReparseGuardMissing' }
. ([scriptblock]::Create($function.Extent.Text))
$global:hashTouched = $false
function Get-Item {
    [pscustomobject]@{
        Attributes = [IO.FileAttributes]::ReparsePoint
        Parent = $null
    }
}
function Get-FileHash { $global:hashTouched = $true; throw 'hash_must_not_run' }
try {
    Assert-RunnerNoReparsePath -Path 'C:\safe\task6-input-binding.json'
    'passed'
} catch {
    [pscustomobject]@{
        error = $_.Exception.Message
        hashTouched = $global:hashTouched
    } | ConvertTo-Json -Compress
}
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=_powershell_environment({"HERMES_QA_RUNNER": str(RUNNER_PATH)}),
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "error": "EvalRunnerReparsePath",
        "hashTouched": False,
    }


def test_runner_no_reparse_guard_accepts_ordinary_file_endpoint(tmp_path: Path) -> None:
    """runner의 실제 AST guard는 ordinary binding file과 모든 기존 상위를 순회합니다."""
    binding_path = tmp_path / "task6-input-binding.json"
    _ = binding_path.write_text("{}", encoding="utf-8")
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_RUNNER,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count) { throw 'RunnerParseFailed' }
$function = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Assert-RunnerNoReparsePath'
}, $true) | Select-Object -First 1
if ($null -eq $function) { throw 'NoReparseGuardMissing' }
. ([scriptblock]::Create($function.Extent.Text))
Assert-RunnerNoReparsePath -Path $env:HERMES_QA_BINDING
'passed'
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=_powershell_environment(
            {"HERMES_QA_RUNNER": str(RUNNER_PATH), "HERMES_QA_BINDING": str(binding_path)}
        ),
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "passed", result.stderr


def test_runner_bios_guid_uses_v2_association_without_nonexistent_setting_type() -> None:
    """Hyper-V V2 VSSD에는 SettingType이 없으므로 single association으로 BIOSGUID를 선택합니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_RUNNER,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count) { throw 'RunnerParseFailed' }
$function = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Get-RunnerVmBiosGuid'
}, $true) | Select-Object -First 1
if ($null -eq $function) { throw 'BiosGuidGuardMissing' }
Set-StrictMode -Version Latest
$vmId = [guid]'2275c148-f4ba-4f1e-85bb-2695c6439bb6'
$vmName = 'HermesBridge-Eval-20260908'
function Get-VM { [pscustomobject]@{ Name = $vmName; State = 'Running' } }
function Get-CimInstance { [pscustomobject]@{ Name = $vmId.Guid } }
function Get-CimAssociatedInstance {
    [pscustomobject]@{ BIOSGUID = '11111111-1111-1111-1111-111111111111' }
}
. ([scriptblock]::Create($function.Extent.Text))
try {
    (Get-RunnerVmBiosGuid).Guid
} catch {
    [pscustomobject]@{
        exceptionType = $_.Exception.GetType().FullName
        hresult = [int]$_.Exception.HResult
        fullyQualifiedErrorId = $_.FullyQualifiedErrorId
    } | ConvertTo-Json -Compress
}
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=_powershell_environment({"HERMES_QA_RUNNER": str(RUNNER_PATH)}),
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "11111111-1111-1111-1111-111111111111", result.stdout


def test_guest_identity_gate_fixture_exposes_matching_strict_mode_hresult() -> None:
    """실제 guest identity ScriptBlock은 결손 CIM 속성에서 receipt와 같은 HRESULT로 실패합니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_RUNNER,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count) { throw 'RunnerParseFailed' }
$node = @($ast.FindAll({
    param($candidate)
    ($candidate -is [System.Management.Automation.Language.ScriptBlockAst]) -and
        $candidate.Extent.Text -match 'Win32_ComputerSystemProduct' -and
        $candidate.Extent.Text -match 'hostGuestUuidMatches'
}, $true) | Sort-Object { $_.Extent.Text.Length } | Select-Object -First 1)[0]
if ($null -eq $node) { throw 'GuestIdentityGateMissing' }
$guest = [scriptblock]::Create([string]$node.EndBlock.Extent.Text)
Set-StrictMode -Version Latest
function Get-CimInstance {
    if ($env:HERMES_QA_PRODUCT_FIXTURE -ceq 'complete') {
        return [pscustomobject]@{
            Vendor = 'Microsoft Corporation'; Name = 'Virtual Machine'
            UUID = '11111111-1111-1111-1111-111111111111'
        }
    }
    return [pscustomobject]@{ UUID = '11111111-1111-1111-1111-111111111111' }
}
function Get-Service { return @() }
function Get-ScheduledTask { return @() }
$probe = @'
function Get-HermesEvalInteractiveTokenEvidence {
    param($EvidenceScope)
    [pscustomobject]@{
        classification = 'verified'; activeWtsSession = 'verified'
        explorerTokenElevation = 'verified'; evidenceSource = 'guest_observation'
    }
}
'@
try {
    $result = @(& $guest ([guid]'11111111-1111-1111-1111-111111111111') $probe)[0]
    [ordered]@{
        outcome = 'returned'; exceptionType = $null; hresult = $null
        fullyQualifiedErrorId = $null; uuidMatch = [bool]$result.hostGuestUuidMatches
    } | ConvertTo-Json -Compress
} catch {
    [ordered]@{
        outcome = 'threw'; exceptionType = $_.Exception.GetType().FullName
        hresult = [int]$_.Exception.HResult
        fullyQualifiedErrorId = $_.FullyQualifiedErrorId; uuidMatch = $null
    } | ConvertTo-Json -Compress
}
"""
    complete = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(RUNNER_PATH),
                "HERMES_QA_PRODUCT_FIXTURE": "complete",
            }
        ),
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    missing = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=_powershell_environment(
            {
                "HERMES_QA_RUNNER": str(RUNNER_PATH),
                "HERMES_QA_PRODUCT_FIXTURE": "missing_vendor",
            }
        ),
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert complete.returncode == 0, complete.stderr
    assert GUEST_IDENTITY_FIXTURE_REPORT_ADAPTER.validate_json(complete.stdout) == {
        "outcome": "returned",
        "exceptionType": None,
        "hresult": None,
        "fullyQualifiedErrorId": None,
        "uuidMatch": True,
    }
    assert missing.returncode == 0, missing.stderr
    assert GUEST_IDENTITY_FIXTURE_REPORT_ADAPTER.validate_json(missing.stdout) == {
        "outcome": "threw",
        "exceptionType": "System.Management.Automation.PropertyNotFoundException",
        "hresult": -2146233087,
        "fullyQualifiedErrorId": "PropertyNotFoundStrict",
        "uuidMatch": None,
    }


def test_success_report_retains_diagnostic_contract() -> None:
    """성공 report도 wrapper allowlist가 읽는 진단 필드를 유지합니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_RUNNER,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count) { throw 'RunnerParseFailed' }
$assignment = @($ast.FindAll({
    param($candidate)
    ($candidate -is [System.Management.Automation.Language.AssignmentStatementAst]) -and
        $candidate.Left.Extent.Text -ceq '$report' -and
        $candidate.Extent.Text -match 'hostVmIdMatches'
}, $true) | Select-Object -First 1)[0]
if ($null -eq $assignment) { throw 'SuccessReportAssignmentMissing' }
    Set-StrictMode -Version Latest
    $summary = [pscustomobject]@{ terminalState = 'passed' }
    $runtimeReady = [pscustomobject]@{ registryRuntimeCurrent = $true }
    $vcExitCode = $null
    $priorJobCleanupSucceeded = $true
    $priorSessionCleanupSucceeded = $true
    . ([scriptblock]::Create($assignment.Extent.Text))
[ordered]@{
    executionStage = [string]$report.executionStage
    errorIdentifier = [string]$report.errorIdentifier
} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=_powershell_environment({"HERMES_QA_RUNNER": str(RUNNER_PATH)}),
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "executionStage": "host_summary",
        "errorIdentifier": "unclassified",
    }


def test_outer_failure_catch_preserves_stage_and_maps_allowlisted_identifier() -> None:
    """실제 outer catch는 raw error 없이 stage와 allowlisted FQID만 보존합니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_RUNNER,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count) { throw 'RunnerParseFailed' }
$reportFunction = $ast.Find({
    param($candidate)
    ($candidate -is [System.Management.Automation.Language.FunctionDefinitionAst]) -and
        $candidate.Name -ceq 'New-SafeRunnerReport'
}, $true) | Select-Object -First 1
$catchClause = @($ast.FindAll({
    param($candidate)
    ($candidate -is [System.Management.Automation.Language.CatchClauseAst]) -and
        $candidate.Extent.StartLineNumber -gt 300
}, $true) | Sort-Object { $_.Extent.StartLineNumber } -Descending | Select-Object -First 1)[0]
if ($null -eq $reportFunction -or $null -eq $catchClause) { throw 'FailureContractMissing' }
Set-StrictMode -Version Latest
. ([scriptblock]::Create($reportFunction.Extent.Text))
$report = New-SafeRunnerReport `
    -Outcome 'failed' `
    -FailureKind 'unclassified' `
    -CredentialPrompted $true `
    -VmConnectionCreated $true
$report.executionStage = 'guest_identity_gate'
$catchBody = [string]$catchClause.Body.Extent.Text
$program = "try { `$record = [pscustomobject]@{}; `$record.missing | Out-Null } catch $catchBody"
. ([scriptblock]::Create($program))
[ordered]@{
    executionStage = [string]$report.executionStage
    errorIdentifier = [string]$report.errorIdentifier
    exceptionType = [string]$report.exceptionType
    hresult = [int]$report.hresult
} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=_powershell_environment({"HERMES_QA_RUNNER": str(RUNNER_PATH)}),
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "executionStage": "guest_identity_gate",
        "errorIdentifier": "property_not_found_strict",
        "exceptionType": "Other",
        "hresult": -2146233087,
    }


@pytest.mark.parametrize(
    ("message", "expected_identifier"),
    [
        ("canonical_child_execution_deadline", "canonical_child_execution_deadline"),
        ("canonical_child_observation_failed", "canonical_child_observation_failed"),
    ],
)
def test_outer_failure_catch_keeps_canonical_child_failure_categories_safe(
    message: str, expected_identifier: str
) -> None:
    """outer catch는 canonical child의 deadline과 관측 실패를 raw error 없이 구분합니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_RUNNER,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count) { throw 'RunnerParseFailed' }
$reportFunction = $ast.Find({
    param($candidate)
    ($candidate -is [System.Management.Automation.Language.FunctionDefinitionAst]) -and
        $candidate.Name -ceq 'New-SafeRunnerReport'
}, $true) | Select-Object -First 1
$catchClause = @($ast.FindAll({
    param($candidate)
    ($candidate -is [System.Management.Automation.Language.CatchClauseAst]) -and
        $candidate.Extent.StartLineNumber -gt 300
}, $true) | Sort-Object { $_.Extent.StartLineNumber } -Descending | Select-Object -First 1)[0]
if ($null -eq $reportFunction -or $null -eq $catchClause) { throw 'FailureContractMissing' }
. ([scriptblock]::Create($reportFunction.Extent.Text))
$report = New-SafeRunnerReport `
    -Outcome 'failed' `
    -FailureKind 'unclassified' `
    -CredentialPrompted $true `
    -VmConnectionCreated $true
$report.executionStage = 'guest_lifecycle'
$catchBody = [string]$catchClause.Body.Extent.Text
$program = "try { throw [InvalidOperationException]::new(" +
    "'$($env:HERMES_QA_CHILD_FAILURE)') } catch $catchBody"
. ([scriptblock]::Create($program))
[ordered]@{
    executionStage = [string]$report.executionStage
    errorIdentifier = [string]$report.errorIdentifier
    exceptionType = [string]$report.exceptionType
} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=_powershell_environment(
            {"HERMES_QA_RUNNER": str(RUNNER_PATH), "HERMES_QA_CHILD_FAILURE": message}
        ),
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "executionStage": "guest_lifecycle",
        "errorIdentifier": expected_identifier,
        "exceptionType": "Other",
    }


def test_runner_summary_boundary_rejects_extra_raw_failure_field() -> None:
    """host summary gate는 allowlist 밖 guest failure 내용을 수신하지 않습니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_RUNNER,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count) { throw 'RunnerParseFailed' }
$function = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Test-StrictRunnerSummary'
}, $true) | Select-Object -First 1
if ($null -eq $function) { throw 'SummaryGuardMissing' }
. ([scriptblock]::Create($function.Extent.Text))
$nonce = [guid]'00000000-0000-0000-0000-000000000001'
$artifact = [pscustomobject]@{ present = $true; sha256 = ('A' * 64) }
$summary = [pscustomobject]@{
    schemaVersion = 1; nonce = $nonce.Guid
    terminalState = 'passed'; preflightState = 'preflight-passed'
    artifacts = [pscustomobject]@{
        'preflight.json' = $artifact; 'task6-result.json' = $artifact
        'doctor.json' = $artifact; 'uninstall-receipt.json' = $artifact
    }
    rawFailure = 'credential=do-not-expose'
}
if (Test-StrictRunnerSummary -Summary $summary -Nonce $nonce) { 'passed' } else { 'rejected' }
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={**os.environ, "HERMES_QA_RUNNER": str(RUNNER_PATH)},
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "rejected"


def test_runner_guest_job_wrapper_cleans_owned_job_after_timeout() -> None:
    """fake transport timeout은 runner가 만든 job만 stop/remove하고 session은 건드리지 않습니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_RUNNER,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count) { throw 'RunnerParseFailed' }
$function = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Invoke-RunnerGuestJob'
}, $true) | Select-Object -First 1
if ($null -eq $function) { throw 'GuestJobWrapperMissing' }
. ([scriptblock]::Create($function.Extent.Text))
$script:session = [pscustomobject]@{ id = 'fake-session' }
$global:stopped = $false; $global:removed = $false
function Invoke-Command { [pscustomobject]@{ id = 'owned-job' } }
function Wait-Job { return $null }
function Stop-Job { $global:stopped = $true }
function Remove-Job { $global:removed = $true }
try {
    Invoke-RunnerGuestJob -ScriptBlock { 'not-run' } -ArgumentList @('fixture') -TimeoutSeconds 1
    'passed'
} catch {
    [ordered]@{
        error = $_.Exception.Message
        stopped = $global:stopped
        removed = $global:removed
        jobCleared = ($null -eq $script:job)
    } | ConvertTo-Json -Compress
}
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={**os.environ, "HERMES_QA_RUNNER": str(RUNNER_PATH)},
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    outcome = GUEST_JOB_TIMEOUT_REPORT_ADAPTER.validate_json(result.stdout)
    assert outcome == {
        "error": "EvalRunnerGuestDeadlineExpired",
        "stopped": True,
        "removed": True,
        "jobCleared": True,
    }


def test_runner_guest_job_wrapper_returns_fake_transport_result_and_cleans_job() -> None:
    """fake transport success는 결과를 전달하고 runner 소유 job handle을 제거합니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_RUNNER,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count) { throw 'RunnerParseFailed' }
$function = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Invoke-RunnerGuestJob'
}, $true) | Select-Object -First 1
if ($null -eq $function) { throw 'GuestJobWrapperMissing' }
. ([scriptblock]::Create($function.Extent.Text))
$script:session = [pscustomobject]@{ id = 'fake-session' }
$global:removed = $false
function Invoke-Command { [pscustomobject]@{ id = 'owned-job' } }
function Wait-Job { param($Job) return $Job }
function Receive-Job { [pscustomobject]@{ transition = 'guest-gate-passed' } }
function Remove-Job { $global:removed = $true }
$result = Invoke-RunnerGuestJob `
    -ScriptBlock { 'not-run' } `
    -ArgumentList @() `
    -TimeoutSeconds 1
[ordered]@{
    transition = $result[0].transition
    removed = $global:removed
    jobCleared = ($null -eq $script:job)
} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={**os.environ, "HERMES_QA_RUNNER": str(RUNNER_PATH)},
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "transition": "guest-gate-passed",
        "removed": True,
        "jobCleared": True,
    }


@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        (
            "success",
            {
                "outcome": "preflight-passed",
                "polls": 2,
                "disposed": True,
                "childCleared": True,
                "sameObject": True,
            },
        ),
        (
            "exit2",
            {
                "outcome": "canonical_child_failed",
                "polls": 1,
                "disposed": True,
                "childCleared": True,
                "sameObject": True,
            },
        ),
        (
            "deadline",
            {
                "outcome": "canonical_child_execution_deadline",
                "polls": 1,
                "disposed": False,
                "childCleared": False,
                "sameObject": True,
            },
        ),
        (
            "observation",
            {
                "outcome": "canonical_child_observation_failed",
                "polls": 0,
                "disposed": False,
                "childCleared": False,
                "sameObject": False,
            },
        ),
    ],
)
def test_canonical_child_starts_once_and_reuses_same_session_process_across_polls(
    scenario: str,
    expected: dict[str, str | int | bool],
) -> None:
    """canonical child는 PID lookup 없이 동일 session Process를 한 번 시작해 짧게 poll합니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_RUNNER,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count) { throw 'RunnerParseFailed' }
$function = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Invoke-RunnerCanonicalChild'
}, $true) | Select-Object -First 1
if ($null -eq $function) { throw 'CanonicalChildHelperMissing' }
. ([scriptblock]::Create($function.Extent.Text))
$script:runnerCanonicalChild = $null
$global:startCount = 0; $global:pollCount = 0; $global:stopCount = 0
$global:disposed = $false; $global:sameObject = $false; $global:jobCount = 0
$global:maximumGuestTimeout = 0; $global:timeoutCallCount = 0
function Get-RunnerTimeout {
    $global:timeoutCallCount++
    if ($env:HERMES_QA_SCENARIO -ceq 'deadline' -and $global:timeoutCallCount -ge 3) {
        throw [TimeoutException]::new('EvalRunnerDeadlineExpired')
    }
    return 45
}
function Invoke-RunnerGuestJob {
    param($ScriptBlock, $ArgumentList, $TimeoutSeconds)
    $global:jobCount++
    $global:maximumGuestTimeout = [Math]::Max($global:maximumGuestTimeout, [int]$TimeoutSeconds)
    if ($env:HERMES_QA_SCENARIO -ceq 'observation' -and $global:jobCount -eq 2) {
        throw [IO.IOException]::new('transport_failed')
    }
    return @(& $ScriptBlock @ArgumentList)
}
function Start-Process {
    $global:startCount++
    $exitCode = if ($env:HERMES_QA_SCENARIO -ceq 'exit2') { 2 } else { 0 }
    $process = [pscustomobject]@{ Id = 5248; ExitCode = $exitCode }
    $global:startedChild = $process
    Add-Member -InputObject $process -MemberType ScriptMethod -Name WaitForExit -Value {
        param($milliseconds)
        $global:pollCount++
        $global:sameObject = [object]::ReferenceEquals($this, $global:startedChild)
        if ($env:HERMES_QA_SCENARIO -eq 'deadline') { return $false }
        if ($env:HERMES_QA_SCENARIO -eq 'exit2') { return $true }
        return $global:pollCount -ge 2
    }
    Add-Member -InputObject $process -MemberType ScriptMethod -Name Dispose -Value {
        $global:disposed = $true
    }
    return $process
}
function Stop-Process { $global:stopCount++ }
function Get-Process { throw 'pid_lookup_forbidden' }
function Get-Content {
    return '{"nonce":"00000000-0000-0000-0000-000000000001","state":"preflight-passed"}'
}
try {
    $outcome = Invoke-RunnerCanonicalChild `
        -InputRoot 'C:\fixture\input' `
        -ChildArguments @('-Nonce', '00000000-0000-0000-0000-000000000001') `
        -OutputRoot 'C:\fixture\output' `
        -ExpectedNonce '00000000-0000-0000-0000-000000000001' `
        -Deadline ([DateTime]::UtcNow.AddMinutes(5)) `
        -ScriptName 'task6-guest-preflight.ps1' `
        -ResultName 'preflight.json'
} catch {
    $outcome = $_.Exception.Message
}
[ordered]@{
    outcome = $outcome
    starts = $global:startCount
    polls = $global:pollCount
    stopped = $global:stopCount
    disposed = $global:disposed
    childCleared = ($null -eq $script:runnerCanonicalChild)
    sameObject = $global:sameObject
    maximumGuestTimeout = $global:maximumGuestTimeout
} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=_powershell_environment(
            {"HERMES_QA_RUNNER": str(RUNNER_PATH), "HERMES_QA_SCENARIO": scenario}
        ),
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        **expected,
        "starts": 1,
        "stopped": 0,
        "maximumGuestTimeout": 60,
    }


@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        (
            "terminal",
            {
                "canonicalChildState": "terminal",
                "canonicalChildTerminalObserved": True,
                "canonicalChildCleanupVerified": True,
                "canonicalChildReconciliationRequired": False,
                "childDisposed": True,
                "childCleared": True,
                "receiptReads": 1,
            },
        ),
        (
            "running",
            {
                "canonicalChildState": "running",
                "canonicalChildTerminalObserved": False,
                "canonicalChildCleanupVerified": False,
                "canonicalChildReconciliationRequired": True,
                "childDisposed": False,
                "childCleared": False,
                "receiptReads": 0,
            },
        ),
        (
            "unreachable",
            {
                "canonicalChildState": "unreachable",
                "canonicalChildTerminalObserved": False,
                "canonicalChildCleanupVerified": False,
                "canonicalChildReconciliationRequired": True,
                "childDisposed": False,
                "childCleared": False,
                "receiptReads": 0,
            },
        ),
    ],
)
def test_runner_cleanup_observes_saved_child_before_session_removal_without_forcing_it(
    scenario: str,
    expected: dict[str, str | bool | int],
) -> None:
    """실패 cleanup은 저장한 guest handle만 한 번 관측하고 강제 종료하지 않습니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_RUNNER,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count) { throw 'RunnerParseFailed' }
foreach ($name in @('New-SafeRunnerReport', 'Complete-RunnerCleanup')) {
    $function = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true) | Select-Object -First 1
    if ($null -eq $function) { throw ('FunctionMissing:' + $name) }
    . ([scriptblock]::Create($function.Extent.Text))
}
$expectedNonce = '00000000-0000-0000-0000-000000000001'
$script:session = [pscustomobject]@{ id = 'same-session' }
$script:job = [pscustomobject]@{ id = 'host-job' }
$script:credential = [pscustomobject]@{ opaque = $true }
$script:runnerCanonicalChild = [pscustomobject]@{
    Id = 5248
    HasExited = ($env:HERMES_QA_SCENARIO -ceq 'terminal')
    ExitCode = 0
}
$script:runnerCanonicalChildReceipt = [ordered]@{
    outputRoot = 'C:\fixture\output'
    resultName = 'task6-result.json'
    expectedNonce = $expectedNonce
}
$global:childDisposed = $false; $global:receiptReads = 0; $global:statusProbeCount = 0
$global:jobRemoved = $false; $global:sessionRemoved = $false
$global:forcedStops = 0; $global:restarts = 0; $global:pidLookups = 0
Add-Member -InputObject $script:runnerCanonicalChild `
    -MemberType ScriptMethod -Name WaitForExit -Value {
    param($milliseconds)
    if ($milliseconds -ne 0) { throw 'cleanup_wait_must_be_status_only' }
    return [bool]$this.HasExited
}
Add-Member -InputObject $script:runnerCanonicalChild -MemberType ScriptMethod -Name Dispose -Value {
    $global:childDisposed = $true
}
function Invoke-RunnerGuestJob {
    param($ScriptBlock, $ArgumentList, $TimeoutSeconds)
    $global:statusProbeCount++
    if ($global:statusProbeCount -ne 1) { throw 'cleanup_must_use_one_status_probe' }
    if ($env:HERMES_QA_SCENARIO -ceq 'unreachable') {
        throw [IO.IOException]::new('same_session_transport_unreachable')
    }
    return @(& $ScriptBlock @ArgumentList)
}
function Get-Content {
    param($LiteralPath, [switch]$Raw, $ErrorAction)
    $global:receiptReads++
    if ($LiteralPath -cne 'C:\fixture\output\task6-result.json') {
        throw 'unexpected_cleanup_receipt'
    }
    return ('{"nonce":"' + $expectedNonce + '","state":"passed"}')
}
function Remove-Job { $global:jobRemoved = $true }
function Remove-PSSession {
    if ($global:statusProbeCount -ne 1) { throw 'session_removed_before_status_probe' }
    $global:sessionRemoved = $true
}
function Stop-Process { $global:forcedStops++; throw 'forced_stop_forbidden' }
function taskkill { $global:forcedStops++; throw 'taskkill_forbidden' }
function Start-Process { $global:restarts++; throw 'restart_forbidden' }
function Get-Process { $global:pidLookups++; throw 'pid_lookup_forbidden' }
$report = New-SafeRunnerReport `
    -Outcome 'completed' `
    -FailureKind 'unclassified' `
    -CredentialPrompted $true `
    -VmConnectionCreated $true
Complete-RunnerCleanup -Report $report
function Get-ReportValue {
    param([string]$Name)
    if (-not $report.Contains($Name)) { return '__missing__' }
    return $report[$Name]
}
[ordered]@{
    outcome = $report.outcome
    jobCleanupSucceeded = $report.jobCleanupSucceeded
    sessionCleanupSucceeded = $report.sessionCleanupSucceeded
    canonicalChildState = Get-ReportValue 'canonicalChildState'
    canonicalChildTerminalObserved = Get-ReportValue 'canonicalChildTerminalObserved'
    canonicalChildCleanupVerified = Get-ReportValue 'canonicalChildCleanupVerified'
    canonicalChildReconciliationRequired = Get-ReportValue 'canonicalChildReconciliationRequired'
    childDisposed = $global:childDisposed
    childCleared = ($null -eq $script:runnerCanonicalChild)
    receiptReads = $global:receiptReads
    statusProbeCount = $global:statusProbeCount
    jobRemoved = $global:jobRemoved
    sessionRemoved = $global:sessionRemoved
    forcedStops = $global:forcedStops
    restarts = $global:restarts
    pidLookups = $global:pidLookups
} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=_powershell_environment(
            {"HERMES_QA_RUNNER": str(RUNNER_PATH), "HERMES_QA_SCENARIO": scenario}
        ),
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "outcome": "failed",
        "jobCleanupSucceeded": True,
        "sessionCleanupSucceeded": True,
        **expected,
        "statusProbeCount": 1,
        "jobRemoved": True,
        "sessionRemoved": True,
        "forcedStops": 0,
        "restarts": 0,
        "pidLookups": 0,
    }


def test_completed_summary_keeps_terminal_and_host_cleanup_receipt_fields() -> None:
    """성공 summary도 finally 뒤 completed와 독립 cleanup receipt를 유지해야 합니다."""
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_RUNNER,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count) { throw 'RunnerParseFailed' }
$function = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Complete-RunnerCleanup'
}, $true) | Select-Object -First 1
if ($null -eq $function) { throw 'CompleteCleanupMissing' }
$assignment = @($ast.FindAll({
    param($candidate)
    ($candidate -is [System.Management.Automation.Language.AssignmentStatementAst]) -and
        $candidate.Left.Extent.Text -ceq '$report' -and
        $candidate.Extent.Text -match 'hostVmIdMatches'
}, $true) | Select-Object -First 1)[0]
if ($null -eq $assignment) { throw 'SuccessReportAssignmentMissing' }
. ([scriptblock]::Create($function.Extent.Text))
$script:job = [pscustomobject]@{ id = 'host-job' }
$script:session = [pscustomobject]@{ id = 'same-session' }
$script:credential = [pscustomobject]@{ opaque = $true }
$script:runnerCanonicalChildReceipt = $null
$script:runnerCanonicalChildTerminalObserved = $true
$script:runnerCanonicalChildReceiptVerified = $true
$global:jobRemoved = $false; $global:sessionRemoved = $false
function Remove-Job { $global:jobRemoved = $true }
function Remove-PSSession { $global:sessionRemoved = $true }
$summary = [pscustomobject]@{ terminalState = 'passed' }
$runtimeReady = [pscustomobject]@{ registryRuntimeCurrent = $true }
$vcExitCode = $null
$priorJobCleanupSucceeded = $true
$priorSessionCleanupSucceeded = $true
. ([scriptblock]::Create($assignment.Extent.Text))
Complete-RunnerCleanup -Report $report
$cleanupReady = ($report.jobCleanupSucceeded -and $report.sessionCleanupSucceeded)
if (-not $cleanupReady) {
    $report.outcome = 'failed'
    $report.failureKind = 'cleanup_failed'
}
function Get-ReportValue {
    param([string]$Name)
    if (-not $report.Contains($Name)) { return '__missing__' }
    return $report[$Name]
}
[ordered]@{
    outcome = $report.outcome
    failureKind = $report.failureKind
    jobCleanupSucceeded = Get-ReportValue 'jobCleanupSucceeded'
    sessionCleanupSucceeded = Get-ReportValue 'sessionCleanupSucceeded'
    canonicalChildState = Get-ReportValue 'canonicalChildState'
    canonicalChildTerminalObserved = Get-ReportValue 'canonicalChildTerminalObserved'
    canonicalChildCleanupVerified = Get-ReportValue 'canonicalChildCleanupVerified'
    canonicalChildReconciliationRequired = Get-ReportValue 'canonicalChildReconciliationRequired'
    jobRemoved = $global:jobRemoved
    sessionRemoved = $global:sessionRemoved
} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env=_powershell_environment({"HERMES_QA_RUNNER": str(RUNNER_PATH)}),
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "outcome": "completed",
        "failureKind": None,
        "jobCleanupSucceeded": True,
        "sessionCleanupSucceeded": True,
        "canonicalChildState": "terminal",
        "canonicalChildTerminalObserved": True,
        "canonicalChildCleanupVerified": True,
        "canonicalChildReconciliationRequired": False,
        "jobRemoved": True,
        "sessionRemoved": True,
    }


def test_post_connection_failure_cleans_session_without_creating_summary(tmp_path: Path) -> None:
    """post-session fake failure는 cleanup result를 남기고 host summary를 만들지 않습니다."""
    summary_path = tmp_path / "runner-summary-00000000-0000-0000-0000-000000000001.json"
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_RUNNER,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count) { throw 'RunnerParseFailed' }
foreach ($name in @(
    'New-SafeRunnerReport',
    'Complete-RunnerCleanup',
    'Assert-RunnerFreshSummaryPath'
)) {
    $function = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true) | Select-Object -First 1
    if ($null -eq $function) { throw ('FunctionMissing:' + $name) }
    . ([scriptblock]::Create($function.Extent.Text))
}
$script:session = [pscustomobject]@{ id = 'post-connection-session' }
$script:job = $null; $script:credential = [pscustomobject]@{ opaque = $true }
$global:sessionRemoved = $false
function Remove-PSSession { $global:sessionRemoved = $true }
$report = New-SafeRunnerReport `
    -Outcome 'failed' `
    -FailureKind 'guest_inventory_gate_rejected' `
    -CredentialPrompted $true `
    -VmConnectionCreated $true
Complete-RunnerCleanup -Report $report
try {
    Assert-RunnerFreshSummaryPath -Path $env:HERMES_QA_SUMMARY
    'fresh'
} catch {
    $_.Exception.Message
}
[ordered]@{
    sessionRemoved = $global:sessionRemoved
    cleanup = $report.sessionCleanupSucceeded
    summaryExists = (Test-Path -LiteralPath $env:HERMES_QA_SUMMARY)
} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={
            **os.environ,
            "HERMES_QA_RUNNER": str(RUNNER_PATH),
            "HERMES_QA_SUMMARY": str(summary_path),
        },
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[-1] == (
        '{"sessionRemoved":true,"cleanup":true,"summaryExists":false}'
    )


def test_manifest_relative_copy_preserves_nested_guest_hierarchy(tmp_path: Path) -> None:
    """actual runner copy loop forwards nested files to their manifest-relative guest parent."""
    source_root = tmp_path / "source"
    destination_root = tmp_path / "guest-input"
    payloads = {
        "src/hermes_windows_bridge/__init__.py": "source",
        "scripts/service-runtime.ps1": "script",
        "config/example.yaml": "config",
    }
    for relative_path, content in payloads.items():
        target = source_root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        _ = target.write_text(content, encoding="utf-8")
    binding_path = source_root / "task6-input-binding.json"
    _ = binding_path.write_text("{}", encoding="utf-8")
    command = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:HERMES_QA_RUNNER,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count) { throw 'RunnerParseFailed' }
$function = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Copy-EvalBundleFilesToGuest'
}, $true) | Select-Object -First 1
if ($null -eq $function) { throw 'CopyLoopMissing' }
. ([scriptblock]::Create($function.Extent.Text))
function Invoke-RunnerGuestJob { return @() }
$global:copies = @()
function Copy-Item {
    param($LiteralPath, $Destination, $ToSession, $ErrorAction)
    $global:copies += [pscustomobject]@{ source = $LiteralPath; destination = $Destination }
}
$binding = [pscustomobject]@{ inputFiles = @(
    [pscustomobject]@{ relativePath = 'src/hermes_windows_bridge/__init__.py' },
    [pscustomobject]@{ relativePath = 'scripts/service-runtime.ps1' },
    [pscustomobject]@{ relativePath = 'config/example.yaml' }
) }
Copy-EvalBundleFilesToGuest `
    -Binding $binding `
    -BundleRoot $env:HERMES_QA_SOURCE `
    -GuestInputRoot $env:HERMES_QA_DESTINATION `
    -BindingPath (Join-Path $env:HERMES_QA_SOURCE 'task6-input-binding.json') `
    -Session ([pscustomobject]@{ id = 'fake' })
$global:copies | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        env={
            **os.environ,
            "HERMES_QA_RUNNER": str(RUNNER_PATH),
            "HERMES_QA_SOURCE": str(source_root),
            "HERMES_QA_DESTINATION": str(destination_root),
        },
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    copies = COPY_RECEIPTS_ADAPTER.validate_json(result.stdout)
    observed = [
        (
            Path(copy["source"]).relative_to(source_root).as_posix(),
            Path(copy["destination"]).relative_to(destination_root).as_posix(),
        )
        for copy in copies
    ]
    assert observed == [
        ("src/hermes_windows_bridge/__init__.py", "src/hermes_windows_bridge"),
        ("scripts/service-runtime.ps1", "scripts"),
        ("config/example.yaml", "config"),
        ("task6-input-binding.json", "."),
    ]
