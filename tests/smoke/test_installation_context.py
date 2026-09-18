"""Strict installation-context boundary regressions."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from base64 import b64decode
from pathlib import Path
from typing import ClassVar, Final, Literal

import pytest
import yaml
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from hermes_windows_bridge.models.config import BridgeSettings, EnvironmentContext

PROJECT_ROOT: Final = Path(__file__).parents[2]
CONTEXT_SCRIPT: Final = PROJECT_ROOT / "scripts" / "installation-context.ps1"
INSTALL_SCRIPT: Final = PROJECT_ROOT / "scripts" / "install.ps1"
POWERSHELL_PATH: Final = shutil.which("powershell.exe")
assert POWERSHELL_PATH is not None


class InstallationContext(BaseModel):
    """Public, hash-bound subset of a parsed installation context."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    schema_version: int = Field(alias="schemaVersion")
    nonce: str
    port: int
    prefix: str
    gateway_service_name: str = Field(alias="gatewayServiceName")
    privileged_service_name: str = Field(alias="privilegedServiceName")
    worker_task_name: str = Field(alias="workerTaskName")


class InstallationRegistration(BaseModel):
    """Nonce-derived registration name emitted by the installer plan."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    name: str


class InstallationGatewayConfiguration(BaseModel):
    """Gateway fields that must remain bound to the paired context."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    port: int
    allowed_hosts: list[str] = Field(alias="allowedHosts")


class InstallationContextPlan(BaseModel):
    """Read-only installer result relevant to nonce-context forwarding."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    mode: Literal["what-if"]
    registrations: list[InstallationRegistration]
    gateway_configuration: InstallationGatewayConfiguration = Field(
        alias="gatewayConfiguration"
    )
    final_mcp_url: str = Field(alias="finalMcpUrl")


class PreparationRoot(BaseModel):
    """Narrow durable receipt root used for external reconciliation."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    path: str
    absent_before: bool = Field(alias="absentBefore")
    created: bool
    native_identity: str | None = Field(alias="nativeIdentity")


class PreparationReceipt(BaseModel):
    """Typed durable receipt emitted when nonce preparation cannot finish."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = Field(alias="schemaVersion")
    nonce: str
    state: str
    reconciliation_required: bool = Field(alias="reconciliationRequired")
    roots: list[PreparationRoot]
    created: list[str]
    bindings: list[str]
    token_created: bool = Field(alias="tokenCreated")


def _write_context(path: Path, payload: dict[str, int | str]) -> str:
    """Writes a canonical compact context and returns its lowercase SHA-256."""
    _ = path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _parse_context(path: Path, digest: str) -> subprocess.CompletedProcess[str]:
    """Calls the PowerShell boundary exactly as context-aware consumers do."""
    command = (
        f". '{CONTEXT_SCRIPT}';"
        f"Get-BridgeInstallationContext -Path '{path}' -Sha256 '{digest}' | "
        "ConvertTo-Json -Compress"
    )
    return subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def _run_install_with_context(
    *arguments: str,
) -> subprocess.CompletedProcess[str]:
    """Runs the actual installer in WhatIf mode without an external mutation."""
    return subprocess.run(
        [
            POWERSHELL_PATH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(INSTALL_SCRIPT),
            "-WhatIf",
            "-Json",
            *arguments,
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )


def test_context_accepts_winps5_int32_schema_values_and_derives_nonce_names(tmp_path: Path) -> None:
    # Given: `powershell.exe` / WinPS5 parses these small JSON integer literals as Int32.
    path = tmp_path / "installation-context.json"
    nonce = "0123456789abcdef0123456789abcdef"
    digest = _write_context(path, {"schemaVersion": 1, "nonce": nonce, "port": 49152})

    # When: the real WinPS5 parser resolves it through the paired path/hash interface.
    result = _parse_context(path, digest)

    # Then: strict Int32 acceptance preserves the deterministic nonce-derived registrations.
    assert result.returncode == 0, result.stderr
    context = InstallationContext.model_validate_json(result.stdout)
    assert context.schema_version == 1
    assert context.port == 49152
    assert context.prefix == f"HermesWindowsBridgeEval-{nonce}"
    assert context.gateway_service_name == f"{context.prefix}-Gateway"
    assert context.privileged_service_name == f"{context.prefix}-Privileged"
    assert context.worker_task_name == f"{context.prefix}-Worker"


def test_actual_installer_preserves_complete_context_pair_across_runtime_library_import(
    tmp_path: Path,
) -> None:
    # Given: a valid nonce context that must select nonce-derived registrations.
    path = tmp_path / "installation-context.json"
    nonce = "0123456789abcdef0123456789abcdef"
    digest = _write_context(path, {"schemaVersion": 1, "nonce": nonce, "port": 49152})

    # When: the actual installer imports service-runtime in read-only WhatIf mode.
    result = _run_install_with_context(
        "-InstallationContextPath",
        str(path),
        "-InstallationContextSha256",
        digest,
    )

    # Then: the plan remains bound to the nonce instead of falling back to canonical names.
    assert result.returncode == 0, result.stderr
    plan = InstallationContextPlan.model_validate_json(result.stdout)
    assert plan.mode == "what-if"
    assert [registration.name for registration in plan.registrations] == [
        f"HermesWindowsBridgeEval-{nonce}-Gateway",
        f"HermesWindowsBridgeEval-{nonce}-Privileged",
        f"HermesWindowsBridgeEval-{nonce}-Worker",
    ]
    assert plan.gateway_configuration.port == 49152
    assert plan.gateway_configuration.allowed_hosts == [f"eval-{nonce}.ts.net"]
    assert plan.final_mcp_url == f"https://eval-{nonce}.ts.net/mcp"


@pytest.mark.parametrize(
    "arguments",
    [
        ("-InstallationContextPath", "C:\\fixture\\context.json"),
        ("-InstallationContextSha256", "a" * 64),
    ],
)
def test_actual_installer_rejects_context_pair_half_after_runtime_library_import(
    arguments: tuple[str, str],
) -> None:
    # Given: one half of the installer context boundary.
    # When: the actual installer imports the colliding runtime library.
    result = _run_install_with_context(*arguments)

    # Then: restoration preserves the half-pair so the shared parser rejects it fail-closed.
    assert result.returncode != 0
    assert "BridgeInstallationContextPairRequired" in result.stderr


@pytest.mark.parametrize(
    ("payload", "digest_mutation"),
    [
        (
            {
                "schemaVersion": 1,
                "nonce": "0123456789abcdef0123456789abcdef",
                "port": 49152,
                "extra": 1,
            },
            "same",
        ),
        (
            {"schemaVersion": 1, "nonce": "0123456789abcdef0123456789abcdef", "port": 49151},
            "same",
        ),
        (
            {"schemaVersion": 1, "nonce": "0123456789abcdef0123456789abcdef", "port": 49152},
            "wrong",
        ),
    ],
)
def test_context_rejects_unknown_invalid_or_hash_mismatched_input(
    tmp_path: Path,
    payload: dict[str, int | str],
    digest_mutation: str,
) -> None:
    # Given: an untrusted context violating exactly one boundary invariant.
    path = tmp_path / "installation-context.json"
    actual_digest = _write_context(path, payload)
    requested_digest = "0" * 64 if digest_mutation == "wrong" else actual_digest

    # When: a consumer attempts the paired parse.
    result = _parse_context(path, requested_digest)

    # Then: it fails before a caller can derive roots or registration names.
    assert result.returncode != 0
    assert result.stdout == ""


def test_context_library_load_preserves_installer_calling_parameters() -> None:
    # Given: an installer caller has already bound its apply/json and context pair values.
    command = (
        "$Apply=$true;$Json=$true;"
        "$InstallationContextPath='C:\\fixture\\context.json';"
        "$InstallationContextSha256='a'*64;"
        f". '{CONTEXT_SCRIPT}' -LibraryMode;"
        "[pscustomobject]@{apply=$Apply;json=$Json;path=$InstallationContextPath;"
        "sha=$InstallationContextSha256}|ConvertTo-Json -Compress"
    )

    # When: the context library is dot-sourced by that caller.
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    # Then: context loading cannot erase or substitute the caller's paired boundary values.
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "apply": True,
        "json": True,
        "path": r"C:\fixture\context.json",
        "sha": "a" * 64,
    }


def test_context_uses_readonly_nonce_containers() -> None:
    # Given: the deterministic context preparation source.
    source = CONTEXT_SCRIPT.read_text(encoding="utf-8")

    # When: its protected-directory contracts are inspected without preparing resources.
    # Then: bindings/config containers deny LocalService modification.
    assert "Set-BridgeInstallationBindingsDirectoryAcl" in source
    assert "Set-BridgeInstallationReadonlyDirectoryAcl" in source
    assert "Rights ReadAndExecute" in source
    assert "BridgeInstallationContextPreparedStateUnverified" in source


def test_context_config_generation_binds_all_runtime_paths_without_environment_placeholders(
) -> None:
    # Given: source that produces the hash-bound nonce configuration.
    source = CONTEXT_SCRIPT.read_text(encoding="utf-8")

    # When: the configuration generation contract is inspected.
    # Then: config selects explicit IPC, token, data, and browser paths with JSON quoting.
    assert "contextServeHost = 'eval-{0}.ts.net'" in source
    assert "worker_pipe:" in source
    assert "privileged_pipe:" in source
    assert "program_data:" in source
    assert "user_data:" in source
    assert "profile_dir:" in source
    assert "token_file:" in source
    assert "ConvertTo-Json -Compress" in source


def test_context_installer_never_mutates_process_environment_for_doctor() -> None:
    # Given: the context-aware actual installer source.
    source = (PROJECT_ROOT / "scripts" / "install.ps1").read_text(encoding="utf-8")

    # When: its doctor invocation environment boundary is inspected.
    # Then: ProgramData/LocalAppData assignments stay inside the legacy-only context-null guard.
    expected_guard = (
        "if ($null -eq $installationContext) {\n"
        "                        $env:ProgramData"
    )
    assert expected_guard in source
    assert (
        "if ($null -eq $installationContext) {\n"
        "                        $env:ProgramData = $savedProgramData"
    ) in source


def test_context_rejects_escaped_duplicate_schema_key(tmp_path: Path) -> None:
    # Given: a JSON object that spells nonce twice, once with an escaped key character.
    path = tmp_path / "installation-context.json"
    body = (
        '{"schemaVersion":1,"nonce":"0123456789abcdef0123456789abcdef",'
        '"\\u006eonce":"0123456789abcdef0123456789abcdef","port":49152}'
    )
    _ = path.write_text(body, encoding="utf-8")

    # When: the hash-bound parser reads the exact file bytes.
    result = _parse_context(path, hashlib.sha256(path.read_bytes()).hexdigest())

    # Then: its literal-schema gate rejects it before JSON's last-key-wins behavior can apply.
    assert result.returncode != 0


def test_context_config_is_yaml_and_has_no_environment_path_fallback() -> None:
    # Given: a complete derived context supplied to the shared configuration generator.
    command = (
        f". '{CONTEXT_SCRIPT}' -LibraryMode;"
        "$context=[pscustomobject]@{"
        "nonce='0123456789abcdef0123456789abcdef';prefix='HermesWindowsBridgeEval-0123456789abcdef0123456789abcdef';"
        "port=49152;serveHost='eval-0123456789abcdef0123456789abcdef.ts.net';"
        "workerPipe='\\\\.\\pipe\\HermesWindowsBridgeEval-0123456789abcdef0123456789abcdef-Worker';"
        "privilegedPipe='\\\\.\\pipe\\HermesWindowsBridgeEval-0123456789abcdef0123456789abcdef-Privileged';"
        "runtimeRoot='C:\\ProgramData\\HermesWindowsBridgeEval-0123456789abcdef0123456789abcdef\\HermesWindowsBridge';"
        "userRoot='C:\\Users\\fixture\\AppData\\Local\\HermesWindowsBridgeEval-0123456789abcdef0123456789abcdef\\HermesWindowsBridge';"
        "tokenPath='C:\\ProgramData\\HermesWindowsBridgeEval-0123456789abcdef0123456789abcdef\\HermesWindowsBridge\\secrets\\token'"
        "};"
        "$text=New-BridgeInstallationContextConfigText -Context $context -ProjectRoot '"
        f"{PROJECT_ROOT}';[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($text))"
    )

    # When: the actual shared generator is exercised in the focused test.
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    # Then: YAML parses and every bound runtime path is explicit rather than environment-derived.
    assert result.returncode == 0, result.stderr
    generated = b64decode(result.stdout.strip()).decode("utf-8")
    config = BridgeSettings.model_validate(
        yaml.safe_load(generated), context=EnvironmentContext(environ={})
    )
    assert config.server.allowed_hosts[-1].endswith(".ts.net")
    assert config.ipc.worker_pipe.endswith("-Worker")
    assert config.ipc.privileged_pipe.endswith("-Privileged")
    assert str(config.paths.token_file).endswith(r"secrets\token")
    assert config.computer.emergency_stop_hotkey == "ctrl+alt+shift+f10"
    assert "%ProgramData%" not in generated
    assert "%LOCALAPPDATA%" not in generated


def test_binding_reader_uses_one_protected_file_and_ancestor_boundary() -> None:
    # Given: the context binding reader that host and installer share before mutation.
    source = CONTEXT_SCRIPT.read_text(encoding="utf-8")

    # When: its file protection boundary is inspected.
    # Then: it requires trusted owner/DACL, no reparse, one link, and every ancestor to each root.
    assert "function Assert-BridgeInstallationContextProtectedFile" in source
    assert "Test-BridgeInstallationContextAclProtected" in source
    assert "Get-BridgeInstallationFileLinkCount" in source
    assert "Get-BridgeFileLinkCount" not in source
    assert "while ($true)" in source
    assert "BridgeRuntimeBindingFileUnprotected" in source


def test_binding_reader_rejects_tampered_binding_config_or_worker_policy_before_hash_use() -> None:
    # Given: the three distinct protected files consumed by a runtime binding.
    source = CONTEXT_SCRIPT.read_text(encoding="utf-8")

    # When: the binding reader prepares to parse/hash those inputs.
    # Then: each passes the shared protected-file validator before its hash can be trusted.
    binding_index = source.index("BridgeRuntimeBindingFileUnprotected")
    config_index = source.index("BridgeRuntimeBindingConfigUnprotected")
    policy_index = source.index("BridgeRuntimeBindingPolicyUnprotected")
    hash_index = source.index("BridgeRuntimeBindingTargetHashMismatch")
    assert binding_index < config_index < hash_index
    assert config_index < policy_index < hash_index


def test_context_integer_boundary_accepts_only_int32_or_int64_source_contract() -> None:
    # Given: the shared numeric boundary used by both context and binding schema parsing.
    source = CONTEXT_SCRIPT.read_text(encoding="utf-8")

    # When: its accepted CLR integer types are inspected.
    # Then: WinPS5 Int32 and PS7 Int64 are accepted without admitting bool, float, or string values.
    assert "return (($Value -is [int]) -or ($Value -is [long]))" in source
    assert source.count("Test-BridgeInstallationContextJsonInteger") >= 4


def test_preparation_creates_schema2_reconciliation_receipt_after_first_nonce_root(
) -> None:
    # Given: an initially absent nonce namespace whose preparation can fail mid-flight.
    source = CONTEXT_SCRIPT.read_text(encoding="utf-8")

    # When: preparation creates its first ProgramData nonce root.
    # Then: it records the root's native identity in a durable schema-2 journal first.
    root_creation = source.index("[IO.Directory]::CreateDirectory([string]$Context.runtimeRoot)")
    first_journal = source.index("Write-BridgeInstallationContextPreparationJournal", root_creation)
    next_mutation = source.index("CreateDirectory([string]$directory)", root_creation)
    assert root_creation < first_journal < next_mutation
    assert "schemaVersion = 2" in source
    assert "absentBefore = -not (Test-Path" in source
    assert "nativeIdentity = Get-BridgeInstallationNativeIdentity" in source
    assert 'return info.Volume.ToString("X8")' in source
    assert 'index.ToString("X16") + ":" + info.Links.ToString()' in source


def test_preparation_failure_receipt_is_narrow_and_requires_reconciliation() -> None:
    # Given: a mutation error after the first durable checkpoint.
    source = CONTEXT_SCRIPT.read_text(encoding="utf-8")

    # When: preparation's catch path persists the failed state.
    # Then: it leaves only nonce-root identities for literal external reconciliation.
    catch_index = source.index(
        "$journal.state = 'partial'; $journal.reconciliationRequired = $true"
    )
    assert "Write-BridgeInstallationContextPreparationJournal" in source[catch_index:]
    assert "$failure.Data['reconciliationRequired'] = $true" in source[catch_index:]
    assert "$failure.Data['receipt']" in source[catch_index:]
    assert "roots = @($RootRecords)" in source
    assert "Set-BridgeInstallationPreparationJournalAcl" in source
    assert "Set-BridgeInstallationTrustedOwner -Path $Path" in source


def test_preparation_mid_failure_leaves_durable_identity_bound_receipt(
    tmp_path: Path,
) -> None:
    # Given: isolated nonce roots and an injected ACL mutation failure after journaling.
    fixture_root = tmp_path / "nonce-fixture"
    fixture_root.mkdir()
    command = (
        f". '{CONTEXT_SCRIPT}' -LibraryMode;"
        "function Test-BridgeAdministrator { $true };"
        "function Set-BridgeInstallationReadonlyDirectoryAcl { param($Path,$WorkerSid) };"
        "function Set-BridgeInstallationBindingsDirectoryAcl { param($Path,$WorkerSid) };"
        "function Set-BridgeAuditDirectoryAcl { param($Path) };"
        "function Set-BridgeSecretsDirectoryAcl { param($Path) };"
        "function Set-BridgeBrowserDirectoryAcl { param($Path,$UserSid) };"
        "function Set-BridgeInstallationTrustedOwner { param($Path) };"
        "function Set-BridgeInstallationPreparationJournalAcl { param($Path) };"
        "$script:fixtureOriginalJournalWriter=${function:Write-BridgeInstallationContextPreparationJournal};"
        "$script:fixtureJournalWrites=0;"
        "function Write-BridgeInstallationContextPreparationJournal {"
        "param($Path,$Journal,$RootRecords);$script:fixtureJournalWrites++;"
        "if($script:fixtureJournalWrites -eq 2){throw 'fixture-journal-failure'};"
        "& $script:fixtureOriginalJournalWriter @PSBoundParameters"
        "};"
        "$root=[IO.Path]::GetFullPath($env:HERMES_CONTEXT_FIXTURE_ROOT);"
        "$programRoot=[IO.Path]::Combine($root,'program');"
        "$programDataRoot=[IO.Path]::Combine($root,'program-data');"
        "$localDataRoot=[IO.Path]::Combine($root,'local-data');"
        "$runtimeRoot=[IO.Path]::Combine($programDataRoot,'HermesWindowsBridge');"
        "$context=[pscustomobject]@{"
        "nonce='0123456789abcdef0123456789abcdef';"
        "prefix='HermesWindowsBridgeEval-0123456789abcdef0123456789abcdef';"
        "port=49152;programRoot=$programRoot;programDataRoot=$programDataRoot;"
        "localDataRoot=$localDataRoot;runtimeRoot=$runtimeRoot;"
        "bindingsDirectory=[IO.Path]::Combine($programRoot,'bindings');"
        "userRoot=[IO.Path]::Combine($localDataRoot,'HermesWindowsBridge');"
        "configPath=[IO.Path]::Combine($runtimeRoot,'config.yaml');"
        "policyPath=[IO.Path]::Combine($runtimeRoot,'policy.yaml');"
        "tokenPath=[IO.Path]::Combine($runtimeRoot,'secrets','token');"
        "workerPipe='\\\\.\\pipe\\fixture-worker';"
        "privilegedPipe='\\\\.\\pipe\\fixture-privileged';"
        "preparationJournalPath=[IO.Path]::Combine($runtimeRoot,'installation-context-preparation.json')"
        "};"
        "try { Invoke-BridgeInstallationContextPreparation -Context $context -ProjectRoot '"
        f"{PROJECT_ROOT}' -Confirm:$false | Out-Null;throw 'fixture-missing-failure' }} catch {{ "
        "$journal=[IO.File]::ReadAllText($context.preparationJournalPath);"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($journal)) }"
    )

    # When: preparation reaches the injected failure after the first journal checkpoint.
    result = subprocess.run(
        [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={**os.environ, "HERMES_CONTEXT_FIXTURE_ROOT": str(fixture_root)},
    )

    # Then: the retained journal can authorize only exact nonce-root reconciliation.
    assert result.returncode == 0, result.stderr
    receipt = TypeAdapter(PreparationReceipt).validate_json(
        b64decode(result.stdout.strip()).decode("utf-8")
    )
    assert receipt.schema_version == 2
    assert receipt.state == "partial"
    assert receipt.reconciliation_required is True
    assert len(receipt.roots) == 3
    assert receipt.bindings == ["gateway", "privileged", "worker"]
    assert receipt.token_created is False
    assert receipt.created
    assert [root.absent_before for root in receipt.roots] == [True, True, True]
    assert receipt.roots[0].created is True
    assert receipt.roots[1].created is True
    assert receipt.roots[0].native_identity is not None
    assert receipt.roots[1].native_identity is not None
    assert receipt.roots[0].native_identity.endswith(":1")
    assert receipt.roots[1].native_identity.endswith(":1")
    assert receipt.roots[2].native_identity is None
