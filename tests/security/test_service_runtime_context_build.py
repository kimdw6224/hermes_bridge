"""Runtime checks for context-bound protected release builds."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path
from typing import ClassVar, Final

from pydantic import BaseModel, ConfigDict, Field

PROJECT_ROOT: Final = Path(__file__).parents[2]
RUNTIME_SCRIPT: Final = PROJECT_ROOT / "scripts" / "service-runtime.ps1"
POWERSHELL: Final = shutil.which("powershell.exe")
assert POWERSHELL is not None
NONCE: Final = "0123456789abcdef0123456789abcdef"


class ResolverReceipt(BaseModel):
    """Observed result from the build-context resolver boundary."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    state: str
    context_present: bool | None = Field(validation_alias="contextPresent")
    message: str


class ForwardingReceipt(BaseModel):
    """Arguments observed by the narrow release-plan test double."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    state: str
    context_path: str = Field(validation_alias="contextPath")
    context_sha256: str = Field(validation_alias="contextSha256")


def _run_resolver(arguments: str) -> subprocess.CompletedProcess[str]:
    """Run the real resolver while containing rejection details at the test boundary."""

    command = " ".join(
        (
            "$ErrorActionPreference='Stop';",
            f". '{RUNTIME_SCRIPT}' -LibraryMode;",
            "try {",
            f"$context=Get-BridgeRuntimeBuildInstallationContext {arguments};",
            "[pscustomobject]@{state='accepted';contextPresent=($null -ne $context);message=''}",
            "| ConvertTo-Json -Compress; exit 0",
            "} catch {",
            "[pscustomobject]@{state='rejected';contextPresent=$null;message=$_.Exception.Message}",
            "| ConvertTo-Json -Compress; exit 2",
            "}",
        )
    )
    return subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )


def _write_context(path: Path) -> tuple[Path, str]:
    """Create an authentic schema-1 context that deliberately has no prepared roots."""

    context_path = path / "installation-context.json"
    body = f'{{"schemaVersion":1,"nonce":"{NONCE}","port":50123}}'
    _ = context_path.write_text(body, encoding="utf-8")
    return context_path, hashlib.sha256(body.encode()).hexdigest()


def test_context_resolver_returns_null_when_pair_is_absent() -> None:
    # Given: the real service-runtime library with no context values.
    result = _run_resolver("")

    # When: the optional context resolver runs for a production caller.
    receipt = ResolverReceipt.model_validate_json(result.stdout)

    # Then: legacy production mode has no nonce context and succeeds.
    assert result.returncode == 0, result.stderr
    assert receipt.state == "accepted"
    assert receipt.context_present is False


def test_context_resolver_rejects_partial_pair(tmp_path: Path) -> None:
    # Given: a caller supplies only an installation-context path.
    context_path, _ = _write_context(tmp_path)

    # When: the resolver receives the incomplete pair.
    result = _run_resolver(f"-InstallationContextPath '{context_path}'")
    receipt = ResolverReceipt.model_validate_json(result.stdout)

    # Then: it fails before a context file or runtime root can be trusted.
    assert result.returncode == 2
    assert receipt.state == "rejected"
    assert receipt.message == "BridgeRuntimeInstallationContextPairRequired"


def test_context_resolver_rejects_tampered_context_hash(tmp_path: Path) -> None:
    # Given: a schema-1 context whose caller-provided digest is wrong.
    context_path, _ = _write_context(tmp_path)

    # When: the resolver verifies the supplied pair.
    result = _run_resolver(
        f"-InstallationContextPath '{context_path}' -InstallationContextSha256 {'a' * 64}"
    )
    receipt = ResolverReceipt.model_validate_json(result.stdout)

    # Then: digest verification fails before any derived root is considered.
    assert result.returncode == 2
    assert receipt.state == "rejected"
    assert receipt.message == "BridgeInstallationContextHashMismatch"


def test_context_resolver_rejects_valid_but_unprepared_context(tmp_path: Path) -> None:
    # Given: an authentic context file with no protected bindings or prepared roots.
    context_path, context_sha256 = _write_context(tmp_path)

    # When: the resolver receives a valid context pair.
    result = _run_resolver(
        f"-InstallationContextPath '{context_path}' -InstallationContextSha256 {context_sha256}"
    )
    receipt = ResolverReceipt.model_validate_json(result.stdout)

    # Then: it cannot authorize a nonce ProgramRoot from unprepared state.
    assert result.returncode == 2
    assert receipt.state == "rejected"
    assert receipt.context_present is None


def test_build_release_forwards_context_pair_to_release_plan(tmp_path: Path) -> None:
    # Given: the actual BuildRelease entrypoint and a minimal plan callee that records inputs.
    runtime_copy = tmp_path / "service-runtime.ps1"
    _ = shutil.copy2(RUNTIME_SCRIPT, runtime_copy)
    context_path, context_sha256 = _write_context(tmp_path)
    build_helper = tmp_path / "service-runtime-build.ps1"
    _ = build_helper.write_text(
        """
function Get-BridgeReleaseBuildPlan {
    param($SourceRoot, $ProgramRoot, $TrustedUvPath, $ExpectedSourceDigest,
        $ExpectedLockDigest, $ExpectedUvSha256, $InstallationContextPath,
        $InstallationContextSha256, $TimeoutSeconds)
    [pscustomobject]@{state='planned';contextPath=$InstallationContextPath;contextSha256=$InstallationContextSha256}
}
function Invoke-BridgeProtectedReleaseBuild { throw 'unexpected-apply' }
""",
        encoding="utf-8",
    )

    # When: BuildRelease selects its non-mutating plan path with a complete pair.
    result = subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(runtime_copy),
            "-BuildRelease",
            "-SourceRoot",
            str(tmp_path),
            "-ProgramRoot",
            str(tmp_path / "program"),
            "-TrustedUvPath",
            "fixture-uv.exe",
            "-ExpectedSourceDigest",
            "a" * 64,
            "-ExpectedLockDigest",
            "b" * 64,
            "-ExpectedUvSha256",
            "c" * 64,
            "-InstallationContextPath",
            str(context_path),
            "-InstallationContextSha256",
            context_sha256,
            "-Json",
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    receipt = ForwardingReceipt.model_validate_json(result.stdout)

    # Then: the plan receives the exact path/hash pair without an Apply action.
    assert result.returncode == 0, result.stderr
    assert receipt.state == "planned"
    assert receipt.context_path == str(context_path)
    assert receipt.context_sha256 == context_sha256
