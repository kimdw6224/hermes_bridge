from __future__ import annotations

import subprocess
from pathlib import Path
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

SERVE_HOST = "main-pc.example.ts.net"
CAPABILITY = "hermes.local/windows-control"
PROJECT_ROOT = Path(__file__).parents[2]


class _ServeStatus(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore")

    query: list[str]
    matches_desired: bool = Field(alias="matchesDesired")
    version: str | None
    app_capabilities_supported: bool = Field(alias="appCapabilitiesSupported")


class _TailscalePlan(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore")

    read_only: bool = Field(alias="readOnly")
    applied: bool
    funnel_enabled: bool = Field(alias="funnelEnabled")
    desired_serve_argv: list[str] = Field(alias="desiredServeArgv")
    recommended_grant_fragment: str = Field(alias="recommendedGrantFragment")
    hermes_config_snippet: str = Field(alias="hermesConfigSnippet")
    serve_status: _ServeStatus = Field(alias="serveStatus")


class _SimulatedTailscalePlan(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore")

    read_only: bool = Field(alias="readOnly")
    applied: bool
    state: str
    adapter_mode: str = Field(alias="adapterMode")
    external_calls: int = Field(alias="externalCalls")


class _TailscaleValidationError(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore")

    code: str
    field: str


class _TailscaleValidationFailure(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore")

    schema_version: int = Field(alias="schemaVersion")
    kind: str
    error: _TailscaleValidationError
    adapter_calls: list[str] = Field(alias="adapterCalls")


def _command(*arguments: str) -> list[str]:
    return [
        "powershell.exe",
        "-NoProfile",
        "-File",
        str(PROJECT_ROOT / "scripts" / "configure-tailscale.ps1"),
        *arguments,
    ]


class TestConfigureTailscaleScript:
    def test_what_if_json_is_read_only_and_contains_merge_fragments(self) -> None:
        completed = subprocess.run(
            _command(
                "-WhatIf",
                "-Json",
                "-ServeHost",
                SERVE_HOST,
                "-HermesSource",
                "tag:hermes",
                "-WindowsDestination",
                "tag:windows-bridge",
            ),
            check=False,
            capture_output=True,
            text=True,
        )

        assert completed.returncode == 0, completed.stderr
        plan = _TailscalePlan.model_validate_json(completed.stdout)
        assert plan.read_only is True
        assert plan.applied is False
        assert plan.funnel_enabled is False
        assert plan.desired_serve_argv == [
            "serve",
            "--bg",
            f"--accept-app-caps={CAPABILITY}",
            "8765",
        ]
        assert "tag:hermes" in plan.recommended_grant_fragment
        assert "tag:windows-bridge" in plan.recommended_grant_fragment
        assert "mcp_servers:" in plan.hermes_config_snippet
        assert "${HERMES_WINDOWS_BRIDGE_TOKEN}" in plan.hermes_config_snippet
        assert plan.serve_status.query == ["serve", "status", "--json"]
        assert isinstance(plan.serve_status.matches_desired, bool)
        assert isinstance(plan.serve_status.app_capabilities_supported, bool)

    def test_repeated_what_if_output_has_same_desired_configuration(self) -> None:
        command = _command("-WhatIf", "-Json", "-ServeHost", SERVE_HOST)

        first = subprocess.run(command, check=False, capture_output=True, text=True)
        second = subprocess.run(command, check=False, capture_output=True, text=True)

        assert first.returncode == second.returncode == 0
        first_plan = _TailscalePlan.model_validate_json(first.stdout)
        second_plan = _TailscalePlan.model_validate_json(second.stdout)
        assert first_plan.desired_serve_argv == second_plan.desired_serve_argv
        assert (
            first_plan.recommended_grant_fragment
            == second_plan.recommended_grant_fragment
        )
        assert first_plan.hermes_config_snippet == second_plan.hermes_config_snippet
        assert first_plan.funnel_enabled == second_plan.funnel_enabled

    def test_simulated_apply_readback_conflict_fails_closed_without_external_calls(self) -> None:
        completed = subprocess.run(
            _command(
                "-Json",
                "-ServeHost",
                SERVE_HOST,
                "-Apply",
                "-AdapterMode",
                "Simulate",
                "-SimulationScenario",
                "ConcurrentConflict",
            ),
            check=False,
            capture_output=True,
            text=True,
        )

        assert completed.returncode == 2
        plan = _SimulatedTailscalePlan.model_validate_json(completed.stdout)
        assert plan.read_only is True
        assert plan.applied is False
        assert plan.state == "apply-verification-conflict"
        assert plan.adapter_mode == "Simulate"
        assert plan.external_calls == 0

    def test_script_bounds_read_only_tailscale_queries(self) -> None:
        source = (PROJECT_ROOT / "scripts" / "configure-tailscale.ps1").read_text(
            encoding="utf-8"
        )

        assert "WaitForExit($externalCommandTimeoutSeconds * 1000)" in source
        assert "$process.Kill()" in source
        assert "$process.Dispose()" in source
        assert "tailscale funnel" not in source.lower()

    def test_hostile_hostname_is_rejected_before_execution(self) -> None:
        completed = subprocess.run(
            _command(
                "-Json",
                "-Apply",
                "-AdapterMode",
                "Simulate",
                "-ServeHost",
                "safe.example; Remove-Item C:\\",
            ),
            check=False,
            capture_output=True,
            text=True,
        )

        assert completed.returncode == 2
        failure = _TailscaleValidationFailure.model_validate_json(completed.stdout)
        assert failure.schema_version == 1
        assert failure.kind == "hermes-windows-bridge-tailscale-validation-error"
        assert failure.error.code == "invalid-serve-host"
        assert failure.error.field == "ServeHost"
        assert failure.adapter_calls == []
