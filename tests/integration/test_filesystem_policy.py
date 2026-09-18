from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

import pytest
from pydantic import ValidationError

from hermes_windows_bridge.ipc.protocol import IpcRequest, PeerRole
from hermes_windows_bridge.models.config import (
    BridgeSettings,
    FilesystemPolicy,
    PolicySettings,
    RuntimePaths,
)
from hermes_windows_bridge.tools.filesystem import FilesystemTools, ListInput, ReadInput
from hermes_windows_bridge.worker.operations import WorkerOperationDispatcher
from hermes_windows_bridge.worker.path_safety import PathPolicyError

if TYPE_CHECKING:
    from uuid import UUID

    from hermes_windows_bridge.ipc.protocol import JsonPayload


def configured_tools(root: Path, additions: tuple[Path, ...]) -> FilesystemTools:
    program_data, user_data = root / "program-data", root / "user-data"
    program_data.mkdir(exist_ok=True)
    user_data.mkdir(exist_ok=True)
    return FilesystemTools.from_settings(
        bridge=BridgeSettings(paths=RuntimePaths(program_data=program_data, user_data=user_data)),
        policy=PolicySettings(filesystem=FilesystemPolicy(additional_allowed_roots=additions)),
    )


@pytest.mark.integration
def test_explicit_roots_allow_workspace_without_allowing_its_sibling(tmp_path: Path) -> None:
    project, user, outside = tmp_path / "project", tmp_path / "user", tmp_path / "outside"
    for directory in (project, user, outside):
        directory.mkdir()
    _ = (project / "note.txt").write_text("workspace", encoding="utf-8")
    tools = configured_tools(tmp_path, (project, user))

    assert tools.fs_stat(ReadInput(path=project)).kind == "directory"
    assert [entry.name for entry in tools.fs_list(ListInput(path=project)).entries] == ["note.txt"]
    assert tools.fs_stat(ReadInput(path=user)).kind == "directory"
    assert tools.fs_stat(ReadInput(path=tmp_path / "user-data")).kind == "directory"
    with pytest.raises(PathPolicyError, match="outside_allowed_roots"):
        _ = tools.fs_stat(ReadInput(path=outside))


@pytest.mark.integration
def test_default_roots_do_not_grant_workspace_access(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    tools = configured_tools(tmp_path, ())
    with pytest.raises(PathPolicyError, match="outside_allowed_roots"):
        _ = tools.fs_list(ListInput(path=project))


@pytest.mark.integration
def test_listing_reports_reserved_file_without_opening_the_device(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    ordinary = project / "note.txt"
    _ = ordinary.write_text("keep", encoding="utf-8")
    reserved = Path("\\\\?\\" + str(project / "NUL"))
    _ = reserved.write_text("reserved file", encoding="utf-8")
    try:
        tools = configured_tools(tmp_path, (project,))
        listing = tools.fs_list(ListInput(path=project))
        assert [entry.name for entry in listing.entries] == ["note.txt"]
        assert [(entry.name, entry.reason) for entry in listing.unavailable_entries] == [
            ("NUL", "device_namespace_denied"),
        ]
        with pytest.raises(PathPolicyError, match="device_namespace_denied"):
            _ = tools.fs_stat(ReadInput(path=project / "NUL"))
        assert reserved.read_text(encoding="utf-8") == "reserved file"
    finally:
        reserved.unlink()


@pytest.mark.parametrize(
    "path", ["relative", "C:\\project\\..\\Windows", "%UNDEFINED_HERMES_ROOT%"],
)
def test_additional_roots_reject_ambiguous_configuration(path: str) -> None:
    with pytest.raises(ValidationError):
        _ = FilesystemPolicy.model_validate({"additional_allowed_roots": [path]})


@dataclass(frozen=True, slots=True)
class StatHandler:
    tools: FilesystemTools

    def __call__(self, request: IpcRequest) -> JsonPayload:
        result = self.tools.fs_stat(ReadInput.model_validate(request.payload))
        return {"kind": result.kind}

    def cancel(self, request_id: UUID) -> bool:
        del request_id
        return False


@pytest.mark.integration
def test_path_denial_keeps_a_safe_code_at_worker_boundary(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    worker = WorkerOperationDispatcher({"fs_stat": StatHandler(configured_tools(tmp_path, ()))})
    response = worker.exchange(IpcRequest(
        request_id=uuid4(), target=PeerRole.WORKER, operation="fs_stat",
        payload={"path": str(outside)}, timeout_ms=1_000,
    ))
    assert not response.ok
    assert response.error_code == "path_outside_allowed_roots"
    assert str(outside) not in response.model_dump_json()
