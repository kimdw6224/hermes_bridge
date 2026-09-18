from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from hermes_windows_bridge.tools.filesystem import (
    FilesystemLimits,
    FilesystemTools,
    ReadInput,
    WriteInput,
)
from hermes_windows_bridge.worker.filesystem import FilesystemWorker
from hermes_windows_bridge.worker.path_safety import PathPolicyError, SafePathPolicy

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(autouse=True)
def cleanup_test_root(tmp_path: Path) -> Iterator[None]:
    yield
    # pytest가 이 테스트에 할당한 고유 루트만 즉시 정리합니다.
    if tmp_path.exists():
        shutil.rmtree(tmp_path)


def build_tools(root: Path) -> FilesystemTools:
    return FilesystemTools(
        FilesystemWorker(
            path_policy=SafePathPolicy(allowed_roots=(root,)),
            limits=FilesystemLimits(64, 64, 10, frozenset()),
        )
    )


@pytest.mark.security
class TestPathEscape:
    @pytest.mark.parametrize(
        "raw_path",
        [r"\\.\PhysicalDrive0", r"\\?\GLOBALROOT\Device\HarddiskVolume1", r"\\host\share"],
    )
    def test_raw_namespaces_are_rejected(self, tmp_path: Path, raw_path: str) -> None:
        # Given
        tools = build_tools(tmp_path)
        request = ReadInput.model_validate({"path": raw_path})

        # When / Then
        with pytest.raises(PathPolicyError):
            _ = tools.fs_read(request)

    def test_real_junction_escape_is_rejected(self, tmp_path: Path) -> None:
        # Given
        allowed = tmp_path / "allowed"
        outside = tmp_path / "outside"
        junction = allowed / "escape"
        allowed.mkdir()
        outside.mkdir()
        _ = (outside / "secret.txt").write_text("secret", encoding="utf-8")
        completed = subprocess.run(
            [os.environ["COMSPEC"], "/c", "mklink", "/J", os.fspath(junction), os.fspath(outside)],
            capture_output=True,
            check=False,
            text=True,
        )
        if completed.returncode != 0:
            pytest.skip(f"junction unsupported: {completed.stderr.strip()}")
        tools = build_tools(allowed)

        try:
            # When / Then
            with pytest.raises(PathPolicyError, match="outside_allowed_roots"):
                _ = tools.fs_read(ReadInput(path=junction / "secret.txt"))
        finally:
            junction.rmdir()

    def test_revalidates_after_junction_swap(self, tmp_path: Path) -> None:
        # Given
        allowed = tmp_path / "allowed"
        inside = allowed / "link"
        outside = tmp_path / "outside"
        allowed.mkdir()
        inside.mkdir()
        outside.mkdir()
        _ = (inside / "secret.txt").write_text("inside", encoding="utf-8")
        _ = (outside / "secret.txt").write_text("outside", encoding="utf-8")
        tools = build_tools(allowed)
        assert tools.fs_read(ReadInput(path=inside / "secret.txt")).text == "inside"
        (inside / "secret.txt").unlink()
        inside.rmdir()
        completed = subprocess.run(
            [os.environ["COMSPEC"], "/c", "mklink", "/J", os.fspath(inside), os.fspath(outside)],
            capture_output=True,
            check=False,
            text=True,
        )
        if completed.returncode != 0:
            pytest.skip(f"junction unsupported: {completed.stderr.strip()}")

        try:
            # When / Then
            with pytest.raises(PathPolicyError, match="outside_allowed_roots"):
                _ = tools.fs_read(ReadInput(path=inside / "secret.txt"))
        finally:
            inside.rmdir()

    def test_handle_bound_read_rejects_swap_after_resolve(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Given
        allowed = tmp_path / "allowed"
        victim = allowed / "victim"
        parked = allowed / "parked"
        outside = tmp_path / "outside"
        victim.mkdir(parents=True)
        outside.mkdir()
        _ = (victim / "secret.txt").write_text("inside", encoding="utf-8")
        _ = (outside / "secret.txt").write_text("outside", encoding="utf-8")
        tools = build_tools(allowed)
        original_resolve = Path.resolve
        swapped = False

        def swap_after_resolve(path: Path, *, strict: bool = False) -> Path:
            nonlocal swapped
            resolved = original_resolve(path, strict=strict)
            if path == victim / "secret.txt" and not swapped:
                swapped = True
                _ = victim.rename(parked)
                completed = subprocess.run(
                    [
                        os.environ["COMSPEC"],
                        "/c",
                        "mklink",
                        "/J",
                        os.fspath(victim),
                        os.fspath(outside),
                    ],
                    capture_output=True,
                    check=False,
                    text=True,
                )
                if completed.returncode != 0:
                    pytest.skip(f"junction unsupported: {completed.stderr.strip()}")
            return resolved

        monkeypatch.setattr(Path, "resolve", swap_after_resolve)

        try:
            # When / Then
            with pytest.raises(PathPolicyError, match="outside_allowed_roots"):
                _ = tools.fs_read(ReadInput(path=victim / "secret.txt"))
        finally:
            if victim.is_junction():
                victim.rmdir()
            if parked.exists():
                _ = parked.rename(victim)

    def test_directory_handle_guard_rejects_write_parent_swap(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Given
        allowed = tmp_path / "allowed"
        victim = allowed / "victim"
        parked = allowed / "parked"
        outside = tmp_path / "outside"
        victim.mkdir(parents=True)
        outside.mkdir()
        tools = build_tools(allowed)
        original_resolve = Path.resolve
        swapped = False

        def swap_parent_after_resolve(path: Path, *, strict: bool = False) -> Path:
            nonlocal swapped
            resolved = original_resolve(path, strict=strict)
            if path == victim and not swapped:
                swapped = True
                _ = victim.rename(parked)
                completed = subprocess.run(
                    [
                        os.environ["COMSPEC"],
                        "/c",
                        "mklink",
                        "/J",
                        os.fspath(victim),
                        os.fspath(outside),
                    ],
                    capture_output=True,
                    check=False,
                    text=True,
                )
                if completed.returncode != 0:
                    pytest.skip(f"junction unsupported: {completed.stderr.strip()}")
            return resolved

        monkeypatch.setattr(Path, "resolve", swap_parent_after_resolve)

        try:
            # When / Then
            with pytest.raises(PathPolicyError, match="outside_allowed_roots"):
                _ = tools.fs_write(WriteInput(path=victim / "escaped.txt", text="blocked"))
            assert not (outside / "escaped.txt").exists()
        finally:
            if victim.is_junction():
                victim.rmdir()
            if parked.exists():
                _ = parked.rename(victim)
