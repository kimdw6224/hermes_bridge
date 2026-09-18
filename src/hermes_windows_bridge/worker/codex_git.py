"""Codex pre/postflight용 read-only Git snapshot입니다."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final, override

from hermes_windows_bridge.tools.codex import GitSnapshot, run_bounded_command

_GIT_TIMEOUT_S: Final = 10


@dataclass(frozen=True, slots=True)
class GitProbeError(RuntimeError):
    """Repository 판별 뒤 필수 STATUS-only probe가 실패했습니다."""

    reason: str

    @override
    def __str__(self) -> str:
        return f"git_probe_failed:{self.reason}"


def capture_git_snapshot(cwd: Path) -> GitSnapshot:
    """Git STATUS-only 명령으로 현재 repository를 읽습니다."""
    root = run_bounded_command(
        ("git", "-C", str(cwd), "rev-parse", "--show-toplevel"), cwd, _GIT_TIMEOUT_S
    )
    if root.exit_code != 0:
        return GitSnapshot(is_repository=False)
    repo_root = Path(_first_line(root.stdout) or str(cwd)).resolve()
    branch = _git_optional(repo_root, "branch", "--show-current")
    head = _git_optional(repo_root, "rev-parse", "HEAD")
    status = run_bounded_command(
        ("git", "-C", str(repo_root), "status", "--porcelain=v1", "-z"),
        repo_root,
        _GIT_TIMEOUT_S,
    )
    if status.exit_code != 0:
        raise GitProbeError(reason="status_unavailable")
    entries = tuple(entry for entry in status.stdout.split("\0") if entry)
    dirty_files = tuple(sorted({entry[3:] for entry in entries if " " in entry}))
    diff = run_bounded_command(
        ("git", "-C", str(repo_root), "diff", "--stat"), repo_root, _GIT_TIMEOUT_S
    )
    return GitSnapshot(
        is_repository=True,
        repo_root=repo_root,
        branch=branch,
        head=head,
        status_porcelain=entries,
        dirty_files=dirty_files,
        diff_stat=diff.stdout.strip() if diff.exit_code == 0 else "",
    )


def _git_optional(repo: Path, *args: str) -> str | None:
    result = run_bounded_command(("git", "-C", str(repo), *args), repo, _GIT_TIMEOUT_S)
    return _first_line(result.stdout) if result.exit_code == 0 else None


def _first_line(text: str) -> str | None:
    lines = text.splitlines()
    return lines[0][:256] if lines else None
