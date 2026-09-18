"""Codex durable job의 adapter-owned deadline monitor입니다."""

from __future__ import annotations

from collections.abc import Callable
from threading import Event, Thread
from time import monotonic
from typing import Protocol, final
from uuid import UUID

from hermes_windows_bridge.gateway.job_models import TERMINAL_JOB_STATES, JobState

type JobStateReader = Callable[[UUID], JobState]
type JobCanceller = Callable[[UUID], None]


class DeadlineScheduler(Protocol):
    """Adapter가 deadline implementation에 요구하는 최소 계약입니다."""

    def arm(
        self,
        job_id: UUID,
        timeout_s: float,
        state_reader: JobStateReader,
        canceller: JobCanceller,
    ) -> None:
        """Terminal 또는 deadline까지 한 job을 감시합니다."""
        ...


@final
class ThreadDeadlineScheduler:
    """Daemon monitor가 terminal에서 종료되고 deadline에서 한 번 취소합니다."""

    def __init__(self, *, poll_interval_s: float = 0.05) -> None:
        """Event.wait에 사용할 bounded 감시 간격을 고정합니다."""
        self._poll_interval_s = poll_interval_s

    def arm(
        self,
        job_id: UUID,
        timeout_s: float,
        state_reader: JobStateReader,
        canceller: JobCanceller,
    ) -> None:
        """Service 종료를 막지 않는 daemon monitor를 시작합니다."""
        thread = Thread(
            target=_watch,
            args=(job_id, timeout_s, self._poll_interval_s, state_reader, canceller),
            name=f"codex-deadline-{job_id}",
            daemon=True,
        )
        thread.start()


def _watch(
    job_id: UUID,
    timeout_s: float,
    poll_interval_s: float,
    state_reader: JobStateReader,
    canceller: JobCanceller,
) -> None:
    deadline = monotonic() + timeout_s
    waiter = Event()
    while state_reader(job_id) not in TERMINAL_JOB_STATES:
        remaining = deadline - monotonic()
        if remaining <= 0:
            canceller(job_id)
            return
        _ = waiter.wait(min(remaining, poll_interval_s))
