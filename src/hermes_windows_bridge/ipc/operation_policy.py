"""Privileged Helper IPC operation allowlist입니다."""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field


class PrivilegedOperation(StrEnum):
    """V1 Privileged Helper가 실행할 수 있는 명시적 operation입니다."""

    REBOOT = "reboot"
    SHUTDOWN = "shutdown"


class _PrivilegedPayload(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)


class RebootPayload(_PrivilegedPayload):
    """Reboot operation의 검증된 구조화 인자입니다."""

    delay_seconds: int = Field(ge=0, le=300)
    reason: str = Field(min_length=1, max_length=200)


class ShutdownPayload(_PrivilegedPayload):
    """Shutdown operation의 검증된 구조화 인자입니다."""

    delay_seconds: int = Field(ge=0, le=300)
    reason: str = Field(min_length=1, max_length=200)
