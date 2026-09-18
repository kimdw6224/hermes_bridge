"""Privileged Helper의 pywin32 Service Control Manager 진입점입니다."""

# pyright: reportUnknownMemberType=false

from __future__ import annotations

from hermes_windows_bridge.privileged.windows_service import (
    PRIVILEGED_SERVICE,
    PrivilegedHelperWindowsService,
)


def service_name() -> str:
    """SCM adapter가 사용할 고정 서비스 이름을 반환합니다."""
    return PRIVILEGED_SERVICE.name


def main() -> None:
    """현재 process를 단일 Privileged Helper ServiceFramework로 SCM에 연결합니다."""
    import servicemanager  # noqa: PLC0415 - pywin32 SCM entrypoint를 실행 시점에만 import합니다.

    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(PrivilegedHelperWindowsService)
    servicemanager.StartServiceCtrlDispatcher()


if __name__ == "__main__":
    main()
