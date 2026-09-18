"""실제 전원 API는 차단하고 권한 활성화·복원 경계를 확인합니다."""

from unittest.mock import patch

import pytest

from hermes_windows_bridge.privileged.operations import RebootRequest
from hermes_windows_bridge.privileged.runtime import WindowsPowerActionExecutor


@pytest.mark.parametrize("power_fails", [False, True])
def test_shutdown_privilege_is_enabled_and_restored(*, power_fails: bool) -> None:
    token = 123
    previous = [(19, 0)]
    events: list[str] = []

    def initiate(*args: str | int | None) -> None:
        del args
        events.append("power")
        if power_fails:
            raise PermissionError

    with (
        patch("win32security.OpenProcessToken", return_value=token),
        patch("win32api.CloseHandle") as close,
        patch("win32security.LookupPrivilegeValue", return_value=19),
        patch("win32security.AdjustTokenPrivileges", return_value=previous) as adjust,
        patch("win32api.GetLastError", return_value=0),
        patch("win32api.InitiateSystemShutdown", side_effect=initiate) as power,
    ):
        def adjust_privilege(*args: int | list[tuple[int, int]]) -> list[tuple[int, int]]:
            del args
            events.append("adjust")
            return previous

        adjust.side_effect = adjust_privilege
        request = RebootRequest(operation="reboot", reason="fixture", delay_seconds=30)
        if power_fails:
            with pytest.raises(PermissionError):
                WindowsPowerActionExecutor().reboot(request)
        else:
            WindowsPowerActionExecutor().reboot(request)
        assert events == ["adjust", "power", "adjust"]
        assert adjust.call_args_list[-1].args == (token, False, previous)
        assert power.call_count == 1
        close.assert_called_once_with(token)


def test_unassigned_privilege_prevents_power_call() -> None:
    token = 123
    with (
        patch("win32security.OpenProcessToken", return_value=token),
        patch("win32api.CloseHandle"),
        patch("win32security.LookupPrivilegeValue", return_value=19),
        patch("win32security.AdjustTokenPrivileges", return_value=[]),
        patch("win32api.GetLastError", return_value=1300),
        patch("win32api.InitiateSystemShutdown") as power,
    ):
        with pytest.raises(OSError, match="1300"):
            WindowsPowerActionExecutor().reboot(
                RebootRequest(operation="reboot", reason="fixture", delay_seconds=30)
            )
        power.assert_not_called()
