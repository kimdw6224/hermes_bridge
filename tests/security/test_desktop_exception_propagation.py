from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING

import pytest

from hermes_windows_bridge.worker.desktop_lock import (
    DesktopErrorCode,
    DesktopLimitationError,
    DesktopStateUncertainError,
)

if TYPE_CHECKING:
    from collections.abc import Generator


@contextmanager
def _exception_boundary() -> Generator[None]:
    yield


@pytest.mark.parametrize(
    ("error_type", "expected_code"),
    [
        (DesktopLimitationError, "limitation"),
        (DesktopStateUncertainError, "state_uncertain"),
    ],
)
def test_contextmanager_preserves_desktop_error_and_receipt(
    error_type: type[DesktopLimitationError | DesktopStateUncertainError],
    expected_code: DesktopErrorCode,
) -> None:
    # Given: 커서나 Worker 실행이 필요 없는 실제 typed 예외와 원인입니다.
    error = error_type(before=(11, 22), observed=(33, 44), target=(55, 66))
    cause = OSError("input observation failed")

    # When: contextlib가 예외를 다시 전파하며 traceback을 갱신합니다.
    with pytest.raises(error_type) as caught, _exception_boundary():
        raise error from cause

    # Then: 다른 TypeError에 가려지지 않고 원래 예외와 관측값을 보존합니다.
    assert caught.value is error
    assert caught.value.code == expected_code
    assert (caught.value.before, caught.value.observed, caught.value.target) == (
        (11, 22), (33, 44), (55, 66)
    )
    assert caught.value.__cause__ is cause
    assert caught.value.__traceback__ is not None
