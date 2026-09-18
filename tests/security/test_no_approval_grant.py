import pytest

from hermes_windows_bridge.gateway.policy import (
    PROHIBITED_TOOL_NAMES,
    UnknownToolError,
    evaluate_tool,
    registered_tool_names,
)


@pytest.mark.security
def test_model_callable_approval_surfaces_are_absent() -> None:
    # Given: 실제 정책 레지스트리
    names = registered_tool_names()

    # When/Then: approve/deny/list 계열 이름이 하나도 노출되지 않는다.
    assert names.isdisjoint(PROHIBITED_TOOL_NAMES)
    assert all("approval" not in name and "approve" not in name for name in names)


@pytest.mark.security
@pytest.mark.parametrize("name", sorted(PROHIBITED_TOOL_NAMES))
def test_forged_approval_tool_name_is_rejected(name: str) -> None:
    # Given/When/Then: model이 승인 도구명을 위조해도 registry lookup이 fail-closed 한다.
    with pytest.raises(UnknownToolError):
        _ = evaluate_tool(name)
