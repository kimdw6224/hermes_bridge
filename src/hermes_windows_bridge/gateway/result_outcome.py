"""Peer payload의 semantic action 실패를 audit outcome으로 분류합니다."""

from typing import TYPE_CHECKING, Final

from hermes_windows_bridge.gateway.audit import AuditOutcome

if TYPE_CHECKING:
    from hermes_windows_bridge.ipc.protocol import JsonPayload

_SEMANTIC_ACTION_RESULT_TOOLS: Final = frozenset(
    [
        "computer_click",
        "computer_hotkey",
        "computer_key",
        "computer_move",
        "computer_scroll",
        "computer_type",
        "uia_action",
        "uia_find",
    ]
)


def semantic_result_outcome(tool_name: str, payload: JsonPayload) -> AuditOutcome:
    """명시된 action 결과 contract의 거부만 MCP 오류로 분류합니다."""
    if tool_name in _SEMANTIC_ACTION_RESULT_TOOLS and payload.get("ok") is False:
        return AuditOutcome.REJECTED
    return AuditOutcome.SUCCEEDED
