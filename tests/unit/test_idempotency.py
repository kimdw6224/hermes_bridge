from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from hermes_windows_bridge.gateway.idempotency import (
    IdempotencyConflictError,
    IdempotencyStore,
    OperationCall,
)

NOW = datetime(2026, 9, 5, tzinfo=UTC)
OPERATION_ID = UUID("018f0000-0000-7000-8000-000000000002")


class TestIdempotency:
    def test_same_id_same_payload_replays_result(self) -> None:
        # Given: 실행 횟수를 독립 관찰하는 실제 callback
        store = IdempotencyStore(ttl=timedelta(minutes=30))
        executions = 0

        def execute() -> bytes:
            nonlocal executions
            executions += 1
            return b'{"ok":true}'

        call = OperationCall(
            operation_id=OPERATION_ID,
            payload={"path": "C:/tmp/a", "content": "hello"},
            requested_at=NOW,
        )

        # When: 같은 ID와 canonical-equivalent payload를 두 번 실행하면
        first = store.execute(call, execute)
        second = store.execute(
            OperationCall(
                operation_id=OPERATION_ID,
                payload={"content": "hello", "path": "C:/tmp/a"},
                requested_at=NOW + timedelta(seconds=1),
            ),
            execute,
        )

        # Then: 실제 실행은 한 번이고 cached bytes가 동일하다.
        assert executions == 1
        assert first.payload == second.payload == b'{"ok":true}'
        assert first.replayed is False
        assert second.replayed is True

    def test_same_id_altered_payload_is_rejected(self) -> None:
        # Given: 완료된 operation ID
        store = IdempotencyStore(ttl=timedelta(minutes=30))
        call = OperationCall(
            operation_id=OPERATION_ID,
            payload={"value": 1},
            requested_at=NOW,
        )
        _ = store.execute(call, lambda: b"first")

        # When/Then: 같은 ID의 다른 payload는 callback 실행 전에 거부된다.
        with pytest.raises(IdempotencyConflictError):
            _ = store.execute(
                OperationCall(
                    operation_id=OPERATION_ID,
                    payload={"value": 2},
                    requested_at=NOW + timedelta(seconds=1),
                ),
                lambda: b"misleading success",
            )

    def test_expired_entry_executes_again(self) -> None:
        # Given: TTL이 지난 완료 기록
        store = IdempotencyStore(ttl=timedelta(seconds=5))
        executions = 0

        def execute() -> bytes:
            nonlocal executions
            executions += 1
            return str(executions).encode()

        _ = store.execute(
            OperationCall(operation_id=OPERATION_ID, payload={"value": 1}, requested_at=NOW),
            execute,
        )

        # When: TTL 뒤 같은 요청을 재시도하면
        result = store.execute(
            OperationCall(
                operation_id=OPERATION_ID,
                payload={"value": 1},
                requested_at=NOW + timedelta(seconds=6),
            ),
            execute,
        )

        # Then: stale cache를 쓰지 않고 재실행한다.
        assert executions == 2
        assert result.payload == b"2"
        assert result.replayed is False

    def test_failed_execution_is_not_cached(self) -> None:
        # Given: 첫 실행이 중단되는 callback
        store = IdempotencyStore(ttl=timedelta(minutes=30))

        def interrupted() -> bytes:
            raise KeyboardInterrupt

        call = OperationCall(operation_id=OPERATION_ID, payload={}, requested_at=NOW)

        # When: 실행이 interrupt되면
        with pytest.raises(KeyboardInterrupt):
            _ = store.execute(call, interrupted)

        # Then: 재개 요청은 가짜 성공을 재생하지 않고 실제로 실행된다.
        resumed = store.execute(call, lambda: b"resumed")
        assert resumed.payload == b"resumed"
        assert resumed.replayed is False
