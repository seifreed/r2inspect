from __future__ import annotations

import time

import pytest

from r2inspect.error_handling.policies import ErrorHandlingStrategy, ErrorPolicy
from r2inspect.error_handling.unified_handler import (
    CircuitState,
    get_circuit_breaker_stats,
    handle_errors,
    reset_circuit_breakers,
)


def test_retry_policy_success_after_failures():
    state = {"count": 0}

    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.RETRY,
        max_retries=2,
        retry_delay=0.0,
        retry_backoff=1.0,
        retry_jitter=False,
    )

    @handle_errors(policy)
    def flaky():
        state["count"] += 1
        if state["count"] < 3:
            raise RuntimeError("boom")
        return "ok"

    assert flaky() == "ok"
    assert state["count"] == 3


def test_fallback_policy():
    policy = ErrorPolicy(strategy=ErrorHandlingStrategy.FALLBACK, fallback_value=123)

    @handle_errors(policy)
    def bad():
        raise ValueError("nope")

    assert bad() == 123


def test_circuit_breaker_opens_and_fallback():
    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.CIRCUIT_BREAK,
        max_retries=0,
        retry_delay=0.0,
        retry_backoff=1.0,
        retry_jitter=False,
        circuit_threshold=1,
        circuit_timeout=999,
        fallback_value="fallback",
    )

    @handle_errors(policy)
    def failer():
        raise RuntimeError("fail")

    with pytest.raises(RuntimeError):
        failer()

    # Circuit should now be open; fallback should be returned
    assert failer() == "fallback"

    stats = get_circuit_breaker_stats()
    assert any(
        info["state"] in {CircuitState.OPEN.value, CircuitState.HALF_OPEN.value}
        for info in stats.values()
    )

    reset_circuit_breakers()
    stats2 = get_circuit_breaker_stats()
    assert all(info["state"] == CircuitState.CLOSED.value for info in stats2.values())
