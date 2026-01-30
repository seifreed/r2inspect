import pytest

from r2inspect.utils.circuit_breaker import CircuitBreaker, CircuitBreakerError, CircuitState


def test_circuit_opens_after_failures_and_recovers():
    breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=0.0)
    call_count = {"count": 0}

    def flake():
        call_count["count"] += 1
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        breaker.call(flake)
    with pytest.raises(RuntimeError):
        breaker.call(flake)

    assert breaker.state == CircuitState.OPEN

    def ok():
        return "ok"

    # Recovery timeout is 0, so next call should attempt half-open and succeed
    assert breaker.call(ok) == "ok"
    assert breaker.state == CircuitState.CLOSED
    assert call_count["count"] == 2


def test_circuit_open_raises_fast():
    breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=60.0)

    def fail():
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        breaker.call(fail)

    with pytest.raises(CircuitBreakerError):
        breaker.call(fail)
