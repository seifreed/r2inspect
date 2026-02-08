from __future__ import annotations

import time

import pytest

from r2inspect.utils.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerError,
    CircuitState,
    R2CommandCircuitBreaker,
)


def test_circuit_breaker_transitions():
    breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=0.01, name="test")

    def fail():
        raise RuntimeError("boom")

    def ok():
        return "ok"

    # First failure
    with pytest.raises(RuntimeError):
        breaker.call(fail)
    assert breaker.state == CircuitState.CLOSED

    # Second failure opens circuit
    with pytest.raises(RuntimeError):
        breaker.call(fail)
    assert breaker.state == CircuitState.OPEN

    # Open circuit blocks
    with pytest.raises(CircuitBreakerError):
        breaker.call(ok)

    # After timeout, half-open, then success closes
    time.sleep(0.02)
    assert breaker.call(ok) == "ok"
    assert breaker.state == CircuitState.CLOSED


def test_r2_command_circuit_breaker_execute():
    class FakeR2:
        def __init__(self):
            self.calls = 0

        def cmd(self, _cmd):
            self.calls += 1
            if self.calls < 2:
                raise RuntimeError("fail")
            return "ok"

        def cmdj(self, _cmd):
            self.calls += 1
            if self.calls < 2:
                raise RuntimeError("fail")
            return {"ok": True}

    breaker = R2CommandCircuitBreaker()
    r2 = FakeR2()

    # Text command failure returns empty string
    result1 = breaker.execute_command(r2, "pd 1", command_type="generic")
    assert result1 == ""

    # Second call succeeds
    result2 = breaker.execute_command(r2, "pd 1", command_type="generic")
    assert result2 == "ok"

    # JSON command failure returns None
    r2 = FakeR2()
    result3 = breaker.execute_command(r2, "ij", command_type="analysis")
    assert result3 is None

    # Stats present
    stats = breaker.get_stats()
    assert "command_generic" in stats
    assert "breaker_analysis" in stats

    breaker.reset_all()
