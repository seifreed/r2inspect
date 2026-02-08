from __future__ import annotations

import time

import pytest

from r2inspect.utils.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerError,
    CircuitState,
    R2CommandCircuitBreaker,
)


def test_circuit_breaker_opens_and_recovers() -> None:
    breaker = CircuitBreaker(
        failure_threshold=2, recovery_timeout=0.05, expected_exception=(ValueError,)
    )

    def fail() -> None:
        raise ValueError("boom")

    with pytest.raises(ValueError):
        breaker.call(fail)
    with pytest.raises(ValueError):
        breaker.call(fail)

    with pytest.raises(CircuitBreakerError):
        breaker.call(lambda: "never")

    time.sleep(0.06)
    assert breaker.call(lambda: "ok") == "ok"
    assert breaker.state == CircuitState.CLOSED
    stats = breaker.get_stats()
    assert stats["total_calls"] >= 3
    assert stats["total_failures"] >= 2


def test_r2_command_circuit_breaker_stats() -> None:
    class MiniR2:
        def __init__(self) -> None:
            self.calls = 0

        def cmd(self, _command: str) -> str:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("fail")
            return "ok"

        def cmdj(self, _command: str) -> dict:
            return {"ok": True}

    breaker = R2CommandCircuitBreaker()
    r2 = MiniR2()
    assert breaker.execute_command(r2, "i", "info") == ""
    assert breaker.execute_command(r2, "i", "info") == "ok"
    assert breaker.execute_command(r2, "ij", "info") == {"ok": True}
    stats = breaker.get_stats()
    assert "breaker_info" in stats
    assert "command_info" in stats
    breaker.reset_all()
    after = breaker.get_stats()
    assert "breaker_info" in after
    assert "command_info" not in after
