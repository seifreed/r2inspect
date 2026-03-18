import pytest

"""Comprehensive tests for circuit_breaker.py - 100% coverage target."""

from r2inspect.infrastructure.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerError,
    CircuitState,
    R2CommandCircuitBreaker,
    create_r2_circuit_breaker,
)


def test_circuit_breaker_init():
    """Test CircuitBreaker initialization."""
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout=10.0, name="test")
    assert cb is not None
    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 0
    assert cb.name == "test"


def test_circuit_breaker_successful_call():
    """Test CircuitBreaker with successful calls."""
    cb = CircuitBreaker(failure_threshold=3)
    result = cb.call(lambda x: x * 2, 5)
    assert result == 10
    assert cb.total_calls == 1
    assert cb.total_successes == 1


def test_circuit_breaker_failure_opens_circuit():
    """Test that repeated failures open the circuit."""
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout=9999.0)

    def failing():
        raise ValueError("fail")

    for _ in range(2):
        try:
            cb.call(failing)
        except ValueError:
            pass

    assert cb.state == CircuitState.OPEN
    assert cb.failure_count == 2


def test_circuit_breaker_open_raises_error():
    """Test that calling on open circuit raises CircuitBreakerError."""
    cb = CircuitBreaker(failure_threshold=1, recovery_timeout=9999.0)

    try:
        cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
    except ValueError:
        pass

    try:
        cb.call(lambda: "ok")
        pytest.fail("Should have raised")
    except CircuitBreakerError:
        pass


def test_circuit_breaker_get_stats():
    """Test get_stats returns proper structure."""
    cb = CircuitBreaker(name="stats_test")
    cb.call(lambda: 42)
    stats = cb.get_stats()
    assert stats["name"] == "stats_test"
    assert stats["state"] == "closed"
    assert stats["total_calls"] == 1
    assert stats["total_successes"] == 1
    assert "success_rate" in stats


def test_circuit_breaker_reset():
    """Test reset clears the circuit breaker state."""
    cb = CircuitBreaker(failure_threshold=1, recovery_timeout=9999.0)
    try:
        cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
    except ValueError:
        pass
    assert cb.state == CircuitState.OPEN
    cb.reset()
    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 0


def test_circuit_breaker_as_decorator():
    """Test CircuitBreaker used as a decorator."""
    cb = CircuitBreaker()

    @cb
    def my_func(x):
        return x + 1

    assert my_func(5) == 6


def test_r2_command_circuit_breaker_init():
    """Test R2CommandCircuitBreaker initialization."""
    rcb = R2CommandCircuitBreaker()
    assert rcb is not None
    assert isinstance(rcb.breakers, dict)


def test_r2_command_circuit_breaker_get_breaker():
    """Test get_breaker creates breakers with appropriate thresholds."""
    rcb = R2CommandCircuitBreaker()
    analysis_breaker = rcb.get_breaker("analysis")
    assert analysis_breaker.failure_threshold == 10
    search_breaker = rcb.get_breaker("search")
    assert search_breaker.failure_threshold == 7
    generic_breaker = rcb.get_breaker("generic")
    assert generic_breaker.failure_threshold == 5


def test_r2_command_circuit_breaker_get_stats():
    """Test get_stats on R2CommandCircuitBreaker."""
    rcb = R2CommandCircuitBreaker()
    rcb.get_breaker("test")
    stats = rcb.get_stats()
    assert isinstance(stats, dict)


def test_r2_command_circuit_breaker_reset_all():
    """Test reset_all clears all breakers."""
    rcb = R2CommandCircuitBreaker()
    rcb.get_breaker("test")
    rcb.reset_all()
    assert rcb.command_stats == {}


def test_create_r2_circuit_breaker():
    """Test factory function."""
    rcb = create_r2_circuit_breaker()
    assert isinstance(rcb, R2CommandCircuitBreaker)
