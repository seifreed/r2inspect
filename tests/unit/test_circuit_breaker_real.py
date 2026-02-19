"""Comprehensive tests for circuit breaker - 0% coverage target"""
import time
import threading
import pytest

from r2inspect.utils.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerError,
    CircuitState,
    R2CommandCircuitBreaker,
    r2_circuit_breaker,
)


def test_circuit_breaker_init():
    breaker = CircuitBreaker(
        failure_threshold=5,
        recovery_timeout=60.0,
        expected_exception=(ValueError,),
        name="test_breaker",
    )
    assert breaker.failure_threshold == 5
    assert breaker.recovery_timeout == 60.0
    assert breaker.name == "test_breaker"
    assert breaker.state == CircuitState.CLOSED


def test_circuit_breaker_basic_success():
    breaker = CircuitBreaker(failure_threshold=3)
    
    def successful_func():
        return "success"
    
    result = breaker.call(successful_func)
    assert result == "success"
    assert breaker.total_successes == 1
    assert breaker.state == CircuitState.CLOSED


def test_circuit_breaker_basic_failure():
    breaker = CircuitBreaker(failure_threshold=3)
    
    def failing_func():
        raise RuntimeError("fail")
    
    with pytest.raises(RuntimeError):
        breaker.call(failing_func)
    
    assert breaker.total_failures == 1
    assert breaker.failure_count == 1


def test_circuit_breaker_opens_after_threshold():
    breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=60.0)
    
    def failing_func():
        raise RuntimeError("fail")
    
    # Fail threshold times
    for _ in range(3):
        with pytest.raises(RuntimeError):
            breaker.call(failing_func)
    
    assert breaker.state == CircuitState.OPEN
    
    # Next call should raise CircuitBreakerError
    with pytest.raises(CircuitBreakerError):
        breaker.call(failing_func)


def test_circuit_breaker_half_open_recovery():
    breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=0.0)
    
    def failing_func():
        raise RuntimeError("fail")
    
    # Open the circuit
    for _ in range(2):
        with pytest.raises(RuntimeError):
            breaker.call(failing_func)
    
    assert breaker.state == CircuitState.OPEN
    
    # Should transition to half-open
    def successful_func():
        return "ok"
    
    result = breaker.call(successful_func)
    assert result == "ok"
    assert breaker.state == CircuitState.CLOSED


def test_circuit_breaker_half_open_failure():
    breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=0.0)
    
    def failing_func():
        raise RuntimeError("fail")
    
    # Open the circuit
    with pytest.raises(RuntimeError):
        breaker.call(failing_func)
    
    assert breaker.state == CircuitState.OPEN
    
    # Fail again in half-open
    with pytest.raises(RuntimeError):
        breaker.call(failing_func)
    
    assert breaker.state == CircuitState.OPEN


def test_circuit_breaker_recovery_timeout():
    breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=0.1)
    
    def failing_func():
        raise RuntimeError("fail")
    
    # Open the circuit
    with pytest.raises(RuntimeError):
        breaker.call(failing_func)
    
    # Immediate retry should fail
    with pytest.raises(CircuitBreakerError):
        breaker.call(failing_func)
    
    # Wait for recovery timeout
    time.sleep(0.15)
    
    # Should try again
    def success_func():
        return "recovered"
    
    result = breaker.call(success_func)
    assert result == "recovered"


def test_circuit_breaker_decorator():
    breaker = CircuitBreaker(failure_threshold=2)
    
    @breaker
    def decorated_func(x):
        if x < 0:
            raise ValueError("negative")
        return x * 2
    
    assert decorated_func(5) == 10
    
    with pytest.raises(ValueError):
        decorated_func(-1)


def test_circuit_breaker_expected_exception():
    breaker = CircuitBreaker(
        failure_threshold=2,
        expected_exception=(ValueError,),
    )
    
    def value_error_func():
        raise ValueError("expected")
    
    def runtime_error_func():
        raise RuntimeError("unexpected")
    
    # ValueError counts as failure
    with pytest.raises(ValueError):
        breaker.call(value_error_func)
    assert breaker.failure_count == 1
    
    # RuntimeError doesn't count (will still raise)
    with pytest.raises(RuntimeError):
        breaker.call(runtime_error_func)
    assert breaker.failure_count == 1  # Unchanged


def test_circuit_breaker_reset():
    breaker = CircuitBreaker(failure_threshold=2)
    
    def failing_func():
        raise RuntimeError("fail")
    
    # Open circuit
    for _ in range(2):
        with pytest.raises(RuntimeError):
            breaker.call(failing_func)
    
    assert breaker.state == CircuitState.OPEN
    
    # Manual reset
    breaker.reset()
    assert breaker.state == CircuitState.CLOSED
    assert breaker.failure_count == 0


def test_circuit_breaker_get_stats():
    breaker = CircuitBreaker(failure_threshold=3, name="stats_test")
    
    def success_func():
        return "ok"
    
    def fail_func():
        raise RuntimeError("fail")
    
    breaker.call(success_func)
    breaker.call(success_func)
    
    try:
        breaker.call(fail_func)
    except RuntimeError:
        pass
    
    stats = breaker.get_stats()
    assert stats["name"] == "stats_test"
    assert stats["state"] == CircuitState.CLOSED.value
    assert stats["total_calls"] == 3
    assert stats["total_successes"] == 2
    assert stats["total_failures"] == 1
    assert stats["success_rate"] > 0


def test_circuit_breaker_state_changes():
    breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=0.0)
    
    initial_changes = breaker.state_changes
    
    # Open circuit
    def fail_func():
        raise RuntimeError("fail")
    
    with pytest.raises(RuntimeError):
        breaker.call(fail_func)
    
    assert breaker.state_changes == initial_changes + 1
    
    # Recover
    def success_func():
        return "ok"
    
    breaker.call(success_func)
    assert breaker.state_changes == initial_changes + 3  # OPEN -> HALF_OPEN -> CLOSED


def test_circuit_breaker_concurrent_access():
    breaker = CircuitBreaker(failure_threshold=5)
    results = []
    
    def concurrent_func():
        try:
            return breaker.call(lambda: "success")
        except Exception as e:
            return str(e)
    
    threads = [threading.Thread(target=lambda: results.append(concurrent_func())) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    assert all(r == "success" for r in results)


def test_r2_command_circuit_breaker_init():
    cb = R2CommandCircuitBreaker()
    assert len(cb.breakers) == 0
    assert len(cb.command_stats) == 0


def test_r2_command_circuit_breaker_get_breaker():
    cb = R2CommandCircuitBreaker()
    
    breaker1 = cb.get_breaker("analysis")
    assert breaker1.name == "r2_command_analysis"
    assert breaker1.failure_threshold == 10
    
    breaker2 = cb.get_breaker("search")
    assert breaker2.name == "r2_command_search"
    assert breaker2.failure_threshold == 7
    
    breaker3 = cb.get_breaker("other")
    assert breaker3.failure_threshold == 5


def test_r2_command_circuit_breaker_same_instance():
    cb = R2CommandCircuitBreaker()
    
    breaker1 = cb.get_breaker("analysis")
    breaker2 = cb.get_breaker("analysis")
    
    assert breaker1 is breaker2


def test_r2_command_execute_success():
    cb = R2CommandCircuitBreaker()
    
    class MockR2:
        def cmdj(self, cmd):
            return {"result": "success"}
        
        def cmd(self, cmd):
            return "success"
    
    r2 = MockR2()
    
    # JSON command
    result = cb.execute_command(r2, "ij", "info")
    assert result == {"result": "success"}
    
    # Text command
    result = cb.execute_command(r2, "i", "info")
    assert result == "success"


def test_r2_command_execute_failure():
    cb = R2CommandCircuitBreaker()
    
    class MockR2:
        def cmdj(self, cmd):
            raise RuntimeError("command failed")
        
        def cmd(self, cmd):
            raise RuntimeError("command failed")
    
    r2 = MockR2()
    
    # Should return None for JSON on failure
    result = cb.execute_command(r2, "ij", "info")
    assert result is None
    
    # Should return empty string for text on failure
    result = cb.execute_command(r2, "i", "info")
    assert result == ""


def test_r2_command_execute_circuit_open():
    cb = R2CommandCircuitBreaker()
    
    class MockR2:
        def cmdj(self, cmd):
            raise RuntimeError("fail")
    
    r2 = MockR2()
    
    # Fail enough times to open circuit
    for _ in range(6):
        cb.execute_command(r2, "testj", "generic")
    
    # Circuit should be open, returns None
    result = cb.execute_command(r2, "testj", "generic")
    assert result is None


def test_r2_command_record_stats():
    cb = R2CommandCircuitBreaker()
    
    class MockR2:
        def cmdj(self, cmd):
            return {"ok": True}
    
    r2 = MockR2()
    
    cb.execute_command(r2, "ij", "info")
    
    stats = cb.command_stats["info"]
    assert stats["calls"] == 1
    assert stats["failures"] == 0


def test_r2_command_stats_failure():
    cb = R2CommandCircuitBreaker()
    
    class MockR2:
        def cmdj(self, cmd):
            raise RuntimeError("fail")
    
    r2 = MockR2()
    
    cb.execute_command(r2, "testj", "test")
    
    stats = cb.command_stats["test"]
    assert stats["calls"] == 1
    assert stats["failures"] == 1


def test_r2_command_avg_execution_time():
    cb = R2CommandCircuitBreaker()
    
    class MockR2:
        def cmdj(self, cmd):
            time.sleep(0.01)
            return {}
    
    r2 = MockR2()
    
    cb.execute_command(r2, "testj", "timing")
    cb.execute_command(r2, "testj", "timing")
    
    stats = cb.command_stats["timing"]
    assert stats["avg_time"] > 0


def test_r2_command_get_stats():
    cb = R2CommandCircuitBreaker()
    
    class MockR2:
        def cmdj(self, cmd):
            return {}
        
        def cmd(self, cmd):
            return ""
    
    r2 = MockR2()
    
    cb.execute_command(r2, "ij", "info")
    cb.execute_command(r2, "testj", "test")
    
    stats = cb.get_stats()
    assert "breaker_r2_command_info" in stats
    assert "command_info" in stats


def test_r2_command_reset_all():
    cb = R2CommandCircuitBreaker()
    
    class MockR2:
        def cmdj(self, cmd):
            raise RuntimeError("fail")
    
    r2 = MockR2()
    
    # Create some failures
    for _ in range(3):
        cb.execute_command(r2, "testj", "reset_test")
    
    cb.reset_all()
    
    # Breakers should be reset
    for breaker in cb.breakers.values():
        assert breaker.failure_count == 0
    
    # Stats should be cleared
    assert len(cb.command_stats) == 0


def test_r2_command_recent_failures():
    cb = R2CommandCircuitBreaker()
    
    class MockR2:
        def cmdj(self, cmd):
            raise RuntimeError("fail")
    
    r2 = MockR2()
    
    # Add some failures
    for _ in range(5):
        cb.execute_command(r2, "testj", "recent")
    
    stats = cb.get_stats()
    cmd_stats = stats["command_recent"]
    assert cmd_stats["recent_failures"] > 0


def test_global_r2_circuit_breaker():
    # Test that global instance exists
    assert r2_circuit_breaker is not None
    assert isinstance(r2_circuit_breaker, R2CommandCircuitBreaker)


def test_circuit_breaker_should_attempt_reset_false():
    breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=60.0)
    
    def fail_func():
        raise RuntimeError("fail")
    
    with pytest.raises(RuntimeError):
        breaker.call(fail_func)
    
    assert breaker._should_attempt_reset() is False


def test_circuit_breaker_should_attempt_reset_true():
    breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=0.0)
    
    def fail_func():
        raise RuntimeError("fail")
    
    with pytest.raises(RuntimeError):
        breaker.call(fail_func)
    
    time.sleep(0.01)
    assert breaker._should_attempt_reset() is True


def test_circuit_breaker_should_attempt_reset_no_failure():
    breaker = CircuitBreaker()
    assert breaker._should_attempt_reset() is False


def test_circuit_breaker_on_success_in_closed():
    breaker = CircuitBreaker()
    
    def success_func():
        return "ok"
    
    breaker.call(success_func)
    assert breaker.state == CircuitState.CLOSED
    assert breaker.failure_count == 0


def test_circuit_breaker_on_failure_threshold_not_reached():
    breaker = CircuitBreaker(failure_threshold=5)
    
    def fail_func():
        raise RuntimeError("fail")
    
    with pytest.raises(RuntimeError):
        breaker.call(fail_func)
    
    assert breaker.state == CircuitState.CLOSED
    assert breaker.failure_count == 1


def test_circuit_breaker_multiple_exception_types():
    breaker = CircuitBreaker(
        failure_threshold=2,
        expected_exception=(ValueError, TypeError, RuntimeError),
    )
    
    def value_error():
        raise ValueError("val")
    
    def type_error():
        raise TypeError("type")
    
    with pytest.raises(ValueError):
        breaker.call(value_error)
    
    with pytest.raises(TypeError):
        breaker.call(type_error)
    
    # Both should count
    assert breaker.state == CircuitState.OPEN


def test_r2_command_analysis_commands():
    cb = R2CommandCircuitBreaker()
    
    for cmd in ["analysis", "aaa", "aac", "af"]:
        breaker = cb.get_breaker(cmd)
        assert breaker.failure_threshold == 10
        assert breaker.recovery_timeout == 120.0


def test_r2_command_search_commands():
    cb = R2CommandCircuitBreaker()
    
    for cmd in ["search", "/x", "/c"]:
        breaker = cb.get_breaker(cmd)
        assert breaker.failure_threshold == 7
        assert breaker.recovery_timeout == 60.0


def test_r2_command_default_commands():
    cb = R2CommandCircuitBreaker()
    
    breaker = cb.get_breaker("unknown_command")
    assert breaker.failure_threshold == 5
    assert breaker.recovery_timeout == 30.0


def test_r2_command_execution_time_exponential_average():
    cb = R2CommandCircuitBreaker()
    
    class MockR2:
        def __init__(self):
            self.call_count = 0
        
        def cmdj(self, cmd):
            self.call_count += 1
            if self.call_count == 1:
                time.sleep(0.02)
            else:
                time.sleep(0.01)
            return {}
    
    r2 = MockR2()
    
    cb.execute_command(r2, "testj", "ema")
    first_avg = cb.command_stats["ema"]["avg_time"]
    
    cb.execute_command(r2, "testj", "ema")
    second_avg = cb.command_stats["ema"]["avg_time"]
    
    # Average should have changed
    assert second_avg != first_avg


def test_r2_command_success_rate_calculation():
    cb = R2CommandCircuitBreaker()
    
    class MockR2:
        def __init__(self):
            self.should_fail = False
        
        def cmdj(self, cmd):
            if self.should_fail:
                raise RuntimeError("fail")
            return {}
    
    r2 = MockR2()
    
    # 3 successes
    cb.execute_command(r2, "testj", "rate")
    cb.execute_command(r2, "testj", "rate")
    cb.execute_command(r2, "testj", "rate")
    
    # 1 failure
    r2.should_fail = True
    cb.execute_command(r2, "testj", "rate")
    
    stats = cb.get_stats()
    cmd_stats = stats["command_rate"]
    assert cmd_stats["success_rate"] == 75.0  # 3/4


def test_circuit_breaker_last_times():
    breaker = CircuitBreaker(failure_threshold=1)
    
    def success_func():
        return "ok"
    
    def fail_func():
        raise RuntimeError("fail")
    
    # Success
    before_success = time.time()
    breaker.call(success_func)
    after_success = time.time()
    
    assert before_success <= breaker.last_success_time <= after_success
    
    # Failure
    before_failure = time.time()
    with pytest.raises(RuntimeError):
        breaker.call(fail_func)
    after_failure = time.time()
    
    assert before_failure <= breaker.last_failure_time <= after_failure


def test_circuit_breaker_decorator_with_args():
    breaker = CircuitBreaker(failure_threshold=2)
    
    @breaker
    def add(a, b):
        return a + b
    
    assert add(2, 3) == 5
    assert add(a=5, b=7) == 12


def test_r2_command_text_command():
    cb = R2CommandCircuitBreaker()
    
    class MockR2:
        def cmd(self, cmd):
            return "text result"
    
    r2 = MockR2()
    
    result = cb.execute_command(r2, "i", "info")
    assert result == "text result"


def test_r2_command_circuit_breaker_error():
    cb = R2CommandCircuitBreaker()
    
    class MockR2:
        def cmdj(self, cmd):
            raise RuntimeError("fail")
    
    r2 = MockR2()
    
    # Open circuit
    for _ in range(6):
        cb.execute_command(r2, "testj", "open")
    
    # Next call returns None due to open circuit
    result = cb.execute_command(r2, "testj", "open")
    assert result is None
    
    stats = cb.command_stats["open"]
    # Calls that hit open circuit still count
    assert stats["calls"] >= 6


def test_command_stats_recent_failures_time_window():
    cb = R2CommandCircuitBreaker()
    
    # Manually add old failure
    cb.command_stats["old"]["recent_failures"].append(time.time() - 400)
    
    stats = cb.get_stats()
    cmd_stats = stats["command_old"]
    # Old failure should not count in 5-minute window
    assert cmd_stats["recent_failures"] == 0
