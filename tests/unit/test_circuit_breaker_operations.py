"""Comprehensive tests for circuit_breaker.py - achieving 100% coverage."""

import pytest
import time
import threading
from r2inspect.utils.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerError,
    CircuitState,
    R2CommandCircuitBreaker,
)


def test_circuit_state_enum():
    assert CircuitState.CLOSED.value == "closed"
    assert CircuitState.OPEN.value == "open"
    assert CircuitState.HALF_OPEN.value == "half_open"


def test_circuit_breaker_error():
    error = CircuitBreakerError("test error")
    assert str(error) == "test error"


def test_circuit_breaker_initialization():
    cb = CircuitBreaker(
        failure_threshold=3,
        recovery_timeout=10.0,
        expected_exception=(ValueError, TypeError),
        name="test_breaker"
    )

    assert cb.failure_threshold == 3
    assert cb.recovery_timeout == 10.0
    assert cb.expected_exception == (ValueError, TypeError)
    assert cb.name == "test_breaker"
    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 0
    assert cb.total_calls == 0
    assert cb.total_failures == 0
    assert cb.total_successes == 0


def test_circuit_breaker_default_initialization():
    cb = CircuitBreaker()

    assert cb.failure_threshold == 5
    assert cb.recovery_timeout == 60.0
    assert cb.expected_exception == (Exception,)
    assert cb.name == "default"


def test_circuit_breaker_successful_call():
    cb = CircuitBreaker(failure_threshold=5)

    def successful_func():
        return "success"

    result = cb.call(successful_func)

    assert result == "success"
    assert cb.total_calls == 1
    assert cb.total_successes == 1
    assert cb.total_failures == 0
    assert cb.state == CircuitState.CLOSED


def test_circuit_breaker_failed_call():
    cb = CircuitBreaker(failure_threshold=5)

    def failing_func():
        raise ValueError("test error")

    with pytest.raises(ValueError):
        cb.call(failing_func)

    assert cb.total_calls == 1
    assert cb.total_successes == 0
    assert cb.total_failures == 1
    assert cb.failure_count == 1
    assert cb.state == CircuitState.CLOSED


def test_circuit_breaker_opens_after_threshold():
    cb = CircuitBreaker(failure_threshold=3)

    def failing_func():
        raise ValueError("test error")

    for _ in range(3):
        with pytest.raises(ValueError):
            cb.call(failing_func)

    assert cb.state == CircuitState.OPEN
    assert cb.failure_count == 3

    with pytest.raises(CircuitBreakerError):
        cb.call(failing_func)


def test_circuit_breaker_half_open_recovery():
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)

    def failing_func():
        raise ValueError("test error")

    for _ in range(2):
        with pytest.raises(ValueError):
            cb.call(failing_func)

    assert cb.state == CircuitState.OPEN

    time.sleep(0.15)

    def successful_func():
        return "success"

    result = cb.call(successful_func)

    assert result == "success"
    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 0


def test_circuit_breaker_half_open_failure():
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)

    def failing_func():
        raise ValueError("test error")

    for _ in range(2):
        with pytest.raises(ValueError):
            cb.call(failing_func)

    assert cb.state == CircuitState.OPEN

    time.sleep(0.15)

    with pytest.raises(ValueError):
        cb.call(failing_func)

    assert cb.state == CircuitState.OPEN


def test_circuit_breaker_reset():
    cb = CircuitBreaker(failure_threshold=2)

    def failing_func():
        raise ValueError("test error")

    for _ in range(2):
        with pytest.raises(ValueError):
            cb.call(failing_func)

    assert cb.state == CircuitState.OPEN

    cb.reset()

    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 0
    assert cb.last_failure_time is None


def test_circuit_breaker_decorator():
    cb = CircuitBreaker(failure_threshold=3)

    @cb
    def test_function():
        return "decorated"

    result = test_function()
    assert result == "decorated"
    assert cb.total_calls == 1


def test_circuit_breaker_decorator_with_args():
    cb = CircuitBreaker(failure_threshold=3)

    @cb
    def test_function(x, y):
        return x + y

    result = test_function(5, 10)
    assert result == 15
    assert cb.total_calls == 1


def test_circuit_breaker_get_stats():
    cb = CircuitBreaker(failure_threshold=5, name="test")

    def successful_func():
        return "success"

    def failing_func():
        raise ValueError("error")

    cb.call(successful_func)
    cb.call(successful_func)

    try:
        cb.call(failing_func)
    except ValueError:
        pass

    stats = cb.get_stats()

    assert stats["name"] == "test"
    assert stats["state"] == "closed"
    assert stats["total_calls"] == 3
    assert stats["total_successes"] == 2
    assert stats["total_failures"] == 1
    assert stats["success_rate"] == pytest.approx(66.666, rel=0.1)
    assert stats["failure_count"] == 1
    assert stats["failure_threshold"] == 5
    assert stats["last_failure_time"] is not None
    assert stats["last_success_time"] is not None


def test_circuit_breaker_thread_safety():
    cb = CircuitBreaker(failure_threshold=100)
    results = []
    errors = []

    def thread_func(thread_id):
        def work():
            if thread_id % 5 == 0:
                raise ValueError("error")
            return f"success-{thread_id}"

        try:
            result = cb.call(work)
            results.append(result)
        except ValueError:
            errors.append(thread_id)

    threads = []
    for i in range(50):
        thread = threading.Thread(target=thread_func, args=(i,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    assert len(results) + len(errors) == 50
    assert cb.total_calls == 50


def test_circuit_breaker_unexpected_exception():
    cb = CircuitBreaker(failure_threshold=3, expected_exception=(ValueError,))

    def failing_func():
        raise TypeError("unexpected")

    with pytest.raises(TypeError):
        cb.call(failing_func)

    assert cb.total_failures == 0
    assert cb.failure_count == 0


def test_circuit_breaker_state_changes():
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.05)

    def failing_func():
        raise ValueError("error")

    def successful_func():
        return "success"

    initial_state_changes = cb.state_changes

    for _ in range(2):
        with pytest.raises(ValueError):
            cb.call(failing_func)

    assert cb.state_changes == initial_state_changes + 1

    time.sleep(0.1)

    cb.call(successful_func)

    assert cb.state_changes == initial_state_changes + 3


def test_r2_command_circuit_breaker_initialization():
    r2cb = R2CommandCircuitBreaker()

    assert isinstance(r2cb.breakers, dict)
    assert isinstance(r2cb.command_stats, dict)


def test_r2_command_circuit_breaker_get_breaker_analysis():
    r2cb = R2CommandCircuitBreaker()

    breaker = r2cb.get_breaker("aaa")

    assert breaker.name == "r2_command_aaa"
    assert breaker.failure_threshold == 10
    assert breaker.recovery_timeout == 120.0


def test_r2_command_circuit_breaker_get_breaker_search():
    r2cb = R2CommandCircuitBreaker()

    breaker = r2cb.get_breaker("/x")

    assert breaker.name == "r2_command_/x"
    assert breaker.failure_threshold == 7
    assert breaker.recovery_timeout == 60.0


def test_r2_command_circuit_breaker_get_breaker_generic():
    r2cb = R2CommandCircuitBreaker()

    breaker = r2cb.get_breaker("generic")

    assert breaker.name == "r2_command_generic"
    assert breaker.failure_threshold == 5
    assert breaker.recovery_timeout == 30.0


def test_r2_command_circuit_breaker_get_breaker_cached():
    r2cb = R2CommandCircuitBreaker()

    breaker1 = r2cb.get_breaker("test")
    breaker2 = r2cb.get_breaker("test")

    assert breaker1 is breaker2


def test_r2_command_circuit_breaker_execute_command_json():
    r2cb = R2CommandCircuitBreaker()
    r2_instance = type('R2', (), {})()
    r2_instance.cmdj = lambda cmd: {"result": "success"}

    result = r2cb.execute_command(r2_instance, "ij", "generic")

    assert result == {"result": "success"}
    assert r2cb.command_stats["generic"]["calls"] == 1
    assert r2cb.command_stats["generic"]["failures"] == 0


def test_r2_command_circuit_breaker_execute_command_text():
    r2cb = R2CommandCircuitBreaker()
    r2_instance = type('R2', (), {})()
    r2_instance.cmd = lambda cmd: "success"

    result = r2cb.execute_command(r2_instance, "i", "generic")

    assert result == "success"
    assert r2cb.command_stats["generic"]["calls"] == 1


def test_r2_command_circuit_breaker_execute_command_failure():
    r2cb = R2CommandCircuitBreaker()
    r2_instance = type('R2', (), {})()
    r2_instance.cmdj = lambda cmd: (_ for _ in ()).throw(ValueError("error"))

    result = r2cb.execute_command(r2_instance, "ij", "generic")

    assert result is None
    assert r2cb.command_stats["generic"]["failures"] == 1


def test_r2_command_circuit_breaker_execute_command_circuit_open():
    r2cb = R2CommandCircuitBreaker()
    r2_instance = type('R2', (), {})()
    r2_instance.cmdj = lambda cmd: (_ for _ in ()).throw(ValueError("error"))

    for _ in range(5):
        r2cb.execute_command(r2_instance, "ij", "test_cmd")

    result = r2cb.execute_command(r2_instance, "ij", "test_cmd")

    assert result is None


def test_r2_command_circuit_breaker_get_stats():
    r2cb = R2CommandCircuitBreaker()
    r2_instance = type('R2', (), {})()
    r2_instance.cmdj = lambda cmd: {"result": "success"}

    r2cb.execute_command(r2_instance, "ij", "test")

    stats = r2cb.get_stats()

    assert "breaker_test" in stats
    assert "command_test" in stats
    assert stats["command_test"]["total_calls"] == 1


def test_r2_command_circuit_breaker_reset_all():
    r2cb = R2CommandCircuitBreaker()
    r2_instance = type('R2', (), {})()
    r2_instance.cmdj = lambda cmd: {"result": "success"}

    r2cb.execute_command(r2_instance, "ij", "test")

    assert len(r2cb.command_stats) > 0

    r2cb.reset_all()

    assert len(r2cb.command_stats) == 0


def test_r2_command_circuit_breaker_avg_execution_time():
    r2cb = R2CommandCircuitBreaker()
    r2_instance = type('R2', (), {})()

    def slow_cmd(cmd):
        time.sleep(0.01)
        return {"result": "success"}

    r2_instance.cmdj = slow_cmd

    r2cb.execute_command(r2_instance, "ij", "test")
    r2cb.execute_command(r2_instance, "ij", "test")

    stats = r2cb.get_stats()

    assert stats["command_test"]["avg_execution_time"] > 0


def test_r2_command_circuit_breaker_recent_failures():
    r2cb = R2CommandCircuitBreaker()
    r2_instance = type('R2', (), {})()
    r2_instance.cmdj = lambda cmd: (_ for _ in ()).throw(ValueError("error"))

    for _ in range(3):
        r2cb.execute_command(r2_instance, "ij", "test")

    stats = r2cb.get_stats()

    assert stats["command_test"]["recent_failures"] == 3


def test_circuit_breaker_should_attempt_reset_no_failure():
    cb = CircuitBreaker()
    assert cb._should_attempt_reset() is False


def test_circuit_breaker_should_attempt_reset_within_timeout():
    cb = CircuitBreaker(recovery_timeout=10.0)
    cb.last_failure_time = time.time()

    assert cb._should_attempt_reset() is False


def test_circuit_breaker_should_attempt_reset_after_timeout():
    cb = CircuitBreaker(recovery_timeout=0.05)
    cb.last_failure_time = time.time() - 0.1

    assert cb._should_attempt_reset() is True


def test_circuit_breaker_set_state():
    cb = CircuitBreaker()
    initial_changes = cb.state_changes

    cb._set_state(CircuitState.OPEN)
    assert cb.state == CircuitState.OPEN
    assert cb.state_changes == initial_changes + 1

    cb._set_state(CircuitState.OPEN)
    assert cb.state_changes == initial_changes + 1


def test_circuit_breaker_on_success_closed():
    cb = CircuitBreaker()
    initial_successes = cb.total_successes

    cb._on_success()

    assert cb.total_successes == initial_successes + 1
    assert cb.last_success_time > 0


def test_circuit_breaker_on_success_half_open():
    cb = CircuitBreaker()
    cb.state = CircuitState.HALF_OPEN
    cb.failure_count = 5

    cb._on_success()

    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 0


def test_circuit_breaker_on_failure():
    cb = CircuitBreaker(failure_threshold=3)
    initial_failures = cb.total_failures

    cb._on_failure()

    assert cb.total_failures == initial_failures + 1
    assert cb.failure_count == 1
    assert cb.last_failure_time is not None


def test_circuit_breaker_on_failure_reaches_threshold():
    cb = CircuitBreaker(failure_threshold=3)

    cb._on_failure()
    cb._on_failure()
    assert cb.state == CircuitState.CLOSED

    cb._on_failure()
    assert cb.state == CircuitState.OPEN


def test_r2_command_circuit_breaker_record_command_stats():
    r2cb = R2CommandCircuitBreaker()

    r2cb._record_command_stats("test", True, 0.5)

    assert r2cb.command_stats["test"]["calls"] == 1
    assert r2cb.command_stats["test"]["failures"] == 0
    assert r2cb.command_stats["test"]["avg_time"] == 0.5


def test_r2_command_circuit_breaker_record_command_stats_failure():
    r2cb = R2CommandCircuitBreaker()

    r2cb._record_command_stats("test", False, 0.5)

    assert r2cb.command_stats["test"]["calls"] == 1
    assert r2cb.command_stats["test"]["failures"] == 1
    assert len(r2cb.command_stats["test"]["recent_failures"]) == 1


def test_r2_command_circuit_breaker_exponential_moving_average():
    r2cb = R2CommandCircuitBreaker()

    r2cb._record_command_stats("test", True, 1.0)
    r2cb._record_command_stats("test", True, 2.0)

    assert 1.0 < r2cb.command_stats["test"]["avg_time"] < 2.0


def test_r2_command_circuit_breaker_thread_safety():
    r2cb = R2CommandCircuitBreaker()
    r2_instance = type('R2', (), {})()
    r2_instance.cmdj = lambda cmd: {"result": "success"}

    def execute_commands():
        for _ in range(10):
            r2cb.execute_command(r2_instance, "ij", "thread_test")

    threads = []
    for _ in range(5):
        thread = threading.Thread(target=execute_commands)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    assert r2cb.command_stats["thread_test"]["calls"] == 50


def test_circuit_breaker_half_open_state_allows_one_call():
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.05)

    def failing_func():
        raise ValueError("error")

    for _ in range(2):
        with pytest.raises(ValueError):
            cb.call(failing_func)

    assert cb.state == CircuitState.OPEN

    time.sleep(0.1)

    call_attempted = False
    try:
        cb.call(failing_func)
    except ValueError:
        call_attempted = True

    assert call_attempted is True


def test_r2_command_circuit_breaker_success_rate():
    r2cb = R2CommandCircuitBreaker()
    r2_instance = type('R2', (), {})()

    call_count = [0]

    def mixed_cmd(cmd):
        call_count[0] += 1
        if call_count[0] % 2 == 0:
            raise ValueError("error")
        return {"result": "success"}

    r2_instance.cmdj = mixed_cmd

    for _ in range(10):
        r2cb.execute_command(r2_instance, "ij", "mixed")

    stats = r2cb.get_stats()

    assert stats["command_mixed"]["success_rate"] == 50.0


def test_r2_command_circuit_breaker_text_command_failure():
    r2cb = R2CommandCircuitBreaker()
    r2_instance = type('R2', (), {})()
    r2_instance.cmd = lambda cmd: (_ for _ in ()).throw(ValueError("error"))

    result = r2cb.execute_command(r2_instance, "i", "generic")

    assert result == ""
