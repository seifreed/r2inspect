from __future__ import annotations

import time

import pytest

from r2inspect.infrastructure.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerError,
    CircuitState,
    R2CommandCircuitBreaker,
)
from r2inspect.infrastructure.retry_manager import (
    RetryConfig,
    RetryManager,
    RetryStrategy,
    configure_retry_for_command,
    get_retry_stats,
    reset_retry_stats,
    retry_on_failure,
    retry_r2_operation,
)
from tests.helpers import FakeR2Adapter, FakeSession, run_cli


def test_fake_r2_adapter_consumes_ordered_responses_without_monkeypatch() -> None:
    adapter = FakeR2Adapter(
        cmd_responses={"i": ["first", "second"]},
        cmdj_responses={"ij": [{"bin": {"arch": "x86"}}, {"bin": {"arch": "arm"}}]},
    )

    adapter.open()
    assert adapter.is_open is True
    assert adapter.cmd("i") == "first"
    assert adapter.cmd("i") == "second"
    assert adapter.cmdj("ij") == {"bin": {"arch": "x86"}}
    assert adapter.get_file_info() == [{"bin": {"arch": "arm"}}]
    adapter.close()
    assert adapter.is_open is False


def test_fake_session_wraps_adapter_lifecycle() -> None:
    adapter = FakeR2Adapter(cmdj_responses={"ij": {"bin": {"arch": "x86"}}})
    session = FakeSession(adapter)

    opened_adapter = session.open()
    assert opened_adapter is adapter
    assert session.opened is True
    assert adapter.is_open is True
    session.close()
    assert session.opened is False
    assert adapter.is_open is False


def test_cli_runner_executes_real_help_without_patching() -> None:
    result = run_cli(["--help"])
    assert result.returncode == 0
    assert "Usage: python -m r2inspect" in result.stdout


def test_circuit_breaker_decorator_and_half_open_guard() -> None:
    breaker = CircuitBreaker(
        failure_threshold=1,
        recovery_timeout=0.0,
        expected_exception=(ValueError,),
        name="phase0",
    )

    @breaker
    def explode() -> None:
        raise ValueError("boom")

    with pytest.raises(ValueError):
        explode()

    breaker.last_failure_time = time.time() - 1.0
    assert breaker._should_attempt_reset() is True
    breaker.state = CircuitState.HALF_OPEN
    breaker.half_open_probe_in_flight = True

    with pytest.raises(CircuitBreakerError, match="HALF_OPEN"):
        breaker.call(lambda: "probe")


def test_circuit_breaker_open_without_reset_and_half_open_success() -> None:
    breaker = CircuitBreaker(
        failure_threshold=1,
        recovery_timeout=60.0,
        expected_exception=(RuntimeError,),
        name="phase1",
    )

    with pytest.raises(RuntimeError):
        breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("boom")))

    with pytest.raises(CircuitBreakerError, match="OPEN"):
        breaker.call(lambda: "blocked")

    breaker.state = CircuitState.HALF_OPEN
    breaker.half_open_probe_in_flight = False
    breaker.failure_count = 3
    assert breaker.call(lambda: "recovered") == "recovered"
    assert breaker.state == CircuitState.CLOSED
    assert breaker.failure_count == 0


def test_circuit_breaker_open_state_can_transition_to_half_open_probe() -> None:
    breaker = CircuitBreaker(
        failure_threshold=1,
        recovery_timeout=0.0,
        expected_exception=(RuntimeError,),
        name="phase1-reset",
    )
    breaker.state = CircuitState.OPEN
    breaker.last_failure_time = time.time() - 1.0

    assert breaker.call(lambda: "ok") == "ok"
    assert breaker.state == CircuitState.CLOSED
    assert breaker.state_changes >= 2


def test_r2_command_circuit_breaker_variants_and_stats() -> None:
    adapter = FakeR2Adapter(
        cmd_responses={"i": RuntimeError("fail"), "s": "ok"},
        cmdj_responses={"ij": [{"ok": True}]},
    )
    breaker = R2CommandCircuitBreaker()

    analysis_breaker = breaker.get_breaker("aaa")
    search_breaker = breaker.get_breaker("/x")
    generic_breaker = breaker.get_breaker("misc")
    assert analysis_breaker.failure_threshold == 10
    assert search_breaker.failure_threshold == 7
    assert generic_breaker.failure_threshold == 5

    assert breaker.execute_command(adapter, "i", "misc") == ""
    assert breaker.execute_command(adapter, "ij", "misc") == {"ok": True}
    generic_breaker.state = CircuitState.OPEN
    generic_breaker.last_failure_time = time.time()
    assert breaker.execute_command(adapter, "ij", "misc") is None
    stats = breaker.get_stats()
    assert stats["command_misc"]["total_calls"] == 3
    assert stats["command_misc"]["total_failures"] == 2
    breaker.reset_all()
    assert set(breaker.get_stats()) == {"breaker_aaa", "breaker_/x", "breaker_misc"}


def test_retry_manager_handles_zero_attempts_retry_success_and_reset() -> None:
    manager = RetryManager()
    assert manager.retry_operation(lambda: "unused", config=RetryConfig(max_attempts=0)) is None

    attempts = {"count": 0}

    def flaky() -> str:
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise TimeoutError("temporary timeout")
        return "ok"

    config = RetryConfig(
        max_attempts=2,
        base_delay=0.0,
        jitter=False,
        strategy=RetryStrategy.FIXED_DELAY,
    )
    assert manager.retry_operation(lambda **_kwargs: flaky(), config=config, command="ij") == "ok"
    stats = manager.get_stats()
    assert stats["total_retries"] == 1
    assert stats["successful_retries"] == 1
    assert stats["commands_retried"]["ij"] == 1
    manager.reset_stats()
    assert manager.get_stats()["total_retries"] == 0


def test_retry_manager_failed_after_retries_and_timeout_helpers() -> None:
    manager = RetryManager()
    config = RetryConfig(max_attempts=2, base_delay=0.0, jitter=False, timeout=0.0)

    with pytest.raises(TimeoutError):
        manager._check_timeout(time.time() - 1.0, config)

    with pytest.raises(TimeoutError):
        manager.retry_operation(
            lambda **_kwargs: (_ for _ in ()).throw(TimeoutError("connection reset")),
            config=RetryConfig(max_attempts=1, base_delay=0.0, jitter=False),
            command="aaa",
        )

    stats = manager.get_stats()
    assert stats["failed_after_retries"] == 1
    assert stats["error_types_retried"]["TimeoutError"] == 1


def test_retry_manager_non_retryable_path_in_base_manager() -> None:
    manager = RetryManager()

    with pytest.raises(ValueError):
        manager.retry_operation(
            lambda: (_ for _ in ()).throw(ValueError("fatal")),
            config=RetryConfig(max_attempts=2, base_delay=0.0, jitter=False),
        )


def test_retry_manager_command_detection_non_retryable_and_break_path() -> None:
    class BreakOnceRetryManager(RetryManager):
        def _handle_retry_exception(
            self, exc: Exception, attempt: int, config: RetryConfig, kwargs: dict[str, object]
        ) -> bool:
            self._update_retry_stats(exc, attempt, kwargs)
            return False

    manager = BreakOnceRetryManager()
    assert manager.is_retryable_command("aflj @@ sym.*") is True
    assert manager.is_retryable_command("pd 10") is False

    with pytest.raises(ValueError):
        manager.retry_operation(
            lambda: (_ for _ in ()).throw(ValueError("fatal")), config=RetryConfig(max_attempts=2)
        )

    with pytest.raises(ConnectionError):
        manager.retry_operation(
            lambda: (_ for _ in ()).throw(ConnectionError("temporary unavailable")),
            config=RetryConfig(max_attempts=2, base_delay=0.0, jitter=False),
        )

    stats = manager.get_stats()
    assert stats["total_retries"] == 2
    assert stats["commands_retried"]["unknown"] == 2


def test_retry_module_level_helpers_without_patching() -> None:
    reset_retry_stats()
    configure_retry_for_command(
        "phase0",
        RetryConfig(max_attempts=1, base_delay=0.0, jitter=False),
    )

    @retry_on_failure(command_type="generic", auto_retry=False)
    def passthrough(*_args: object, **kwargs: object) -> str:
        return str(kwargs["command"])

    assert passthrough(object(), "ij") == "ij"

    calls = {"count": 0}

    def op(command: str) -> str:
        calls["count"] += 1
        return command

    assert retry_r2_operation(op, "aflj", command_type="phase0") == "aflj"
    assert calls["count"] == 1
    assert get_retry_stats()["total_retries"] == 0
