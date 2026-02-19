#!/usr/bin/env python3
"""
Coverage tests for r2inspect/utils/retry_manager.py

Targets previously uncovered lines:
- 225-228: break + raise last_exception path via subclass override
- 308-309: reset_stats method body
- 366:     get_retry_stats module function
- 371-372: reset_retry_stats module function
- 377-378: configure_retry_for_command module function
"""

import pytest

from r2inspect.utils.retry_manager import (
    RetryConfig,
    RetryManager,
    RetryStrategy,
    configure_retry_for_command,
    get_retry_stats,
    reset_retry_stats,
    retry_r2_operation,
)


def test_reset_stats_clears_counters():
    manager = RetryManager()

    def flaky():
        raise TimeoutError("temporary")

    config = RetryConfig(max_attempts=2, base_delay=0.0, max_delay=0.0, jitter=False)
    with pytest.raises(TimeoutError):
        manager.retry_operation(flaky, config=config)

    assert manager.retry_stats["total_retries"] == 1
    manager.reset_stats()
    stats = manager.get_stats()
    assert stats["total_retries"] == 0
    assert stats["successful_retries"] == 0
    assert stats["failed_after_retries"] == 0


def test_get_retry_stats_returns_dict():
    stats = get_retry_stats()
    assert isinstance(stats, dict)
    assert "total_retries" in stats
    assert "successful_retries" in stats
    assert "failed_after_retries" in stats


def test_reset_retry_stats_resets_global():
    reset_retry_stats()
    stats = get_retry_stats()
    assert stats["total_retries"] == 0


def test_configure_retry_for_command_updates_config():
    custom = RetryConfig(max_attempts=7, base_delay=0.5, jitter=False)
    configure_retry_for_command("custom_test_type", custom)

    manager = RetryManager()
    retrieved = manager._get_retry_config("custom_test_type", None)

    from r2inspect.utils import retry_manager as rm_module

    assert rm_module.global_retry_manager.DEFAULT_CONFIGS["custom_test_type"].max_attempts == 7


def test_retry_operation_stops_when_handler_returns_false():
    """Cover lines 225-228: break then raise last_exception."""

    class StopAfterFirstRetryManager(RetryManager):
        def _handle_retry_exception(self, e, attempt, config, kwargs):
            return False

    manager = StopAfterFirstRetryManager()
    call_count = {"n": 0}

    def always_fails():
        call_count["n"] += 1
        raise TimeoutError("fail always")

    config = RetryConfig(max_attempts=5, base_delay=0.0, max_delay=0.0, jitter=False)

    with pytest.raises(TimeoutError, match="fail always"):
        manager.retry_operation(always_fails, config=config)

    # Only first attempt runs before break
    assert call_count["n"] == 1


def test_retry_r2_operation_success():
    calls = {"n": 0}

    def fake_op(cmd):
        calls["n"] += 1
        return f"result:{cmd}"

    result = retry_r2_operation(fake_op, "isj", command_type="info")
    assert result == "result:isj"


def test_retry_r2_operation_retries_on_timeout():
    calls = {"n": 0}

    def flaky_op(cmd):
        calls["n"] += 1
        if calls["n"] == 1:
            raise TimeoutError("temporary")
        return "ok"

    result = retry_r2_operation(flaky_op, "isj", command_type="info")
    assert result == "ok"
    assert calls["n"] == 2


def test_calculate_delay_random_jitter_strategy():
    manager = RetryManager()
    config = RetryConfig(
        base_delay=0.5,
        max_delay=10.0,
        jitter=False,
        strategy=RetryStrategy.RANDOM_JITTER,
    )
    delay = manager.calculate_delay(1, config)
    assert delay >= 0.5


def test_is_retryable_command_known_unstable():
    manager = RetryManager()
    assert manager.is_retryable_command("aaa") is True
    assert manager.is_retryable_command("not_in_list") is False


def test_is_retryable_error_by_message():
    manager = RetryManager()

    class FakeError(Exception):
        pass

    assert manager.is_retryable_error(FakeError("connection reset")) is True
    assert manager.is_retryable_error(FakeError("some unrelated error")) is False


def test_retry_operation_timeout_exceeded():
    manager = RetryManager()

    def slow():
        raise TimeoutError("slow")

    config = RetryConfig(max_attempts=3, base_delay=0.0, max_delay=0.0, jitter=False, timeout=0.0)

    with pytest.raises(TimeoutError):
        manager.retry_operation(slow, config=config)
