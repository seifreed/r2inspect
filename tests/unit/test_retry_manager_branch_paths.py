#!/usr/bin/env python3
"""Branch-path tests for r2inspect/utils/retry_manager.py."""
from __future__ import annotations

import time

import pytest

from r2inspect.utils.retry_manager import (
    RetryConfig,
    RetryManager,
    RetryStrategy,
    configure_retry_for_command,
    get_retry_stats,
    reset_retry_stats,
    retry_on_failure,
    retry_r2_operation,
)


# ---------------------------------------------------------------------------
# is_retryable_command - lines 148-149
# ---------------------------------------------------------------------------


def test_is_retryable_command_known_unstable_command():
    """Lines 148-149: command in UNSTABLE_COMMANDS returns True."""
    manager = RetryManager()
    assert manager.is_retryable_command("aaa") is True


def test_is_retryable_command_unknown_command_returns_false():
    """Lines 148-149: command not in UNSTABLE_COMMANDS returns False."""
    manager = RetryManager()
    assert manager.is_retryable_command("xyz_unknown") is False


def test_is_retryable_command_empty_string_returns_false():
    """Line 148: empty string -> command_base is empty string -> False."""
    manager = RetryManager()
    assert manager.is_retryable_command("") is False


def test_is_retryable_command_with_trailing_args():
    """Line 148: command with arguments splits on first space."""
    manager = RetryManager()
    assert manager.is_retryable_command("aaa --all") is True
    assert manager.is_retryable_command("aflj @main") is True


# ---------------------------------------------------------------------------
# is_retryable_error - lines 153-154, 157-158, 161
# ---------------------------------------------------------------------------


def test_is_retryable_error_by_exception_type_match():
    """Lines 153-158: TimeoutError type is in RETRYABLE_EXCEPTIONS -> True."""
    manager = RetryManager()
    assert manager.is_retryable_error(TimeoutError("timeout")) is True


def test_is_retryable_error_by_message_pattern_match():
    """Lines 153-154, 161: error message contains retryable pattern -> True."""
    manager = RetryManager()

    class CustomError(Exception):
        pass

    assert manager.is_retryable_error(CustomError("connection reset by peer")) is True
    assert manager.is_retryable_error(CustomError("broken pipe")) is True


def test_is_retryable_error_not_matching_returns_false():
    """Lines 153-154, 161: unknown type and unrelated message -> False."""
    manager = RetryManager()

    class NotRetryable(Exception):
        pass

    assert manager.is_retryable_error(NotRetryable("completely unrelated text")) is False


# ---------------------------------------------------------------------------
# calculate_delay - lines 165, 167-168, 170-171, 173-174, 176-177, 180-182, 185
# ---------------------------------------------------------------------------


def test_calculate_delay_fixed_strategy_returns_base_delay():
    """Lines 165, 167-168, 185: FIXED_DELAY strategy returns base_delay."""
    manager = RetryManager()
    config = RetryConfig(
        base_delay=0.5,
        max_delay=10.0,
        strategy=RetryStrategy.FIXED_DELAY,
        jitter=False,
    )
    delay = manager.calculate_delay(1, config)
    assert delay == 0.5


def test_calculate_delay_exponential_backoff_grows_with_attempt():
    """Lines 165, 170-171, 185: EXPONENTIAL_BACKOFF increases with attempt number."""
    manager = RetryManager()
    config = RetryConfig(
        base_delay=0.1,
        max_delay=100.0,
        strategy=RetryStrategy.EXPONENTIAL_BACKOFF,
        jitter=False,
        backoff_multiplier=2.0,
    )
    delay1 = manager.calculate_delay(1, config)
    delay2 = manager.calculate_delay(2, config)
    assert delay2 > delay1


def test_calculate_delay_linear_backoff_multiplies_by_attempt():
    """Lines 165, 173-174, 185: LINEAR_BACKOFF = base_delay * attempt."""
    manager = RetryManager()
    config = RetryConfig(
        base_delay=0.1,
        max_delay=100.0,
        strategy=RetryStrategy.LINEAR_BACKOFF,
        jitter=False,
    )
    delay = manager.calculate_delay(3, config)
    assert abs(delay - 0.3) < 0.001


def test_calculate_delay_random_jitter_strategy_adds_randomness():
    """Lines 165, 176-177, 185: RANDOM_JITTER strategy produces delay >= base_delay."""
    manager = RetryManager()
    config = RetryConfig(
        base_delay=1.0,
        max_delay=100.0,
        strategy=RetryStrategy.RANDOM_JITTER,
        jitter=False,
    )
    delay = manager.calculate_delay(1, config)
    assert delay >= 1.0


def test_calculate_delay_jitter_enabled_applies_variation():
    """Lines 180-182: jitter=True with non-RANDOM_JITTER strategy adjusts delay."""
    manager = RetryManager()
    config = RetryConfig(
        base_delay=0.5,
        max_delay=10.0,
        strategy=RetryStrategy.FIXED_DELAY,
        jitter=True,
    )
    delays = [manager.calculate_delay(1, config) for _ in range(20)]
    assert all(d > 0 for d in delays)
    assert all(d <= 10.0 for d in delays)


def test_calculate_delay_capped_at_max_delay():
    """Line 185: delay exceeding max_delay is capped."""
    manager = RetryManager()
    config = RetryConfig(
        base_delay=100.0,
        max_delay=1.0,
        strategy=RetryStrategy.FIXED_DELAY,
        jitter=False,
    )
    delay = manager.calculate_delay(1, config)
    assert delay == 1.0


# ---------------------------------------------------------------------------
# retry_operation success paths - lines 211-220
# ---------------------------------------------------------------------------


def test_retry_operation_success_on_first_attempt():
    """Lines 211-220: operation succeeds first time -> result returned."""
    manager = RetryManager()
    calls = {"n": 0}

    def op():
        calls["n"] += 1
        return "success"

    config = RetryConfig(max_attempts=3, base_delay=0.0, jitter=False)
    result = manager.retry_operation(op, config=config)
    assert result == "success"
    assert calls["n"] == 1


def test_retry_operation_success_on_second_attempt_increments_stat():
    """Lines 211-220, 243-246: succeeds on attempt 2 -> successful_retries incremented."""
    manager = RetryManager()
    calls = {"n": 0}

    def op():
        calls["n"] += 1
        if calls["n"] == 1:
            raise TimeoutError("transient")
        return "ok"

    config = RetryConfig(max_attempts=3, base_delay=0.0, max_delay=0.0, jitter=False)
    result = manager.retry_operation(op, config=config)
    assert result == "ok"
    assert manager.retry_stats["successful_retries"] == 1


# ---------------------------------------------------------------------------
# _get_retry_config - lines 232-234
# ---------------------------------------------------------------------------


def test_get_retry_config_returns_provided_config():
    """Line 234: when config is provided, returns it directly."""
    manager = RetryManager()
    custom = RetryConfig(max_attempts=7)
    result = manager._get_retry_config("generic", custom)
    assert result.max_attempts == 7


def test_get_retry_config_falls_back_to_command_type():
    """Lines 232-233: config=None -> lookup by command_type."""
    manager = RetryManager()
    result = manager._get_retry_config("analysis", None)
    assert result.max_attempts == RetryManager.DEFAULT_CONFIGS["analysis"].max_attempts


def test_get_retry_config_unknown_type_returns_generic():
    """Line 233: unknown command_type falls back to 'generic' defaults."""
    manager = RetryManager()
    result = manager._get_retry_config("nonexistent_type", None)
    assert result.max_attempts == RetryManager.DEFAULT_CONFIGS["generic"].max_attempts


# ---------------------------------------------------------------------------
# _check_timeout - lines 238-239
# ---------------------------------------------------------------------------


def test_check_timeout_raises_when_time_exceeded():
    """Lines 238-239: elapsed time > config.timeout -> TimeoutError raised."""
    manager = RetryManager()
    config = RetryConfig(timeout=0.001)
    with pytest.raises(TimeoutError, match="Retry timeout exceeded"):
        manager._check_timeout(time.time() - 1.0, config)


def test_check_timeout_no_timeout_configured_does_not_raise():
    """Line 238: config.timeout is None -> no exception raised."""
    manager = RetryManager()
    config = RetryConfig(timeout=None)
    manager._check_timeout(time.time(), config)


# ---------------------------------------------------------------------------
# _handle_success - lines 243-246
# ---------------------------------------------------------------------------


def test_handle_success_on_first_attempt_does_not_increment():
    """Lines 243-246: attempt=1 -> successful_retries stays at 0."""
    manager = RetryManager()
    manager._handle_success(1)
    assert manager.retry_stats["successful_retries"] == 0


def test_handle_success_on_later_attempt_increments_stat():
    """Lines 243-246: attempt>1 -> successful_retries incremented by 1."""
    manager = RetryManager()
    manager._handle_success(2)
    assert manager.retry_stats["successful_retries"] == 1


# ---------------------------------------------------------------------------
# Non-retryable error stops retry loop - lines 252-254
# ---------------------------------------------------------------------------


def test_retry_operation_non_retryable_error_raises_immediately():
    """Lines 252-254: non-retryable error type is re-raised without retrying."""
    manager = RetryManager()
    calls = {"n": 0}

    class HardError(ValueError):
        pass

    def op():
        calls["n"] += 1
        raise HardError("not retryable at all")

    config = RetryConfig(max_attempts=5, base_delay=0.0, jitter=False)
    with pytest.raises(HardError):
        manager.retry_operation(op, config=config)
    assert calls["n"] == 1


# ---------------------------------------------------------------------------
# _update_retry_stats - lines 269-273, 277-278
# ---------------------------------------------------------------------------


def test_update_retry_stats_first_attempt_increments_total():
    """Lines 269-273: attempt=1 -> total_retries incremented."""
    manager = RetryManager()
    manager._update_retry_stats(TimeoutError("test"), 1, {"command": "test_cmd"})
    assert manager.retry_stats["total_retries"] == 1
    assert "test_cmd" in manager.retry_stats["commands_retried"]


def test_update_retry_stats_tracks_error_type():
    """Lines 277-278: error class name tracked in error_types_retried."""
    manager = RetryManager()
    manager._update_retry_stats(TimeoutError("test"), 1, {})
    assert "TimeoutError" in manager.retry_stats["error_types_retried"]


def test_update_retry_stats_second_attempt_does_not_double_count():
    """Line 270: attempt != 1 -> total_retries not incremented."""
    manager = RetryManager()
    manager._update_retry_stats(TimeoutError("test"), 2, {"command": "cmd"})
    assert manager.retry_stats["total_retries"] == 0


def test_update_retry_stats_unknown_command_tracked():
    """Lines 272-273: no command key in kwargs -> 'unknown' tracked."""
    manager = RetryManager()
    manager._update_retry_stats(TimeoutError("test"), 1, {})
    assert "unknown" in manager.retry_stats["commands_retried"]


# ---------------------------------------------------------------------------
# max_attempts exceeded path - lines 258-262
# ---------------------------------------------------------------------------


def test_retry_operation_exhausts_max_attempts_increments_failed():
    """Lines 258-262: all attempts exhausted -> failed_after_retries incremented."""
    manager = RetryManager()
    calls = {"n": 0}

    def op():
        calls["n"] += 1
        raise TimeoutError("keep failing")

    config = RetryConfig(max_attempts=2, base_delay=0.0, max_delay=0.0, jitter=False)
    with pytest.raises(TimeoutError):
        manager.retry_operation(op, config=config)
    assert manager.retry_stats["failed_after_retries"] == 1
    assert calls["n"] == 2


# ---------------------------------------------------------------------------
# _wait_for_retry - lines 284-285, 288
# ---------------------------------------------------------------------------


def test_wait_for_retry_completes_without_error():
    """Lines 284-285, 288: _wait_for_retry calculates delay and sleeps."""
    manager = RetryManager()
    config = RetryConfig(
        base_delay=0.0,
        max_delay=0.0,
        jitter=False,
        strategy=RetryStrategy.FIXED_DELAY,
    )
    manager._wait_for_retry(1, config)


# ---------------------------------------------------------------------------
# reset_stats - lines 308-309
# ---------------------------------------------------------------------------


def test_reset_stats_clears_all_statistics():
    """Lines 308-309: reset_stats zeroes every counter."""
    manager = RetryManager()
    manager.retry_stats["total_retries"] = 5
    manager.retry_stats["successful_retries"] = 3
    manager.retry_stats["failed_after_retries"] = 2
    manager.reset_stats()
    stats = manager.get_stats()
    assert stats["total_retries"] == 0
    assert stats["successful_retries"] == 0
    assert stats["failed_after_retries"] == 0


# ---------------------------------------------------------------------------
# retry_on_failure decorator - lines 326-357
# ---------------------------------------------------------------------------


def test_retry_on_failure_decorator_applied_to_function():
    """Lines 326-357: decorator wraps function and executes it."""

    @retry_on_failure(command_type="generic")
    def my_func(self, cmd: str, **_kwargs: object) -> str:
        return f"ran:{cmd}"

    result = my_func(object(), "isj")
    assert "ran:isj" in result


def test_retry_on_failure_decorator_retries_unstable_command():
    """Lines 337-344: auto_retry=True, command in UNSTABLE_COMMANDS -> retry path."""
    calls = {"n": 0}

    @retry_on_failure(command_type="generic", auto_retry=True)
    def my_func(self, cmd: str, **_kwargs: object) -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            raise TimeoutError("transient")
        return "ok"

    result = my_func(object(), "aaa")
    assert result == "ok"
    assert calls["n"] == 2


def test_retry_on_failure_decorator_non_unstable_command_no_retry():
    """Lines 337-353: auto_retry=True but command not unstable -> direct call."""
    calls = {"n": 0}

    @retry_on_failure(command_type="generic", auto_retry=True)
    def my_func(self, cmd: str) -> str:
        calls["n"] += 1
        return "direct"

    result = my_func(object(), "safe_command_xyz")
    assert result == "direct"
    assert calls["n"] == 1


def test_retry_on_failure_decorator_no_args_always_retries():
    """Lines 330-341: no command in args -> should_retry=True -> retry path."""
    calls = {"n": 0}

    @retry_on_failure(command_type="generic", auto_retry=False)
    def my_func(**_kwargs: object) -> str:
        calls["n"] += 1
        return "ok"

    result = my_func()
    assert result == "ok"


def test_retry_on_failure_decorator_command_from_kwargs():
    """Lines 333-334: command key in kwargs is extracted."""

    @retry_on_failure(command_type="generic", auto_retry=True)
    def my_func(**kwargs) -> str:
        return "ok"

    # "safe_xyz" not in UNSTABLE_COMMANDS -> should_retry=False -> direct call
    result = my_func(command="safe_xyz")
    assert result == "ok"


# ---------------------------------------------------------------------------
# reset_retry_stats module function - lines 371-372
# ---------------------------------------------------------------------------


def test_reset_retry_stats_module_function_resets_global():
    """Lines 371-372: reset_retry_stats() resets the global retry manager stats."""
    reset_retry_stats()
    stats = get_retry_stats()
    assert stats["total_retries"] == 0
    assert stats["successful_retries"] == 0


# ---------------------------------------------------------------------------
# configure_retry_for_command - lines 377-378
# ---------------------------------------------------------------------------


def test_configure_retry_for_command_updates_global_config():
    """Lines 377-378: configure_retry_for_command sets config on global manager."""
    from r2inspect.utils import retry_manager as rm

    custom = RetryConfig(max_attempts=11, base_delay=0.0, jitter=False)
    configure_retry_for_command("test_branch_type", custom)
    assert rm.global_retry_manager.DEFAULT_CONFIGS["test_branch_type"].max_attempts == 11


# ---------------------------------------------------------------------------
# retry_r2_operation - lines 399-400, 402
# ---------------------------------------------------------------------------


def test_retry_r2_operation_calls_operation_with_command():
    """Lines 399-400, 402: _execute closure calls operation(command)."""
    calls = []

    def fake_op(cmd: str) -> str:
        calls.append(cmd)
        return f"result:{cmd}"

    result = retry_r2_operation(fake_op, "isj", command_type="info")
    assert result == "result:isj"
    assert calls == ["isj"]


def test_retry_r2_operation_retries_on_timeout_error():
    """Lines 399-400, 402: TimeoutError triggers retry via global manager."""
    calls = {"n": 0}

    def flaky_op(cmd: str) -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            raise TimeoutError("temporary failure")
        return "ok"

    result = retry_r2_operation(flaky_op, "iij", command_type="info")
    assert result == "ok"
    assert calls["n"] == 2
