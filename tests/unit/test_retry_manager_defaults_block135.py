from __future__ import annotations

from r2inspect.utils.retry_manager import RetryManager, RetryStrategy


def test_retry_manager_is_retryable_command():
    manager = RetryManager()
    assert manager.is_retryable_command("aaa") is True
    assert manager.is_retryable_command("aflj") is True
    assert manager.is_retryable_command("unknowncmd") is False


def test_retry_manager_calculate_delay_strategies():
    manager = RetryManager()
    config = manager.DEFAULT_CONFIGS["generic"]

    fixed = manager.calculate_delay(1, config)
    assert fixed >= 0.0

    config.strategy = RetryStrategy.LINEAR_BACKOFF
    assert manager.calculate_delay(2, config) >= manager.calculate_delay(1, config)

    config.strategy = RetryStrategy.EXPONENTIAL_BACKOFF
    assert manager.calculate_delay(2, config) >= manager.calculate_delay(1, config)
