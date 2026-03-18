"""Retry manager facade."""

from __future__ import annotations

import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any, TypedDict, cast

from .logging import get_logger
from .retry_manager_support import (
    calculate_delay as _calculate_delay_impl,
    check_timeout as _check_timeout_impl,
    get_retry_config as _get_retry_config_impl,
    init_retry_stats as _init_retry_stats,
    is_retryable_command as _is_retryable_command_impl,
    is_retryable_error as _is_retryable_error_impl,
    retry_on_failure_decorator as _retry_on_failure_decorator_impl,
    RETRYABLE_EXCEPTIONS,
    RETRYABLE_ERROR_MESSAGES,
    UNSTABLE_COMMANDS,
    wait_for_retry as _wait_for_retry_impl,
)

logger = get_logger(__name__)


class RetryStats(TypedDict):
    total_retries: int
    successful_retries: int
    failed_after_retries: int
    commands_retried: dict[str, int]
    error_types_retried: dict[str, int]


class RetryStrategy(Enum):
    FIXED_DELAY = "fixed_delay"
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    LINEAR_BACKOFF = "linear_backoff"
    RANDOM_JITTER = "random_jitter"


@dataclass
class RetryConfig:
    max_attempts: int = 3
    base_delay: float = 0.1
    max_delay: float = 5.0
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF
    jitter: bool = True
    backoff_multiplier: float = 2.0
    timeout: float | None = None


class RetryableError(Exception): ...


class NonRetryableError(Exception): ...


class RetryManager:
    DEFAULT_CONFIGS: dict[str, RetryConfig] = {
        "analysis": RetryConfig(max_attempts=3, base_delay=0.2),
        "info": RetryConfig(max_attempts=2, base_delay=0.1, strategy=RetryStrategy.FIXED_DELAY),
        "search": RetryConfig(
            max_attempts=4, base_delay=0.3, strategy=RetryStrategy.LINEAR_BACKOFF
        ),
        "print": RetryConfig(max_attempts=2, base_delay=0.1, strategy=RetryStrategy.FIXED_DELAY),
        "sections": RetryConfig(max_attempts=3, base_delay=0.15),
        "functions": RetryConfig(max_attempts=3, base_delay=0.2),
        "memory": RetryConfig(max_attempts=2, base_delay=0.1, strategy=RetryStrategy.FIXED_DELAY),
        "generic": RetryConfig(max_attempts=2, base_delay=0.1, strategy=RetryStrategy.FIXED_DELAY),
    }
    UNSTABLE_COMMANDS = UNSTABLE_COMMANDS
    RETRYABLE_EXCEPTIONS = RETRYABLE_EXCEPTIONS
    RETRYABLE_ERROR_MESSAGES = RETRYABLE_ERROR_MESSAGES

    def __init__(self) -> None:
        self.retry_stats: RetryStats = cast(RetryStats, _init_retry_stats())
        self.lock = threading.Lock()

    def is_retryable_command(self, command: str) -> bool:
        return _is_retryable_command_impl(command, self.UNSTABLE_COMMANDS)

    def is_retryable_error(self, exception: Exception) -> bool:
        return _is_retryable_error_impl(
            exception,
            self.RETRYABLE_EXCEPTIONS,
            self.RETRYABLE_ERROR_MESSAGES,
        )

    def calculate_delay(self, attempt: int, config: RetryConfig) -> float:
        return _calculate_delay_impl(attempt, config, RetryStrategy)

    def retry_operation(
        self,
        operation: Callable[..., Any],
        *args: Any,
        command_type: str = "generic",
        config: RetryConfig | None = None,
        **kwargs: Any,
    ) -> Any:
        config = self._get_retry_config(command_type, config)
        if config.max_attempts <= 0:
            return None
        start_time = time.time()
        last_exception: Exception | None = None
        for attempt in range(1, config.max_attempts + 1):
            try:
                self._check_timeout(start_time, config)
                result = operation(*args, **kwargs)
                self._handle_success(attempt)
                return result
            except Exception as exc:
                last_exception = exc
                if not self._handle_retry_exception(exc, attempt, config, kwargs):
                    break
        if last_exception:
            raise last_exception
        return None

    def _get_retry_config(self, command_type: str, config: RetryConfig | None) -> RetryConfig:
        return cast(RetryConfig, _get_retry_config_impl(self.DEFAULT_CONFIGS, command_type, config))

    def _check_timeout(self, start_time: float, config: RetryConfig) -> None:
        _check_timeout_impl(start_time, config)

    def _handle_success(self, attempt: int) -> None:
        if attempt > 1:
            with self.lock:
                self.retry_stats["successful_retries"] += 1
                logger.debug("Operation succeeded on attempt %s", attempt)

    def _handle_retry_exception(
        self, exc: Exception, attempt: int, config: RetryConfig, kwargs: dict[str, Any]
    ) -> bool:
        if not self.is_retryable_error(exc):
            logger.debug("Non-retryable error: %s: %s", type(exc).__name__, exc)
            raise exc
        self._update_retry_stats(exc, attempt, kwargs)
        if attempt >= config.max_attempts:
            with self.lock:
                self.retry_stats["failed_after_retries"] += 1
            logger.warning("Operation failed after %s attempts: %s", config.max_attempts, exc)
            raise exc
        self._wait_for_retry(attempt, config)
        return True

    def _update_retry_stats(self, exc: Exception, attempt: int, kwargs: dict[str, Any]) -> None:
        with self.lock:
            if attempt == 1:
                self.retry_stats["total_retries"] += 1
                command_name = kwargs.get("command", "unknown")
                self.retry_stats["commands_retried"][command_name] = (
                    self.retry_stats["commands_retried"].get(command_name, 0) + 1
                )
                error_type = type(exc).__name__
                self.retry_stats["error_types_retried"][error_type] = (
                    self.retry_stats["error_types_retried"].get(error_type, 0) + 1
                )

    def _wait_for_retry(self, attempt: int, config: RetryConfig) -> None:
        _wait_for_retry_impl(attempt, config, self.calculate_delay, logger=logger)

    def get_stats(self) -> dict[str, Any]:
        with self.lock:
            return {
                "total_retries": self.retry_stats["total_retries"],
                "successful_retries": self.retry_stats["successful_retries"],
                "failed_after_retries": self.retry_stats["failed_after_retries"],
                "success_rate": (
                    self.retry_stats["successful_retries"]
                    / max(1, self.retry_stats["total_retries"])
                )
                * 100,
                "commands_retried": dict(self.retry_stats["commands_retried"]),
                "error_types_retried": dict(self.retry_stats["error_types_retried"]),
            }

    def reset_stats(self) -> None:
        with self.lock:
            self.retry_stats = cast(RetryStats, _init_retry_stats())


def retry_on_failure(
    command_type: str = "generic", config: RetryConfig | None = None, auto_retry: bool = True
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    return _retry_on_failure_decorator_impl(global_retry_manager, command_type, config, auto_retry)


global_retry_manager = RetryManager()


def get_retry_stats() -> dict[str, Any]:
    return global_retry_manager.get_stats()


def reset_retry_stats() -> None:
    global_retry_manager.reset_stats()
    logger.info("Retry statistics have been reset")


def configure_retry_for_command(command_type: str, config: RetryConfig) -> None:
    global_retry_manager.DEFAULT_CONFIGS[command_type] = config
    logger.info("Updated retry configuration for %s", command_type)


def retry_r2_operation(
    operation: Callable[[str], Any], command: str, command_type: str = "generic"
) -> Any:
    return global_retry_manager.retry_operation(
        lambda **_kwargs: operation(command), command_type=command_type, command=command
    )


__all__ = [
    "NonRetryableError",
    "RetryConfig",
    "RetryManager",
    "RetryStrategy",
    "RetryableError",
    "configure_retry_for_command",
    "get_retry_stats",
    "global_retry_manager",
    "reset_retry_stats",
    "retry_on_failure",
    "retry_r2_operation",
]
