#!/usr/bin/env python3
"""Support functions and constants for retry manager."""

from __future__ import annotations

import json
import random
import time
from collections.abc import Callable
from typing import Any

_secure_rng = random.SystemRandom()


class RetryableError(Exception): ...


class NonRetryableError(Exception): ...


# JSONDecodeError covers malformed r2pipe JSON responses, which are
# transient and worth retrying (BrokenPipeError is an OSError subclass).
RETRYABLE_EXCEPTIONS = (
    TimeoutError,
    ConnectionError,
    OSError,
    json.JSONDecodeError,
)
RETRYABLE_ERROR_MESSAGES = (
    "timeout",
    "temporarily unavailable",
    "resource temporarily unavailable",
    "resource busy",
    "device busy",
    "connection reset",
    "broken pipe",
    "try again",
    "no json object could be decoded",
    "expecting value: line 1 column 1",
    "extra data: line 1 column 2",
)
UNSTABLE_COMMANDS = ("aa", "aaa", "aaaa", "aflj", "izj", "iSj", "isj")


def init_retry_stats() -> dict[str, Any]:
    return {
        "total_retries": 0,
        "successful_retries": 0,
        "failed_after_retries": 0,
        "commands_retried": {},
        "error_types_retried": {},
    }


def get_stats(retry_stats: Any, lock: Any) -> dict[str, Any]:
    with lock:
        total = retry_stats["total_retries"]
        successful = retry_stats["successful_retries"]
        return {
            "total_retries": total,
            "successful_retries": successful,
            "failed_after_retries": retry_stats["failed_after_retries"],
            "success_rate": successful / max(1, total) * 100,
            "commands_retried": dict(retry_stats["commands_retried"]),
            "error_types_retried": dict(retry_stats["error_types_retried"]),
        }


def is_retryable_command(command: str, unstable_commands: tuple[str, ...]) -> bool:
    command_base = command.split(" ", 1)[0].strip()
    return bool(command_base) and command_base in unstable_commands


def is_retryable_error(
    exception: Exception,
    retryable_exceptions: tuple[type[BaseException], ...],
    retryable_messages: tuple[str, ...],
) -> bool:
    # The sentinel exceptions are an explicit caller contract and must be
    # honored by type, independent of message/RETRYABLE_EXCEPTIONS.
    if isinstance(exception, NonRetryableError):
        return False
    if isinstance(exception, (RetryableError, *retryable_exceptions)):
        return True
    message = str(exception).lower()
    return any(fragment in message for fragment in retryable_messages)


def calculate_delay(attempt: int, config: Any, retry_strategy_enum: Any) -> float:
    delay = config.base_delay
    if config.strategy == retry_strategy_enum.EXPONENTIAL_BACKOFF:
        # Cap exponent to prevent float overflow on large attempt counts
        capped_exp = min(max(0, attempt - 1), 20)
        delay *= config.backoff_multiplier**capped_exp
    elif config.strategy == retry_strategy_enum.LINEAR_BACKOFF:
        delay *= max(1, attempt)
    elif config.strategy == retry_strategy_enum.RANDOM_JITTER:
        # base_delay plus up to one extra base_delay of jitter, i.e.
        # [base_delay, 2*base_delay] — not the full [base_delay, max_delay].
        delay = config.base_delay + _secure_rng.uniform(0, config.base_delay)
    delay = min(delay, config.max_delay)
    if config.jitter:
        delay += _secure_rng.uniform(0, min(0.1, delay / 4))
    return float(delay)


def wait_for_retry(
    attempt: int, config: Any, calculate_delay_fn: Callable[[int, Any], float], *, logger: Any
) -> None:
    delay = calculate_delay_fn(attempt, config)
    logger.debug("Retrying in %.2fs (attempt %s/%s)", delay, attempt + 1, config.max_attempts)
    time.sleep(delay)


def get_retry_config(default_configs: dict[str, Any], command_type: str, config: Any) -> Any:
    return config or default_configs.get(command_type, default_configs["generic"])


def check_timeout(start_time: float, config: Any) -> None:
    if config.timeout is None:
        return
    if time.time() - start_time > config.timeout:
        raise TimeoutError(f"Retry timeout exceeded after {config.timeout:.2f}s")


def retry_on_failure_decorator(
    retry_manager: Any,
    command_type: str,
    config: Any,
    auto_retry: bool,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not auto_retry:
                if "command" in kwargs:
                    raise TypeError(
                        "command must be passed positionally when auto_retry is disabled"
                    )
                if len(args) >= 2:
                    return func(*args[:1], command=args[1], **kwargs)
                return func(*args, **kwargs)
            return retry_manager.retry_operation(
                func, *args, command_type=command_type, config=config, **kwargs
            )

        return wrapper

    return decorator
