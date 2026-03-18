"""Retry and fallback helpers for unified error handling."""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from typing import Any


def calculate_retry_delay(attempt: int, policy: Any) -> float:
    if attempt <= 0:
        return 0.0

    delay = policy.retry_delay * (policy.retry_backoff ** (attempt - 1))

    if policy.retry_jitter:
        jitter_range = delay * 0.2
        if jitter_range > 0:
            jitter_bound = max(1, int(jitter_range * 2000))
            jitter = (secrets.randbelow(jitter_bound) / 1000.0) - jitter_range
            delay = max(0.01, delay + jitter)

    return float(delay)


def retry_execution(
    func: Callable, policy: Any, func_args: tuple, func_kwargs: dict, logger: Any
) -> Any:
    last_exception = None

    for attempt in range(policy.max_retries + 1):
        try:
            result = func(*func_args, **func_kwargs)
            if attempt > 0:
                logger.debug("Operation succeeded on retry attempt %s", attempt + 1)
            return result
        except Exception as exc:
            last_exception = exc

            if not policy.is_retryable(exc):
                logger.debug("Non-retryable error: %s", type(exc).__name__)
                raise

            if attempt >= policy.max_retries:
                logger.warning(
                    "Operation failed after %s attempts: %s: %s",
                    policy.max_retries + 1,
                    type(exc).__name__,
                    exc,
                )
                raise

            delay = calculate_retry_delay(attempt + 1, policy)
            logger.debug(
                "Retrying after error (%s), attempt %s/%s in %.2fs",
                type(exc).__name__,
                attempt + 2,
                policy.max_retries + 1,
                delay,
            )
            time.sleep(delay)

    if last_exception:  # pragma: no cover
        raise last_exception  # pragma: no cover
    raise RuntimeError("Retry execution completed without result")  # pragma: no cover


def fallback_execution(
    func: Callable, policy: Any, func_args: tuple, func_kwargs: dict, logger: Any
) -> Any:
    try:
        return func(*func_args, **func_kwargs)
    except Exception as exc:
        logger.debug(
            "Operation failed, returning fallback value: %s: %s",
            type(exc).__name__,
            exc,
        )
        return policy.fallback_value
