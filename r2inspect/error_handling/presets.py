#!/usr/bin/env python3
"""
Error Handling Policy Presets

Common error handling configurations for typical use cases.

Copyright (C) 2025 Marc Rivero Lopez

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Author: Marc Rivero Lopez
"""

import json
from typing import Any

from .policies import ErrorHandlingStrategy, ErrorPolicy

# Common retryable exceptions in r2pipe operations
COMMON_RETRYABLE_EXCEPTIONS: set[type[BaseException]] = {
    ConnectionError,
    TimeoutError,
    BrokenPipeError,
    OSError,
}

# Fatal exceptions that should never be retried
FATAL_EXCEPTIONS: set[type[BaseException]] = {
    MemoryError,
    KeyboardInterrupt,
    SystemExit,
}


def _empty_list():
    """Return empty list (for mutable default)"""
    return []


def _empty_dict():
    """Return empty dict (for mutable default)"""
    return {}


# Fail fast policy - re-raise all exceptions immediately
FAIL_FAST_POLICY = ErrorPolicy(
    strategy=ErrorHandlingStrategy.FAIL_FAST,
    fatal_exceptions=FATAL_EXCEPTIONS,
)

# Retry policy - retry up to 3 times with exponential backoff
RETRY_POLICY = ErrorPolicy(
    strategy=ErrorHandlingStrategy.RETRY,
    max_retries=3,
    retry_delay=0.5,
    retry_backoff=2.0,
    retry_jitter=True,
    retryable_exceptions=COMMON_RETRYABLE_EXCEPTIONS,
    fatal_exceptions=FATAL_EXCEPTIONS,
)

# Aggressive retry policy - more retries for unstable operations
AGGRESSIVE_RETRY_POLICY = ErrorPolicy(
    strategy=ErrorHandlingStrategy.RETRY,
    max_retries=5,
    retry_delay=0.3,
    retry_backoff=1.5,
    retry_jitter=True,
    retryable_exceptions=COMMON_RETRYABLE_EXCEPTIONS,
    fatal_exceptions=FATAL_EXCEPTIONS,
)

# Gentle retry policy - fewer retries with longer delays
GENTLE_RETRY_POLICY = ErrorPolicy(
    strategy=ErrorHandlingStrategy.RETRY,
    max_retries=2,
    retry_delay=1.0,
    retry_backoff=2.0,
    retry_jitter=True,
    retryable_exceptions=COMMON_RETRYABLE_EXCEPTIONS,
    fatal_exceptions=FATAL_EXCEPTIONS,
)

# Safe fallback policy - return empty dict on any error
SAFE_POLICY = ErrorPolicy(
    strategy=ErrorHandlingStrategy.FALLBACK,
    fallback_value={},
)

# Fallback to empty list
FALLBACK_LIST_POLICY = ErrorPolicy(
    strategy=ErrorHandlingStrategy.FALLBACK,
    fallback_value=[],
)

# Fallback to None
FALLBACK_NONE_POLICY = ErrorPolicy(
    strategy=ErrorHandlingStrategy.FALLBACK,
    fallback_value=None,
)

# Fallback to empty string
FALLBACK_STRING_POLICY = ErrorPolicy(
    strategy=ErrorHandlingStrategy.FALLBACK,
    fallback_value="",
)

# Generic fallback (alias for SAFE_POLICY)
FALLBACK_POLICY = SAFE_POLICY

# Circuit breaker policy - open circuit after 5 failures
CIRCUIT_BREAK_POLICY = ErrorPolicy(
    strategy=ErrorHandlingStrategy.CIRCUIT_BREAK,
    max_retries=2,
    retry_delay=0.5,
    retry_backoff=2.0,
    circuit_threshold=5,
    circuit_timeout=60,
    fallback_value={},
    retryable_exceptions=COMMON_RETRYABLE_EXCEPTIONS,
    fatal_exceptions=FATAL_EXCEPTIONS,
)

# Strict circuit breaker - fail fast with low threshold
STRICT_CIRCUIT_POLICY = ErrorPolicy(
    strategy=ErrorHandlingStrategy.CIRCUIT_BREAK,
    max_retries=1,
    retry_delay=0.2,
    circuit_threshold=3,
    circuit_timeout=30,
    fallback_value={},
    retryable_exceptions=COMMON_RETRYABLE_EXCEPTIONS,
    fatal_exceptions=FATAL_EXCEPTIONS,
)

# Tolerant circuit breaker - higher threshold, longer timeout
TOLERANT_CIRCUIT_POLICY = ErrorPolicy(
    strategy=ErrorHandlingStrategy.CIRCUIT_BREAK,
    max_retries=3,
    retry_delay=1.0,
    retry_backoff=2.0,
    circuit_threshold=10,
    circuit_timeout=120,
    fallback_value={},
    retryable_exceptions=COMMON_RETRYABLE_EXCEPTIONS,
    fatal_exceptions=FATAL_EXCEPTIONS,
)


# R2Pipe-specific policies

# For JSON commands that should return empty dict on error
R2_JSON_DICT_POLICY = ErrorPolicy(
    strategy=ErrorHandlingStrategy.FALLBACK,
    fallback_value={},
    retryable_exceptions=COMMON_RETRYABLE_EXCEPTIONS | {json.JSONDecodeError},
    fatal_exceptions=FATAL_EXCEPTIONS,
)

# For JSON commands that should return empty list on error
R2_JSON_LIST_POLICY = ErrorPolicy(
    strategy=ErrorHandlingStrategy.FALLBACK,
    fallback_value=[],
    retryable_exceptions=COMMON_RETRYABLE_EXCEPTIONS | {json.JSONDecodeError},
    fatal_exceptions=FATAL_EXCEPTIONS,
)

# For text commands that should return empty string on error
R2_TEXT_POLICY = ErrorPolicy(
    strategy=ErrorHandlingStrategy.FALLBACK,
    fallback_value="",
    retryable_exceptions=COMMON_RETRYABLE_EXCEPTIONS,
    fatal_exceptions=FATAL_EXCEPTIONS,
)

# For analysis commands that may be unstable - retry with circuit breaker
R2_ANALYSIS_POLICY = ErrorPolicy(
    strategy=ErrorHandlingStrategy.CIRCUIT_BREAK,
    max_retries=3,
    retry_delay=0.5,
    retry_backoff=2.0,
    circuit_threshold=7,
    circuit_timeout=90,
    fallback_value={},
    retryable_exceptions=COMMON_RETRYABLE_EXCEPTIONS | {json.JSONDecodeError},
    fatal_exceptions=FATAL_EXCEPTIONS,
)

# For critical operations that should fail fast
R2_CRITICAL_POLICY = ErrorPolicy(
    strategy=ErrorHandlingStrategy.FAIL_FAST,
    fatal_exceptions=FATAL_EXCEPTIONS,
)


def create_custom_policy(
    strategy: ErrorHandlingStrategy,
    fallback_value: Any = None,
    max_retries: int = 3,
    **kwargs: Any,
) -> ErrorPolicy:
    """
    Create a custom error policy with sensible defaults

    Args:
        strategy: Error handling strategy
        fallback_value: Value to return on error (for FALLBACK strategy)
        max_retries: Maximum retry attempts
        **kwargs: Additional policy parameters

    Returns:
        Configured ErrorPolicy instance

    Example:
        policy = create_custom_policy(
            ErrorHandlingStrategy.RETRY,
            max_retries=5,
            retry_delay=1.0
        )
    """
    defaults: dict[str, Any] = {
        "retry_delay": 0.5,
        "retry_backoff": 2.0,
        "retry_jitter": True,
        "circuit_threshold": 5,
        "circuit_timeout": 60,
        "retryable_exceptions": COMMON_RETRYABLE_EXCEPTIONS,
        "fatal_exceptions": FATAL_EXCEPTIONS,
    }

    defaults.update(kwargs)

    base_policy = ErrorPolicy(
        strategy=strategy,
        fallback_value=fallback_value,
        max_retries=max_retries,
    )

    return base_policy.copy_with_overrides(**defaults)
