#!/usr/bin/env python3
"""
Error Handling Policies

Defines declarative policies for error handling strategies.

Copyright (C) 2025 Marc Rivero Lopez

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Author: Marc Rivero Lopez
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ErrorHandlingStrategy(Enum):
    """Error handling strategies for different scenarios"""

    FAIL_FAST = "fail_fast"  # Re-raise exceptions immediately
    RETRY = "retry"  # Retry operation with backoff
    FALLBACK = "fallback"  # Return fallback value on error
    CIRCUIT_BREAK = "circuit_break"  # Open circuit after threshold failures


@dataclass
class ErrorPolicy:
    """
    Unified error handling policy configuration

    This dataclass consolidates retry logic, circuit breaking, and fallback
    strategies into a single declarative configuration.

    Attributes:
        strategy: Primary error handling strategy to apply
        max_retries: Maximum number of retry attempts (for RETRY and CIRCUIT_BREAK)
        retry_delay: Base delay between retries in seconds
        retry_backoff: Backoff multiplier for exponential delay (1.0 = no backoff)
        retry_jitter: Add random jitter to retry delays (reduces thundering herd)
        fallback_value: Value to return when recovery fails (for FALLBACK)
        circuit_threshold: Number of failures before opening circuit
        circuit_timeout: Time in seconds before attempting circuit recovery
        retryable_exceptions: Specific exceptions that should trigger retry
        fatal_exceptions: Exceptions that should never be retried
    """

    strategy: ErrorHandlingStrategy
    max_retries: int = 3
    retry_delay: float = 1.0
    retry_backoff: float = 2.0
    retry_jitter: bool = True
    fallback_value: Any = None
    circuit_threshold: int = 5
    circuit_timeout: int = 60
    retryable_exceptions: set[type[BaseException]] = field(default_factory=lambda: {Exception})
    fatal_exceptions: set[type[BaseException]] = field(default_factory=set)

    def __post_init__(self):
        """Validate policy configuration"""
        if self.max_retries < 0:
            raise ValueError("max_retries must be non-negative")

        if self.retry_delay < 0:
            raise ValueError("retry_delay must be non-negative")

        if self.retry_backoff < 1.0:
            raise ValueError("retry_backoff must be >= 1.0")

        if self.circuit_threshold < 1:
            raise ValueError("circuit_threshold must be positive")

        if self.circuit_timeout < 0:
            raise ValueError("circuit_timeout must be non-negative")

    def is_retryable(self, exception: BaseException) -> bool:
        """
        Determine if exception should trigger retry based on policy

        Args:
            exception: Exception to evaluate

        Returns:
            True if exception should trigger retry
        """
        # Fatal exceptions are never retryable
        for fatal_exc in self.fatal_exceptions:
            if isinstance(exception, fatal_exc):
                return False

        # Check if exception matches retryable types
        for retryable_exc in self.retryable_exceptions:
            if isinstance(exception, retryable_exc):
                return True

        return False

    def copy_with_overrides(self, **overrides) -> "ErrorPolicy":
        """
        Create a copy of this policy with specific overrides

        Args:
            **overrides: Attributes to override

        Returns:
            New ErrorPolicy instance with overrides applied
        """
        from copy import deepcopy

        new_policy = deepcopy(self)
        for key, value in overrides.items():
            if hasattr(new_policy, key):
                setattr(new_policy, key, value)
            else:
                raise AttributeError(f"ErrorPolicy has no attribute '{key}'")

        return new_policy
