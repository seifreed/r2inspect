#!/usr/bin/env python3
"""
Unified Error Handler

Single decorator that consolidates retry, circuit breaker, and fallback logic.

Copyright (C) 2025 Marc Rivero Lopez

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Author: Marc Rivero Lopez
"""

import functools
import secrets
import threading
import time
from collections.abc import Callable
from enum import Enum
from typing import Any

try:
    from typing import assert_never
except ImportError:  # pragma: no cover - Python < 3.11
    from typing_extensions import assert_never

from ..utils.logger import get_logger
from .policies import ErrorHandlingStrategy, ErrorPolicy

logger = get_logger(__name__)


class CircuitState(Enum):
    """Circuit breaker states"""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Circuit tripped, failing fast
    HALF_OPEN = "half_open"  # Testing recovery


class CircuitBreakerState:
    """Thread-safe circuit breaker state management"""

    def __init__(self, policy: ErrorPolicy):
        self.policy = policy
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time: float | None = None
        self.lock = threading.Lock()

    def should_allow_request(self) -> bool:
        """Check if request should be allowed through circuit"""
        with self.lock:
            if self.state == CircuitState.CLOSED:
                return True

            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self.state = CircuitState.HALF_OPEN
                    return True
                return False

            # HALF_OPEN state allows one request
            return True

    def record_success(self):
        """Record successful execution"""
        with self.lock:
            if self.state == CircuitState.HALF_OPEN:
                self.state = CircuitState.CLOSED
            self.failure_count = 0
            self.last_failure_time = None

    def record_failure(self):
        """Record failed execution"""
        with self.lock:
            self.failure_count += 1
            self.last_failure_time = time.time()

            if self.failure_count >= self.policy.circuit_threshold:
                self.state = CircuitState.OPEN
                logger.warning(
                    f"Circuit breaker opened after {self.failure_count} failures, "
                    f"will retry in {self.policy.circuit_timeout}s"
                )

    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset"""
        if self.last_failure_time is None:
            return False
        return (time.time() - self.last_failure_time) >= self.policy.circuit_timeout


# Global circuit breaker registry by function
_circuit_breakers: dict[str, CircuitBreakerState] = {}
_circuit_lock = threading.Lock()


def _get_circuit_breaker(func_id: str, policy: ErrorPolicy) -> CircuitBreakerState:
    """Get or create circuit breaker for function"""
    with _circuit_lock:
        if func_id not in _circuit_breakers:
            _circuit_breakers[func_id] = CircuitBreakerState(policy)
        return _circuit_breakers[func_id]


def _calculate_retry_delay(attempt: int, policy: ErrorPolicy) -> float:
    """Calculate delay before retry using exponential backoff with optional jitter"""
    if attempt <= 0:
        return 0.0

    # Exponential backoff
    delay = policy.retry_delay * (policy.retry_backoff ** (attempt - 1))

    # Add jitter to prevent thundering herd
    if policy.retry_jitter:
        # Add ±20% jitter
        jitter_range = delay * 0.2
        jitter = (secrets.randbelow(int(jitter_range * 2000)) / 1000.0) - jitter_range
        delay = max(0.01, delay + jitter)

    return delay


def _retry_execution(
    func: Callable, policy: ErrorPolicy, func_args: tuple, func_kwargs: dict
) -> Any:
    """
    Execute function with retry logic

    Args:
        func: Function to execute
        policy: Error policy configuration
        func_args: Positional arguments for function
        func_kwargs: Keyword arguments for function

    Returns:
        Function result

    Raises:
        Exception: If all retries exhausted or non-retryable error
    """
    last_exception = None

    for attempt in range(policy.max_retries + 1):
        try:
            result = func(*func_args, **func_kwargs)
            if attempt > 0:
                logger.debug(f"Operation succeeded on retry attempt {attempt + 1}")
            return result

        except Exception as e:
            last_exception = e

            # Check if error is retryable
            if not policy.is_retryable(e):
                logger.debug(f"Non-retryable error: {type(e).__name__}")
                raise

            # Check if we have retries left
            if attempt >= policy.max_retries:
                logger.warning(
                    f"Operation failed after {policy.max_retries + 1} attempts: "
                    f"{type(e).__name__}: {e}"
                )
                raise

            # Calculate delay and wait
            delay = _calculate_retry_delay(attempt + 1, policy)
            logger.debug(
                f"Retrying after error ({type(e).__name__}), "
                f"attempt {attempt + 2}/{policy.max_retries + 1} in {delay:.2f}s"
            )
            time.sleep(delay)

    # Should not reach here, but handle gracefully
    if last_exception:
        raise last_exception
    raise RuntimeError("Retry execution completed without result")


def _circuit_break_execution(
    func: Callable,
    policy: ErrorPolicy,
    func_args: tuple,
    func_kwargs: dict,
    func_id: str,
) -> Any:
    """
    Execute function with circuit breaker pattern

    Args:
        func: Function to execute
        policy: Error policy configuration
        func_args: Positional arguments for function
        func_kwargs: Keyword arguments for function
        func_id: Unique identifier for circuit breaker

    Returns:
        Function result or fallback value

    Raises:
        Exception: If circuit is open and no fallback configured
    """
    circuit = _get_circuit_breaker(func_id, policy)

    # Check if circuit allows request
    if not circuit.should_allow_request():
        logger.debug(f"Circuit breaker open for {func_id}, returning fallback")
        if policy.fallback_value is not None:
            return policy.fallback_value
        raise RuntimeError(f"Circuit breaker open for {func_id}")

    # Attempt execution with retry logic
    try:
        result = _retry_execution(func, policy, func_args, func_kwargs)
        circuit.record_success()
        return result

    except Exception:
        circuit.record_failure()
        raise


def _fallback_execution(
    func: Callable, policy: ErrorPolicy, func_args: tuple, func_kwargs: dict
) -> Any:
    """
    Execute function with fallback on error

    Args:
        func: Function to execute
        policy: Error policy configuration
        func_args: Positional arguments for function
        func_kwargs: Keyword arguments for function

    Returns:
        Function result or fallback value on error
    """
    try:
        return func(*func_args, **func_kwargs)
    except Exception as e:
        logger.debug(f"Operation failed, returning fallback value: {type(e).__name__}: {e}")
        return policy.fallback_value


def handle_errors(policy: ErrorPolicy) -> Callable:
    """
    Unified error handling decorator

    This decorator consolidates retry logic, circuit breaker, and fallback
    strategies based on the provided policy configuration.

    Args:
        policy: ErrorPolicy configuration defining handling strategy

    Returns:
        Decorator function

    Example:
        @handle_errors(ErrorPolicy(ErrorHandlingStrategy.RETRY, max_retries=3))
        def get_data():
            return risky_operation()

        @handle_errors(ErrorPolicy(ErrorHandlingStrategy.FALLBACK, fallback_value={}))
        def get_metadata():
            return parse_metadata()
    """

    def decorator(func: Callable) -> Callable:
        # Create unique identifier for this function
        func_id = f"{func.__module__}.{func.__qualname__}"

        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            try:
                # Select execution strategy based on policy
                match policy.strategy:
                    case ErrorHandlingStrategy.FAIL_FAST:
                        return func(*args, **kwargs)
                    case ErrorHandlingStrategy.RETRY:
                        return _retry_execution(func, policy, args, kwargs)
                    case ErrorHandlingStrategy.FALLBACK:
                        return _fallback_execution(func, policy, args, kwargs)
                    case ErrorHandlingStrategy.CIRCUIT_BREAK:
                        return _circuit_break_execution(func, policy, args, kwargs, func_id)
                    case _ as unreachable:
                        assert_never(unreachable)

            except Exception as e:
                # Log error details for debugging
                logger.debug(
                    f"Error in {func_id}: {type(e).__name__}: {e}",
                    extra={
                        "function": func.__name__,
                        "module": func.__module__,
                        "strategy": policy.strategy.value,
                    },
                )
                raise

        return wrapper

    return decorator


def reset_circuit_breakers():
    """Reset all circuit breakers to closed state"""
    with _circuit_lock:
        for circuit in _circuit_breakers.values():
            with circuit.lock:
                circuit.state = CircuitState.CLOSED
                circuit.failure_count = 0
                circuit.last_failure_time = None
    logger.info("All circuit breakers have been reset")


def get_circuit_breaker_stats() -> dict[str, Any]:
    """
    Get statistics for all circuit breakers

    Returns:
        Dictionary mapping function IDs to circuit state information
    """
    stats = {}
    with _circuit_lock:
        for func_id, circuit in _circuit_breakers.items():
            with circuit.lock:
                stats[func_id] = {
                    "state": circuit.state.value,
                    "failure_count": circuit.failure_count,
                    "last_failure_time": circuit.last_failure_time,
                    "threshold": circuit.policy.circuit_threshold,
                    "timeout": circuit.policy.circuit_timeout,
                }
    return stats
