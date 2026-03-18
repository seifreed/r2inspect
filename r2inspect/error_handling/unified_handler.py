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
from collections.abc import Callable
from typing import Any, assert_never, overload

from ..infrastructure.logging import get_logger
from .policies import ErrorHandlingStrategy, ErrorPolicy
from .unified_handler_circuit_support import (
    CircuitBreakerState,
    CircuitState,
    _circuit_breakers,
    _circuit_lock,
    get_circuit_breaker as _get_circuit_breaker_impl,
    get_circuit_breaker_stats as _get_circuit_breaker_stats_impl,
    reset_circuit_breakers as _reset_circuit_breakers_impl,
)
from .unified_handler_retry_support import (
    calculate_retry_delay as _calculate_retry_delay_impl,
    fallback_execution as _fallback_execution_impl,
    retry_execution as _retry_execution_impl,
)

logger = get_logger(__name__)


def _get_circuit_breaker(func_id: str, policy: ErrorPolicy) -> CircuitBreakerState:
    """Get or create circuit breaker for function"""
    return _get_circuit_breaker_impl(func_id, policy, logger)


def _calculate_retry_delay(attempt: int, policy: ErrorPolicy) -> float:
    """Calculate delay before retry using exponential backoff with optional jitter"""
    return _calculate_retry_delay_impl(attempt, policy)


def _retry_execution(
    func: Callable, policy: ErrorPolicy, func_args: tuple, func_kwargs: dict
) -> Any:
    return _retry_execution_impl(func, policy, func_args, func_kwargs, logger)


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
        logger.debug("Circuit breaker open for %s, returning fallback", func_id)
        if policy.fallback_value is not None:
            return policy.fallback_value
        raise RuntimeError(f"Circuit breaker open for {func_id}")

    # Use the standard retry logic, then record a single success/failure
    # on the circuit breaker. This keeps threshold semantics simple:
    # circuit_threshold counts function invocations, not individual attempts.
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
    return _fallback_execution_impl(func, policy, func_args, func_kwargs, logger)


@overload
def handle_errors(policy: ErrorPolicy) -> Callable[[Callable[..., Any]], Callable[..., Any]]: ...


@overload
def handle_errors(policy: ErrorPolicy, func: Callable[..., Any]) -> Callable[..., Any]: ...


def handle_errors(
    policy: ErrorPolicy, func: Callable[..., Any] | None = None
) -> Callable[..., Any] | Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Unified error handling decorator

    This decorator consolidates retry logic, circuit breaker, and fallback
    strategies based on the provided policy configuration.

    Args:
        policy: ErrorPolicy configuration defining handling strategy
        func: Optional function to decorate (allows @handle_errors(policy) syntax)

    Returns:
        Decorator function or decorated function

    Example:
        @handle_errors(ErrorPolicy(ErrorHandlingStrategy.RETRY, max_retries=3))
        def get_data():
            return risky_operation()

        @handle_errors(ErrorPolicy(ErrorHandlingStrategy.FALLBACK, fallback_value={}))
        def get_metadata():
            return parse_metadata()
    """

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        # Create unique identifier for this function
        func_id = f"{fn.__module__}.{fn.__qualname__}"

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                # Select execution strategy based on policy
                match policy.strategy:
                    case ErrorHandlingStrategy.FAIL_FAST:
                        return fn(*args, **kwargs)
                    case ErrorHandlingStrategy.RETRY:
                        return _retry_execution(fn, policy, args, kwargs)
                    case ErrorHandlingStrategy.FALLBACK:
                        return _fallback_execution(fn, policy, args, kwargs)
                    case ErrorHandlingStrategy.CIRCUIT_BREAK:
                        return _circuit_break_execution(fn, policy, args, kwargs, func_id)
                    case _ as unreachable:
                        assert_never(unreachable)

            except Exception as e:
                # Log error details for debugging
                logger.debug(
                    f"Error in {func_id}: {type(e).__name__}: {e}",
                    extra={
                        "function": fn.__name__,
                        "module": fn.__module__,
                        "strategy": policy.strategy.value,
                    },
                )
                raise

        return wrapper

    # Support both @handle_errors(policy) and @handle_errors(policy, func) syntax
    if func is not None:
        return decorator(func)
    return decorator


def reset_circuit_breakers() -> None:
    """Reset all circuit breakers to closed state"""
    _reset_circuit_breakers_impl(logger)


def get_circuit_breaker_stats() -> dict[str, Any]:
    """
    Get statistics for all circuit breakers

    Returns:
        Dictionary mapping function IDs to circuit state information
    """
    return _get_circuit_breaker_stats_impl()
