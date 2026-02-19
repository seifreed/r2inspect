#!/usr/bin/env python3
"""Branch path tests for error handling modules."""

from __future__ import annotations

from r2inspect.error_handling.presets import (
    _empty_dict,
    _empty_list,
    create_custom_policy,
)
from r2inspect.error_handling.policies import ErrorHandlingStrategy
from r2inspect.error_handling.stats import get_error_stats_snapshot


# ---------------------------------------------------------------------------
# presets.py
# ---------------------------------------------------------------------------

def test_empty_list_returns_new_list() -> None:
    """_empty_list returns an empty list."""
    result = _empty_list()
    assert result == []
    assert isinstance(result, list)


def test_empty_dict_returns_new_dict() -> None:
    """_empty_dict returns an empty dict."""
    result = _empty_dict()
    assert result == {}
    assert isinstance(result, dict)


def test_create_custom_policy_retry_strategy() -> None:
    """create_custom_policy builds a valid ErrorPolicy with RETRY strategy."""
    policy = create_custom_policy(
        ErrorHandlingStrategy.RETRY,
        max_retries=5,
        retry_delay=1.0,
    )
    assert policy is not None
    assert policy.strategy == ErrorHandlingStrategy.RETRY
    assert policy.max_retries == 5


def test_create_custom_policy_fallback_strategy_with_value() -> None:
    """create_custom_policy builds a fallback policy returning empty list."""
    policy = create_custom_policy(
        ErrorHandlingStrategy.FALLBACK,
        fallback_value=[],
        max_retries=0,
    )
    assert policy is not None
    assert policy.strategy == ErrorHandlingStrategy.FALLBACK


def test_create_custom_policy_with_kwargs_override() -> None:
    """create_custom_policy accepts extra kwargs to override defaults."""
    policy = create_custom_policy(
        ErrorHandlingStrategy.RETRY,
        max_retries=2,
        retry_delay=2.0,
        retry_backoff=3.0,
    )
    assert policy is not None


# ---------------------------------------------------------------------------
# stats.py
# ---------------------------------------------------------------------------

def test_get_error_stats_snapshot_returns_dict_with_keys() -> None:
    """get_error_stats_snapshot returns a dict with the three expected keys."""
    snapshot = get_error_stats_snapshot()
    assert isinstance(snapshot, dict)
    assert "error_stats" in snapshot
    assert "retry_stats" in snapshot
    assert "circuit_breaker_stats" in snapshot
