"""Branch-path coverage for r2inspect/error_handling/policies.py."""

from __future__ import annotations

import pytest

from r2inspect.error_handling.policies import ErrorHandlingStrategy, ErrorPolicy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fallback_policy(**kwargs) -> ErrorPolicy:
    defaults = dict(
        strategy=ErrorHandlingStrategy.FALLBACK,
        max_retries=3,
        retry_delay=1.0,
        retry_backoff=2.0,
        circuit_threshold=5,
        circuit_timeout=60,
    )
    defaults.update(kwargs)
    return ErrorPolicy(**defaults)


# ---------------------------------------------------------------------------
# __post_init__ validation – each error branch (lines 66, 69, 72, 75, 78)
# ---------------------------------------------------------------------------


def test_post_init_raises_when_max_retries_is_negative():
    with pytest.raises(ValueError, match="max_retries"):
        ErrorPolicy(
            strategy=ErrorHandlingStrategy.FALLBACK,
            max_retries=-1,
        )


def test_post_init_raises_when_retry_delay_is_negative():
    with pytest.raises(ValueError, match="retry_delay"):
        ErrorPolicy(
            strategy=ErrorHandlingStrategy.FALLBACK,
            retry_delay=-0.1,
        )


def test_post_init_raises_when_retry_backoff_below_one():
    with pytest.raises(ValueError, match="retry_backoff"):
        ErrorPolicy(
            strategy=ErrorHandlingStrategy.FALLBACK,
            retry_backoff=0.5,
        )


def test_post_init_raises_when_circuit_threshold_is_zero():
    with pytest.raises(ValueError, match="circuit_threshold"):
        ErrorPolicy(
            strategy=ErrorHandlingStrategy.FALLBACK,
            circuit_threshold=0,
        )


def test_post_init_raises_when_circuit_timeout_is_negative():
    with pytest.raises(ValueError, match="circuit_timeout"):
        ErrorPolicy(
            strategy=ErrorHandlingStrategy.FALLBACK,
            circuit_timeout=-1,
        )


def test_post_init_accepts_zero_max_retries():
    policy = _fallback_policy(max_retries=0)
    assert policy.max_retries == 0


def test_post_init_accepts_zero_retry_delay():
    policy = _fallback_policy(retry_delay=0.0)
    assert policy.retry_delay == 0.0


def test_post_init_accepts_exactly_one_retry_backoff():
    policy = _fallback_policy(retry_backoff=1.0)
    assert policy.retry_backoff == 1.0


def test_post_init_accepts_one_circuit_threshold():
    policy = _fallback_policy(circuit_threshold=1)
    assert policy.circuit_threshold == 1


def test_post_init_accepts_zero_circuit_timeout():
    policy = _fallback_policy(circuit_timeout=0)
    assert policy.circuit_timeout == 0


# ---------------------------------------------------------------------------
# is_retryable (lines 91-100)
# ---------------------------------------------------------------------------


def test_is_retryable_returns_true_for_exception_in_retryable_set():
    policy = _fallback_policy(retryable_exceptions={ValueError, RuntimeError})
    assert policy.is_retryable(ValueError("oops")) is True
    assert policy.is_retryable(RuntimeError("boom")) is True


def test_is_retryable_returns_false_for_exception_in_fatal_set():
    policy = _fallback_policy(
        retryable_exceptions={Exception},
        fatal_exceptions={KeyboardInterrupt},
    )
    assert policy.is_retryable(KeyboardInterrupt()) is False


def test_is_retryable_fatal_takes_priority_over_retryable():
    policy = _fallback_policy(
        retryable_exceptions={Exception},
        fatal_exceptions={OSError},
    )
    assert policy.is_retryable(OSError("disk full")) is False


def test_is_retryable_returns_false_when_exception_not_in_any_set():
    policy = _fallback_policy(
        retryable_exceptions={ValueError},
        fatal_exceptions=set(),
    )
    assert policy.is_retryable(TypeError("wrong type")) is False


def test_is_retryable_returns_true_for_subclass_of_retryable():
    policy = _fallback_policy(retryable_exceptions={Exception})
    assert policy.is_retryable(FileNotFoundError("not found")) is True


def test_is_retryable_returns_true_default_retryable_set_matches_exception():
    # Default retryable_exceptions = {Exception}, so any Exception is retryable
    policy = _fallback_policy()
    assert policy.is_retryable(RuntimeError("err")) is True


def test_is_retryable_empty_retryable_set_returns_false():
    policy = _fallback_policy(retryable_exceptions=set())
    assert policy.is_retryable(RuntimeError("err")) is False


# ---------------------------------------------------------------------------
# copy_with_overrides (lines 112-121)
# ---------------------------------------------------------------------------


def test_copy_with_overrides_returns_new_policy_instance():
    original = _fallback_policy(max_retries=3)
    copy = original.copy_with_overrides(max_retries=5)
    assert copy is not original
    assert copy.max_retries == 5
    assert original.max_retries == 3


def test_copy_with_overrides_changes_only_specified_attribute():
    original = _fallback_policy(max_retries=3, retry_delay=1.0)
    copy = original.copy_with_overrides(retry_delay=2.5)
    assert copy.retry_delay == 2.5
    assert copy.max_retries == 3


def test_copy_with_overrides_raises_for_unknown_attribute():
    original = _fallback_policy()
    with pytest.raises(AttributeError, match="nonexistent_attr"):
        original.copy_with_overrides(nonexistent_attr=99)


def test_copy_with_overrides_does_not_mutate_original_retryable_exceptions():
    original = _fallback_policy(retryable_exceptions={ValueError})
    copy = original.copy_with_overrides(retryable_exceptions={RuntimeError})
    assert ValueError in original.retryable_exceptions
    assert RuntimeError in copy.retryable_exceptions


def test_copy_with_overrides_strategy_can_be_changed():
    original = _fallback_policy(strategy=ErrorHandlingStrategy.FALLBACK)
    copy = original.copy_with_overrides(strategy=ErrorHandlingStrategy.RETRY)
    assert copy.strategy == ErrorHandlingStrategy.RETRY
    assert original.strategy == ErrorHandlingStrategy.FALLBACK


def test_copy_with_overrides_multiple_attributes_at_once():
    original = _fallback_policy(max_retries=2, retry_delay=1.0, retry_backoff=2.0)
    copy = original.copy_with_overrides(max_retries=10, retry_delay=0.5)
    assert copy.max_retries == 10
    assert copy.retry_delay == 0.5
    assert copy.retry_backoff == 2.0
