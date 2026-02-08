from __future__ import annotations

from r2inspect.error_handling.policies import ErrorHandlingStrategy
from r2inspect.error_handling.presets import _empty_dict, _empty_list, create_custom_policy


def test_empty_helpers():
    assert _empty_list() == []
    assert _empty_dict() == {}


def test_create_custom_policy_defaults_and_overrides():
    policy = create_custom_policy(ErrorHandlingStrategy.RETRY, max_retries=4, retry_delay=1.0)
    assert policy.strategy == ErrorHandlingStrategy.RETRY
    assert policy.max_retries == 4
    assert policy.retry_delay == 1.0
