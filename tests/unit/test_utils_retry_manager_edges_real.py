from __future__ import annotations

import pytest

from r2inspect.utils.retry_manager import RetryConfig, RetryManager, RetryStrategy, retry_on_failure


def test_retry_manager_jitter_delay() -> None:
    manager = RetryManager()
    config = RetryConfig(strategy=RetryStrategy.FIXED_DELAY, base_delay=0.1, jitter=True)
    delay = manager.calculate_delay(1, config)
    assert delay >= 0.01


def test_retry_on_failure_wrapper_paths() -> None:
    calls = {"count": 0}

    @retry_on_failure(auto_retry=False)
    def _cmd(*_args, **_kwargs) -> str:
        calls["count"] += 1
        return _kwargs.get("command", "ok")

    assert _cmd(None, "ij") == "ij"
    with pytest.raises(TypeError):
        _cmd(None, command="ij")
    assert calls["count"] == 1

    @retry_on_failure(auto_retry=True)
    def _fail(_ctx, command: str) -> None:
        raise ValueError("boom")

    with pytest.raises(ValueError):
        _fail(None, "ij")
