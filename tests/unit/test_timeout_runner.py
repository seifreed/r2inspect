"""Tests for the shared daemon-thread timeout runner."""

from __future__ import annotations

import time

from r2inspect.infrastructure.timeout_runner import run_with_timeout


def test_run_with_timeout_returns_value_on_success() -> None:
    completed, value, error = run_with_timeout(lambda: 42, timeout=1.0)
    assert completed is True
    assert value == 42
    assert error is None


def test_run_with_timeout_captures_exception() -> None:
    def _boom() -> int:
        raise ValueError("boom")

    completed, value, error = run_with_timeout(_boom, timeout=1.0)
    assert completed is True
    assert value is None
    assert isinstance(error, ValueError)
    assert str(error) == "boom"


def test_run_with_timeout_reports_incomplete_on_timeout() -> None:
    # The worker sleeps far longer than the join window; the join returns while
    # the daemon thread is still alive, so completed is False.
    completed, value, error = run_with_timeout(lambda: time.sleep(5), timeout=0.01)
    assert completed is False
    assert value is None
    assert error is None
