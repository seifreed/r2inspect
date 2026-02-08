from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from r2inspect.utils import circuit_breaker, rate_limiter, retry_manager


class _R2Stub:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[str] = []

    def cmd(self, command: str) -> str:
        self.calls.append(command)
        if self.fail:
            raise RuntimeError("boom")
        return f"text:{command}"

    def cmdj(self, command: str) -> Any:
        self.calls.append(command)
        if self.fail:
            raise RuntimeError("boom")
        return {"cmd": command}


def test_token_bucket_basic_and_timeout() -> None:
    bucket = rate_limiter.TokenBucket(capacity=1, refill_rate=0.0)
    assert bucket.acquire(tokens=1, timeout=0.01)
    assert bucket.acquire(tokens=1, timeout=0.01) is False


def test_adaptive_rate_limiter_adjusts_rate() -> None:
    limiter = rate_limiter.AdaptiveRateLimiter(
        base_rate=1.0, max_rate=2.0, min_rate=0.5, memory_threshold=0.0, cpu_threshold=0.0
    )
    before = limiter.current_rate
    limiter._check_system_load()
    assert limiter.current_rate <= before

    limiter.memory_threshold = 0.99
    limiter.cpu_threshold = 0.99
    limiter._check_system_load()
    assert limiter.current_rate <= limiter.max_rate

    limiter.record_success()
    limiter.record_error("err")
    stats = limiter.get_stats()
    assert stats["bucket_capacity"] > 0


def test_batch_rate_limiter_concurrency() -> None:
    limiter = rate_limiter.BatchRateLimiter(
        max_concurrent=1, rate_per_second=100.0, burst_size=1, enable_adaptive=False
    )
    assert limiter.acquire(timeout=0.05)

    result_holder: list[bool] = []

    def _attempt() -> None:
        result_holder.append(limiter.acquire(timeout=0.01))

    thread = threading.Thread(target=_attempt)
    thread.start()
    thread.join()
    assert result_holder == [False]

    limiter.release_success()
    assert limiter.acquire(timeout=0.05)
    limiter.release_error("fail")
    stats = limiter.get_stats()
    assert stats["files_processed"] == 1
    assert stats["files_failed"] == 1


def test_cleanup_memory() -> None:
    info = rate_limiter.cleanup_memory()
    assert info is None or ("rss_mb" in info and "vms_mb" in info)


def test_retry_manager_success_and_timeout() -> None:
    manager = retry_manager.RetryManager()

    calls: list[int] = []

    def _op() -> str:
        calls.append(1)
        if len(calls) < 2:
            raise RuntimeError("timeout occurred")
        return "ok"

    config = retry_manager.RetryConfig(
        max_attempts=3,
        base_delay=0.001,
        max_delay=0.001,
        strategy=retry_manager.RetryStrategy.FIXED_DELAY,
        jitter=False,
    )
    assert manager.retry_operation(_op, command_type="generic", config=config) == "ok"

    timeout_config = retry_manager.RetryConfig(
        max_attempts=2,
        base_delay=0.01,
        max_delay=0.01,
        strategy=retry_manager.RetryStrategy.FIXED_DELAY,
        jitter=False,
        timeout=0.001,
    )

    def _always_fail() -> None:
        raise RuntimeError("timeout occurred")

    with pytest.raises(TimeoutError):
        manager.retry_operation(_always_fail, command_type="generic", config=timeout_config)


def test_retry_decorator_and_stats() -> None:
    retry_manager.reset_retry_stats()

    @retry_manager.retry_on_failure(command_type="generic")
    def _op(_cmd: str, **_kwargs: Any) -> str:
        raise RuntimeError("timeout occurred")

    with pytest.raises(RuntimeError):
        _op("aaa")

    stats = retry_manager.get_retry_stats()
    assert stats["total_retries"] >= 1


def test_circuit_breaker_and_command_wrapper() -> None:
    breaker = circuit_breaker.CircuitBreaker(failure_threshold=1, recovery_timeout=0.01)

    def _fail() -> None:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        breaker.call(_fail)

    with pytest.raises(circuit_breaker.CircuitBreakerError):
        breaker.call(lambda: "nope")

    time.sleep(0.02)
    assert breaker.call(lambda: "ok") == "ok"

    wrapper = circuit_breaker.R2CommandCircuitBreaker()
    r2 = _R2Stub(fail=True)
    assert wrapper.execute_command(r2, "ij", "analysis") is None
    assert wrapper.execute_command(r2, "i", "analysis") == ""

    r2_ok = _R2Stub(fail=False)
    assert wrapper.execute_command(r2_ok, "ij", "analysis") == {"cmd": "ij"}
    assert wrapper.execute_command(r2_ok, "i", "analysis") == "text:i"

    stats = wrapper.get_stats()
    assert "breaker_analysis" in stats
