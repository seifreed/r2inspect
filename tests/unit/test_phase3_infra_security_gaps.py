"""Infrastructure and security gap tests (phase 3).

Real objects, hand-rolled subclass doubles, and plain stubs only.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any, cast

import pytest

from r2inspect.registry import AnalyzerCategory
from r2inspect.registry.analyzer_registry import AnalyzerMetadata, AnalyzerRegistry
from r2inspect.registry.metadata_extraction import auto_extract_metadata
from r2inspect.infrastructure.circuit_breaker import CircuitBreaker, CircuitState
from r2inspect.schemas.results_loader import _load_timestamp
from r2inspect.schemas.results_models import AnalysisResult
from r2inspect.infrastructure.memory import MemoryLimits, MemoryMonitor
from r2inspect.infrastructure.rate_limiter import AdaptiveRateLimiter, BatchRateLimiter, TokenBucket
from r2inspect.infrastructure.retry_manager import RetryConfig, RetryManager, RetryStrategy


class _ProbeAnalyzer:
    __name__ = "_ProbeAnalyzer"

    def __init__(self, **_: Any) -> None:
        pass

    def get_category(self) -> str:
        return "format"

    def get_supported_formats(self) -> set[str]:
        return {"PE"}

    def get_description(self) -> str:
        return "auto"


class _NoopAnalyzer:
    def analyze(self) -> dict[str, Any]:
        return {"available": True}

    __name__ = "_NoopAnalyzer"


class _NoneClassRegistry(AnalyzerRegistry):
    """Registry double whose get_analyzer_class always resolves to None, to
    drive the 'missing analyzer class' skip branches via a real subclass."""

    def get_analyzer_class(self, name: str) -> type | None:
        return None


class _NoRetryManager(RetryManager):
    """RetryManager whose retry decision is always 'do not retry'."""

    def _handle_retry_exception(
        self, exc: Exception, attempt: int, config: RetryConfig, kwargs: dict[str, Any]
    ) -> bool:
        return False


class _CountingRetryManager(RetryManager):
    """RetryManager that always continues retrying and counts the decisions."""

    def __init__(self) -> None:
        super().__init__()
        self.retry_calls = 0

    def _handle_retry_exception(
        self, exc: Exception, attempt: int, config: RetryConfig, kwargs: dict[str, Any]
    ) -> bool:
        self.retry_calls += 1
        return True


class _RecordingGcMonitor(MemoryMonitor):
    """MemoryMonitor that records _trigger_gc invocations instead of running GC."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.gc_calls: list[bool] = []

    def _trigger_gc(self, aggressive: bool = False, *, collect_fn: Any | None = None) -> None:
        self.gc_calls.append(True)


class _FixedStatsMonitor(MemoryMonitor):
    """MemoryMonitor returning canned stats so is_memory_available is
    exercised without touching real psutil."""

    def check_memory(self, force: bool = False) -> dict[str, Any]:
        return {
            "process_memory_mb": self.limits.max_process_memory_mb,
            "system_memory_available_mb": 10_000.0,
        }


def test_auto_extract_metadata_keeps_explicit_metadata() -> None:
    category, file_formats, description = auto_extract_metadata(
        _ProbeAnalyzer,
        name="probe",
        category=AnalyzerCategory.FORMAT,
        file_formats={"ELF"},
        description="explicit",
        auto_extract=True,
        is_base_analyzer=lambda _: True,
    )

    assert category is AnalyzerCategory.FORMAT
    assert file_formats == {"ELF"}
    assert description == "explicit"


def test_registry_get_analyzers_for_format_skips_unsupported_format() -> None:
    registry = AnalyzerRegistry(lazy_loading=False)
    registry._analyzers = {
        "supported": AnalyzerMetadata(
            name="supported",
            analyzer_class=_NoopAnalyzer,
            category=AnalyzerCategory.FORMAT,
            file_formats={"PE"},
        ),
        "unsupported": AnalyzerMetadata(
            name="unsupported",
            analyzer_class=_NoopAnalyzer,
            category=AnalyzerCategory.FORMAT,
            file_formats={"ELF"},
        ),
    }

    result = registry.get_analyzers_for_format("PE")

    assert "supported" in result
    assert "unsupported" not in result


def test_registry_get_by_category_skips_missing_analyzer_class() -> None:
    registry = _NoneClassRegistry(lazy_loading=False)
    registry._analyzers = {
        "meta": AnalyzerMetadata(
            name="meta",
            analyzer_class=_NoopAnalyzer,
            category=AnalyzerCategory.METADATA,
        )
    }

    assert registry.get_by_category(AnalyzerCategory.METADATA) == {}


def test_registry_get_required_skips_missing_analyzer_class() -> None:
    registry = _NoneClassRegistry(lazy_loading=False)
    registry._analyzers = {
        "req": AnalyzerMetadata(
            name="req",
            analyzer_class=_NoopAnalyzer,
            category=AnalyzerCategory.FORMAT,
            required=True,
        )
    }

    assert registry.get_required_analyzers() == {}


def test_registry_get_optional_skips_missing_analyzer_class() -> None:
    registry = _NoneClassRegistry(lazy_loading=False)
    registry._analyzers = {
        "opt": AnalyzerMetadata(
            name="opt",
            analyzer_class=_NoopAnalyzer,
            category=AnalyzerCategory.FORMAT,
            required=False,
        )
    }

    assert registry.get_optional_analyzers() == {}


def test_registry_calculate_in_degrees_skips_external_dependency() -> None:
    registry = AnalyzerRegistry(lazy_loading=False)
    graph = {"A": {"B"}}
    in_degree = {"A": 0}

    registry._calculate_in_degrees(graph=graph, in_degree=in_degree, analyzer_names=["A"])

    assert in_degree == {"A": 0}


def test_registry_topological_sort_when_no_dependencies() -> None:
    registry = AnalyzerRegistry(lazy_loading=False)
    order = registry._topological_sort(
        graph={"A": set(), "B": set()},
        in_degree={"A": 0, "B": 0},
        analyzer_names=["A", "B"],
    )

    assert set(order) == {"A", "B"}
    assert len(order) == 2


def test_results_loader_preserves_timestamp_on_unrecognized_type() -> None:
    result = AnalysisResult()
    original_timestamp = result.timestamp

    _load_timestamp(result, {"timestamp": 123})

    assert result.timestamp is original_timestamp


def test_token_bucket_acquire_without_timeout_continues_loop_until_tokens_arrive() -> None:
    bucket = TokenBucket(capacity=2, refill_rate=10.0)
    bucket.tokens = 0.0

    assert bucket.acquire(tokens=2, timeout=None) is True


def test_adaptive_rate_limiter_no_adjustment_branch() -> None:
    limiter = AdaptiveRateLimiter(
        base_rate=10.0,
        memory_threshold=0.8,
        cpu_threshold=0.9,
        system_load_provider=lambda: (0.75, 0.75),
    )
    limiter.last_system_check = 0

    limiter._check_system_load()

    # At 75% memory/CPU the rate may stay same or decrease slightly
    assert limiter.current_rate <= 10.0


def test_batch_rate_limiter_uses_token_bucket_when_adaptive_disabled() -> None:
    limiter = BatchRateLimiter(
        max_concurrent=1, rate_per_second=1.0, burst_size=2, enable_adaptive=False
    )
    assert isinstance(limiter.rate_limiter, TokenBucket)

    assert limiter.acquire(timeout=1.0)
    limiter.release_success()


def test_retry_manager_calculate_delay_random_jitter_strategy() -> None:
    manager = RetryManager()
    config = RetryConfig(
        base_delay=1.0,
        max_delay=2.0,
        strategy=RetryStrategy.RANDOM_JITTER,
        jitter=False,
    )

    delay = manager.calculate_delay(1, config)
    assert 0.0 <= delay <= 2.0


def test_retry_manager_breaks_and_raises_on_no_retry_decision() -> None:
    manager = _NoRetryManager()

    def _always_fails() -> None:
        raise ValueError("forced failure")

    with pytest.raises(ValueError, match="forced failure"):
        manager.retry_operation(
            _always_fails,
            command_type="generic",
            config=RetryConfig(
                max_attempts=1,
                base_delay=0.0,
                strategy=RetryStrategy.FIXED_DELAY,
                jitter=False,
            ),
        )


class _LazyLoaderStub:
    def __init__(self, analyzer_class: type) -> None:
        self._analyzer_class = analyzer_class

    def is_registered(self, _name: str) -> bool:
        return True

    def get_analyzer_class(self, _name: str) -> type:
        return self._analyzer_class


def test_registry_get_analyzer_class_uses_lazy_loader() -> None:
    registry = AnalyzerRegistry(lazy_loading=True)
    registry._analyzers = {
        "lazy": AnalyzerMetadata(
            name="lazy",
            analyzer_class=_NoopAnalyzer,
            category=AnalyzerCategory.HASHING,
        )
    }
    registry._lazy_loader = _LazyLoaderStub(_NoopAnalyzer)

    assert registry.get_analyzer_class("lazy") is _NoopAnalyzer


def test_registry_get_analyzers_for_format_skips_none_class() -> None:
    registry = _NoneClassRegistry(lazy_loading=False)
    registry._analyzers = {
        "skip": AnalyzerMetadata(
            name="skip",
            analyzer_class=_NoopAnalyzer,
            category=AnalyzerCategory.METADATA,
            file_formats={"PE"},
        )
    }
    result = registry.get_analyzers_for_format("PE")
    assert result == {}


def test_registry_topological_sort_appends_only_on_zero_in_degree() -> None:
    registry = AnalyzerRegistry(lazy_loading=False)
    graph = {"A": set(), "B": {"A"}}
    in_degree = {"A": 0, "B": 0}

    order = registry._topological_sort(graph=graph, in_degree=in_degree, analyzer_names=["A", "B"])

    assert order == ["A", "B"]
    assert in_degree["B"] == -1


def test_rate_limiter_batch_acquire_with_no_timeout_takes_non_adaptive_path() -> None:
    limiter = BatchRateLimiter(
        max_concurrent=1, rate_per_second=2.0, burst_size=2, enable_adaptive=False
    )
    assert limiter.acquire(timeout=None) is True
    limiter.release_success()


def test_retry_manager_allows_retry_flow_without_break() -> None:
    manager = _CountingRetryManager()

    def _always_fails() -> None:
        raise ValueError("retry later")

    with pytest.raises(ValueError, match="retry later"):
        manager.retry_operation(
            _always_fails,
            command_type="generic",
            config=RetryConfig(
                max_attempts=2,
                base_delay=0.0,
                strategy=RetryStrategy.FIXED_DELAY,
                jitter=False,
            ),
        )
    assert manager.retry_calls == 2


def test_retry_manager_calculate_delay_unknown_strategy_falls_back_to_generic_jitter() -> None:
    manager = RetryManager()
    config = RetryConfig(base_delay=1.0, max_delay=2.0)
    config.strategy = cast(RetryStrategy, "not-a-strategy")

    delay = manager.calculate_delay(1, config)
    assert 0.0 <= delay <= 2.0


def test_retry_manager_no_attempts_executes_zero_retries_path() -> None:
    manager = RetryManager()

    def _unused() -> str:
        return "should not execute"

    assert (
        manager.retry_operation(_unused, command_type="generic", config=RetryConfig(max_attempts=0))
        is None
    )


def test_circuit_breaker_state_recovery_from_open_to_half_open_to_closed() -> None:
    breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=5.0)

    with pytest.raises(RuntimeError):
        breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("boom")))

    assert breaker.state == CircuitState.OPEN

    # Push the last failure far enough into the past that the real wall clock
    # already satisfies the recovery timeout.
    breaker.last_failure_time = time.time() - (breaker.recovery_timeout + 1.0)
    assert breaker.call(lambda: "ok") == "ok"

    assert breaker.state == CircuitState.CLOSED


def test_memory_monitor_warning_path_calls_callback_and_triggers_gc() -> None:
    limits = MemoryLimits(max_process_memory_mb=1.0, memory_warning_threshold=0.5)
    warned: list[dict[str, object]] = []

    class _Mem:
        rss = int(0.6 * 1024 * 1024)

    monitor = _RecordingGcMonitor(
        limits=limits,
        process=SimpleNamespace(memory_info=lambda: _Mem()),
        system_memory_provider=lambda: SimpleNamespace(
            total=2048 * 1024 * 1024,
            available=1024 * 1024 * 1024,
            percent=10.0,
        ),
    )
    monitor.warning_callback = lambda payload: warned.append(payload)

    stats = monitor.check_memory(force=True)

    assert stats["status"] == "warning"
    assert monitor.memory_warnings == 1
    assert warned
    assert monitor.gc_calls


def test_memory_monitor_is_memory_available_respects_process_limit() -> None:
    monitor = _FixedStatsMonitor(process=SimpleNamespace())

    assert not monitor.is_memory_available(1)
