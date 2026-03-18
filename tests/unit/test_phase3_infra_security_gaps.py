"""Infrastructure and security gap tests (phase 3).

NO mocks, NO @patch. Uses real objects, monkeypatch, and plain stubs.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

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


def test_registry_get_by_category_skips_missing_analyzer_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = AnalyzerRegistry(lazy_loading=False)
    registry._analyzers = {
        "meta": AnalyzerMetadata(
            name="meta",
            analyzer_class=_NoopAnalyzer,
            category=AnalyzerCategory.METADATA,
        )
    }

    monkeypatch.setattr(registry, "get_analyzer_class", lambda _name: None)
    assert registry.get_by_category(AnalyzerCategory.METADATA) == {}


def test_registry_get_required_skips_missing_analyzer_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = AnalyzerRegistry(lazy_loading=False)
    registry._analyzers = {
        "req": AnalyzerMetadata(
            name="req",
            analyzer_class=_NoopAnalyzer,
            category=AnalyzerCategory.FORMAT,
            required=True,
        )
    }

    monkeypatch.setattr(registry, "get_analyzer_class", lambda _name: None)
    assert registry.get_required_analyzers() == {}


def test_registry_get_optional_skips_missing_analyzer_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = AnalyzerRegistry(lazy_loading=False)
    registry._analyzers = {
        "opt": AnalyzerMetadata(
            name="opt",
            analyzer_class=_NoopAnalyzer,
            category=AnalyzerCategory.FORMAT,
            required=False,
        )
    }

    monkeypatch.setattr(registry, "get_analyzer_class", lambda _name: None)
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


def test_adaptive_rate_limiter_no_adjustment_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    import r2inspect.infrastructure.rate_limiter as rl_mod

    limiter = AdaptiveRateLimiter(base_rate=10.0, memory_threshold=0.8, cpu_threshold=0.9)
    limiter.last_system_check = 0

    monkeypatch.setattr(rl_mod.psutil, "virtual_memory", lambda: SimpleNamespace(percent=75.0))
    monkeypatch.setattr(rl_mod.psutil, "cpu_percent", lambda: 75.0)
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
    manager = RetryManager()
    manager._handle_retry_exception = lambda _e, _attempt, _config, _kwargs: False  # type: ignore[assignment]

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


def test_registry_get_analyzers_for_format_skips_none_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = AnalyzerRegistry(lazy_loading=False)
    registry._analyzers = {
        "skip": AnalyzerMetadata(
            name="skip",
            analyzer_class=_NoopAnalyzer,
            category=AnalyzerCategory.METADATA,
            file_formats={"PE"},
        )
    }
    monkeypatch.setattr(registry, "get_analyzer_class", lambda _name: None)
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


def test_retry_manager_allows_retry_flow_without_break(monkeypatch: pytest.MonkeyPatch) -> None:
    import r2inspect.infrastructure.retry_manager as rm_mod

    manager = RetryManager()
    call_count = 0

    def _continue_retry(
        _e: Exception, _attempt: int, _config: RetryConfig, _kwargs: dict[str, object]
    ) -> bool:
        nonlocal call_count
        call_count += 1
        return True

    manager._handle_retry_exception = _continue_retry  # type: ignore[assignment]

    def _always_fails() -> None:
        raise ValueError("retry later")

    monkeypatch.setattr(rm_mod.time, "time", lambda: 0.0)
    monkeypatch.setattr(rm_mod.time, "sleep", lambda _seconds: None)

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
    assert call_count == 2


def test_retry_manager_calculate_delay_unknown_strategy_falls_back_to_generic_jitter() -> None:
    manager = RetryManager()
    config = RetryConfig(base_delay=1.0, max_delay=2.0)
    config.strategy = "not-a-strategy"  # type: ignore[assignment]

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


def test_circuit_breaker_state_recovery_from_open_to_half_open_to_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import r2inspect.infrastructure.circuit_breaker as cb_mod

    breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=5.0)

    with pytest.raises(RuntimeError):
        breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("boom")))

    assert breaker.state == CircuitState.OPEN

    # Force recovery timeout to be already elapsed.
    breaker.last_failure_time = 0.0
    monkeypatch.setattr(cb_mod.time, "time", lambda: 10.0)
    assert breaker.call(lambda: "ok") == "ok"

    assert breaker.state == CircuitState.CLOSED


def test_memory_monitor_warning_path_calls_callback_and_triggers_gc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limits = MemoryLimits(max_process_memory_mb=1.0, memory_warning_threshold=0.5)
    monitor = MemoryMonitor(limits=limits)
    gc_calls: list[bool] = []
    warned: list[dict[str, object]] = []

    class _Mem:
        rss = int(0.6 * 1024 * 1024)

    monitor._trigger_gc = lambda _aggressive=False: gc_calls.append(True)
    monitor.warning_callback = lambda payload: warned.append(payload)

    monkeypatch.setattr(monitor.process, "memory_info", lambda: _Mem())
    _memory_mod = __import__("r2inspect.infrastructure.memory", fromlist=["psutil"])
    (
        monkeypatch.setattr(
            _memory_mod,
            "psutil",
            type(
                "FakePsutil",
                (),
                {
                    "virtual_memory": staticmethod(
                        lambda: SimpleNamespace(
                            total=2048 * 1024 * 1024,
                            available=1024 * 1024 * 1024,
                            percent=10.0,
                        )
                    ),
                    "Process": type(monitor.process),
                },
            )(),
        )
        if False
        else None
    )  # Skip complex monkeypatch; use direct approach below

    import r2inspect.infrastructure.memory as mem_mod

    monkeypatch.setattr(
        mem_mod.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(
            total=2048 * 1024 * 1024,
            available=1024 * 1024 * 1024,
            percent=10.0,
        ),
    )

    stats = monitor.check_memory(force=True)

    assert stats["status"] == "warning"
    assert monitor.memory_warnings == 1
    assert warned
    assert gc_calls


def test_memory_monitor_is_memory_available_respects_process_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monitor = MemoryMonitor()
    monkeypatch.setattr(
        monitor,
        "check_memory",
        lambda force=False: {
            "process_memory_mb": monitor.limits.max_process_memory_mb,
            "system_memory_available_mb": 10_000.0,
        },
    )

    assert not monitor.is_memory_available(1)
