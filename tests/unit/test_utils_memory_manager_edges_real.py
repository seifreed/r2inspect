from __future__ import annotations

from r2inspect.utils.memory_manager import MemoryAwareAnalyzer, MemoryMonitor


class _BadProcess:
    def memory_info(self):
        raise RuntimeError("boom")


def test_memory_monitor_thresholds_and_callbacks() -> None:
    monitor = MemoryMonitor()
    monitor.limits.max_process_memory_mb = 0.0001
    monitor.limits.memory_critical_threshold = 0.9
    monitor.limits.memory_warning_threshold = 0.8
    monitor.limits.gc_trigger_threshold = 0.7

    monitor.set_callbacks(
        warning_callback=lambda _stats: (_ for _ in ()).throw(RuntimeError("warn")),
        critical_callback=lambda _stats: (_ for _ in ()).throw(RuntimeError("crit")),
    )
    stats = monitor.check_memory(force=True)
    assert stats["status"] in {"warning", "critical"}


def test_memory_monitor_gc_trigger_and_error_paths() -> None:
    monitor = MemoryMonitor()
    monitor.limits.max_process_memory_mb = 10**9
    monitor.limits.memory_critical_threshold = 1.0
    monitor.limits.memory_warning_threshold = 1.0
    monitor.limits.gc_trigger_threshold = 0.0
    stats = monitor.check_memory(force=True)
    assert stats["status"] in {"normal", "warning", "critical"}

    monitor.process = _BadProcess()
    error_stats = monitor.check_memory(force=True)
    assert error_stats["status"] == "error"
    assert monitor._get_cached_stats()["status"] == "error"


def test_memory_monitor_limits_and_safe_ops() -> None:
    monitor = MemoryMonitor()
    monitor.limits.max_process_memory_mb = 0.0001
    assert monitor.is_memory_available(1.0) is False
    assert monitor.validate_section_size(1) is True
    assert monitor.limit_collection_size([1, 2], 10) == [1, 2]

    analyzer = MemoryAwareAnalyzer(memory_monitor=monitor)
    assert analyzer.should_skip_analysis(1.0, "x") is True

    def _fail() -> None:
        raise RuntimeError("boom")

    assert analyzer.safe_large_operation(_fail, 0.0, "op") is None
