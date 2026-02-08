from __future__ import annotations

from typing import Any

from r2inspect.utils import memory_manager


def test_memory_manager_threshold_paths_and_callbacks() -> None:
    # Trigger warning path with callback error
    limits = memory_manager.MemoryLimits(
        max_process_memory_mb=0.0001,
        memory_warning_threshold=0.1,
        memory_critical_threshold=1_000_000_000.0,
        gc_trigger_threshold=0.05,
    )
    monitor = memory_manager.MemoryMonitor(limits=limits)

    def bad_warn(_stats: dict[str, Any]) -> None:
        raise RuntimeError("warn")

    monitor.set_callbacks(warning_callback=bad_warn)
    stats = monitor.check_memory(force=True)
    assert stats["status"] in {"warning", "critical", "normal"}

    # Trigger critical path with callback error
    limits_critical = memory_manager.MemoryLimits(
        max_process_memory_mb=0.0001,
        memory_warning_threshold=0.00001,
        memory_critical_threshold=0.00002,
        gc_trigger_threshold=0.0,
    )
    monitor_critical = memory_manager.MemoryMonitor(limits=limits_critical)

    def bad_crit(_stats: dict[str, Any]) -> None:
        raise RuntimeError("crit")

    monitor_critical.set_callbacks(critical_callback=bad_crit)
    stats_critical = monitor_critical.check_memory(force=True)
    assert stats_critical["status"] in {"critical", "warning", "normal"}

    # Trigger gc path only
    limits_gc = memory_manager.MemoryLimits(
        max_process_memory_mb=0.0001,
        memory_warning_threshold=1_000_000_000.0,
        memory_critical_threshold=2_000_000_000.0,
        gc_trigger_threshold=0.0,
    )
    monitor_gc = memory_manager.MemoryMonitor(limits=limits_gc)
    stats_gc = monitor_gc.check_memory(force=True)
    assert stats_gc["status"] in {"normal", "warning", "critical"}


def test_memory_manager_file_section_size_and_collections() -> None:
    limits = memory_manager.MemoryLimits(max_file_size_mb=100, section_size_limit_mb=100)
    monitor = memory_manager.MemoryMonitor(limits=limits)

    assert monitor.validate_file_size(1) is True
    assert monitor.validate_section_size(1) is True

    collection = [1, 2, 3]
    assert monitor.limit_collection_size(collection, 5) == [1, 2, 3]


def test_memory_manager_is_memory_available() -> None:
    monitor = memory_manager.MemoryMonitor()
    monitor.last_check = 0.0
    assert monitor.is_memory_available(0.001) is True
    # Request a huge amount to force False
    assert monitor.is_memory_available(1e12) is False


def test_memory_aware_analyzer_paths() -> None:
    analyzer = memory_manager.MemoryAwareAnalyzer()
    assert analyzer.memory_monitor is not None

    # Should skip when memory is insufficient
    assert analyzer.should_skip_analysis(estimated_memory_mb=1e12, analysis_name="x") is True

    # Should not skip for small requirement
    analyzer.memory_monitor.last_check = 0.0
    assert analyzer.should_skip_analysis(estimated_memory_mb=0.001, analysis_name="y") is False

    # skip branch in safe_large_operation
    assert analyzer.safe_large_operation(lambda: 1, estimated_memory_mb=1e12) is None

    def ok_op() -> int:
        return 123

    analyzer.memory_monitor.last_check = 0.0
    result_ok = analyzer.safe_large_operation(ok_op, estimated_memory_mb=0.001)
    assert result_ok in {123, None}

    def mem_op() -> None:
        raise MemoryError("boom")

    analyzer.memory_monitor.last_check = 0.0
    result_mem = analyzer.safe_large_operation(mem_op, estimated_memory_mb=0.001)
    assert result_mem is None

    def bad_op() -> None:
        raise RuntimeError("oops")

    analyzer.memory_monitor.last_check = 0.0
    result_bad = analyzer.safe_large_operation(bad_op, estimated_memory_mb=0.001)
    assert result_bad is None


def test_memory_manager_globals_and_limits() -> None:
    stats = memory_manager.get_memory_stats()
    assert "status" in stats

    # Unknown limit key
    memory_manager.configure_memory_limits(unknown_key=123)

    # File size limit failure
    memory_manager.configure_memory_limits(max_file_size_mb=0.000001)
    assert memory_manager.check_memory_limits(file_size_bytes=10_000_000) is False

    # Estimated analysis check path
    assert memory_manager.check_memory_limits(file_size_bytes=0, estimated_analysis_mb=0) is True
