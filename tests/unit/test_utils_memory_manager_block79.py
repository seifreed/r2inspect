from __future__ import annotations

from r2inspect.utils.memory_manager import (
    MemoryAwareAnalyzer,
    MemoryLimits,
    MemoryMonitor,
    check_memory_limits,
    cleanup_memory,
    configure_memory_limits,
    get_memory_stats,
)


def test_memory_monitor_thresholds_and_callbacks():
    limits = MemoryLimits(
        max_process_memory_mb=1,
        memory_warning_threshold=0.1,
        memory_critical_threshold=0.2,
        gc_trigger_threshold=0.05,
    )
    monitor = MemoryMonitor(limits=limits)
    flags = {"warn": False, "crit": False}

    def warn_cb(stats):
        flags["warn"] = True

    def crit_cb(stats):
        flags["crit"] = True

    monitor.set_callbacks(warning_callback=warn_cb, critical_callback=crit_cb)
    stats = monitor.check_memory(force=True)
    assert stats["status"] in {"warning", "critical"}
    assert flags["warn"] or flags["crit"]


def test_memory_validation_helpers():
    monitor = MemoryMonitor()
    assert monitor.validate_file_size(1) is True
    assert monitor.validate_section_size(1) is True

    assert monitor.limit_collection_size([1, 2, 3], 2, name="x") == [1, 2]
    assert monitor.limit_collection_size([1], 2, name="x") == [1]


def test_memory_aware_analyzer_operations():
    monitor = MemoryMonitor(MemoryLimits(max_process_memory_mb=1))
    analyzer = MemoryAwareAnalyzer(memory_monitor=monitor)

    # This should skip due to low limits
    assert analyzer.should_skip_analysis(estimated_memory_mb=10, analysis_name="big") is True

    # Operation success path
    monitor2 = MemoryMonitor(MemoryLimits(max_process_memory_mb=1_000_000))
    analyzer2 = MemoryAwareAnalyzer(memory_monitor=monitor2)
    assert analyzer2.safe_large_operation(lambda: 5, estimated_memory_mb=0.0) == 5

    # MemoryError path
    result = analyzer2.safe_large_operation(lambda: (_ for _ in ()).throw(MemoryError()), 0.1)
    assert result is None


def test_global_helpers():
    stats = get_memory_stats()
    assert "process_memory_mb" in stats

    configure_memory_limits(max_process_memory_mb=1024)
    assert check_memory_limits(file_size_bytes=0, estimated_analysis_mb=0) is True

    cleanup = cleanup_memory()
    assert cleanup["status"] in {"normal", "warning", "critical", "cached"}
