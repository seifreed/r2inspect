#!/usr/bin/env python3
"""
Coverage tests for r2inspect/utils/memory_manager.py
"""

import pytest

from r2inspect.utils.memory_manager import (
    MemoryAwareAnalyzer,
    MemoryLimits,
    MemoryMonitor,
    check_memory_limits,
    cleanup_memory,
    configure_memory_limits,
    get_memory_stats,
)


def test_memory_monitor_check_memory_returns_stats():
    monitor = MemoryMonitor()
    stats = monitor.check_memory(force=True)
    assert "process_memory_mb" in stats
    assert stats["process_memory_mb"] > 0
    assert stats["status"] in ("normal", "warning", "critical")


def test_memory_monitor_cached_stats_returned_quickly():
    monitor = MemoryMonitor()
    monitor.check_memory(force=True)
    stats = monitor.check_memory(force=False)
    assert stats["status"] == "cached"


def test_memory_monitor_validate_file_size_within_limit():
    monitor = MemoryMonitor()
    assert monitor.validate_file_size(1024 * 1024) is True  # 1MB


def test_memory_monitor_validate_file_size_exceeds_limit():
    limits = MemoryLimits(max_file_size_mb=1)
    monitor = MemoryMonitor(limits=limits)
    assert monitor.validate_file_size(2 * 1024 * 1024) is False  # 2MB


def test_memory_monitor_validate_section_size_within_limit():
    monitor = MemoryMonitor()
    assert monitor.validate_section_size(1024 * 1024) is True  # 1MB


def test_memory_monitor_validate_section_size_exceeds_limit():
    limits = MemoryLimits(section_size_limit_mb=1)
    monitor = MemoryMonitor(limits=limits)
    assert monitor.validate_section_size(2 * 1024 * 1024) is False


def test_memory_monitor_limit_collection_size_truncates():
    monitor = MemoryMonitor()
    items = list(range(100))
    result = monitor.limit_collection_size(items, 10, "test_items")
    assert len(result) == 10


def test_memory_monitor_limit_collection_size_no_truncation():
    monitor = MemoryMonitor()
    items = list(range(5))
    result = monitor.limit_collection_size(items, 10, "small_list")
    assert result == items


def test_memory_monitor_is_memory_available():
    monitor = MemoryMonitor()
    monitor.last_check = 0  # Force a full check (includes system_memory_available_mb)
    assert monitor.is_memory_available(1.0) is True


def test_memory_monitor_is_memory_unavailable_if_too_large():
    limits = MemoryLimits(max_process_memory_mb=1)
    monitor = MemoryMonitor(limits=limits)
    assert monitor.is_memory_available(9999.0) is False


def test_memory_monitor_warning_callback_called():
    received = {"stats": None}

    def on_warning(stats):
        received["stats"] = stats

    # Process uses ~60MB; set max=10000MB so usage_percent ~0.006
    # warning threshold below usage, critical threshold above usage
    limits = MemoryLimits(
        max_process_memory_mb=10000,
        gc_trigger_threshold=0.0,
        memory_warning_threshold=0.0,
        memory_critical_threshold=0.1,
    )
    monitor = MemoryMonitor(limits=limits)
    monitor.set_callbacks(warning_callback=on_warning)
    monitor.check_memory(force=True)
    assert received["stats"] is not None


def test_memory_monitor_critical_callback_called():
    received = {"stats": None}

    def on_critical(stats):
        received["stats"] = stats

    # Process uses ~60MB; set max=10000MB so usage_percent ~0.006
    # critical threshold at 0.0 ensures critical is triggered
    limits = MemoryLimits(
        max_process_memory_mb=10000,
        memory_warning_threshold=0.0,
        memory_critical_threshold=0.0,
    )
    monitor = MemoryMonitor(limits=limits)
    monitor.set_callbacks(critical_callback=on_critical)
    monitor.check_memory(force=True)
    assert received["stats"] is not None


def test_memory_monitor_gc_trigger():
    limits = MemoryLimits(
        max_process_memory_mb=100000,
        gc_trigger_threshold=0.0,
        memory_warning_threshold=0.9,
        memory_critical_threshold=1.0,
    )
    monitor = MemoryMonitor(limits=limits)
    gc_before = monitor.gc_count
    monitor.check_memory(force=True)
    assert monitor.gc_count > gc_before


def test_memory_aware_analyzer_should_skip_when_insufficient_memory():
    limits = MemoryLimits(max_process_memory_mb=1)
    monitor = MemoryMonitor(limits=limits)
    analyzer = MemoryAwareAnalyzer(memory_monitor=monitor)
    assert analyzer.should_skip_analysis(9999.0, "huge_analysis") is True


def test_memory_aware_analyzer_should_not_skip_small_operation():
    analyzer = MemoryAwareAnalyzer()
    analyzer.memory_monitor.last_check = 0  # Force full check with system_memory_available_mb
    assert analyzer.should_skip_analysis(1.0, "tiny") is False


def test_memory_aware_analyzer_safe_large_operation_returns_result():
    analyzer = MemoryAwareAnalyzer()
    analyzer.memory_monitor.last_check = 0
    result = analyzer.safe_large_operation(lambda: 42, 1.0, "compute")
    assert result == 42


def test_memory_aware_analyzer_safe_large_operation_skipped():
    limits = MemoryLimits(max_process_memory_mb=1)
    monitor = MemoryMonitor(limits=limits)
    analyzer = MemoryAwareAnalyzer(memory_monitor=monitor)
    result = analyzer.safe_large_operation(lambda: 99, 9999.0, "impossible")
    assert result is None


def test_memory_aware_analyzer_safe_large_operation_handles_exception():
    analyzer = MemoryAwareAnalyzer()

    def boom():
        raise RuntimeError("unexpected")

    result = analyzer.safe_large_operation(boom, 1.0, "failing_op")
    assert result is None


def test_memory_aware_analyzer_safe_large_operation_handles_memory_error():
    analyzer = MemoryAwareAnalyzer()

    def oom():
        raise MemoryError("out of memory")

    result = analyzer.safe_large_operation(oom, 1.0, "oom_op")
    assert result is None


def test_get_memory_stats_returns_dict():
    stats = get_memory_stats()
    assert isinstance(stats, dict)
    assert "process_memory_mb" in stats


def test_check_memory_limits_file_too_large():
    configure_memory_limits(max_file_size_mb=1)
    result = check_memory_limits(file_size_bytes=2 * 1024 * 1024)
    assert result is False
    configure_memory_limits(max_file_size_mb=512)


def test_check_memory_limits_within_bounds():
    from r2inspect.utils import memory_manager as mm
    mm.global_memory_monitor.last_check = 0  # Force full check with system stats
    result = check_memory_limits(file_size_bytes=1024, estimated_analysis_mb=1.0)
    assert result is True


def test_check_memory_limits_zero_file_size():
    from r2inspect.utils import memory_manager as mm
    mm.global_memory_monitor.last_check = 0
    result = check_memory_limits(file_size_bytes=0, estimated_analysis_mb=1.0)
    assert result is True


def test_configure_memory_limits_unknown_key_logged():
    # Should not raise, just log a warning
    configure_memory_limits(nonexistent_key=999)


def test_cleanup_memory_returns_stats():
    stats = cleanup_memory()
    assert isinstance(stats, dict)
    assert "process_memory_mb" in stats


def test_warning_callback_exception_handled():
    def bad_callback(stats):
        raise RuntimeError("callback error")

    limits = MemoryLimits(
        max_process_memory_mb=10000,
        gc_trigger_threshold=0.0,
        memory_warning_threshold=0.0,
        memory_critical_threshold=0.1,
    )
    monitor = MemoryMonitor(limits=limits)
    monitor.set_callbacks(warning_callback=bad_callback)
    # Should not raise
    monitor.check_memory(force=True)


def test_critical_callback_exception_handled():
    def bad_callback(stats):
        raise RuntimeError("critical callback error")

    limits = MemoryLimits(
        max_process_memory_mb=10000,
        memory_warning_threshold=0.0,
        memory_critical_threshold=0.0,
    )
    monitor = MemoryMonitor(limits=limits)
    monitor.set_callbacks(critical_callback=bad_callback)
    # Should not raise
    monitor.check_memory(force=True)
