"""Tests for memory_manager.py covering missing branch paths."""

from __future__ import annotations

import gc

import pytest

from r2inspect.utils.memory_manager import (
    MemoryAwareAnalyzer,
    MemoryLimits,
    MemoryMonitor,
    check_memory_limits,
    cleanup_memory,
    configure_memory_limits,
    get_memory_stats,
    global_memory_monitor,
)


# ---------------------------------------------------------------------------
# MemoryLimits dataclass defaults
# ---------------------------------------------------------------------------


def test_memory_limits_defaults():
    limits = MemoryLimits()
    assert limits.max_process_memory_mb == 2048
    assert limits.max_file_size_mb == 512
    assert limits.memory_warning_threshold == 0.8
    assert limits.memory_critical_threshold == 0.9
    assert limits.gc_trigger_threshold == 0.75
    assert limits.section_size_limit_mb == 100
    assert limits.string_limit == 50000
    assert limits.function_limit == 10000


def test_memory_limits_custom_values():
    limits = MemoryLimits(max_process_memory_mb=512, max_file_size_mb=100)
    assert limits.max_process_memory_mb == 512
    assert limits.max_file_size_mb == 100


# ---------------------------------------------------------------------------
# MemoryMonitor.check_memory - forced full check
# ---------------------------------------------------------------------------


def test_check_memory_force_returns_full_stats():
    monitor = MemoryMonitor()
    stats = monitor.check_memory(force=True)

    assert "process_memory_mb" in stats
    assert "process_memory_limit_mb" in stats
    assert "process_usage_percent" in stats
    assert "system_memory_total_mb" in stats
    assert "system_memory_available_mb" in stats
    assert "system_usage_percent" in stats
    assert "peak_memory_mb" in stats
    assert "memory_warnings" in stats
    assert "gc_count" in stats
    assert "status" in stats


def test_check_memory_status_is_normal_with_large_limit():
    limits = MemoryLimits(max_process_memory_mb=999999)
    monitor = MemoryMonitor(limits)
    stats = monitor.check_memory(force=True)
    assert stats["status"] == "normal"


def test_check_memory_updates_peak_memory():
    monitor = MemoryMonitor()
    monitor.peak_memory_mb = 0.0
    stats = monitor.check_memory(force=True)
    assert stats["peak_memory_mb"] > 0


def test_check_memory_interval_returns_cached():
    monitor = MemoryMonitor()
    monitor.check_interval = 9999.0
    monitor.check_memory(force=True)

    cached = monitor.check_memory(force=False)
    assert cached["status"] == "cached"


def test_check_memory_cached_stats_has_process_memory():
    monitor = MemoryMonitor()
    monitor.check_interval = 9999.0
    monitor.check_memory(force=True)

    stats = monitor.check_memory(force=False)
    assert stats["process_memory_mb"] > 0
    assert "process_usage_percent" in stats


# ---------------------------------------------------------------------------
# MemoryMonitor - warning threshold path
# ---------------------------------------------------------------------------


def test_check_memory_warning_threshold_triggers_gc():
    limits = MemoryLimits(
        max_process_memory_mb=999999,
        gc_trigger_threshold=0.0,
        memory_warning_threshold=0.0,
        memory_critical_threshold=0.9,
    )
    monitor = MemoryMonitor(limits)
    before_gc = monitor.gc_count

    stats = monitor.check_memory(force=True)

    assert stats["status"] == "warning"
    assert monitor.memory_warnings >= 1
    assert monitor.gc_count > before_gc


def test_check_memory_warning_calls_warning_callback():
    received = []

    def on_warning(stats):
        received.append(stats)

    limits = MemoryLimits(
        max_process_memory_mb=999999,
        gc_trigger_threshold=0.0,
        memory_warning_threshold=0.0,
        memory_critical_threshold=0.9,
    )
    monitor = MemoryMonitor(limits)
    monitor.set_callbacks(warning_callback=on_warning)

    monitor.check_memory(force=True)

    assert len(received) >= 1
    assert "process_memory_mb" in received[0]


def test_check_memory_warning_callback_exception_is_swallowed():
    def bad_callback(stats):
        raise RuntimeError("callback exploded")

    limits = MemoryLimits(
        max_process_memory_mb=999999,
        gc_trigger_threshold=0.0,
        memory_warning_threshold=0.0,
        memory_critical_threshold=0.9,
    )
    monitor = MemoryMonitor(limits)
    monitor.set_callbacks(warning_callback=bad_callback)

    stats = monitor.check_memory(force=True)
    assert stats["status"] == "warning"


# ---------------------------------------------------------------------------
# MemoryMonitor - critical threshold path
# ---------------------------------------------------------------------------


def test_check_memory_critical_threshold_status():
    limits = MemoryLimits(
        max_process_memory_mb=999999,
        gc_trigger_threshold=0.0,
        memory_warning_threshold=0.0,
        memory_critical_threshold=0.0,
    )
    monitor = MemoryMonitor(limits)

    stats = monitor.check_memory(force=True)
    assert stats["status"] == "critical"


def test_check_memory_critical_calls_critical_callback():
    received = []

    def on_critical(stats):
        received.append(stats)

    limits = MemoryLimits(
        max_process_memory_mb=999999,
        gc_trigger_threshold=0.0,
        memory_warning_threshold=0.0,
        memory_critical_threshold=0.0,
    )
    monitor = MemoryMonitor(limits)
    monitor.set_callbacks(critical_callback=on_critical)

    monitor.check_memory(force=True)

    assert len(received) >= 1


def test_check_memory_critical_callback_exception_is_swallowed():
    def bad_callback(stats):
        raise RuntimeError("critical exploded")

    limits = MemoryLimits(
        max_process_memory_mb=999999,
        gc_trigger_threshold=0.0,
        memory_warning_threshold=0.0,
        memory_critical_threshold=0.0,
    )
    monitor = MemoryMonitor(limits)
    monitor.set_callbacks(critical_callback=bad_callback)

    stats = monitor.check_memory(force=True)
    assert stats["status"] == "critical"


# ---------------------------------------------------------------------------
# MemoryMonitor._trigger_gc
# ---------------------------------------------------------------------------


def test_trigger_gc_non_aggressive_increments_count():
    monitor = MemoryMonitor()
    before = monitor.gc_count
    monitor._trigger_gc(aggressive=False)
    assert monitor.gc_count == before + 1


def test_trigger_gc_aggressive_increments_count():
    monitor = MemoryMonitor()
    before = monitor.gc_count
    monitor._trigger_gc(aggressive=True)
    assert monitor.gc_count == before + 1


# ---------------------------------------------------------------------------
# MemoryMonitor._get_error_stats
# ---------------------------------------------------------------------------


def test_get_error_stats_returns_zero_memory():
    monitor = MemoryMonitor()
    stats = monitor._get_error_stats()

    assert stats["process_memory_mb"] == 0.0
    assert stats["process_usage_percent"] == 0.0
    assert stats["status"] == "error"
    assert "process_memory_limit_mb" in stats


# ---------------------------------------------------------------------------
# MemoryMonitor.is_memory_available
# ---------------------------------------------------------------------------


def test_is_memory_available_false_when_would_exceed_process_limit():
    limits = MemoryLimits(max_process_memory_mb=1)
    monitor = MemoryMonitor(limits)
    assert monitor.is_memory_available(999999.0) is False


def test_is_memory_available_true_for_small_amount():
    limits = MemoryLimits(max_process_memory_mb=999999)
    monitor = MemoryMonitor(limits)
    monitor.check_memory(force=True)  # Populate system_memory_available_mb in cache
    monitor.check_interval = 9999.0   # Keep interval high so next call uses cached stats
    # Force a new full check to include system_memory_available_mb
    monitor.last_check = 0.0
    assert monitor.is_memory_available(0.001) is True


def test_is_memory_available_false_when_exceeds_system_memory():
    limits = MemoryLimits(max_process_memory_mb=999999)
    monitor = MemoryMonitor(limits)
    assert monitor.is_memory_available(999999999.0) is False


# ---------------------------------------------------------------------------
# MemoryMonitor.validate_file_size
# ---------------------------------------------------------------------------


def test_validate_file_size_within_limit_returns_true():
    limits = MemoryLimits(max_file_size_mb=10)
    monitor = MemoryMonitor(limits)
    assert monitor.validate_file_size(5 * 1024 * 1024) is True


def test_validate_file_size_at_limit_returns_true():
    limits = MemoryLimits(max_file_size_mb=10)
    monitor = MemoryMonitor(limits)
    assert monitor.validate_file_size(10 * 1024 * 1024) is True


def test_validate_file_size_exceeds_limit_returns_false():
    limits = MemoryLimits(max_file_size_mb=1)
    monitor = MemoryMonitor(limits)
    assert monitor.validate_file_size(2 * 1024 * 1024) is False


def test_validate_file_size_zero_returns_true():
    monitor = MemoryMonitor()
    assert monitor.validate_file_size(0) is True


# ---------------------------------------------------------------------------
# MemoryMonitor.validate_section_size
# ---------------------------------------------------------------------------


def test_validate_section_size_within_limit_returns_true():
    limits = MemoryLimits(section_size_limit_mb=100)
    monitor = MemoryMonitor(limits)
    assert monitor.validate_section_size(50 * 1024 * 1024) is True


def test_validate_section_size_exceeds_limit_returns_false():
    limits = MemoryLimits(section_size_limit_mb=1)
    monitor = MemoryMonitor(limits)
    assert monitor.validate_section_size(2 * 1024 * 1024) is False


# ---------------------------------------------------------------------------
# MemoryMonitor.limit_collection_size
# ---------------------------------------------------------------------------


def test_limit_collection_size_truncates_large_collection():
    monitor = MemoryMonitor()
    items = list(range(100))
    result = monitor.limit_collection_size(items, 50, "test_items")
    assert len(result) == 50
    assert result == list(range(50))


def test_limit_collection_size_keeps_small_collection():
    monitor = MemoryMonitor()
    items = list(range(5))
    result = monitor.limit_collection_size(items, 10, "small")
    assert result == items


def test_limit_collection_size_empty_collection():
    monitor = MemoryMonitor()
    result = monitor.limit_collection_size([], 10, "empty")
    assert result == []


def test_limit_collection_size_exact_max():
    monitor = MemoryMonitor()
    items = list(range(10))
    result = monitor.limit_collection_size(items, 10, "exact")
    assert result == items


# ---------------------------------------------------------------------------
# MemoryMonitor.set_callbacks
# ---------------------------------------------------------------------------


def test_set_callbacks_assigns_warning_callback():
    monitor = MemoryMonitor()
    cb = lambda s: None
    monitor.set_callbacks(warning_callback=cb)
    assert monitor.warning_callback is cb


def test_set_callbacks_assigns_critical_callback():
    monitor = MemoryMonitor()
    cb = lambda s: None
    monitor.set_callbacks(critical_callback=cb)
    assert monitor.critical_callback is cb


def test_set_callbacks_none_clears_callbacks():
    monitor = MemoryMonitor()
    monitor.set_callbacks(warning_callback=lambda s: None)
    monitor.set_callbacks(warning_callback=None)
    assert monitor.warning_callback is None


# ---------------------------------------------------------------------------
# MemoryAwareAnalyzer.should_skip_analysis
# ---------------------------------------------------------------------------


def test_should_skip_analysis_false_when_memory_available():
    limits = MemoryLimits(max_process_memory_mb=999999)
    monitor = MemoryMonitor(limits)
    monitor.last_check = 0.0  # Force full check so system_memory_available_mb is populated
    analyzer = MemoryAwareAnalyzer(monitor)

    result = analyzer.should_skip_analysis(0.001, "tiny_analysis")
    assert result is False


def test_should_skip_analysis_true_when_memory_unavailable():
    limits = MemoryLimits(max_process_memory_mb=1)
    monitor = MemoryMonitor(limits)
    analyzer = MemoryAwareAnalyzer(monitor)

    result = analyzer.should_skip_analysis(999999.0, "huge_analysis")
    assert result is True


# ---------------------------------------------------------------------------
# MemoryAwareAnalyzer.safe_large_operation
# ---------------------------------------------------------------------------


def test_safe_large_operation_runs_when_memory_available():
    limits = MemoryLimits(max_process_memory_mb=999999)
    monitor = MemoryMonitor(limits)
    monitor.last_check = 0.0  # Force full check so system_memory_available_mb is populated
    analyzer = MemoryAwareAnalyzer(monitor)

    def op():
        return "computed"

    result = analyzer.safe_large_operation(op, estimated_memory_mb=0.001, operation_name="test_op")
    assert result == "computed"


def test_safe_large_operation_returns_none_when_skipped():
    limits = MemoryLimits(max_process_memory_mb=1)
    monitor = MemoryMonitor(limits)
    analyzer = MemoryAwareAnalyzer(monitor)

    result = analyzer.safe_large_operation(lambda: "x", estimated_memory_mb=999999.0)
    assert result is None


def test_safe_large_operation_returns_none_on_memory_error():
    limits = MemoryLimits(max_process_memory_mb=999999)
    monitor = MemoryMonitor(limits)
    analyzer = MemoryAwareAnalyzer(monitor)

    def op():
        raise MemoryError("out of memory")

    result = analyzer.safe_large_operation(op, estimated_memory_mb=0.001, operation_name="oom_op")
    assert result is None


def test_safe_large_operation_returns_none_on_generic_exception():
    limits = MemoryLimits(max_process_memory_mb=999999)
    monitor = MemoryMonitor(limits)
    analyzer = MemoryAwareAnalyzer(monitor)

    def op():
        raise ValueError("unexpected error")

    result = analyzer.safe_large_operation(op, estimated_memory_mb=0.001, operation_name="err_op")
    assert result is None


def test_memory_aware_analyzer_default_monitor():
    analyzer = MemoryAwareAnalyzer()
    assert analyzer.memory_monitor is not None
    assert isinstance(analyzer.memory_monitor, MemoryMonitor)


# ---------------------------------------------------------------------------
# Global utility functions
# ---------------------------------------------------------------------------


def test_get_memory_stats_returns_dict():
    stats = get_memory_stats()
    assert isinstance(stats, dict)
    assert "process_memory_mb" in stats


def test_check_memory_limits_no_args_returns_true():
    result = check_memory_limits()
    assert result is True


def test_check_memory_limits_small_file_returns_true():
    result = check_memory_limits(file_size_bytes=1024)
    assert result is True


def test_check_memory_limits_large_file_returns_false():
    result = check_memory_limits(file_size_bytes=999 * 1024 * 1024 * 1024)
    assert result is False


def test_check_memory_limits_small_analysis_returns_true():
    global_memory_monitor.last_check = 0.0  # Force full check to populate system memory stats
    result = check_memory_limits(estimated_analysis_mb=0.001)
    assert result is True


def test_check_memory_limits_huge_analysis_returns_false():
    result = check_memory_limits(estimated_analysis_mb=999999999.0)
    assert result is False


def test_configure_memory_limits_updates_known_key():
    original = global_memory_monitor.limits.max_file_size_mb
    try:
        configure_memory_limits(max_file_size_mb=256)
        assert global_memory_monitor.limits.max_file_size_mb == 256
    finally:
        configure_memory_limits(max_file_size_mb=original)


def test_configure_memory_limits_ignores_unknown_key():
    configure_memory_limits(nonexistent_key=42)


def test_cleanup_memory_returns_stats():
    stats = cleanup_memory()
    assert isinstance(stats, dict)
    assert "process_memory_mb" in stats
    assert "status" in stats
