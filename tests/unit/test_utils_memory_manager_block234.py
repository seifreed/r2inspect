from __future__ import annotations

from typing import Any

from r2inspect.utils.memory_manager import (
    MemoryAwareAnalyzer,
    MemoryLimits,
    MemoryMonitor,
    check_memory_limits,
    cleanup_memory,
    configure_memory_limits,
    global_memory_monitor,
)


def test_memory_monitor_basic_checks() -> None:
    limits = MemoryLimits(
        max_process_memory_mb=0.001, memory_warning_threshold=0.1, memory_critical_threshold=0.2
    )
    monitor = MemoryMonitor(limits)
    warnings: list[dict[str, Any]] = []
    criticals: list[dict[str, Any]] = []
    monitor.set_callbacks(warning_callback=warnings.append, critical_callback=criticals.append)

    stats = monitor.check_memory(force=True)
    assert stats["status"] in {"warning", "critical", "normal"}
    if stats["status"] == "critical":
        assert criticals
    elif stats["status"] == "warning":
        assert warnings

    cached = monitor.check_memory(force=False)
    assert cached["status"] in {"cached", "warning", "critical", "normal"}


def test_memory_monitor_limits_and_truncation() -> None:
    limits = MemoryLimits(max_process_memory_mb=1024, max_file_size_mb=1, section_size_limit_mb=1)
    monitor = MemoryMonitor(limits)

    assert monitor.validate_file_size(512 * 1024) is True
    assert monitor.validate_file_size(2 * 1024 * 1024) is False

    assert monitor.validate_section_size(512 * 1024) is True
    assert monitor.validate_section_size(2 * 1024 * 1024) is False

    data = list(range(10))
    assert monitor.limit_collection_size(data, 5, name="items") == list(range(5))
    assert monitor.limit_collection_size(data, 20, name="items") == data


def test_memory_aware_analyzer_operations() -> None:
    low_limits = MemoryLimits(max_process_memory_mb=0.001)
    low_monitor = MemoryMonitor(low_limits)
    analyzer = MemoryAwareAnalyzer(low_monitor)

    def op() -> str:
        return "ok"

    assert (
        analyzer.safe_large_operation(op, estimated_memory_mb=1.0, operation_name="heavy") is None
    )

    high_limits = MemoryLimits(max_process_memory_mb=4096)
    high_monitor = MemoryMonitor(high_limits)
    analyzer_ok = MemoryAwareAnalyzer(high_monitor)
    assert (
        analyzer_ok.safe_large_operation(op, estimated_memory_mb=0.0, operation_name="light")
        == "ok"
    )


def test_global_memory_helpers() -> None:
    original_limits = global_memory_monitor.limits
    try:
        configure_memory_limits(max_process_memory_mb=1024)
        assert check_memory_limits(file_size_bytes=0, estimated_analysis_mb=0) is True
        stats = cleanup_memory()
        assert "process_memory_mb" in stats
    finally:
        global_memory_monitor.limits = original_limits
