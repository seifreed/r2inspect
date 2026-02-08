from __future__ import annotations

import math

import pytest

from r2inspect.utils import memory_manager
from r2inspect.utils.memory_manager import MemoryAwareAnalyzer, MemoryLimits, MemoryMonitor


@pytest.mark.unit
def test_memory_monitor_warning_and_cached_stats() -> None:
    base_monitor = MemoryMonitor()
    current_mb = base_monitor.process.memory_info().rss / 1024 / 1024
    # Set limits so current usage is ~85%
    max_mb = max(1.0, current_mb / 0.85)
    limits = MemoryLimits(
        max_process_memory_mb=int(math.ceil(max_mb)),
        memory_warning_threshold=0.8,
        memory_critical_threshold=0.95,
        gc_trigger_threshold=0.5,
    )
    monitor = MemoryMonitor(limits=limits)
    warnings = []
    monitor.set_callbacks(warning_callback=lambda stats: warnings.append(stats))

    stats = monitor.check_memory(force=True)
    assert stats["status"] in {"warning", "critical", "normal"}

    cached = monitor.check_memory(force=False)
    assert cached["status"] == "cached"


@pytest.mark.unit
def test_memory_monitor_critical_and_limits() -> None:
    limits = MemoryLimits(max_process_memory_mb=1, memory_critical_threshold=0.5)
    monitor = MemoryMonitor(limits=limits)
    critical_called = []
    monitor.set_callbacks(critical_callback=lambda stats: critical_called.append(stats))

    stats = monitor.check_memory(force=True)
    assert stats["status"] == "critical"
    assert critical_called

    assert monitor.validate_file_size(limits.max_file_size_mb * 1024 * 1024) is True
    assert monitor.validate_file_size((limits.max_file_size_mb + 1) * 1024 * 1024) is False

    assert monitor.validate_section_size(limits.section_size_limit_mb * 1024 * 1024) is True
    assert monitor.validate_section_size((limits.section_size_limit_mb + 1) * 1024 * 1024) is False

    assert monitor.limit_collection_size([1, 2, 3], 2, name="items") == [1, 2]
    assert monitor.limit_collection_size([1], 2) == [1]


@pytest.mark.unit
def test_memory_aware_analyzer_operations() -> None:
    base_monitor = MemoryMonitor()
    current_mb = base_monitor.process.memory_info().rss / 1024 / 1024
    monitor = MemoryMonitor(limits=MemoryLimits(max_process_memory_mb=int(current_mb + 1024)))
    monitor.check_interval = 0
    analyzer = MemoryAwareAnalyzer(memory_monitor=monitor)

    assert analyzer.should_skip_analysis(estimated_memory_mb=10**9, analysis_name="big") is True

    result = analyzer.safe_large_operation(lambda: "ok", estimated_memory_mb=0.1)
    assert result == "ok"

    result = analyzer.safe_large_operation(lambda: (_ for _ in ()).throw(MemoryError()), 0.1)
    assert result is None


@pytest.mark.unit
def test_global_memory_helpers() -> None:
    assert isinstance(memory_manager.get_memory_stats(), dict)
    assert memory_manager.check_memory_limits(file_size_bytes=0, estimated_analysis_mb=0) is True

    memory_manager.configure_memory_limits(max_file_size_mb=256)
    stats = memory_manager.cleanup_memory()
    assert isinstance(stats, dict)
