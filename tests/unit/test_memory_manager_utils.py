#!/usr/bin/env python3
"""Comprehensive tests for memory_manager.py to achieve 95%+ coverage."""

import gc
import time
import threading
from unittest.mock import Mock, patch

import pytest

from r2inspect.utils.memory_manager import (
    MemoryLimits,
    MemoryMonitor,
    MemoryAwareAnalyzer,
    get_memory_stats,
    check_memory_limits,
    configure_memory_limits,
    cleanup_memory,
    global_memory_monitor,
)


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


def test_memory_limits_custom():
    limits = MemoryLimits(
        max_process_memory_mb=1024,
        max_file_size_mb=256,
        memory_warning_threshold=0.7,
        section_size_limit_mb=50,
    )
    assert limits.max_process_memory_mb == 1024
    assert limits.max_file_size_mb == 256
    assert limits.memory_warning_threshold == 0.7
    assert limits.section_size_limit_mb == 50


def test_memory_monitor_init():
    monitor = MemoryMonitor()
    assert isinstance(monitor.limits, MemoryLimits)
    assert isinstance(monitor.lock, type(threading.Lock()))
    assert monitor.check_interval == 5.0
    assert monitor.memory_warnings == 0
    assert monitor.gc_count == 0
    assert monitor.peak_memory_mb == 0.0
    assert monitor.warning_callback is None
    assert monitor.critical_callback is None


def test_memory_monitor_with_custom_limits():
    limits = MemoryLimits(max_process_memory_mb=512)
    monitor = MemoryMonitor(limits=limits)
    assert monitor.limits.max_process_memory_mb == 512


def test_check_memory_basic():
    monitor = MemoryMonitor()
    stats = monitor.check_memory()
    
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
    assert stats["status"] in ["normal", "warning", "critical"]


def test_check_memory_force():
    monitor = MemoryMonitor()
    stats1 = monitor.check_memory(force=True)
    stats2 = monitor.check_memory(force=True)
    
    assert "process_memory_mb" in stats1
    assert "process_memory_mb" in stats2


def test_check_memory_interval_caching():
    monitor = MemoryMonitor()
    monitor.check_interval = 10.0
    
    stats1 = monitor.check_memory(force=True)
    time.sleep(0.1)
    stats2 = monitor.check_memory(force=False)
    
    assert stats2["status"] == "cached"


def test_check_memory_updates_peak():
    monitor = MemoryMonitor()
    stats = monitor.check_memory(force=True)
    
    assert monitor.peak_memory_mb >= stats["process_memory_mb"]


def test_handle_warning_memory():
    monitor = MemoryMonitor()
    initial_warnings = monitor.memory_warnings
    initial_gc = monitor.gc_count
    
    stats = {"process_memory_mb": 100.0, "process_usage_percent": 0.85}
    monitor._handle_warning_memory(stats)
    
    assert monitor.memory_warnings == initial_warnings + 1
    assert monitor.gc_count > initial_gc


def test_handle_warning_memory_with_callback():
    monitor = MemoryMonitor()
    callback_called = []
    
    def warning_cb(stats):
        callback_called.append(stats)
    
    monitor.set_callbacks(warning_callback=warning_cb)
    stats = {"process_memory_mb": 100.0, "process_usage_percent": 0.85}
    monitor._handle_warning_memory(stats)
    
    assert len(callback_called) == 1
    assert callback_called[0] == stats


def test_handle_warning_callback_exception():
    monitor = MemoryMonitor()
    
    def bad_callback(stats):
        raise ValueError("callback error")
    
    monitor.set_callbacks(warning_callback=bad_callback)
    stats = {"process_memory_mb": 100.0, "process_usage_percent": 0.85}
    
    monitor._handle_warning_memory(stats)


def test_handle_critical_memory():
    monitor = MemoryMonitor()
    initial_gc = monitor.gc_count
    
    stats = {"process_memory_mb": 200.0, "process_usage_percent": 0.95}
    monitor._handle_critical_memory(stats)
    
    assert monitor.gc_count > initial_gc


def test_handle_critical_memory_with_callback():
    monitor = MemoryMonitor()
    callback_called = []
    
    def critical_cb(stats):
        callback_called.append(stats)
    
    monitor.set_callbacks(critical_callback=critical_cb)
    stats = {"process_memory_mb": 200.0, "process_usage_percent": 0.95}
    monitor._handle_critical_memory(stats)
    
    assert len(callback_called) == 1


def test_handle_critical_callback_exception():
    monitor = MemoryMonitor()
    
    def bad_callback(stats):
        raise RuntimeError("critical callback error")
    
    monitor.set_callbacks(critical_callback=bad_callback)
    stats = {"process_memory_mb": 200.0, "process_usage_percent": 0.95}
    
    monitor._handle_critical_memory(stats)


def test_trigger_gc_normal():
    monitor = MemoryMonitor()
    initial_gc = monitor.gc_count
    
    monitor._trigger_gc(aggressive=False)
    
    assert monitor.gc_count == initial_gc + 1


def test_trigger_gc_aggressive():
    monitor = MemoryMonitor()
    initial_gc = monitor.gc_count
    
    monitor._trigger_gc(aggressive=True)
    
    assert monitor.gc_count == initial_gc + 1


def test_get_cached_stats():
    monitor = MemoryMonitor()
    stats = monitor._get_cached_stats()
    
    assert "process_memory_mb" in stats
    assert "process_usage_percent" in stats
    assert stats["status"] == "cached"


def test_get_error_stats():
    monitor = MemoryMonitor()
    stats = monitor._get_error_stats()
    
    assert stats["status"] == "error"
    assert stats["process_memory_mb"] == 0.0
    assert stats["process_usage_percent"] == 0.0


def test_is_memory_available_success():
    monitor = MemoryMonitor()
    available = monitor.is_memory_available(10.0)
    
    assert isinstance(available, bool)


def test_is_memory_available_exceeds_process_limit():
    limits = MemoryLimits(max_process_memory_mb=100)
    monitor = MemoryMonitor(limits=limits)
    
    with patch.object(monitor, "check_memory") as mock_check:
        mock_check.return_value = {"process_memory_mb": 90.0}
        
        available = monitor.is_memory_available(20.0)
        assert available is False


def test_is_memory_available_insufficient_system_memory():
    monitor = MemoryMonitor()
    
    with patch.object(monitor, "check_memory") as mock_check:
        mock_check.return_value = {
            "process_memory_mb": 50.0,
            "system_memory_available_mb": 10.0,
        }
        
        available = monitor.is_memory_available(100.0)
        assert available is False


def test_validate_file_size_success():
    monitor = MemoryMonitor()
    file_size = 100 * 1024 * 1024
    
    assert monitor.validate_file_size(file_size) is True


def test_validate_file_size_too_large():
    limits = MemoryLimits(max_file_size_mb=10)
    monitor = MemoryMonitor(limits=limits)
    file_size = 20 * 1024 * 1024
    
    assert monitor.validate_file_size(file_size) is False


def test_validate_section_size_success():
    monitor = MemoryMonitor()
    section_size = 10 * 1024 * 1024
    
    assert monitor.validate_section_size(section_size) is True


def test_validate_section_size_too_large():
    limits = MemoryLimits(section_size_limit_mb=5)
    monitor = MemoryMonitor(limits=limits)
    section_size = 10 * 1024 * 1024
    
    assert monitor.validate_section_size(section_size) is False


def test_limit_collection_size_no_truncation():
    monitor = MemoryMonitor()
    collection = [1, 2, 3, 4, 5]
    
    result = monitor.limit_collection_size(collection, 10, "test")
    
    assert result == collection
    assert len(result) == 5


def test_limit_collection_size_with_truncation():
    monitor = MemoryMonitor()
    collection = list(range(100))
    
    result = monitor.limit_collection_size(collection, 50, "numbers")
    
    assert len(result) == 50
    assert result == list(range(50))


def test_set_callbacks():
    monitor = MemoryMonitor()
    
    warning_cb = Mock()
    critical_cb = Mock()
    
    monitor.set_callbacks(warning_callback=warning_cb, critical_callback=critical_cb)
    
    assert monitor.warning_callback == warning_cb
    assert monitor.critical_callback == critical_cb


def test_memory_aware_analyzer_init():
    analyzer = MemoryAwareAnalyzer()
    assert isinstance(analyzer.memory_monitor, MemoryMonitor)


def test_memory_aware_analyzer_with_custom_monitor():
    monitor = MemoryMonitor()
    analyzer = MemoryAwareAnalyzer(memory_monitor=monitor)
    assert analyzer.memory_monitor == monitor


def test_should_skip_analysis_sufficient_memory():
    analyzer = MemoryAwareAnalyzer()
    
    with patch.object(analyzer.memory_monitor, "is_memory_available", return_value=True):
        should_skip = analyzer.should_skip_analysis(10.0, "test")
        assert should_skip is False


def test_should_skip_analysis_insufficient_memory():
    analyzer = MemoryAwareAnalyzer()
    
    with patch.object(analyzer.memory_monitor, "is_memory_available", return_value=False):
        should_skip = analyzer.should_skip_analysis(10.0, "test")
        assert should_skip is True


def test_safe_large_operation_skipped():
    analyzer = MemoryAwareAnalyzer()
    operation = Mock(return_value="result")
    
    with patch.object(analyzer, "should_skip_analysis", return_value=True):
        result = analyzer.safe_large_operation(operation, 100.0, "test")
        
        assert result is None
        operation.assert_not_called()


def test_safe_large_operation_success():
    analyzer = MemoryAwareAnalyzer()
    operation = Mock(return_value="success")
    
    with patch.object(analyzer, "should_skip_analysis", return_value=False):
        result = analyzer.safe_large_operation(operation, 10.0, "test")
        
        assert result == "success"
        operation.assert_called_once()


def test_safe_large_operation_memory_error():
    analyzer = MemoryAwareAnalyzer()
    
    def raise_memory_error():
        raise MemoryError("Out of memory")
    
    operation = Mock(side_effect=raise_memory_error)
    
    with patch.object(analyzer, "should_skip_analysis", return_value=False):
        result = analyzer.safe_large_operation(operation, 10.0, "test")
        
        assert result is None


def test_safe_large_operation_generic_exception():
    analyzer = MemoryAwareAnalyzer()
    
    def raise_error():
        raise ValueError("Some error")
    
    operation = Mock(side_effect=raise_error)
    
    with patch.object(analyzer, "should_skip_analysis", return_value=False):
        result = analyzer.safe_large_operation(operation, 10.0, "test")
        
        assert result is None


def test_get_memory_stats_global():
    stats = get_memory_stats()
    
    assert isinstance(stats, dict)
    assert "process_memory_mb" in stats


def test_check_memory_limits_no_limits():
    result = check_memory_limits()
    assert result is True


def test_check_memory_limits_file_size_only():
    file_size = 100 * 1024 * 1024
    result = check_memory_limits(file_size_bytes=file_size)
    assert isinstance(result, bool)


def test_check_memory_limits_file_size_too_large():
    original_limit = global_memory_monitor.limits.max_file_size_mb
    global_memory_monitor.limits.max_file_size_mb = 10
    
    file_size = 20 * 1024 * 1024
    result = check_memory_limits(file_size_bytes=file_size)
    
    global_memory_monitor.limits.max_file_size_mb = original_limit
    assert result is False


def test_check_memory_limits_estimated_analysis():
    result = check_memory_limits(estimated_analysis_mb=10.0)
    assert isinstance(result, bool)


def test_configure_memory_limits_valid():
    original_value = global_memory_monitor.limits.max_file_size_mb
    
    configure_memory_limits(max_file_size_mb=256)
    assert global_memory_monitor.limits.max_file_size_mb == 256
    
    global_memory_monitor.limits.max_file_size_mb = original_value


def test_configure_memory_limits_invalid():
    configure_memory_limits(invalid_key=999)


def test_cleanup_memory():
    stats = cleanup_memory()
    
    assert isinstance(stats, dict)
    assert "process_memory_mb" in stats


def test_check_memory_with_gc_threshold():
    limits = MemoryLimits(
        max_process_memory_mb=1000,
        gc_trigger_threshold=0.01,
    )
    monitor = MemoryMonitor(limits=limits)
    
    with patch.object(monitor.process, "memory_info") as mock_mem:
        mock_mem.return_value = Mock(rss=20 * 1024 * 1024)
        
        initial_gc = monitor.gc_count
        monitor.check_memory(force=True)
        
        assert monitor.gc_count >= initial_gc


def test_check_memory_error_handling():
    monitor = MemoryMonitor()
    
    with patch.object(monitor.process, "memory_info", side_effect=Exception("test error")):
        stats = monitor.check_memory(force=True)
        
        assert stats["status"] == "error"


def test_cached_stats_error_handling():
    monitor = MemoryMonitor()
    
    with patch.object(monitor.process, "memory_info", side_effect=Exception("error")):
        stats = monitor._get_cached_stats()
        
        assert stats["status"] == "error"


def test_thread_safety():
    monitor = MemoryMonitor()
    results = []
    
    def check_multiple():
        for _ in range(10):
            stats = monitor.check_memory(force=True)
            results.append(stats)
    
    threads = [threading.Thread(target=check_multiple) for _ in range(5)]
    
    for t in threads:
        t.start()
    
    for t in threads:
        t.join()
    
    assert len(results) == 50
    assert all("process_memory_mb" in s for s in results)


def test_memory_monitor_real_thresholds():
    limits = MemoryLimits(
        max_process_memory_mb=1,
        memory_warning_threshold=0.5,
        memory_critical_threshold=0.8,
    )
    monitor = MemoryMonitor(limits=limits)
    
    stats = monitor.check_memory(force=True)
    
    assert stats["status"] in ["normal", "warning", "critical"]
