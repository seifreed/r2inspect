import time

from r2inspect.utils.memory_manager import MemoryAwareAnalyzer, MemoryLimits, MemoryMonitor


def test_validate_file_and_section_size():
    limits = MemoryLimits(max_file_size_mb=1, section_size_limit_mb=1)
    monitor = MemoryMonitor(limits)

    assert monitor.validate_file_size(512 * 1024) is True
    assert monitor.validate_file_size(2 * 1024 * 1024) is False

    assert monitor.validate_section_size(512 * 1024) is True
    assert monitor.validate_section_size(2 * 1024 * 1024) is False


def test_limit_collection_size_truncates():
    monitor = MemoryMonitor(MemoryLimits())
    data = list(range(10))
    assert monitor.limit_collection_size(data, 5) == list(range(5))
    assert monitor.limit_collection_size(data, 20) == data


def test_check_memory_returns_stats():
    monitor = MemoryMonitor(MemoryLimits(max_process_memory_mb=2048))
    stats = monitor.check_memory(force=True)
    assert "process_memory_mb" in stats
    assert "status" in stats


def test_is_memory_available_respects_limits():
    limits = MemoryLimits(max_process_memory_mb=1)
    monitor = MemoryMonitor(limits)
    assert monitor.is_memory_available(10_000) is False


def test_safe_large_operation_executes_when_available():
    limits = MemoryLimits(max_process_memory_mb=2048)
    monitor = MemoryMonitor(limits)
    monitor.check_interval = 0.0
    analyzer = MemoryAwareAnalyzer(monitor)

    def op():
        time.sleep(0.01)
        return "ok"

    assert analyzer.safe_large_operation(op, estimated_memory_mb=0.001) == "ok"
