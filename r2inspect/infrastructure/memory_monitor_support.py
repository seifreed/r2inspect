"""Helper operations for memory monitoring."""

from __future__ import annotations

from typing import Any, cast


def handle_warning_memory(monitor: Any, stats: dict[str, Any], *, logger: Any) -> None:
    monitor.memory_warnings += 1
    logger.warning(
        f"Memory usage high: {stats['process_memory_mb']:.1f}MB "
        f"({stats['process_usage_percent']:.1%})"
    )
    monitor._trigger_gc()
    if monitor.warning_callback:
        try:
            monitor.warning_callback(stats)
        except Exception as exc:
            logger.error("Error in warning callback: %s", exc)


def handle_critical_memory(monitor: Any, stats: dict[str, Any], *, logger: Any) -> None:
    logger.error(
        f"Critical memory usage: {stats['process_memory_mb']:.1f}MB "
        f"({stats['process_usage_percent']:.1%})"
    )
    monitor._trigger_gc(aggressive=True)
    if monitor.critical_callback:
        try:
            monitor.critical_callback(stats)
        except Exception as exc:
            logger.error("Error in critical callback: %s", exc)


def trigger_gc(collect_garbage: Any, *, aggressive: bool, logger: Any, gc_count: int) -> int:
    if aggressive:
        for _ in range(3):
            collect_garbage()
    else:
        collect_garbage()
    gc_count += 1
    logger.debug("Garbage collection triggered (count: %s)", gc_count)
    return gc_count


def get_cached_stats(
    process: Any, max_process_memory_mb: int, get_error_stats: Any
) -> dict[str, Any]:
    try:
        memory_info = process.memory_info()
        memory_mb = memory_info.rss / 1024 / 1024
        process_usage_percent = memory_mb / max_process_memory_mb
        return {
            "process_memory_mb": memory_mb,
            "process_memory_limit_mb": max_process_memory_mb,
            "process_usage_percent": process_usage_percent,
            "status": "cached",
        }
    except Exception:
        return cast(dict[str, Any], get_error_stats())


def is_memory_available(monitor: Any, required_mb: float) -> bool:
    stats = monitor.check_memory()
    current_mb = float(stats.get("process_memory_mb", 0))
    if current_mb + required_mb > monitor.limits.max_process_memory_mb:
        return False
    system_available = float(stats.get("system_memory_available_mb", 0))
    return required_mb <= system_available * 0.8


def safe_large_operation(
    analyzer: Any,
    operation: Any,
    estimated_memory_mb: float,
    operation_name: str,
    *,
    logger: Any,
) -> Any | None:
    if analyzer.should_skip_analysis(estimated_memory_mb, operation_name):
        return None
    start_stats = analyzer.memory_monitor.check_memory(force=True)
    try:
        logger.debug(
            f"Starting {operation_name} "
            f"(estimated: {estimated_memory_mb:.1f}MB, "
            f"current: {start_stats['process_memory_mb']:.1f}MB)"
        )
        result = operation()
        end_stats = analyzer.memory_monitor.check_memory(force=True)
        actual_used = end_stats["process_memory_mb"] - start_stats["process_memory_mb"]
        logger.debug("Completed %s (actual memory used: %.1fMB)", operation_name, actual_used)
        return result
    except MemoryError:
        logger.error("Memory error during %s", operation_name)
        analyzer.memory_monitor._trigger_gc(aggressive=True)
        return None
    except Exception as exc:
        logger.error("Error during %s: %s", operation_name, exc)
        return None
