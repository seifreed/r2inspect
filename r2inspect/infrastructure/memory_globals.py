"""Process-wide singleton accessors and helpers for ``MemoryMonitor``.

Kept separate from ``memory.py`` so the facade module stays under its line
budget while still re-exporting the public surface.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from .logging import get_logger
from .proxying import LazyProxy

if TYPE_CHECKING:
    from .memory import MemoryMonitor

logger = get_logger(__name__)

_global_memory_monitor: MemoryMonitor | None = None


def get_global_memory_monitor() -> MemoryMonitor:
    """Return the lazily-created global MemoryMonitor singleton."""
    global _global_memory_monitor
    if _global_memory_monitor is None:
        from .memory import MemoryMonitor as _MM

        _global_memory_monitor = _MM()
    return _global_memory_monitor


global_memory_monitor: MemoryMonitor = cast("MemoryMonitor", LazyProxy(get_global_memory_monitor))


def get_memory_stats() -> dict[str, Any]:
    return get_global_memory_monitor().check_memory()


def check_memory_limits(file_size_bytes: int = 0, estimated_analysis_mb: float = 0) -> bool:
    monitor = get_global_memory_monitor()
    if file_size_bytes > 0 and not monitor.validate_file_size(file_size_bytes):
        return False
    return estimated_analysis_mb <= 0 or monitor.is_memory_available(estimated_analysis_mb)


def configure_memory_limits(**kwargs: Any) -> None:
    monitor = get_global_memory_monitor()
    for key, value in kwargs.items():
        if hasattr(monitor.limits, key):
            setattr(monitor.limits, key, value)
            logger.info("Updated memory limit %s = %s", key, value)
        else:
            logger.warning("Unknown memory limit: %s", key)


def cleanup_memory() -> dict[str, Any]:
    monitor = get_global_memory_monitor()
    monitor._trigger_gc(aggressive=True)
    return monitor.check_memory(force=True)


__all__ = [
    "check_memory_limits",
    "cleanup_memory",
    "configure_memory_limits",
    "get_global_memory_monitor",
    "get_memory_stats",
    "global_memory_monitor",
]
