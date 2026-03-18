"""Memory monitoring facade."""

from __future__ import annotations

import gc
import os
import threading
import time
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
import psutil

from .logging import get_logger
from .memory_monitor_support import (
    get_cached_stats as _get_cached_stats_impl,
    handle_critical_memory as _handle_critical_memory_impl,
    handle_warning_memory as _handle_warning_memory_impl,
    is_memory_available as _is_memory_available_impl,
    safe_large_operation as _safe_large_operation_impl,
    trigger_gc as _trigger_gc_impl,
)

if TYPE_CHECKING:
    from ..interfaces import MemoryMonitorLike

logger = get_logger(__name__)


def _collect_garbage() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ResourceWarning)
        gc.collect()


@dataclass
class MemoryLimits:
    max_process_memory_mb: int = 2048
    max_file_size_mb: int = 512
    memory_warning_threshold: float = 0.8
    memory_critical_threshold: float = 0.9
    gc_trigger_threshold: float = 0.75
    section_size_limit_mb: int = 100
    string_limit: int = 50000
    function_limit: int = 10000


class MemoryMonitor:
    def __init__(self, limits: MemoryLimits | None = None):
        self.limits = limits or MemoryLimits()
        self.lock = threading.Lock()
        self.process = psutil.Process(os.getpid())
        self.last_check = time.time()
        self.check_interval = 5.0
        self.memory_warnings = 0
        self.gc_count = 0
        self.peak_memory_mb = 0.0
        self.warning_callback: Callable[[dict[str, Any]], Any] | None = None
        self.critical_callback: Callable[[dict[str, Any]], Any] | None = None

    def check_memory(self, force: bool = False) -> dict[str, Any]:
        now = time.time()
        if not force and (now - self.last_check) < self.check_interval:
            return self._get_cached_stats()

        with self.lock:
            try:
                memory_info = self.process.memory_info()
                memory_mb = memory_info.rss / 1024 / 1024
                self.peak_memory_mb = max(self.peak_memory_mb, memory_mb)

                system_memory = psutil.virtual_memory()
                system_memory_mb = system_memory.total / 1024 / 1024
                system_available_mb = system_memory.available / 1024 / 1024
                process_usage_percent = memory_mb / self.limits.max_process_memory_mb
                system_usage_percent = system_memory.percent / 100.0
                self.last_check = now

                stats = {
                    "process_memory_mb": memory_mb,
                    "process_memory_limit_mb": self.limits.max_process_memory_mb,
                    "process_usage_percent": process_usage_percent,
                    "system_memory_total_mb": system_memory_mb,
                    "system_memory_available_mb": system_available_mb,
                    "system_usage_percent": system_usage_percent,
                    "peak_memory_mb": self.peak_memory_mb,
                    "memory_warnings": self.memory_warnings,
                    "gc_count": self.gc_count,
                    "status": "normal",
                }

                if process_usage_percent >= self.limits.memory_critical_threshold:
                    stats["status"] = "critical"
                    self._handle_critical_memory(stats)
                elif process_usage_percent >= self.limits.memory_warning_threshold:
                    stats["status"] = "warning"
                    self._handle_warning_memory(stats)
                elif process_usage_percent >= self.limits.gc_trigger_threshold:
                    self._trigger_gc()

                return stats
            except Exception as exc:
                logger.error("Error checking memory: %s", exc)
                return self._get_error_stats()

    def _handle_warning_memory(self, stats: dict[str, Any]) -> None:
        _handle_warning_memory_impl(self, stats, logger=logger)

    def _handle_critical_memory(self, stats: dict[str, Any]) -> None:
        _handle_critical_memory_impl(self, stats, logger=logger)

    def _trigger_gc(self, aggressive: bool = False) -> None:
        self.gc_count = _trigger_gc_impl(
            _collect_garbage,
            aggressive=aggressive,
            logger=logger,
            gc_count=self.gc_count,
        )

    def _get_cached_stats(self) -> dict[str, Any]:
        return _get_cached_stats_impl(
            self.process,
            self.limits.max_process_memory_mb,
            self._get_error_stats,
        )

    def _get_error_stats(self) -> dict[str, Any]:
        # Report status as "unknown" instead of "normal" (0% usage) to prevent
        # callers from treating memory-check failures as "all is well".
        return {
            "process_memory_mb": 0.0,
            "process_memory_limit_mb": self.limits.max_process_memory_mb,
            "process_usage_percent": 0.0,
            "status": "unknown",
            "memory_check_failed": True,
        }

    def is_memory_available(self, required_mb: float) -> bool:
        return _is_memory_available_impl(self, required_mb)

    def validate_file_size(self, file_size_bytes: int) -> bool:
        file_size_mb = file_size_bytes / 1024 / 1024
        if file_size_mb > self.limits.max_file_size_mb:
            logger.warning(
                "File too large: %.1fMB (limit: %sMB)", file_size_mb, self.limits.max_file_size_mb
            )
            return False
        return True

    def validate_section_size(self, section_size_bytes: int) -> bool:
        section_size_mb = section_size_bytes / 1024 / 1024
        if section_size_mb > self.limits.section_size_limit_mb:
            logger.debug(
                "Section too large for analysis: %.1fMB (limit: %sMB)",
                section_size_mb,
                self.limits.section_size_limit_mb,
            )
            return False
        return True

    def limit_collection_size(
        self, collection: list[Any], max_size: int, name: str = "collection"
    ) -> list[Any]:
        if len(collection) > max_size:
            logger.debug("Truncating %s from %s to %s items", name, len(collection), max_size)
            return collection[:max_size]
        return collection

    def set_callbacks(
        self,
        warning_callback: Any | None = None,
        critical_callback: Any | None = None,
    ) -> None:
        self.warning_callback = warning_callback
        self.critical_callback = critical_callback


class MemoryAwareAnalyzer:
    def __init__(self, memory_monitor: MemoryMonitorLike | None = None):
        self.memory_monitor = memory_monitor or MemoryMonitor()

    def should_skip_analysis(
        self, estimated_memory_mb: float, analysis_name: str = "analysis"
    ) -> bool:
        if not self.memory_monitor.is_memory_available(estimated_memory_mb):
            logger.warning(
                "Skipping %s due to memory constraints (requires ~%.1fMB)",
                analysis_name,
                estimated_memory_mb,
            )
            return True
        return False

    def safe_large_operation(
        self,
        operation: Callable[[], Any],
        estimated_memory_mb: float,
        operation_name: str = "operation",
    ) -> Any | None:
        return _safe_large_operation_impl(
            self,
            operation,
            estimated_memory_mb,
            operation_name,
            logger=logger,
        )


_global_memory_monitor: MemoryMonitor | None = None


def get_global_memory_monitor() -> MemoryMonitor:
    """Return the lazily-created global MemoryMonitor singleton."""
    global _global_memory_monitor
    if _global_memory_monitor is None:
        _global_memory_monitor = MemoryMonitor()
    return _global_memory_monitor


class _MemoryMonitorProxy:
    """Thin proxy so that ``global_memory_monitor.xxx`` still works at
    module level without eagerly creating the real instance."""

    def __getattr__(self, name: str) -> Any:
        return getattr(get_global_memory_monitor(), name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(get_global_memory_monitor(), name, value)


global_memory_monitor: MemoryMonitor = _MemoryMonitorProxy()  # type: ignore[assignment]


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
    "MemoryAwareAnalyzer",
    "MemoryLimits",
    "MemoryMonitor",
    "check_memory_limits",
    "cleanup_memory",
    "configure_memory_limits",
    "get_global_memory_monitor",
    "get_memory_stats",
    "global_memory_monitor",
]
