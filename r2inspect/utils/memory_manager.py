#!/usr/bin/env python3
"""
Memory management utilities for r2inspect
"""

import gc
import os
import threading
import time
from dataclasses import dataclass
from typing import Any

import psutil

from .logger import get_logger

logger = get_logger(__name__)


@dataclass
class MemoryLimits:
    """Memory limit configuration"""

    max_process_memory_mb: int = 2048  # 2GB max for process
    max_file_size_mb: int = 512  # 512MB max per file
    memory_warning_threshold: float = 0.8  # Warn at 80% of limit
    memory_critical_threshold: float = 0.9  # Critical at 90% of limit
    gc_trigger_threshold: float = 0.75  # Trigger GC at 75% of limit
    section_size_limit_mb: int = 100  # Max section size to analyze
    string_limit: int = 50000  # Max strings to process
    function_limit: int = 10000  # Max functions to analyze


class MemoryMonitor:
    """Thread-safe memory monitoring and management"""

    def __init__(self, limits: MemoryLimits | None = None):
        self.limits = limits or MemoryLimits()
        self.lock = threading.Lock()
        self.process = psutil.Process(os.getpid())

        # Monitoring state
        self.last_check = time.time()
        self.check_interval = 5.0  # Check every 5 seconds
        self.memory_warnings = 0
        self.gc_count = 0
        self.peak_memory_mb = 0.0

        # Callbacks
        from collections.abc import Callable

        self.warning_callback: Callable[[dict[str, Any]], Any] | None = None
        self.critical_callback: Callable[[dict[str, Any]], Any] | None = None

    def check_memory(self, force: bool = False) -> dict[str, Any]:
        """
        Check current memory usage

        Args:
            force: Force check regardless of interval

        Returns:
            Dictionary with memory information
        """
        now = time.time()

        if not force and (now - self.last_check) < self.check_interval:
            return self._get_cached_stats()

        with self.lock:
            try:
                # Get process memory info
                memory_info = self.process.memory_info()
                memory_mb = memory_info.rss / 1024 / 1024

                # Update peak memory
                self.peak_memory_mb = max(self.peak_memory_mb, memory_mb)

                # Get system memory info
                system_memory = psutil.virtual_memory()
                system_memory_mb = system_memory.total / 1024 / 1024
                system_available_mb = system_memory.available / 1024 / 1024

                # Calculate usage percentages
                process_usage_percent = memory_mb / self.limits.max_process_memory_mb
                system_usage_percent = system_memory.percent / 100.0

                self.last_check = now

                # Create stats dictionary
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

                # Check thresholds and trigger actions
                if process_usage_percent >= self.limits.memory_critical_threshold:
                    stats["status"] = "critical"
                    self._handle_critical_memory(stats)
                elif process_usage_percent >= self.limits.memory_warning_threshold:
                    stats["status"] = "warning"
                    self._handle_warning_memory(stats)
                elif process_usage_percent >= self.limits.gc_trigger_threshold:
                    self._trigger_gc()

                return stats

            except Exception as e:
                logger.error(f"Error checking memory: {e}")
                return self._get_error_stats()

    def _handle_warning_memory(self, stats: dict[str, Any]):
        """Handle warning memory threshold"""
        self.memory_warnings += 1
        logger.warning(
            f"Memory usage high: {stats['process_memory_mb']:.1f}MB "
            f"({stats['process_usage_percent']:.1%})"
        )

        # Trigger garbage collection
        self._trigger_gc()

        # Call warning callback if set
        if self.warning_callback:
            try:
                self.warning_callback(stats)
            except Exception as e:
                logger.error(f"Error in warning callback: {e}")

    def _handle_critical_memory(self, stats: dict[str, Any]):
        """Handle critical memory threshold"""
        logger.error(
            f"Critical memory usage: {stats['process_memory_mb']:.1f}MB "
            f"({stats['process_usage_percent']:.1%})"
        )

        # Aggressive garbage collection
        self._trigger_gc(aggressive=True)

        # Call critical callback if set
        if self.critical_callback:
            try:
                self.critical_callback(stats)
            except Exception as e:
                logger.error(f"Error in critical callback: {e}")

    def _trigger_gc(self, aggressive: bool = False):
        """Trigger garbage collection"""
        if aggressive:
            # Multiple GC passes for aggressive cleanup
            for _ in range(3):
                gc.collect()
        else:
            gc.collect()

        self.gc_count += 1
        logger.debug(f"Garbage collection triggered (count: {self.gc_count})")

    def _get_cached_stats(self) -> dict[str, Any]:
        """Get cached stats when not checking"""
        try:
            memory_info = self.process.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024
            process_usage_percent = memory_mb / self.limits.max_process_memory_mb

            return {
                "process_memory_mb": memory_mb,
                "process_memory_limit_mb": self.limits.max_process_memory_mb,
                "process_usage_percent": process_usage_percent,
                "status": "cached",
            }
        except Exception:
            return self._get_error_stats()

    def _get_error_stats(self) -> dict[str, Any]:
        """Get error stats when monitoring fails"""
        return {
            "process_memory_mb": 0.0,
            "process_memory_limit_mb": self.limits.max_process_memory_mb,
            "process_usage_percent": 0.0,
            "status": "error",
        }

    def is_memory_available(self, required_mb: float) -> bool:
        """
        Check if enough memory is available for operation

        Args:
            required_mb: Required memory in MB

        Returns:
            True if memory is available
        """
        stats = self.check_memory()
        current_mb = float(stats.get("process_memory_mb", 0))

        # Check if we would exceed process limit
        if current_mb + required_mb > self.limits.max_process_memory_mb:
            return False

        # Check system memory availability
        system_available = float(stats.get("system_memory_available_mb", 0))
        return required_mb <= system_available * 0.8  # Leave 20% buffer

    def validate_file_size(self, file_size_bytes: int) -> bool:
        """
        Validate if file size is within limits

        Args:
            file_size_bytes: File size in bytes

        Returns:
            True if file size is acceptable
        """
        file_size_mb = file_size_bytes / 1024 / 1024

        if file_size_mb > self.limits.max_file_size_mb:
            logger.warning(
                f"File too large: {file_size_mb:.1f}MB (limit: {self.limits.max_file_size_mb}MB)"
            )
            return False

        return True

    def validate_section_size(self, section_size_bytes: int) -> bool:
        """
        Validate if section size is within limits

        Args:
            section_size_bytes: Section size in bytes

        Returns:
            True if section size is acceptable
        """
        section_size_mb = section_size_bytes / 1024 / 1024

        if section_size_mb > self.limits.section_size_limit_mb:
            logger.debug(
                f"Section too large for analysis: {section_size_mb:.1f}MB "
                f"(limit: {self.limits.section_size_limit_mb}MB)"
            )
            return False

        return True

    def limit_collection_size(
        self, collection: list[Any], max_size: int, name: str = "collection"
    ) -> list[Any]:
        """
        Limit collection size and log if truncated

        Args:
            collection: Collection to limit
            max_size: Maximum size
            name: Name for logging

        Returns:
            Limited collection
        """
        if len(collection) > max_size:
            logger.debug(f"Truncating {name} from {len(collection)} to {max_size} items")
            return collection[:max_size]

        return collection

    def set_callbacks(
        self,
        warning_callback: Any | None = None,
        critical_callback: Any | None = None,
    ) -> None:
        """Set memory threshold callbacks"""
        self.warning_callback = warning_callback
        self.critical_callback = critical_callback


class MemoryAwareAnalyzer:
    """Base class for memory-aware analyzers"""

    def __init__(self, memory_monitor: MemoryMonitor | None = None):
        self.memory_monitor = memory_monitor or MemoryMonitor()

    def should_skip_analysis(
        self, estimated_memory_mb: float, analysis_name: str = "analysis"
    ) -> bool:
        """
        Check if analysis should be skipped due to memory constraints

        Args:
            estimated_memory_mb: Estimated memory requirement
            analysis_name: Name of analysis for logging

        Returns:
            True if analysis should be skipped
        """
        if not self.memory_monitor.is_memory_available(estimated_memory_mb):
            logger.warning(
                f"Skipping {analysis_name} due to memory constraints "
                f"(requires ~{estimated_memory_mb:.1f}MB)"
            )
            return True

        return False

    def safe_large_operation(
        self,
        operation,
        estimated_memory_mb: float,
        operation_name: str = "operation",
    ):
        """
        Safely execute a large operation with memory monitoring

        Args:
            operation: Function to execute
            estimated_memory_mb: Estimated memory requirement
            operation_name: Name for logging

        Returns:
            Operation result or None if skipped
        """
        if self.should_skip_analysis(estimated_memory_mb, operation_name):
            return None

        # Check memory before operation
        start_stats = self.memory_monitor.check_memory(force=True)

        try:
            logger.debug(
                f"Starting {operation_name} "
                f"(estimated: {estimated_memory_mb:.1f}MB, "
                f"current: {start_stats['process_memory_mb']:.1f}MB)"
            )

            result = operation()

            # Check memory after operation
            end_stats = self.memory_monitor.check_memory(force=True)
            actual_used = end_stats["process_memory_mb"] - start_stats["process_memory_mb"]

            logger.debug(f"Completed {operation_name} (actual memory used: {actual_used:.1f}MB)")

            return result

        except MemoryError:
            logger.error(f"Memory error during {operation_name}")
            # Force garbage collection on memory error
            self.memory_monitor._trigger_gc(aggressive=True)
            return None
        except Exception as e:
            logger.error(f"Error during {operation_name}: {e}")
            return None


# Global memory monitor instance
global_memory_monitor = MemoryMonitor()


def get_memory_stats() -> dict[str, Any]:
    """Get global memory statistics"""
    return global_memory_monitor.check_memory()


def check_memory_limits(file_size_bytes: int = 0, estimated_analysis_mb: float = 0) -> bool:
    """
    Check if operation is within memory limits

    Args:
        file_size_bytes: File size in bytes
        estimated_analysis_mb: Estimated analysis memory requirement

    Returns:
        True if within limits
    """
    if file_size_bytes > 0 and not global_memory_monitor.validate_file_size(file_size_bytes):
        return False

    return estimated_analysis_mb <= 0 or global_memory_monitor.is_memory_available(
        estimated_analysis_mb
    )


def configure_memory_limits(**kwargs):
    """Configure global memory limits"""
    global global_memory_monitor

    # Update limits
    for key, value in kwargs.items():
        if hasattr(global_memory_monitor.limits, key):
            setattr(global_memory_monitor.limits, key, value)
            logger.info(f"Updated memory limit {key} = {value}")
        else:
            logger.warning(f"Unknown memory limit: {key}")


def cleanup_memory():
    """Force memory cleanup"""
    global_memory_monitor._trigger_gc(aggressive=True)
    return global_memory_monitor.check_memory(force=True)
