#!/usr/bin/env python3
"""Infrastructure components for r2inspect."""

from .circuit_breaker import CircuitBreaker, CircuitBreakerError, CircuitState, r2_circuit_breaker
from .command_helpers import cmd, cmd_list, cmdj
from .hashing import calculate_hashes, calculate_ssdeep
from .logging import configure_batch_logging, get_logger, reset_logging_levels, setup_logger
from .magic_detector import (
    MagicByteDetector,
    detect_file_type,
    get_file_threat_level,
    is_executable_file,
)
from .magic_patterns import MAGIC_PATTERNS
from .memory import (
    MemoryAwareAnalyzer,
    MemoryLimits,
    MemoryMonitor,
    get_global_memory_monitor,
    global_memory_monitor,
)
from .rate_limiter import AdaptiveRateLimiter, BatchRateLimiter, TokenBucket
from .r2_session import R2Session
from .retry_manager import RetryConfig, RetryManager, RetryStrategy, global_retry_manager

__all__ = [
    "AdaptiveRateLimiter",
    "BatchRateLimiter",
    "CircuitBreaker",
    "CircuitBreakerError",
    "CircuitState",
    "MemoryAwareAnalyzer",
    "MemoryLimits",
    "MemoryMonitor",
    "R2Session",
    "RetryConfig",
    "RetryManager",
    "RetryStrategy",
    "TokenBucket",
    "cmd",
    "cmd_list",
    "cmdj",
    "calculate_hashes",
    "calculate_ssdeep",
    "configure_batch_logging",
    "MagicByteDetector",
    "MAGIC_PATTERNS",
    "detect_file_type",
    "get_global_memory_monitor",
    "global_memory_monitor",
    "global_retry_manager",
    "get_logger",
    "get_file_threat_level",
    "is_executable_file",
    "r2_circuit_breaker",
    "reset_logging_levels",
    "setup_logger",
]
