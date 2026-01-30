#!/usr/bin/env python3
"""
Retry logic for unstable r2 commands and operations
"""

import functools
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .logger import get_logger

logger = get_logger(__name__)


class RetryStrategy(Enum):
    """Different retry strategies"""

    FIXED_DELAY = "fixed_delay"
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    LINEAR_BACKOFF = "linear_backoff"
    RANDOM_JITTER = "random_jitter"


@dataclass
class RetryConfig:
    """Configuration for retry behavior"""

    max_attempts: int = 3
    base_delay: float = 0.1  # Base delay in seconds
    max_delay: float = 5.0  # Maximum delay in seconds
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF
    jitter: bool = True  # Add random jitter to delays
    backoff_multiplier: float = 2.0
    timeout: float | None = None  # Total timeout for all attempts


class RetryableError(Exception):
    """Base class for errors that should trigger retry"""

    pass


class NonRetryableError(Exception):
    """Base class for errors that should NOT trigger retry"""

    pass


class RetryManager:
    """Manages retry logic for r2pipe commands and other operations"""

    # Default retry configurations for different command types
    DEFAULT_CONFIGS = {
        "analysis": RetryConfig(
            max_attempts=3, base_delay=0.2, strategy=RetryStrategy.EXPONENTIAL_BACKOFF
        ),
        "info": RetryConfig(max_attempts=2, base_delay=0.1, strategy=RetryStrategy.FIXED_DELAY),
        "search": RetryConfig(
            max_attempts=4, base_delay=0.3, strategy=RetryStrategy.LINEAR_BACKOFF
        ),
        "print": RetryConfig(max_attempts=2, base_delay=0.1, strategy=RetryStrategy.FIXED_DELAY),
        "sections": RetryConfig(
            max_attempts=3, base_delay=0.15, strategy=RetryStrategy.EXPONENTIAL_BACKOFF
        ),
        "functions": RetryConfig(
            max_attempts=3, base_delay=0.2, strategy=RetryStrategy.EXPONENTIAL_BACKOFF
        ),
        "memory": RetryConfig(max_attempts=2, base_delay=0.1, strategy=RetryStrategy.FIXED_DELAY),
        "generic": RetryConfig(max_attempts=2, base_delay=0.1, strategy=RetryStrategy.FIXED_DELAY),
    }

    # Commands that are known to be unstable and should be retried
    UNSTABLE_COMMANDS = {
        "aaa",
        "aac",
        "aav",
        "aan",  # Analysis commands
        "aflj",
        "aflc",
        "afll",  # Function listing commands
        "iij",
        "iEj",
        "iej",
        "irj",  # Information commands that sometimes fail
        "/aj",
        "/cj",
        "/rj",  # Search commands
        "isj",
        "izj",
        "iSj",  # String and section commands
        "pdfj",
        "pdj",
        "agj",  # Print and graph commands
    }

    # Error types that should trigger retry
    RETRYABLE_EXCEPTIONS = {
        "r2pipe.cmdj.Error",
        "JSONDecodeError",
        "ConnectionError",
        "TimeoutError",
        "BrokenPipeError",
        "OSError",
    }

    # Error messages that indicate temporary failures
    RETRYABLE_ERROR_MESSAGES = [
        "connection reset",
        "broken pipe",
        "timeout",
        "resource temporarily unavailable",
        "device busy",
        "try again",
        "no json object could be decoded",
        "expecting value: line 1 column 1",
        "extra data: line 1 column 2",
    ]

    def __init__(self):
        self.retry_stats = {
            "total_retries": 0,
            "successful_retries": 0,
            "failed_after_retries": 0,
            "commands_retried": {},
            "error_types_retried": {},
        }
        self.lock = threading.Lock()

    def is_retryable_command(self, command: str) -> bool:
        """Check if command is known to be unstable and should be retried"""
        command_base = command.split()[0] if command else ""
        return command_base in self.UNSTABLE_COMMANDS

    def is_retryable_error(self, exception: Exception) -> bool:
        """Check if error should trigger a retry"""
        exception_type = type(exception).__name__
        error_message = str(exception).lower()

        # Check exception type
        if exception_type in self.RETRYABLE_EXCEPTIONS:
            return True

        # Check error message patterns
        return any(pattern in error_message for pattern in self.RETRYABLE_ERROR_MESSAGES)

    def calculate_delay(self, attempt: int, config: RetryConfig) -> float:
        """Calculate delay for given attempt using configured strategy"""
        delay = config.base_delay

        if config.strategy == RetryStrategy.FIXED_DELAY:
            delay = config.base_delay

        elif config.strategy == RetryStrategy.EXPONENTIAL_BACKOFF:
            delay = config.base_delay * (config.backoff_multiplier ** (attempt - 1))

        elif config.strategy == RetryStrategy.LINEAR_BACKOFF:
            delay = config.base_delay * attempt

        elif config.strategy == RetryStrategy.RANDOM_JITTER:
            delay = config.base_delay + (secrets.randbelow(int(config.base_delay * 1000)) / 1000.0)

        # Apply jitter if enabled
        if config.jitter and config.strategy != RetryStrategy.RANDOM_JITTER:
            jitter = delay * 0.1 * ((secrets.randbelow(2000) - 1000) / 1000.0)  # ±10% jitter
            delay = max(0.01, delay + jitter)

        # Ensure delay doesn't exceed maximum
        return min(delay, config.max_delay)

    def retry_operation(
        self,
        operation: Callable,
        *args,
        command_type: str = "generic",
        config: RetryConfig | None = None,
        **kwargs,
    ) -> Any:
        """
        Execute operation with retry logic

        Args:
            operation: Function to execute
            *args: Positional arguments for operation
            command_type: Type of command for configuration lookup
            config: Custom retry configuration
            **kwargs: Keyword arguments for operation

        Returns:
            Result of successful operation

        Raises:
            Exception: If all retry attempts fail
        """
        config = self._get_retry_config(command_type, config)
        start_time = time.time()
        last_exception = None

        for attempt in range(1, config.max_attempts + 1):
            try:
                self._check_timeout(start_time, config)
                result = operation(*args, **kwargs)
                self._handle_success(attempt)
                return result

            except Exception as e:
                last_exception = e
                if not self._handle_retry_exception(e, attempt, config, kwargs):
                    break

        if last_exception:
            raise last_exception

    def _get_retry_config(self, command_type: str, config: RetryConfig | None) -> RetryConfig:
        """Get retry configuration for the operation"""
        if config is None:
            return self.DEFAULT_CONFIGS.get(command_type, self.DEFAULT_CONFIGS["generic"])
        return config

    def _check_timeout(self, start_time: float, config: RetryConfig) -> None:
        """Check if total timeout has been exceeded"""
        if config.timeout and (time.time() - start_time) > config.timeout:
            raise TimeoutError(f"Retry timeout exceeded ({config.timeout}s)")

    def _handle_success(self, attempt: int) -> None:
        """Handle successful operation"""
        if attempt > 1:
            with self.lock:
                self.retry_stats["successful_retries"] += 1
                logger.debug(f"Operation succeeded on attempt {attempt}")

    def _handle_retry_exception(
        self, e: Exception, attempt: int, config: RetryConfig, kwargs: dict
    ) -> bool:
        """Handle exception during retry operation. Returns True if should continue retrying."""
        if not self.is_retryable_error(e):
            logger.debug(f"Non-retryable error: {type(e).__name__}: {e}")
            raise

        self._update_retry_stats(e, attempt, kwargs)

        if attempt >= config.max_attempts:
            with self.lock:
                self.retry_stats["failed_after_retries"] += 1
            logger.warning(f"Operation failed after {config.max_attempts} attempts: {e}")
            raise

        self._wait_for_retry(attempt, config)
        return True

    def _update_retry_stats(self, e: Exception, attempt: int, kwargs: dict) -> None:
        """Update retry statistics"""
        with self.lock:
            if attempt == 1:
                self.retry_stats["total_retries"] += 1
                command_name = kwargs.get("command", "unknown")
                self.retry_stats["commands_retried"][command_name] = (
                    self.retry_stats["commands_retried"].get(command_name, 0) + 1
                )

                error_type = type(e).__name__
                self.retry_stats["error_types_retried"][error_type] = (
                    self.retry_stats["error_types_retried"].get(error_type, 0) + 1
                )

    def _wait_for_retry(self, attempt: int, config: RetryConfig) -> None:
        """Wait before retry attempt"""
        delay = self.calculate_delay(attempt, config)
        logger.debug(
            f"Retrying operation in {delay:.2f}s (attempt {attempt + 1}/{config.max_attempts})"
        )
        time.sleep(delay)

    def get_stats(self) -> dict[str, Any]:
        """Get retry statistics"""
        with self.lock:
            return {
                "total_retries": self.retry_stats["total_retries"],
                "successful_retries": self.retry_stats["successful_retries"],
                "failed_after_retries": self.retry_stats["failed_after_retries"],
                "success_rate": (
                    self.retry_stats["successful_retries"]
                    / max(1, self.retry_stats["total_retries"])
                )
                * 100,
                "commands_retried": dict(self.retry_stats["commands_retried"]),
                "error_types_retried": dict(self.retry_stats["error_types_retried"]),
            }

    def reset_stats(self):
        """Reset retry statistics"""
        with self.lock:
            self.retry_stats = {
                "total_retries": 0,
                "successful_retries": 0,
                "failed_after_retries": 0,
                "commands_retried": {},
                "error_types_retried": {},
            }


def retry_on_failure(
    command_type: str = "generic",
    config: RetryConfig | None = None,
    auto_retry: bool = True,
):
    """
    Decorator for automatic retry on failure

    Args:
        command_type: Type of command for configuration
        config: Custom retry configuration
        auto_retry: Whether to automatically retry on known unstable commands
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Extract command from args/kwargs if available
            command = None
            if len(args) >= 2 and isinstance(args[1], str):
                command = args[1]  # Assume second arg is command
            elif "command" in kwargs:
                command = kwargs["command"]

            # Decide whether to retry
            should_retry = False
            if auto_retry and command:
                should_retry = global_retry_manager.is_retryable_command(command)
            else:
                should_retry = True  # Always retry if decorator is explicitly used

            if should_retry:
                return global_retry_manager.retry_operation(
                    func,
                    *args,
                    command_type=command_type,
                    config=config,
                    command=command,
                    **kwargs,
                )
            else:
                return func(*args, **kwargs)

        return wrapper

    return decorator


# Global retry manager instance
global_retry_manager = RetryManager()


def get_retry_stats() -> dict[str, Any]:
    """Get global retry statistics"""
    return global_retry_manager.get_stats()


def reset_retry_stats():
    """Reset global retry statistics"""
    global_retry_manager.reset_stats()
    logger.info("Retry statistics have been reset")


def configure_retry_for_command(command_type: str, config: RetryConfig):
    """Configure retry behavior for specific command type"""
    global_retry_manager.DEFAULT_CONFIGS[command_type] = config
    logger.info(f"Updated retry configuration for {command_type}")


# Convenient function for retrying r2pipe operations
def retry_r2_operation(
    operation: Callable,
    command: str,
    command_type: str = "generic",
) -> Any:
    """
    Retry r2pipe operation with appropriate configuration

    Args:
        operation: r2pipe operation function (like r2.cmdj)
        command: r2 command to execute
        command_type: Type of command for retry configuration

    Returns:
        Operation result
    """

    def _execute():
        return operation(command)

    return global_retry_manager.retry_operation(
        _execute, command_type=command_type, command=command
    )
