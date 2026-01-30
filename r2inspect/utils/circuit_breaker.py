#!/usr/bin/env python3
"""
Circuit breaker pattern implementation for r2inspect
"""

import functools
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable
from enum import Enum
from typing import Any


class CircuitState(Enum):
    """Circuit breaker states"""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Circuit tripped, failing fast
    HALF_OPEN = "half_open"  # Testing if service recovered


class CircuitBreakerError(Exception):
    """Exception raised when circuit breaker is open"""

    pass


class CircuitBreaker:
    """Circuit breaker for protecting against cascading failures"""

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        expected_exception: tuple[type[BaseException], ...] = (Exception,),
        name: str = "default",
    ):
        """
        Initialize circuit breaker

        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Time to wait before attempting recovery
            expected_exception: Exceptions that count as failures
            name: Name for logging and identification
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        self.name = name

        # State management
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time: float | None = None
        self.last_success_time: float = time.time()

        # Statistics
        self.total_calls = 0
        self.total_failures = 0
        self.total_successes = 0
        self.state_changes = 0

        # Thread safety
        self.lock = threading.Lock()

    def __call__(self, func: Callable) -> Callable:
        """Decorator to wrap function with circuit breaker"""

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return self.call(func, *args, **kwargs)

        return wrapper

    def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Call function with circuit breaker protection

        Args:
            func: Function to call
            *args, **kwargs: Arguments to pass to function

        Returns:
            Function result

        Raises:
            CircuitBreakerError: If circuit is open
        """
        with self.lock:
            self.total_calls += 1

            # Check current state
            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self._set_state(CircuitState.HALF_OPEN)
                else:
                    raise CircuitBreakerError(f"Circuit breaker '{self.name}' is OPEN")

            if self.state == CircuitState.HALF_OPEN:
                # In half-open state, only allow one call through
                pass

        # Attempt the call
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result

        except self.expected_exception:
            self._on_failure()
            raise
        except BaseException:  # pragma: no cover
            # Unexpected exceptions don't count as failures - re-raise them immediately
            # without modifying the exception or counting it as a failure
            raise

    def _on_success(self):
        """Handle successful call"""
        with self.lock:
            self.total_successes += 1
            self.last_success_time = time.time()

            if self.state == CircuitState.HALF_OPEN:
                # Recovery successful, close circuit
                self._set_state(CircuitState.CLOSED)
                self.failure_count = 0

    def _on_failure(self):
        """Handle failed call"""
        with self.lock:
            self.total_failures += 1
            self.failure_count += 1
            self.last_failure_time = time.time()

            if self.failure_count >= self.failure_threshold:
                self._set_state(CircuitState.OPEN)

    def _should_attempt_reset(self) -> bool:
        """Check if we should attempt to reset the circuit"""
        if self.last_failure_time is None:
            return False

        return time.time() - self.last_failure_time >= self.recovery_timeout

    def _set_state(self, new_state: CircuitState):
        """Change circuit state"""
        if self.state != new_state:
            self.state = new_state
            self.state_changes += 1

    def reset(self):
        """Manually reset the circuit breaker"""
        with self.lock:
            self.state = CircuitState.CLOSED
            self.failure_count = 0
            self.last_failure_time = None

    def get_stats(self) -> dict[str, Any]:
        """Get circuit breaker statistics"""
        with self.lock:
            success_rate = (self.total_successes / max(1, self.total_calls)) * 100

            return {
                "name": self.name,
                "state": self.state.value,
                "total_calls": self.total_calls,
                "total_successes": self.total_successes,
                "total_failures": self.total_failures,
                "success_rate": success_rate,
                "failure_count": self.failure_count,
                "failure_threshold": self.failure_threshold,
                "state_changes": self.state_changes,
                "last_failure_time": self.last_failure_time,
                "last_success_time": self.last_success_time,
            }


class R2CommandCircuitBreaker:
    """Circuit breaker specifically for r2pipe commands"""

    def __init__(self):
        self.breakers: dict[str, CircuitBreaker] = {}
        self.command_stats = defaultdict(
            lambda: {
                "calls": 0,
                "failures": 0,
                "avg_time": 0.0,
                "recent_failures": deque(maxlen=50),
            }
        )
        self.lock = threading.Lock()

    def get_breaker(self, command_type: str) -> CircuitBreaker:
        """Get or create circuit breaker for command type"""
        with self.lock:
            if command_type not in self.breakers:
                # Configure different thresholds for different command types
                if command_type in ["analysis", "aaa", "aac", "af"]:
                    # Analysis commands - more tolerant
                    threshold = 10
                    timeout = 120.0
                elif command_type in ["search", "/x", "/c"]:
                    # Search commands - moderately tolerant
                    threshold = 7
                    timeout = 60.0
                else:
                    # Other commands - less tolerant
                    threshold = 5
                    timeout = 30.0

                self.breakers[command_type] = CircuitBreaker(
                    failure_threshold=threshold,
                    recovery_timeout=timeout,
                    expected_exception=(Exception,),
                    name=f"r2_command_{command_type}",
                )

            return self.breakers[command_type]

    def execute_command(self, r2_instance, command: str, command_type: str = "generic"):
        """Execute r2 command with circuit breaker protection"""
        breaker = self.get_breaker(command_type)

        # Record command statistics
        start_time = time.time()

        try:
            # Use circuit breaker to execute command
            if command.endswith("j"):
                result = breaker.call(r2_instance.cmdj, command)
            else:
                result = breaker.call(r2_instance.cmd, command)

            # Record success
            execution_time = time.time() - start_time
            self._record_command_stats(command_type, True, execution_time)

            return result

        except CircuitBreakerError:
            # Circuit is open, return safe default
            self._record_command_stats(command_type, False, 0.0)
            return None if command.endswith("j") else ""

        except Exception:
            # Command failed
            execution_time = time.time() - start_time
            self._record_command_stats(command_type, False, execution_time)

            # For JSON commands, return None; for text commands, return empty string
            return None if command.endswith("j") else ""

    def _record_command_stats(self, command_type: str, success: bool, execution_time: float):
        """Record command execution statistics"""
        with self.lock:
            stats = self.command_stats[command_type]
            stats["calls"] += 1

            if not success:
                stats["failures"] += 1
                stats["recent_failures"].append(time.time())

            # Update average execution time
            if stats["calls"] == 1:
                stats["avg_time"] = execution_time
            else:
                # Exponential moving average
                alpha = 0.1
                stats["avg_time"] = alpha * execution_time + (1 - alpha) * stats["avg_time"]

    def get_stats(self) -> dict[str, Any]:
        """Get comprehensive statistics"""
        stats = {}

        with self.lock:
            # Circuit breaker stats
            for name, breaker in self.breakers.items():
                stats[f"breaker_{name}"] = breaker.get_stats()

            # Command stats
            for cmd_type, cmd_stats in self.command_stats.items():
                recent_failures = len(
                    [t for t in cmd_stats["recent_failures"] if time.time() - t < 300]
                )  # Last 5 minutes

                success_rate = (
                    (cmd_stats["calls"] - cmd_stats["failures"]) / max(1, cmd_stats["calls"])
                ) * 100

                stats[f"command_{cmd_type}"] = {
                    "total_calls": cmd_stats["calls"],
                    "total_failures": cmd_stats["failures"],
                    "success_rate": success_rate,
                    "avg_execution_time": cmd_stats["avg_time"],
                    "recent_failures": recent_failures,
                }

        return stats

    def reset_all(self):
        """Reset all circuit breakers"""
        with self.lock:
            for breaker in self.breakers.values():
                breaker.reset()

            self.command_stats.clear()


# Global instance for r2 commands
r2_circuit_breaker = R2CommandCircuitBreaker()
