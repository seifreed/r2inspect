#!/usr/bin/env python3
"""Circuit breaker helpers for command execution."""

from __future__ import annotations

import functools
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable
from enum import Enum
from typing import Any, TypedDict


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerError(Exception):
    """Raised when the circuit breaker is open."""


class CircuitBreaker:
    """Circuit breaker for protecting against cascading failures."""

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        expected_exception: tuple[type[BaseException], ...] = (Exception,),
        name: str = "default",
    ) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        self.name = name
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time: float | None = None
        self.last_success_time: float = time.time()
        self.total_calls = 0
        self.total_failures = 0
        self.total_successes = 0
        self.state_changes = 0
        self.half_open_probe_in_flight = False
        self.lock = threading.Lock()

    def __call__(self, func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return self.call(func, *args, **kwargs)

        return wrapper

    def call(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        with self.lock:
            self.total_calls += 1
            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self._set_state(CircuitState.HALF_OPEN)
                    self.half_open_probe_in_flight = True
                else:
                    raise CircuitBreakerError(f"Circuit breaker '{self.name}' is OPEN")
            elif self.state == CircuitState.HALF_OPEN:
                if self.half_open_probe_in_flight:
                    raise CircuitBreakerError(f"Circuit breaker '{self.name}' is HALF_OPEN")
                self.half_open_probe_in_flight = True
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except self.expected_exception:
            self._on_failure()
            raise

    def _on_success(self) -> None:
        with self.lock:
            self.total_successes += 1
            self.last_success_time = time.time()
            if self.state == CircuitState.HALF_OPEN:
                self._set_state(CircuitState.CLOSED)
                self.failure_count = 0
            self.half_open_probe_in_flight = False

    def _on_failure(self) -> None:
        with self.lock:
            self.total_failures += 1
            self.failure_count += 1
            self.last_failure_time = time.time()
            self.half_open_probe_in_flight = False
            if self.failure_count >= self.failure_threshold:
                self._set_state(CircuitState.OPEN)

    def _should_attempt_reset(self) -> bool:
        return self.last_failure_time is not None and (
            time.time() - self.last_failure_time >= self.recovery_timeout
        )

    def _set_state(self, new_state: CircuitState) -> None:
        if self.state != new_state:
            self.state = new_state
            self.state_changes += 1

    def reset(self) -> None:
        with self.lock:
            self.state = CircuitState.CLOSED
            self.failure_count = 0
            self.last_failure_time = None
            self.half_open_probe_in_flight = False

    def get_stats(self) -> dict[str, Any]:
        with self.lock:
            return {
                "name": self.name,
                "state": self.state.value,
                "total_calls": self.total_calls,
                "total_successes": self.total_successes,
                "total_failures": self.total_failures,
                "success_rate": (self.total_successes / max(1, self.total_calls)) * 100,
                "failure_count": self.failure_count,
                "failure_threshold": self.failure_threshold,
                "state_changes": self.state_changes,
                "last_failure_time": self.last_failure_time,
                "last_success_time": self.last_success_time,
            }


class CommandStats(TypedDict):
    calls: int
    failures: int
    avg_time: float
    recent_failures: deque[float]


def _default_command_stats() -> CommandStats:
    return {"calls": 0, "failures": 0, "avg_time": 0.0, "recent_failures": deque(maxlen=50)}


class R2CommandCircuitBreaker:
    """Circuit breaker specifically for r2pipe commands."""

    def __init__(self) -> None:
        self.breakers: dict[str, CircuitBreaker] = {}
        self.command_stats: defaultdict[str, CommandStats] = defaultdict(_default_command_stats)
        self.lock = threading.Lock()

    def get_breaker(self, command_type: str) -> CircuitBreaker:
        with self.lock:
            if command_type not in self.breakers:
                if command_type in ["analysis", "aaa", "aac", "af"]:
                    threshold, timeout = 10, 120.0
                elif command_type in ["search", "/x", "/c"]:
                    threshold, timeout = 7, 60.0
                else:
                    threshold, timeout = 5, 30.0
                self.breakers[command_type] = CircuitBreaker(
                    failure_threshold=threshold,
                    recovery_timeout=timeout,
                    expected_exception=(Exception,),
                    name=f"r2_command_{command_type}",
                )
            return self.breakers[command_type]

    def execute_command(self, r2_instance: Any, command: str, command_type: str = "generic") -> Any:
        breaker = self.get_breaker(command_type)
        start_time = time.time()
        try:
            target = r2_instance.cmdj if command.endswith("j") else r2_instance.cmd
            result = breaker.call(target, command)
            self._record_command_stats(command_type, True, time.time() - start_time)
            return result
        except CircuitBreakerError:
            self._record_command_stats(command_type, False, 0.0)
            return None if command.endswith("j") else ""
        except Exception:
            self._record_command_stats(command_type, False, time.time() - start_time)
            return None if command.endswith("j") else ""

    def _record_command_stats(
        self, command_type: str, success: bool, execution_time: float
    ) -> None:
        with self.lock:
            stats = self.command_stats[command_type]
            stats["calls"] += 1
            if not success:
                stats["failures"] += 1
                stats["recent_failures"].append(time.time())
            if stats["calls"] == 1:
                stats["avg_time"] = execution_time
            else:
                alpha = 0.1
                stats["avg_time"] = alpha * execution_time + (1 - alpha) * stats["avg_time"]

    def get_stats(self) -> dict[str, Any]:
        stats: dict[str, Any] = {}
        with self.lock:
            for name, breaker in self.breakers.items():
                stats[f"breaker_{name}"] = breaker.get_stats()
            for cmd_type, cmd_stats in self.command_stats.items():
                recent_failures = len(
                    [t for t in cmd_stats["recent_failures"] if time.time() - t < 300]
                )
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

    def reset_all(self) -> None:
        with self.lock:
            for breaker in self.breakers.values():
                breaker.reset()
            self.command_stats.clear()


def create_r2_circuit_breaker() -> R2CommandCircuitBreaker:
    """Create a new per-session circuit breaker.

    Each R2Session should get its own circuit breaker to prevent
    cross-session state pollution in parallel analysis.
    """
    return R2CommandCircuitBreaker()


# Legacy global instance — prefer create_r2_circuit_breaker() for new code
r2_circuit_breaker = R2CommandCircuitBreaker()


__all__ = [
    "CircuitBreaker",
    "CircuitBreakerError",
    "CircuitState",
    "R2CommandCircuitBreaker",
    "create_r2_circuit_breaker",
    "r2_circuit_breaker",
]
