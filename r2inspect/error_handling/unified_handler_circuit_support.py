"""Circuit breaker state and registry helpers for unified error handling."""

from __future__ import annotations

import threading
import time
from enum import Enum
from typing import Any


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerState:
    """Thread-safe circuit breaker state management."""

    def __init__(self, policy: Any, logger: Any | None = None):
        self.policy = policy
        self._logger = logger
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time: float | None = None
        self.half_open_probe_in_flight = False
        self.lock = threading.Lock()

    def should_allow_request(self) -> bool:
        with self.lock:
            if self.state == CircuitState.CLOSED:
                return True

            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self.state = CircuitState.HALF_OPEN
                    self.half_open_probe_in_flight = True
                    self._probe_start_time = time.time()
                    return True
                return False

            # HALF_OPEN: allow a probe if none is in flight,
            # or if the current probe has been running too long (stale probe recovery)
            if self.half_open_probe_in_flight:
                probe_age = time.time() - getattr(self, "_probe_start_time", 0.0)
                if probe_age > self.policy.circuit_timeout:
                    # Stale probe — reset and allow a new one
                    self.half_open_probe_in_flight = True
                    self._probe_start_time = time.time()
                    return True
                return False
            self.half_open_probe_in_flight = True
            self._probe_start_time = time.time()
            return True

    def record_success(self) -> None:
        with self.lock:
            if self.state == CircuitState.HALF_OPEN:
                self.state = CircuitState.CLOSED
            self.half_open_probe_in_flight = False
            self.failure_count = 0
            self.last_failure_time = None

    def record_failure(self) -> None:
        with self.lock:
            self.failure_count += 1
            self.last_failure_time = time.time()
            self.half_open_probe_in_flight = False

            if self.failure_count >= self.policy.circuit_threshold:
                self.state = CircuitState.OPEN
                if self._logger is not None:
                    self._logger.warning(
                        "Circuit breaker opened after %s failures, will retry in %ss",
                        self.failure_count,
                        self.policy.circuit_timeout,
                    )

    def _should_attempt_reset(self) -> bool:
        if self.last_failure_time is None:
            # Safety: if we're OPEN but have no failure time, allow reset
            return True
        return bool((time.time() - self.last_failure_time) >= self.policy.circuit_timeout)


_circuit_breakers: dict[str, CircuitBreakerState] = {}
_circuit_lock = threading.Lock()


def get_circuit_breaker(func_id: str, policy: Any, logger: Any) -> CircuitBreakerState:
    with _circuit_lock:
        if func_id not in _circuit_breakers:
            _circuit_breakers[func_id] = CircuitBreakerState(policy, logger)
        circuit = _circuit_breakers[func_id]
        with circuit.lock:
            circuit.policy = policy
        return circuit


def reset_circuit_breakers(logger: Any) -> None:
    with _circuit_lock:
        for circuit in _circuit_breakers.values():
            with circuit.lock:
                circuit.state = CircuitState.CLOSED
                circuit.failure_count = 0
                circuit.last_failure_time = None
                circuit.half_open_probe_in_flight = False
    logger.info("All circuit breakers have been reset")


def get_circuit_breaker_stats() -> dict[str, Any]:
    stats = {}
    with _circuit_lock:
        for func_id, circuit in _circuit_breakers.items():
            with circuit.lock:
                stats[func_id] = {
                    "state": circuit.state.value,
                    "failure_count": circuit.failure_count,
                    "last_failure_time": circuit.last_failure_time,
                    "threshold": circuit.policy.circuit_threshold,
                    "timeout": circuit.policy.circuit_timeout,
                }
    return stats
