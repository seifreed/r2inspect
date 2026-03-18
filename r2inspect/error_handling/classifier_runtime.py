"""Runtime helpers for error classification and recovery."""

from __future__ import annotations

import functools
import threading
from collections import defaultdict, deque
from collections.abc import Callable
from typing import Any


class ErrorRecoveryManager:
    """Manage error recovery strategies and aggregate error stats."""

    def __init__(
        self, logger: Any, error_stats: Callable[[Any, list[Any], int], dict[str, Any]]
    ) -> None:
        self._logger = logger
        self._error_stats = error_stats
        self.recovery_strategies: dict[Any, Callable[[Any], Any]] = {}
        self.error_counts: defaultdict[Any, int] = defaultdict(int)
        self.recent_errors: deque[Any] = deque(maxlen=100)
        self.lock = threading.Lock()

    def register_recovery_strategy(self, category: Any, strategy: Callable[[Any], Any]) -> None:
        self.recovery_strategies[category] = strategy

    _MAX_ERROR_CATEGORIES = 10000

    def handle_error(self, error_info: Any) -> tuple[bool, Any]:
        with self.lock:
            self.error_counts[error_info.category] += 1
            # Prevent unbounded growth: evict single-occurrence categories
            # only when well over the limit, preserving diagnostic value.
            if len(self.error_counts) > self._MAX_ERROR_CATEGORIES:
                to_drop = [k for k, v in self.error_counts.items() if v <= 1]
                for k in to_drop[: len(self.error_counts) - self._MAX_ERROR_CATEGORIES]:
                    del self.error_counts[k]
            self.recent_errors.append(error_info)
            _log_error(self._logger, error_info)
            if error_info.category in self.recovery_strategies and error_info.recoverable:
                try:
                    result = self.recovery_strategies[error_info.category](error_info)
                    self._logger.info(
                        f"Successfully recovered from {error_info.category.value} error"
                    )
                    return True, result
                except Exception as recovery_error:
                    self._logger.error("Recovery strategy failed: %s", recovery_error)
                    return False, None
            return False, None

    def get_error_stats(self) -> dict[str, Any]:
        with self.lock:
            return self._error_stats(
                self.error_counts,
                list(self.recent_errors),
                len(self.recovery_strategies),
            )


def build_error_handler(
    *,
    classifier: Any,
    global_error_manager: ErrorRecoveryManager,
    error_category_unknown: Any,
    error_severity_medium: Any,
    category: Any,
    severity: Any,
    context: dict[str, Any] | None,
    fallback_result: Any,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return func(*args, **kwargs)
            except Exception as exc:
                func_context = {
                    "function_name": func.__name__,
                    "module": func.__module__,
                    **(context or {}),
                }
                error_info = classifier.classify(exc, func_context)
                if category != error_category_unknown:
                    error_info.category = category
                if severity != error_severity_medium:
                    error_info.severity = severity
                recovered, result = global_error_manager.handle_error(error_info)
                if recovered:
                    return result
                if error_info.recoverable:
                    return fallback_result
                raise

        return wrapper

    return decorator


def safe_execute_call(
    func: Callable[..., Any],
    *args: Any,
    classifier: Any,
    global_error_manager: ErrorRecoveryManager,
    fallback_result: Any = None,
    context: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Any:
    try:
        return func(*args, **kwargs)
    except Exception as exc:
        func_context = {
            "function_name": getattr(func, "__name__", "unknown"),
            "module": getattr(func, "__module__", "unknown"),
            **(context or {}),
        }
        error_info = classifier.classify(exc, func_context)
        recovered, result = global_error_manager.handle_error(error_info)
        if recovered:
            return result
        if error_info.recoverable:
            return fallback_result
        raise


def register_default_recovery_strategies(
    manager: ErrorRecoveryManager,
    *,
    error_category_memory: Any,
    error_category_r2pipe: Any,
    error_category_file_access: Any,
    memory_recovery: Callable[[Any], Any],
    r2pipe_recovery: Callable[[Any], Any],
    file_access_recovery: Callable[[Any, Any], Any],
    logger: Any,
) -> None:
    manager.register_recovery_strategy(
        error_category_memory,
        lambda _error_info: memory_recovery(logger),
    )
    manager.register_recovery_strategy(error_category_r2pipe, r2pipe_recovery)
    manager.register_recovery_strategy(
        error_category_file_access,
        lambda error_info: file_access_recovery(error_info, logger),
    )


def reset_manager_stats(manager: ErrorRecoveryManager) -> None:
    manager.error_counts.clear()
    manager.recent_errors.clear()


def _log_error(logger: Any, error_info: Any) -> None:
    error_dict = error_info.to_dict()
    severity = error_info.severity.value
    if severity == "critical":
        logger.critical("Critical error: %s", error_dict)
    elif severity == "high":
        logger.error("High severity error: %s", error_dict)
    elif severity == "medium":
        logger.warning("Medium severity error: %s", error_dict)
    else:
        logger.debug("Low severity error: %s", error_dict)
