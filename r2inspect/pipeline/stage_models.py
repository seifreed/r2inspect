"""Stage models and shared context for pipeline execution."""

from __future__ import annotations

from abc import ABC, abstractmethod
import copy
import logging
import threading
from collections.abc import Callable
from typing import Any

from .results_bucket import _results_bucket, merge_stage_results

logger = logging.getLogger(__name__)


class AnalysisStage(ABC):
    """Represents a single stage in the analysis pipeline."""

    def __init__(
        self,
        name: str,
        description: str = "",
        optional: bool = True,
        *,
        dependencies: list[str] | None = None,
        condition: Callable[[dict[str, Any]], bool] | None = None,
        timeout: float | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.name = name
        self.description = description
        self.optional = optional
        self.dependencies: list[str] = dependencies or []
        self.condition = condition
        self.timeout = timeout
        self.metadata: dict[str, Any] = metadata or {}

    def can_execute(
        self, completed_stages: set[str], failed_stages: set[str] | None = None
    ) -> bool:
        if not all(dep in completed_stages for dep in self.dependencies):
            return False
        return not (
            failed_stages
            and not self.optional
            and any(dep in failed_stages for dep in self.dependencies)
        )

    def should_execute(self, context: dict[str, Any]) -> bool:
        if self.condition is None:
            return True
        try:
            return bool(self.condition(context))
        except Exception as e:
            logger.warning("Condition check failed for stage '%s': %s", self.name, e)
            return False

    @abstractmethod
    def _execute(self, _context: dict[str, Any]) -> dict[str, Any]:
        """Default execution for stages; override in subclass."""
        ...

    def execute(self, context: dict[str, Any]) -> dict[str, Any]:
        if not self.should_execute(context):
            logger.debug("Skipping stage '%s' (condition not met)", self.name)
            return {}
        executions = _results_bucket(context).get("_analyzer_executions")
        execution_count = len(executions) if isinstance(executions, list) else 0
        try:
            logger.debug("Executing stage '%s'", self.name)
            result = self._execute(context)
        except Exception as e:
            logger.error("Stage '%s' failed: %s", self.name, e)
            # Return error structure under results
            _results_bucket(context)[self.name] = {"error": str(e), "success": False}
            result = {self.name: {"error": str(e), "success": False}}
        current = _results_bucket(context).get("_analyzer_executions")
        if isinstance(current, list) and len(current) > execution_count:
            result["_analyzer_executions"] = current[execution_count:]
            del current[execution_count:]
        return result


class ThreadSafeContext:
    """Thread-safe context wrapper for parallel stage execution."""

    def __init__(self, initial_data: dict[str, Any] | None = None):
        """
        Initialize thread-safe context.

        Args:
            initial_data: Initial context data
        """
        self._lock = threading.Lock()
        self._data = initial_data or {}

    def update(self, data: dict[str, Any]) -> None:
        """
        Update context data in a thread-safe manner.

        Args:
            data: Dictionary to merge into context
        """
        with self._lock:
            self._data.update(data)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get value from context in a thread-safe manner.

        Args:
            key: Key to retrieve
            default: Default value if key not found

        Returns:
            Value associated with key or default
        """
        with self._lock:
            return self._data.get(key, default)

    def merge_results(self, stage_result: dict[str, Any]) -> None:
        """Atomically merge stage results into the context results dict."""
        if not stage_result:
            return
        with self._lock:
            merge_stage_results(_results_bucket(self._data), stage_result)

    def get_all(self) -> dict[str, Any]:
        """
        Get deep copy of context data (nested dicts are independent copies).

        Returns:
            Deep copy of all context data
        """
        with self._lock:
            return copy.deepcopy(self._data)

    def set(self, key: str, value: Any) -> None:
        """
        Set a value in context.

        Args:
            key: Key to set
            value: Value to associate with key
        """
        with self._lock:
            self._data[key] = value
