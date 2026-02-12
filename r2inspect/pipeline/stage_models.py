"""Stage models and shared context for pipeline execution."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


class AnalysisStage:
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

    def can_execute(self, completed_stages: set[str]) -> bool:
        return all(dep in completed_stages for dep in self.dependencies)

    def should_execute(self, context: dict[str, Any]) -> bool:
        if self.condition is None:
            return True
        try:
            return bool(self.condition(context))
        except Exception as e:
            logger.warning(f"Condition check failed for stage '{self.name}': {e}")
            return False

    def _execute(self, _context: dict[str, Any]) -> dict[str, Any]:
        """Default execution for stages; override in subclass."""
        raise NotImplementedError

    def execute(self, context: dict[str, Any]) -> dict[str, Any]:
        if not self.should_execute(context):
            logger.debug(f"Skipping stage '{self.name}' (condition not met)")
            return {}
        try:
            logger.debug(f"Executing stage '{self.name}'")
            return self._execute(context)
        except Exception as e:
            logger.error(f"Stage '{self.name}' failed: {e}")
            # Return error structure under results
            context.setdefault("results", {})
            context["results"][self.name] = {"error": str(e), "success": False}
            return {self.name: {"error": str(e), "success": False}}


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

    def get_all(self) -> dict[str, Any]:
        """
        Get complete copy of context data.

        Returns:
            Copy of all context data
        """
        with self._lock:
            return self._data.copy()

    def set(self, key: str, value: Any) -> None:
        """
        Set a value in context.

        Args:
            key: Key to set
            value: Value to associate with key
        """
        with self._lock:
            self._data[key] = value
