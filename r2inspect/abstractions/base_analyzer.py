#!/usr/bin/env python3
"""Base analyzer interface and shared utilities."""

from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

from .base_analyzer_support import (
    analysis_context as _analysis_context,
    analyzer_repr as _analyzer_repr,
    analyzer_str as _analyzer_str,
    derive_analyzer_name as _derive_analyzer_name,
    log_with_root as _log_with_root,
    measure_execution_time as _measure_execution_time,
    normalize_filepath as _normalize_filepath,
)
from ..infrastructure.logging import get_logger
from .result_builder import init_result, mark_unavailable

logger = get_logger(__name__)


class BaseAnalyzer(ABC):
    """Abstract base class for analyzers with shared helpers."""

    def __init__(
        self,
        adapter: Any | None = None,
        config: Any | None = None,
        filepath: Any | None = None,
        **kwargs: Any,
    ):
        """Initialize base analyzer with adapter/config/filepath."""
        self.adapter: Any = adapter
        self.config: Any = config
        self.filepath = _normalize_filepath(filepath)
        self._extra_params = kwargs
        self._cached_name: str | None = None
        self._cached_category: str | None = None

    @abstractmethod
    def analyze(self) -> dict[str, Any]:
        """Perform the analysis and return results."""
        pass

    def _init_result_structure(
        self, additional_fields: dict[str, Any | None] | None = None
    ) -> dict[str, Any]:
        return init_result(self.get_name(), additional_fields)

    def _mark_unavailable(
        self,
        result: dict[str, Any],
        error: str,
        *,
        library_available: bool | None = None,
    ) -> dict[str, Any]:
        """Mark a result as unavailable with an error message."""
        return mark_unavailable(result, error, library_available=library_available)

    def get_name(self) -> str:
        if self._cached_name:
            return self._cached_name
        name = _derive_analyzer_name(self)
        self._cached_name = name
        return name

    def get_category(self) -> str:
        if self._cached_category:
            return self._cached_category
        return "unknown"

    def get_description(self) -> str:
        return f"{self.__class__.__name__} - No description provided"

    def supports_format(self, _file_format: str) -> bool:
        return True

    def get_supported_formats(self) -> set[str]:
        return set()

    @classmethod
    def is_available(cls) -> bool:
        return True

    def _log_debug(self, message: str) -> None:
        _log_with_root(logger, "debug", self.get_name(), message)

    def _log_info(self, message: str) -> None:
        _log_with_root(logger, "info", self.get_name(), message)

    def _log_warning(self, message: str) -> None:
        _log_with_root(logger, "warning", self.get_name(), message)

    def _log_error(self, message: str) -> None:
        _log_with_root(logger, "error", self.get_name(), message)

    def _measure_execution_time(self, func: Callable[..., Any]) -> Callable[..., Any]:
        return _measure_execution_time(func)

    def _analysis_context(
        self,
        result: dict[str, Any],
        *,
        error_message: str,
        set_available: bool = True,
    ):
        return _analysis_context(
            self._log_error,
            result,
            error_message=error_message,
            set_available=set_available,
        )

    def get_file_size(self) -> int | None:
        if not self.filepath:
            return None
        try:
            return self.filepath.stat().st_size
        except OSError:
            return None

    def get_file_extension(self) -> str:
        if not self.filepath:
            return ""
        return self.filepath.suffix.lstrip(".").lower()

    def file_exists(self) -> bool:
        if not self.filepath:
            return False
        return self.filepath.exists() and self.filepath.is_file()

    def __str__(self) -> str:
        return _analyzer_str(self)

    def __repr__(self) -> str:
        return _analyzer_repr(self)
