"""Shared analyzer registry helpers for class inspection and metadata parsing."""

from __future__ import annotations

import inspect
from typing import Any

from .categories import AnalyzerCategory
from .metadata_extraction import extract_metadata_from_class, parse_category


class AnalyzerRegistryBaseMixin:
    """Introspection helpers shared by the analyzer registry."""

    _base_analyzer_class: type | None

    def _get_base_analyzer_class(self) -> type | None:
        if self._base_analyzer_class is None:
            try:
                from ..abstractions.base_analyzer import BaseAnalyzer

                self._base_analyzer_class = BaseAnalyzer
            except ImportError:
                pass
        return self._base_analyzer_class

    def is_base_analyzer(self, analyzer_class: type) -> bool:
        base_analyzer = self._get_base_analyzer_class()
        if base_analyzer is None:
            return False
        try:
            return issubclass(analyzer_class, base_analyzer)
        except TypeError:
            return False

    def extract_metadata_from_class(
        self, analyzer_class: type, name: str | None = None
    ) -> dict[str, Any]:
        return extract_metadata_from_class(
            analyzer_class, is_base_analyzer=self.is_base_analyzer, name=name
        )

    def _parse_category(self, category_value: Any) -> AnalyzerCategory:
        return parse_category(category_value)

    def validate_analyzer(self, analyzer_class: type) -> tuple[bool, str | None]:
        if not inspect.isclass(analyzer_class):
            return False, "analyzer_class must be a class, not an instance"
        if self.is_base_analyzer(analyzer_class):
            if not hasattr(analyzer_class, "analyze"):
                return False, "BaseAnalyzer subclass must implement analyze() method"
            if hasattr(analyzer_class.analyze, "__isabstractmethod__"):
                if analyzer_class.analyze.__isabstractmethod__:
                    return False, "analyze() method is not implemented (still abstract)"
        if not hasattr(analyzer_class, "__init__"):  # pragma: no cover
            return False, "Analyzer class must have __init__ method"
        return True, None
