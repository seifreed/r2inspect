#!/usr/bin/env python3
"""Metadata-related pipeline stages."""

from __future__ import annotations

import logging
from typing import Any

from ..interfaces import AnalyzerBackend, AnalyzerFactoryLike, AnalyzerRegistryLike
from .analysis_pipeline import AnalysisStage
from .stages_common import default_analyzer_factory

logger = logging.getLogger(__name__)


class MetadataStage(AnalysisStage):
    """Extract structural metadata from binaries."""

    def __init__(
        self,
        registry: AnalyzerRegistryLike,
        adapter: AnalyzerBackend,
        config: Any,
        filename: str,
        options: dict[str, Any],
        analyzer_factory: AnalyzerFactoryLike = default_analyzer_factory,
    ) -> None:
        super().__init__(
            name="metadata",
            description="Structural metadata extraction",
            optional=True,
            dependencies=["file_info", "format_detection"],
        )
        self.registry = registry
        self.adapter = adapter
        self.config = config
        self.filename = filename
        self.options = options
        self.analyzer_factory = analyzer_factory

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        results: dict[str, Any] = {}

        res = self._extract_sections(context)
        if res is not None:
            results.update(res)

        res = self._extract_imports(context)
        if res is not None:
            results.update(res)

        res = self._extract_exports(context)
        if res is not None:
            results.update(res)

        res = self._extract_strings(context)
        if res is not None:
            results.update(res)

        if self.options.get("analyze_functions", True):
            res = self._extract_functions(context)
            if res is not None:
                results.update(res)

        return results

    def _run_analyzer_method(
        self,
        context: dict[str, Any],
        analyzer_name: str,
        method_name: str,
        result_key: str,
        default_value: list | dict | None = None,
    ) -> dict[str, Any] | None:
        if default_value is None:
            default_value = []

        analyzer_class = self.registry.get_analyzer_class(analyzer_name)
        if not analyzer_class:
            return None

        try:
            analyzer = self.analyzer_factory(
                analyzer_class,
                adapter=self.adapter,
                config=self.config,
                filename=self.filename,
            )
            method = getattr(analyzer, method_name)
            data = method()
            context["results"][result_key] = data
            return {result_key: data}
        except Exception as e:
            logger.warning("%s analysis failed: %s", result_key.replace("_", " ").title(), e)
            context["results"][result_key] = default_value
            return {result_key: default_value}

    def _extract_sections(self, context: dict[str, Any]) -> dict[str, Any] | None:
        return self._run_analyzer_method(
            context, "section_analyzer", "analyze_sections", "sections"
        )

    def _extract_imports(self, context: dict[str, Any]) -> dict[str, Any] | None:
        return self._run_analyzer_method(context, "import_analyzer", "get_imports", "imports")

    def _extract_exports(self, context: dict[str, Any]) -> dict[str, Any] | None:
        return self._run_analyzer_method(context, "export_analyzer", "get_exports", "exports")

    def _extract_strings(self, context: dict[str, Any]) -> dict[str, Any] | None:
        return self._run_analyzer_method(context, "string_analyzer", "extract_strings", "strings")

    def _extract_functions(self, context: dict[str, Any]) -> dict[str, Any] | None:
        return self._run_analyzer_method(
            context, "function_analyzer", "analyze_functions", "functions", {}
        )
