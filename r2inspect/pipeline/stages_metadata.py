#!/usr/bin/env python3
"""Metadata-related pipeline stages."""

from __future__ import annotations

from typing import Any

from ..interfaces import (
    AnalyzerBackend,
    AnalyzerFactoryLike,
    AnalyzerRegistryLike,
    ConfigLike,
)
from .stages_common import (
    RegistryStage,
    default_analyzer_factory,
    run_registered_analyzer,
)


class MetadataStage(RegistryStage):
    """Extract structural metadata from binaries."""

    def __init__(
        self,
        registry: AnalyzerRegistryLike,
        adapter: AnalyzerBackend,
        config: ConfigLike,
        filename: str,
        options: dict[str, Any],
        analyzer_factory: AnalyzerFactoryLike = default_analyzer_factory,
    ) -> None:
        super().__init__(
            name="metadata",
            description="Structural metadata extraction",
            dependencies=["file_info", "format_detection"],
            registry=registry,
            adapter=adapter,
            config=config,
            filename=filename,
            analyzer_factory=analyzer_factory,
        )
        self.options = options

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

        return run_registered_analyzer(
            self,
            context,
            analyzer_name,
            result_key,
            invoke=lambda analyzer: getattr(analyzer, method_name)(),
            error_default=lambda _e: default_value,
            log_label=f"{result_key.replace('_', ' ').title()} analysis",
        )

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
