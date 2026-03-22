#!/usr/bin/env python3
"""Hashing-related pipeline stages."""

from __future__ import annotations

import logging
from typing import Any

from ..interfaces import AnalyzerBackend, AnalyzerFactoryLike, AnalyzerRegistryLike
from ..registry.analyzer_registry import AnalyzerCategory
from .analysis_pipeline import AnalysisStage
from .stages_common import default_analyzer_factory

logger = logging.getLogger(__name__)


class HashingStage(AnalysisStage):
    """Execute hashing analyzers for similarity detection."""

    def __init__(
        self,
        registry: AnalyzerRegistryLike,
        adapter: AnalyzerBackend,
        config: Any,
        filename: str,
        analyzer_factory: AnalyzerFactoryLike = default_analyzer_factory,
    ) -> None:
        super().__init__(
            name="hashing",
            description="Execute fuzzy and similarity hashing",
            optional=True,
            dependencies=["file_info"],
        )
        self.registry = registry
        self.adapter = adapter
        self.config = config
        self.filename = filename
        self.analyzer_factory = analyzer_factory

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        file_format = context.get("metadata", {}).get("file_format", "Unknown")
        hashing_analyzers = self.registry.get_by_category(AnalyzerCategory.HASHING)

        results: dict[str, Any] = {}
        for name, analyzer_class in hashing_analyzers.items():
            try:
                if not self._supports_format(name, file_format):
                    logger.debug("Skipping %s: doesn't support %s", name, file_format)
                    continue
                analyzer = self._build_hashing_analyzer(analyzer_class)
                result = self._run_hashing_analyzer(name, analyzer)
                self._store_hashing_result(context, results, name, result)
            except Exception as e:
                logger.warning("Hashing analyzer '%s' failed: %s", name, e)
                context["results"][name] = {"error": str(e)}

        return results

    def _supports_format(self, name: str, file_format: str) -> bool:
        metadata = self.registry.get_metadata(name)
        return metadata is None or metadata.supports_format(file_format)

    def _build_hashing_analyzer(self, analyzer_class: type[Any]) -> Any:
        return self.analyzer_factory(
            analyzer_class,
            adapter=self.adapter,
            config=self.config,
            filename=self.filename,
        )

    def _run_hashing_analyzer(self, name: str, analyzer: Any) -> Any:
        if name == "tlsh" and hasattr(analyzer, "analyze_sections"):
            return analyzer.analyze_sections()
        if name == "ccbhash" and hasattr(analyzer, "analyze_functions"):
            return analyzer.analyze_functions()
        if name == "simhash" and hasattr(analyzer, "analyze_detailed"):
            return analyzer.analyze_detailed()
        return analyzer.analyze()

    def _store_hashing_result(
        self, context: dict[str, Any], results: dict[str, Any], name: str, result: Any
    ) -> None:
        context["results"][name] = result
        results[name] = result
