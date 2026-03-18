#!/usr/bin/env python3
"""Security-related pipeline stages."""

from __future__ import annotations

import logging
from typing import Any

from ..interfaces import AnalyzerBackend, AnalyzerFactoryLike, AnalyzerRegistryLike
from .analysis_pipeline import AnalysisStage
from .stages_common import default_analyzer_factory

logger = logging.getLogger(__name__)


class SecurityStage(AnalysisStage):
    """Analyze security features and exploit mitigations."""

    def __init__(
        self,
        registry: AnalyzerRegistryLike,
        adapter: AnalyzerBackend,
        config: Any,
        filename: str,
        analyzer_factory: AnalyzerFactoryLike = default_analyzer_factory,
    ) -> None:
        super().__init__(
            name="security",
            description="Security feature and mitigation analysis",
            optional=True,
            dependencies=["format_detection"],
        )
        self.registry = registry
        self.adapter = adapter
        self.config = config
        self.filename = filename
        self.analyzer_factory = analyzer_factory

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        file_format = context.get("metadata", {}).get("file_format", "Unknown")

        results: dict[str, Any] = {}
        if file_format == "PE":
            res = self._analyze_pe_security(context)
            if res is not None:
                results.update(res)

        res = self._analyze_mitigations(context)
        if res is not None:
            results.update(res)

        return results

    def _analyze_pe_security(self, context: dict[str, Any]) -> dict[str, Any] | None:
        pe_analyzer_class = self.registry.get_analyzer_class("pe_analyzer")
        if pe_analyzer_class:
            try:
                analyzer = self.analyzer_factory(
                    pe_analyzer_class,
                    adapter=self.adapter,
                    config=self.config,
                    filename=self.filename,
                )
                data = analyzer.get_security_features()
                context["results"]["security"] = data
                return {"security": data}
            except Exception as e:
                logger.warning("PE security analysis failed: %s", e)
                context["results"]["security"] = {"error": str(e)}
                return {"security": {"error": str(e)}}
        return None

    def _analyze_mitigations(self, context: dict[str, Any]) -> dict[str, Any] | None:
        mitigation_class = self.registry.get_analyzer_class("exploit_mitigation")
        if mitigation_class:
            try:
                analyzer = self.analyzer_factory(
                    mitigation_class, adapter=self.adapter, config=self.config
                )
                mitigations = analyzer.analyze()
                if "security" in context["results"]:
                    context["results"]["security"].update(mitigations)
                else:
                    context["results"]["security"] = mitigations
            except Exception as e:
                logger.debug("Mitigation analysis failed: %s", e)
                return None
            return {"security": context["results"].get("security", {})}
        return None
