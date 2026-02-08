#!/usr/bin/env python3
"""Security-related pipeline stages."""

from __future__ import annotations

from typing import Any

from ..interfaces import AnalyzerBackend
from ..registry.analyzer_registry import AnalyzerRegistry
from ..utils.analyzer_factory import create_analyzer
from ..utils.logger import get_logger
from .analysis_pipeline import AnalysisStage

logger = get_logger(__name__)


class SecurityStage(AnalysisStage):
    """Analyze security features and exploit mitigations."""

    def __init__(
        self,
        registry: AnalyzerRegistry,
        adapter: AnalyzerBackend,
        config: Any,
        filename: str,
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
                analyzer = create_analyzer(
                    pe_analyzer_class,
                    adapter=self.adapter,
                    config=self.config,
                    filename=self.filename,
                )
                data = analyzer.get_security_features()
                context["results"]["security"] = data
                return {"security": data}
            except Exception as e:
                logger.warning(f"PE security analysis failed: {e}")
                context["results"]["security"] = {"error": str(e)}
                return {"security": {"error": str(e)}}
        return None

    def _analyze_mitigations(self, context: dict[str, Any]) -> dict[str, Any] | None:
        mitigation_class = self.registry.get_analyzer_class("exploit_mitigation")
        if mitigation_class:
            try:
                analyzer = create_analyzer(
                    mitigation_class, adapter=self.adapter, config=self.config
                )
                mitigations = analyzer.analyze()
                if "security" in context["results"]:
                    context["results"]["security"].update(mitigations)
                else:
                    context["results"]["security"] = mitigations
            except Exception as e:
                logger.debug(f"Mitigation analysis failed: {e}")
                return None
            return {"security": context["results"].get("security", {})}
        return None
