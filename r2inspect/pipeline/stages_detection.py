#!/usr/bin/env python3
"""Detection-related pipeline stages."""

from __future__ import annotations

from typing import Any

from ..interfaces import AnalyzerBackend
from ..registry.analyzer_registry import AnalyzerRegistry
from ..utils.analyzer_factory import create_analyzer
from ..utils.logger import get_logger
from .analysis_pipeline import AnalysisStage

logger = get_logger(__name__)


class DetectionStage(AnalysisStage):
    """Execute detection analyzers for patterns and signatures."""

    def __init__(
        self,
        registry: AnalyzerRegistry,
        adapter: AnalyzerBackend,
        config: Any,
        filename: str,
        options: dict[str, Any],
    ) -> None:
        super().__init__(
            name="detection",
            description="Pattern and signature detection",
            optional=True,
            dependencies=["format_detection"],
        )
        self.registry = registry
        self.adapter = adapter
        self.config = config
        self.filename = filename
        self.options = options

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        results: dict[str, Any] = {}
        if self.options.get("detect_packer", True):
            res = self._run_packer_detection(context)
            if res is not None:
                results.update(res)

        if self.options.get("detect_crypto", True):
            res = self._run_crypto_detection(context)
            if res is not None:
                results.update(res)

        res = self._run_anti_analysis_detection(context)
        if res is not None:
            results.update(res)

        res = self._run_compiler_detection(context)
        if res is not None:
            results.update(res)

        res = self._run_yara_analysis(context)
        if res is not None:
            results.update(res)

        return results

    def _run_analyzer(
        self, context: dict[str, Any], analyzer_name: str, result_key: str
    ) -> dict[str, Any] | None:
        analyzer_class = self.registry.get_analyzer_class(analyzer_name)
        if analyzer_class:
            try:
                analyzer = create_analyzer(
                    analyzer_class,
                    adapter=self.adapter,
                    config=self.config,
                    filename=self.filename,
                )
                data = analyzer.detect()
                context["results"][result_key] = data
                return {result_key: data}
            except Exception as e:
                logger.warning(f"Analyzer '{analyzer_name}' failed: {e}")
                context["results"][result_key] = {"error": str(e)}
                return {result_key: {"error": str(e)}}
        return None

    def _run_packer_detection(self, context: dict[str, Any]) -> dict[str, Any] | None:
        return self._run_analyzer(context, "packer_detector", "packer")

    def _run_crypto_detection(self, context: dict[str, Any]) -> dict[str, Any] | None:
        return self._run_analyzer(context, "crypto_analyzer", "crypto")

    def _run_anti_analysis_detection(self, context: dict[str, Any]) -> dict[str, Any] | None:
        return self._run_analyzer(context, "anti_analysis", "anti_analysis")

    def _run_compiler_detection(self, context: dict[str, Any]) -> dict[str, Any] | None:
        analyzer_class = self.registry.get_analyzer_class("compiler_detector")
        if analyzer_class:
            try:
                analyzer = create_analyzer(
                    analyzer_class,
                    adapter=self.adapter,
                    config=self.config,
                    filename=self.filename,
                )
                data = analyzer.detect_compiler()
                context["results"]["compiler"] = data
                return {"compiler": data}
            except Exception as e:
                logger.warning(f"Compiler detection failed: {e}")
                context["results"]["compiler"] = {"error": str(e)}
                return {"compiler": {"error": str(e)}}
        return None

    def _run_yara_analysis(self, context: dict[str, Any]) -> dict[str, Any] | None:
        analyzer_class = self.registry.get_analyzer_class("yara_analyzer")
        if analyzer_class:
            try:
                analyzer = create_analyzer(
                    analyzer_class,
                    adapter=self.adapter,
                    config=self.config,
                    filename=self.filename,
                )
                custom_rules = self.options.get("custom_yara")
                data = analyzer.scan(custom_rules)
                context["results"]["yara_matches"] = data
                return {"yara_matches": data}
            except Exception as e:
                logger.warning(f"YARA analysis failed: {e}")
                context["results"]["yara_matches"] = []
                return {"yara_matches": []}
        return None
