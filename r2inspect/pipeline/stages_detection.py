#!/usr/bin/env python3
"""Detection-related pipeline stages."""

from __future__ import annotations

import logging
from typing import Any

from ..interfaces import AnalyzerBackend, AnalyzerFactoryLike, AnalyzerRegistryLike
from .analysis_pipeline import AnalysisStage
from .stages_common import default_analyzer_factory

logger = logging.getLogger(__name__)


class DetectionStage(AnalysisStage):
    """Execute detection analyzers for patterns and signatures."""

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
        self.analyzer_factory = analyzer_factory

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
        self,
        context: dict[str, Any],
        analyzer_name: str,
        result_key: str,
        *,
        analyze_args: tuple[Any, ...] = (),
        error_default: Any = None,
    ) -> dict[str, Any] | None:
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
            data = analyzer.analyze(*analyze_args)
            context["results"][result_key] = data
            return {result_key: data}
        except Exception as e:
            logger.warning("Analyzer '%s' failed: %s", analyzer_name, e)
            fallback = error_default if error_default is not None else {"error": str(e)}
            context["results"][result_key] = fallback
            return {result_key: fallback}

    def _run_packer_detection(self, context: dict[str, Any]) -> dict[str, Any] | None:
        return self._run_analyzer(context, "packer_detector", "packer")

    def _run_crypto_detection(self, context: dict[str, Any]) -> dict[str, Any] | None:
        return self._run_analyzer(context, "crypto_analyzer", "crypto")

    def _run_anti_analysis_detection(self, context: dict[str, Any]) -> dict[str, Any] | None:
        return self._run_analyzer(context, "anti_analysis", "anti_analysis")

    def _run_compiler_detection(self, context: dict[str, Any]) -> dict[str, Any] | None:
        return self._run_analyzer(context, "compiler_detector", "compiler")

    def _run_yara_analysis(self, context: dict[str, Any]) -> dict[str, Any] | None:
        custom_rules = self.options.get("custom_yara")
        return self._run_analyzer(
            context,
            "yara_analyzer",
            "yara_matches",
            analyze_args=(custom_rules,),
            error_default=[],
        )
