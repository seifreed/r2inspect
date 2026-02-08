#!/usr/bin/env python3
"""Common pipeline stages."""

from __future__ import annotations

from typing import Any

from ..core.result_aggregator import ResultAggregator
from ..interfaces import AnalyzerBackend
from ..utils.analyzer_factory import create_analyzer, run_analysis_method
from ..utils.logger import get_logger
from .analysis_pipeline import AnalysisStage

logger = get_logger(__name__)


class AnalyzerStage(AnalysisStage):
    """Generic stage for executing a single analyzer."""

    def __init__(
        self,
        name: str,
        analyzer_class: type[Any],
        adapter: AnalyzerBackend,
        config: Any,
        filename: str,
        result_key: str | None = None,
        optional: bool = True,
    ) -> None:
        super().__init__(
            name=name,
            description=f"Execute {analyzer_class.__name__}",
            optional=optional,
        )
        self.analyzer_class = analyzer_class
        self.adapter = adapter
        self.config = config
        self.filename = filename
        self.result_key = result_key or name

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        try:
            analyzer = create_analyzer(
                self.analyzer_class,
                adapter=self.adapter,
                config=self.config,
                filename=self.filename,
            )
            result = run_analysis_method(analyzer, ("analyze", "detect", "scan"))
            context["results"][self.result_key] = result
        except Exception as e:
            logger.warning(f"Analyzer {self.analyzer_class.__name__} failed: {e}")
            context["results"][self.result_key] = {"error": str(e)}

        return context


class IndicatorStage(AnalysisStage):
    """Generate suspicious indicators from analysis results."""

    def __init__(self) -> None:
        super().__init__(
            name="indicators",
            description="Generate suspicious indicators",
            optional=True,
            dependencies=["metadata", "detection"],
        )

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        indicators = ResultAggregator().generate_indicators(context.get("results", {}))
        context["results"]["indicators"] = indicators
        return {"indicators": indicators}
