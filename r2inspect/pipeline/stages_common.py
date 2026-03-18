#!/usr/bin/env python3
"""Common pipeline stages."""

from __future__ import annotations

import inspect
import logging
from typing import Any

from ..interfaces import AnalyzerBackend, AnalyzerFactoryLike, ResultAggregatorFactoryLike
from .analysis_pipeline import AnalysisStage

logger = logging.getLogger(__name__)


def default_analyzer_factory(analyzer_class: type[Any], **kwargs: Any) -> Any:
    """Instantiate analyzers directly for standalone stage callers."""
    signature = inspect.signature(analyzer_class)
    parameters = signature.parameters
    accepts_kwargs = any(
        param.kind is inspect.Parameter.VAR_KEYWORD for param in parameters.values()
    )

    if "filename" in kwargs and "filename" not in parameters and "filepath" in parameters:
        kwargs = {**kwargs, "filepath": kwargs["filename"]}
        kwargs.pop("filename", None)

    if not accepts_kwargs:
        kwargs = {key: value for key, value in kwargs.items() if key in parameters}

    try:
        return analyzer_class(**kwargs)
    except TypeError as exc:
        if "filename" not in kwargs:
            raise
        fallback_kwargs = dict(kwargs)
        fallback_kwargs["filepath"] = fallback_kwargs.pop("filename")
        try:
            return analyzer_class(**fallback_kwargs)
        except TypeError:
            raise exc


def default_result_aggregator_factory() -> Any:
    """Instantiate the default result aggregator for standalone stage callers."""
    from ..core.result_aggregator import ResultAggregator

    return ResultAggregator()


class AnalyzerStage(AnalysisStage):
    """Generic stage for executing a single analyzer."""

    def __init__(
        self,
        name: str,
        analyzer_class: type[Any],
        adapter: AnalyzerBackend,
        config: Any,
        filename: str,
        analyzer_factory: AnalyzerFactoryLike = default_analyzer_factory,
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
        self.analyzer_factory = analyzer_factory
        self.result_key = result_key or name

    def _execute(self, _context: dict[str, Any]) -> dict[str, Any]:
        try:
            analyzer = self.analyzer_factory(
                self.analyzer_class,
                adapter=self.adapter,
                config=self.config,
                filename=self.filename,
            )
            result = self._run_analysis_method(analyzer, ("analyze", "detect", "scan"))
            return {self.result_key: result}
        except Exception as e:
            logger.warning("Analyzer %s failed: %s", self.analyzer_class.__name__, e)
            return {self.result_key: {"error": str(e), "success": False}}

    @staticmethod
    def _run_analysis_method(analyzer: Any, method_names: tuple[str, ...]) -> Any:
        for method_name in method_names:
            method = getattr(analyzer, method_name, None)
            if callable(method):
                return method()
        return {"error": "No suitable analysis method found"}


class IndicatorStage(AnalysisStage):
    """Generate suspicious indicators from analysis results."""

    def __init__(
        self,
        result_aggregator_factory: ResultAggregatorFactoryLike = default_result_aggregator_factory,
    ) -> None:
        super().__init__(
            name="indicators",
            description="Generate suspicious indicators",
            optional=True,
            dependencies=["metadata", "detection"],
        )
        self.result_aggregator_factory = result_aggregator_factory

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        indicators = self.result_aggregator_factory().generate_indicators(
            context.get("results", {})
        )
        return {"indicators": indicators}
