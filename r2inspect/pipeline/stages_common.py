#!/usr/bin/env python3
"""Common pipeline stages."""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any, ClassVar

from ..infrastructure.logging import get_logger
from ..interfaces import (
    AnalyzerBackend,
    AnalyzerFactoryLike,
    AnalyzerRegistryLike,
    ConfigLike,
    ResultAggregatorFactoryLike,
)
from ..core.analyzer_factory import run_analysis_method
from .results_bucket import _results_bucket
from .analysis_pipeline import AnalysisStage

logger = get_logger(__name__)


def run_registered_analyzer(
    stage: Any,
    context: dict[str, Any],
    analyzer_name: str,
    result_key: str,
    *,
    invoke: Callable[[Any], Any],
    error_default: Callable[[Exception], Any],
    log_label: str,
) -> dict[str, Any] | None:
    """Construct and run a registry analyzer, storing the result under result_key.

    Returns None when the analyzer is not registered. On failure logs a warning
    and stores ``error_default(exc)`` instead. ``invoke`` produces the result
    from the constructed analyzer; ``log_label`` is the subject of the warning.
    """
    analyzer_class = stage.registry.get_analyzer_class(analyzer_name)
    if not analyzer_class:
        return None
    try:
        analyzer = stage.analyzer_factory(
            analyzer_class,
            adapter=stage.adapter,
            config=stage.config,
            filename=stage.filename,
        )
        data = invoke(analyzer)
        _results_bucket(context)[result_key] = data
        return {result_key: data}
    except Exception as e:
        logger.warning("%s failed: %s", log_label, e)
        fallback = error_default(e)
        _results_bucket(context)[result_key] = fallback
        return {result_key: fallback}


def _normalize_analyzer_kwargs(
    parameters: Any, accepts_kwargs: bool, kwargs: dict[str, Any]
) -> dict[str, Any]:
    if "filename" in kwargs and "filename" not in parameters and "filepath" in parameters:
        kwargs = {**kwargs, "filepath": kwargs["filename"]}
        kwargs.pop("filename", None)
    if not accepts_kwargs:
        kwargs = {key: value for key, value in kwargs.items() if key in parameters}
    return kwargs


def _construct_with_filename_fallback(
    analyzer_class: type[Any], kwargs: dict[str, Any], exc: TypeError
) -> Any:
    if "filename" not in kwargs:
        raise exc
    fallback_kwargs = dict(kwargs)
    fallback_kwargs["filepath"] = fallback_kwargs.pop("filename")
    try:
        return analyzer_class(**fallback_kwargs)
    except TypeError:
        raise exc from None


def default_analyzer_factory(analyzer_class: type[Any], **kwargs: Any) -> Any:
    """Instantiate analyzers directly for standalone stage callers."""
    parameters = inspect.signature(analyzer_class).parameters
    accepts_kwargs = any(
        param.kind is inspect.Parameter.VAR_KEYWORD for param in parameters.values()
    )
    kwargs = _normalize_analyzer_kwargs(parameters, accepts_kwargs, kwargs)
    try:
        return analyzer_class(**kwargs)
    except TypeError as exc:
        return _construct_with_filename_fallback(analyzer_class, kwargs, exc)


def default_result_aggregator_factory() -> Any:
    """Instantiate the default result aggregator for standalone stage callers."""
    from ..core.result_aggregator import ResultAggregator

    return ResultAggregator()


class RegistryStage(AnalysisStage):
    """Base for stages that run registry-backed analyzers with shared wiring."""

    def __init__(
        self,
        *,
        name: str,
        description: str,
        dependencies: list[str],
        registry: AnalyzerRegistryLike,
        adapter: AnalyzerBackend,
        config: ConfigLike,
        filename: str,
        analyzer_factory: AnalyzerFactoryLike = default_analyzer_factory,
        condition: Callable[[dict[str, Any]], bool] | None = None,
    ) -> None:
        super().__init__(
            name=name,
            description=description,
            optional=True,
            dependencies=dependencies,
            condition=condition,
        )
        self.registry = registry
        self.adapter = adapter
        self.config = config
        self.filename = filename
        self.analyzer_factory = analyzer_factory


class ConfiguredRegistryStage(RegistryStage):
    """RegistryStage whose name/description/dependencies (and optional run
    condition) come from class attributes, removing per-stage constructor
    boilerplate."""

    stage_name: ClassVar[str]
    stage_description: ClassVar[str]
    stage_dependencies: ClassVar[list[str]]

    @staticmethod
    def _stage_condition() -> Callable[[dict[str, Any]], bool] | None:
        """Optional run condition; None means the stage always runs."""
        return None

    def __init__(
        self,
        registry: AnalyzerRegistryLike,
        adapter: AnalyzerBackend,
        config: ConfigLike,
        filename: str,
        analyzer_factory: AnalyzerFactoryLike = default_analyzer_factory,
    ) -> None:
        super().__init__(
            name=self.stage_name,
            description=self.stage_description,
            dependencies=self.stage_dependencies,
            registry=registry,
            adapter=adapter,
            config=config,
            filename=filename,
            analyzer_factory=analyzer_factory,
            condition=self._stage_condition(),
        )


class OptionsRegistryStage(ConfiguredRegistryStage):
    """ConfiguredRegistryStage that also captures per-run options."""

    def __init__(
        self,
        registry: AnalyzerRegistryLike,
        adapter: AnalyzerBackend,
        config: ConfigLike,
        filename: str,
        options: dict[str, Any],
        analyzer_factory: AnalyzerFactoryLike = default_analyzer_factory,
    ) -> None:
        super().__init__(registry, adapter, config, filename, analyzer_factory)
        self.options = options


class AnalyzerStage(AnalysisStage):
    """Generic stage for executing a single analyzer."""

    def __init__(
        self,
        name: str,
        analyzer_class: type[Any],
        adapter: AnalyzerBackend,
        config: ConfigLike,
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
        # Pure: returns the flat {result_key: result}; the orchestrator
        # (merge_into_plain_context / ThreadSafeContext.merge_results) owns
        # writing it into context["results"]. Required for the parallel
        # runtime — stages must not mutate the shared context concurrently.
        try:
            analyzer = self.analyzer_factory(
                self.analyzer_class,
                adapter=self.adapter,
                config=self.config,
                filename=self.filename,
            )
            result = run_analysis_method(analyzer, ("analyze", "detect", "scan"))
            return {self.result_key: result}
        except Exception as e:
            logger.warning("Analyzer %s failed: %s", self.analyzer_class.__name__, e)
            return {self.result_key: {"error": str(e), "success": False}}


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
        # Reads context["results"] (populated by upstream stages via the
        # orchestrator) but does not mutate it; returns the flat result
        # for the orchestrator to merge. See AnalyzerStage._execute.
        indicators = self.result_aggregator_factory().generate_indicators(
            context.get("results", {})
        )
        return {"indicators": indicators}
