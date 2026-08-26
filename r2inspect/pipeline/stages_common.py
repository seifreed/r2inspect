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
from ..domain.results import TypedAnalyzerResult
from .results_bucket import _results_bucket
from .analysis_pipeline import AnalysisStage

logger = get_logger(__name__)


def _typed_result(
    analyzer_name: str, data: Any, *, status: str = "completed", error: str | None = None
) -> Any:
    """Attach typed metadata while preserving the legacy mapping contract."""
    if isinstance(data, TypedAnalyzerResult) or not isinstance(data, dict):
        return data
    return TypedAnalyzerResult(
        data,
        analyzer_id=analyzer_name,
        status=status,
        error=error,
    )


def _record_analyzer_status(
    context: dict[str, Any], analyzer_name: str, *, status: str, error: str | None = None
) -> None:
    """Keep status for analyzers whose legacy payload is not a mapping."""
    bucket = _results_bucket(context)
    statuses = bucket.setdefault("_analyzer_status", {})
    if not isinstance(statuses, dict):
        statuses = {}
        bucket["_analyzer_status"] = statuses
    payload: dict[str, Any] = {"status": status}
    if error:
        payload["error"] = error
    statuses[analyzer_name] = payload


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
        status = getattr(analyzer, "last_status", None)
        error = getattr(analyzer, "last_error", None)
        errors = getattr(analyzer, "_analysis_errors", None)
        if isinstance(errors, list) and errors:
            error = "; ".join(str(item) for item in errors)
            status = "failed"
        data = _typed_result(
            analyzer_name,
            data,
            status=str(status or "completed"),
            error=str(error) if error else None,
        )
        _results_bucket(context)[result_key] = data
        if error or (status and status != "completed"):
            _record_analyzer_status(
                context,
                analyzer_name,
                status=str(status or "failed"),
                error=str(error) if error else None,
            )
        return {result_key: data}
    except Exception as e:
        logger.warning("%s failed: %s", log_label, e)
        fallback = error_default(e)
        fallback = _typed_result(analyzer_name, fallback, status="failed", error=str(e))
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
