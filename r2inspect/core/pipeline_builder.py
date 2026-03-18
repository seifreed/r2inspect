#!/usr/bin/env python3
"""Pipeline builder for composing analysis stages."""

from typing import Any

from ..interfaces import (
    AnalyzerBackend,
    ConfigLike,
    MagicDetectorProviderLike,
)
from ..pipeline.analysis_pipeline import AnalysisPipeline
from ..pipeline.stages import (
    AnalyzerStage,
    DetectionStage,
    FileInfoStage,
    FormatAnalysisStage,
    FormatDetectionStage,
    HashingStage,
    IndicatorStage,
    MetadataStage,
    SecurityStage,
)
from ..infrastructure.logging import get_logger
from ..pipeline_composition import (
    PipelineRuntimeDependencies,
    default_pipeline_runtime_dependencies,
)
from . import pipeline_stage_specs as _stage_specs
from .pipeline_builder_runtime import apply_runtime_dependencies as _apply_runtime_dependencies

logger = get_logger(__name__)


class PipelineBuilder:
    """Assemble a configured analysis pipeline for one target file."""

    def __init__(
        self,
        adapter: AnalyzerBackend,
        registry: Any,
        config: ConfigLike,
        filename: str,
        magic_detector_provider: MagicDetectorProviderLike | None = None,
        runtime_dependencies: PipelineRuntimeDependencies | None = None,
    ):
        """Store composition inputs and bind runtime dependencies."""
        self.adapter = adapter
        self.registry = registry
        self.config = config
        self.filename = filename
        self.magic_detector_provider = magic_detector_provider
        deps = runtime_dependencies or default_pipeline_runtime_dependencies()
        _apply_runtime_dependencies(self, deps)

    def _pipeline_max_workers(self) -> int:
        return int(self.config.typed_config.pipeline.max_workers)

    def _stage_timeout(self) -> float | None:
        val = self.config.typed_config.pipeline.stage_timeout
        return float(val) if val is not None else None

    def _build_pipeline(self) -> AnalysisPipeline:
        return AnalysisPipeline(max_workers=self._pipeline_max_workers())

    def _file_info_args(self) -> tuple[Any, ...]:
        return _stage_specs.file_info_args(self)

    def _format_detection_args(self) -> tuple[Any, ...]:
        return _stage_specs.format_detection_args(self)

    def _analysis_stage_args(self) -> tuple[Any, Any, Any, str, Any]:
        return _stage_specs.analysis_stage_args(self)

    def _options_stage_args(
        self, options: dict[str, Any]
    ) -> tuple[Any, Any, Any, str, dict[str, Any], Any]:
        return _stage_specs.options_stage_args(self, options)

    def _stage_specs(
        self, options: dict[str, Any]
    ) -> list[tuple[type[Any], tuple[Any, ...], dict[str, Any]]]:
        return _stage_specs.stage_specs(self, options)

    def _add_stage_to_pipeline(
        self,
        pipeline: AnalysisPipeline,
        stage_class: type[Any],
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """Instantiate a stage, apply timeout, and append it to the pipeline."""
        stage_args = self._normalize_stage_args(stage_class, args)
        stage = stage_class(*stage_args, **kwargs)
        stage.timeout = self._stage_timeout()
        pipeline.add_stage(stage)

    def _normalize_stage_args(
        self, stage_class: type[Any], args: tuple[Any, ...]
    ) -> tuple[Any, ...]:
        return _stage_specs.normalize_stage_args(self, stage_class, args)

    def build(self, options: dict[str, Any]) -> AnalysisPipeline:
        """Build the stage sequence for the requested analysis options."""
        pipeline = self._build_pipeline()

        for stage_class, args, kwargs in self._stage_specs(options):
            self._add_stage_to_pipeline(pipeline, stage_class, *args, **kwargs)

        logger.debug("Built pipeline with %s stages", len(pipeline))
        return pipeline


__all__ = ["PipelineBuilder"]
