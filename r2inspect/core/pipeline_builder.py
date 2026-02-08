#!/usr/bin/env python3
"""Pipeline builder for composing analysis stages."""

from typing import Any

from ..interfaces import AnalyzerBackend, ConfigLike
from ..pipeline.analysis_pipeline import AnalysisPipeline
from ..pipeline.stages import (
    DetectionStage,
    FileInfoStage,
    FormatAnalysisStage,
    FormatDetectionStage,
    HashingStage,
    IndicatorStage,
    MetadataStage,
    SecurityStage,
)
from ..utils.logger import get_logger

logger = get_logger(__name__)


class PipelineBuilder:
    """
    Builds analysis pipelines based on configuration and options.

    This class encapsulates the logic for constructing analysis pipelines,
    separating pipeline composition from the main R2Inspector class.

    Attributes:
        adapter: R2Pipe adapter for radare2 operations
        registry: Analyzer registry for dynamic discovery
        config: Configuration object
        filename: Path to file being analyzed
    """

    def __init__(
        self,
        adapter: AnalyzerBackend,
        registry: Any,
        config: ConfigLike,
        filename: str,
    ):
        """
        Initialize PipelineBuilder.

        Args:
            adapter: R2Pipe adapter for radare2 operations
            registry: Analyzer registry for dynamic discovery
            config: Configuration object
            filename: Path to file being analyzed
        """
        self.adapter = adapter
        self.registry = registry
        self.config = config
        self.filename = filename

    def _add_stage_to_pipeline(
        self,
        pipeline: AnalysisPipeline,
        stage_class: type[Any],
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """
        Add a stage to the pipeline with configured timeout.

        This helper method reduces repetition in build() by centralizing
        stage instantiation, timeout configuration, and pipeline addition.

        Args:
            pipeline: The AnalysisPipeline to add the stage to
            stage_class: The stage class to instantiate
            *args: Positional arguments to pass to the stage constructor
            **kwargs: Keyword arguments to pass to the stage constructor
        """
        stage = stage_class(*args, **kwargs)
        stage.timeout = self.config.typed_config.pipeline.stage_timeout
        pipeline.add_stage(stage)

    def build(self, options: dict[str, Any]) -> AnalysisPipeline:
        """
        Build analysis pipeline based on options.

        Constructs a pipeline by adding stages in execution order. The pipeline
        composition is dynamic and adapts to analysis options and file format.

        Args:
            options: Analysis options dictionary

        Returns:
            Configured AnalysisPipeline ready for execution
        """
        # Determine max workers from config
        max_workers = self.config.typed_config.pipeline.max_workers
        pipeline = AnalysisPipeline(max_workers=max_workers)

        stage_specs: list[tuple[type[Any], tuple[Any, ...], dict[str, Any]]] = [
            (FileInfoStage, (self.adapter, self.filename), {}),
            (FormatDetectionStage, (self.adapter, self.filename), {}),
            (
                FormatAnalysisStage,
                (self.registry, self.adapter, self.config, self.filename),
                {},
            ),
            (
                MetadataStage,
                (self.registry, self.adapter, self.config, self.filename, options),
                {},
            ),
            (
                SecurityStage,
                (self.registry, self.adapter, self.config, self.filename),
                {},
            ),
            (
                HashingStage,
                (self.registry, self.adapter, self.config, self.filename),
                {},
            ),
            (
                DetectionStage,
                (self.registry, self.adapter, self.config, self.filename, options),
                {},
            ),
            (IndicatorStage, (), {}),
        ]

        for stage_class, args, kwargs in stage_specs:
            self._add_stage_to_pipeline(pipeline, stage_class, *args, **kwargs)

        logger.debug(f"Built pipeline with {len(pipeline)} stages")
        return pipeline


__all__ = ["PipelineBuilder"]
