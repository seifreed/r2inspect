#!/usr/bin/env python3
"""
r2inspect Core Pipeline Builder - Constructs analysis pipelines

This module provides the PipelineBuilder class that constructs analysis
pipelines based on configuration and options.

Architecture:
    - Builder Pattern: Fluent interface for pipeline construction
    - Strategy Pattern: Different pipeline compositions for different analyses

Copyright (C) 2025 Marc Rivero Lopez
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

from typing import Any

from ..adapters.r2pipe_adapter import R2PipeAdapter
from ..config import Config
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
from ..registry.analyzer_registry import AnalyzerRegistry
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
        adapter: R2PipeAdapter,
        registry: AnalyzerRegistry,
        config: Config,
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
        self, pipeline: AnalysisPipeline, stage_class: type, *args, **kwargs
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
        stage.timeout = self.config.get("pipeline", "stage_timeout", None)
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
        max_workers = self.config.get("pipeline", "max_workers", 4)
        pipeline = AnalysisPipeline(max_workers=max_workers)

        # Stage 1: File information (always required)
        self._add_stage_to_pipeline(pipeline, FileInfoStage, self.adapter, self.filename)

        # Stage 2: Format detection (always required)
        self._add_stage_to_pipeline(pipeline, FormatDetectionStage, self.adapter, self.filename)

        # Stage 3: Format-specific analysis (conditional based on detected format)
        self._add_stage_to_pipeline(
            pipeline,
            FormatAnalysisStage,
            self.registry,
            self.adapter,
            self.config,
            self.filename,
        )

        # Stage 4: Metadata extraction (sections, imports, exports, strings, functions)
        self._add_stage_to_pipeline(
            pipeline,
            MetadataStage,
            self.registry,
            self.adapter,
            self.config,
            self.filename,
            options,
        )

        # Stage 5: Security analysis (exploit mitigations, signatures)
        self._add_stage_to_pipeline(
            pipeline,
            SecurityStage,
            self.registry,
            self.adapter,
            self.config,
            self.filename,
        )

        # Stage 6: Hashing (fuzzy hashing, similarity detection)
        self._add_stage_to_pipeline(
            pipeline,
            HashingStage,
            self.registry,
            self.adapter,
            self.config,
            self.filename,
        )

        # Stage 7: Detection (packer, crypto, anti-analysis, YARA)
        self._add_stage_to_pipeline(
            pipeline,
            DetectionStage,
            self.registry,
            self.adapter,
            self.config,
            self.filename,
            options,
        )

        # Stage 8: Indicator generation (suspicious patterns)
        self._add_stage_to_pipeline(pipeline, IndicatorStage)

        logger.debug(f"Built pipeline with {len(pipeline)} stages")
        return pipeline


__all__ = ["PipelineBuilder"]
