#!/usr/bin/env python3
"""Concrete dependency bundles for pipeline composition roots."""

from __future__ import annotations

from dataclasses import dataclass

from .core.analyzer_factory import create_analyzer
from .core.result_aggregator import ResultAggregator
from .infrastructure.hashing import calculate_hashes
from .infrastructure.magic_detector import detect_file_type
from .interfaces import (
    AnalyzerFactoryLike,
    FileTypeDetectorLike,
    HashCalculatorLike,
    ResultAggregatorFactoryLike,
)


@dataclass(frozen=True)
class PipelineRuntimeDependencies:
    """Concrete collaborators required to build runtime analysis stages."""

    analyzer_factory: AnalyzerFactoryLike
    hash_calculator: HashCalculatorLike
    file_type_detector: FileTypeDetectorLike
    result_aggregator_factory: ResultAggregatorFactoryLike


def default_pipeline_runtime_dependencies() -> PipelineRuntimeDependencies:
    """Return the default concrete dependency bundle used in production."""
    return PipelineRuntimeDependencies(
        analyzer_factory=create_analyzer,
        hash_calculator=calculate_hashes,
        file_type_detector=detect_file_type,
        result_aggregator_factory=ResultAggregator,
    )
