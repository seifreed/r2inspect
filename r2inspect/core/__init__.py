#!/usr/bin/env python3
"""Core analysis components for r2inspect."""

from .constants import (
    HUGE_FILE_THRESHOLD_MB,
    LARGE_FILE_THRESHOLD_MB,
    MIN_EXECUTABLE_SIZE_BYTES,
    MIN_HEADER_SIZE_BYTES,
    MIN_INFO_RESPONSE_LENGTH,
    VERY_LARGE_FILE_THRESHOLD_MB,
)
from .file_validator import FileValidator
from .inspector import R2Inspector
from .pipeline_builder import PipelineBuilder
from .result_aggregator import ResultAggregator

__all__ = [
    # Main class
    "R2Inspector",
    # Component classes
    "FileValidator",
    "PipelineBuilder",
    "ResultAggregator",
    # Constants
    "MIN_EXECUTABLE_SIZE_BYTES",
    "MIN_HEADER_SIZE_BYTES",
    "MIN_INFO_RESPONSE_LENGTH",
    "LARGE_FILE_THRESHOLD_MB",
    "VERY_LARGE_FILE_THRESHOLD_MB",
    "HUGE_FILE_THRESHOLD_MB",
]
