#!/usr/bin/env python3
"""
r2inspect Core Package - Main analysis engine components

This package provides the core components for binary analysis:
- R2Inspector: Main analysis facade class
- FileValidator: File validation logic
- R2Session: r2pipe session management
- Constants: File validation and analysis thresholds

For backward compatibility, R2Inspector is re-exported at the package level.

Copyright (C) 2025 Marc Rivero Lopez
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

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
from .r2_session import R2Session
from .result_aggregator import ResultAggregator

__all__ = [
    # Main class
    "R2Inspector",
    # Component classes
    "FileValidator",
    "R2Session",
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
