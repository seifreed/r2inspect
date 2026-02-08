#!/usr/bin/env python3
"""Protocol interfaces for r2inspect components."""

from .binary_analyzer import (
    BinaryAnalyzerInterface,
    DetectionEngineInterface,
    FormatAnalyzerInterface,
    HashingAnalyzerInterface,
)
from .core import (
    AnalyzerBackend,
    ConfigLike,
    FileValidatorLike,
    MemoryMonitorLike,
    R2CommandInterface,
    ResultAggregatorLike,
)

__all__ = [
    "BinaryAnalyzerInterface",
    "HashingAnalyzerInterface",
    "DetectionEngineInterface",
    "FormatAnalyzerInterface",
    "AnalyzerBackend",
    "ConfigLike",
    "FileValidatorLike",
    "MemoryMonitorLike",
    "R2CommandInterface",
    "ResultAggregatorLike",
]

__version__ = "1.0.0"
__author__ = "Marc Rivero López"
__license__ = "GPLv3"
