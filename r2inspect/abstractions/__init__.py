#!/usr/bin/env python3
"""
r2inspect Abstractions Module

This module provides abstract base classes, dataclasses, and common
infrastructure for implementing analyzers within the r2inspect framework.

The abstractions enforce architectural consistency, eliminate code duplication,
and provide standardized interfaces for result representation and hash
calculation strategies.

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)

Key Components:
    AnalysisResult: Standardized dataclass for analysis results
    BaseAnalyzer: Abstract base class for all analyzers (unified interface)
    HashingStrategy: Abstract base class for hash calculation analyzers (Template Method)

Example:
    >>> from r2inspect.abstractions import AnalysisResult, BaseAnalyzer, HashingStrategy
    >>> from pathlib import Path
    >>>
    >>> # Create a standardized result
    >>> result = AnalysisResult(
    ...     file_path=Path("/path/to/binary"),
    ...     file_format="PE"
    ... )
    >>> result.add_hash("sha256", "abc123...")
    >>> result.add_detection("yara", "Malware.Trojan", severity="high")
    >>>
    >>> # Implement a custom analyzer using BaseAnalyzer
    >>> class CustomAnalyzer(BaseAnalyzer):
    ...     def __init__(self, r2, config):
    ...         super().__init__(r2=r2, config=config)
    ...
    ...     def analyze(self) -> dict[str, Any]:
    ...         result = self._init_result_structure()
    ...         result["data"] = self._extract_custom_data()
    ...         result["available"] = True
    ...         return result
    ...
    ...     def get_category(self) -> str:
    ...         return "metadata"
    >>>
    >>> # Implement a custom hashing strategy (for hash analyzers only)
    >>> class CustomHashAnalyzer(HashingStrategy):
    ...     def _check_library_availability(self):
    ...         return True, None
    ...
    ...     def _calculate_hash(self):
    ...         # Implementation
    ...         pass
    ...
    ...     def _get_hash_type(self):
    ...         return "custom"
    ...
    ...     @staticmethod
    ...     def compare_hashes(h1, h2):
    ...         # Implementation
    ...         pass
    ...
    ...     @staticmethod
    ...     def is_available():
    ...         return True
"""

from .analysis_result import AnalysisResult
from .base_analyzer import BaseAnalyzer
from .hashing_strategy import HashingStrategy

__all__ = [
    "AnalysisResult",
    "BaseAnalyzer",
    "HashingStrategy",
]

__version__ = "1.0.0"
__author__ = "Marc Rivero López"
__license__ = "GPLv3"
