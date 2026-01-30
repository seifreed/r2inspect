#!/usr/bin/env python3
"""
r2inspect Interfaces Module

This module provides Protocol-based interfaces for structural subtyping
within the r2inspect framework. Protocols enable duck typing with type
hints, allowing flexible implementation without inheritance requirements.

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)

Key Interfaces:
    BinaryAnalyzerInterface: Core interface for binary analysis operations
    HashingAnalyzerInterface: Interface for hash calculation analyzers
    DetectionEngineInterface: Interface for pattern/signature detection
    FormatAnalyzerInterface: Interface for format-specific analyzers

Usage:
    Protocols define contracts without requiring inheritance. Any class
    that implements the required methods automatically satisfies the protocol.

Example:
    >>> from r2inspect.interfaces import BinaryAnalyzerInterface
    >>> from typing import TYPE_CHECKING
    >>>
    >>> class MyAnalyzer:
    ...     def get_file_info(self):
    ...         return {"arch": "x86", "bits": 64}
    ...
    ...     def get_sections(self):
    ...         return [{"name": ".text", "size": 1024}]
    ...
    ...     # ... implement other required methods ...
    >>>
    >>> # Type checking works without inheritance
    >>> analyzer = MyAnalyzer()
    >>> assert isinstance(analyzer, BinaryAnalyzerInterface)
    >>>
    >>> # Can be used in type hints
    >>> def process(analyzer: BinaryAnalyzerInterface):
    ...     info = analyzer.get_file_info()
    ...     sections = analyzer.get_sections()

Benefits:
    - No inheritance required: Classes can implement protocols without
      explicitly inheriting from them
    - Structural subtyping: Type compatibility based on structure, not
      inheritance hierarchy
    - Multiple implementations: Same protocol can be implemented by
      unrelated classes
    - Third-party integration: External libraries can satisfy protocols
      without modification
    - Runtime checking: @runtime_checkable enables isinstance() checks
"""

from .binary_analyzer import (
    BinaryAnalyzerInterface,
    DetectionEngineInterface,
    FormatAnalyzerInterface,
    HashingAnalyzerInterface,
)

__all__ = [
    "BinaryAnalyzerInterface",
    "HashingAnalyzerInterface",
    "DetectionEngineInterface",
    "FormatAnalyzerInterface",
]

__version__ = "1.0.0"
__author__ = "Marc Rivero López"
__license__ = "GPLv3"
