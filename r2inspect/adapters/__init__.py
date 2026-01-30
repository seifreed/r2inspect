#!/usr/bin/env python3
"""
r2inspect Adapters Module

This module provides adapter implementations for decoupling binary analysis
components from specific backend implementations. Adapters translate between
the generic Protocol interfaces and concrete tool implementations.

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)

Key Components:
    R2PipeAdapter: Adapter for radare2/r2pipe backend
    validation: Data validation and sanitization utilities

Usage:
    The adapter pattern allows for flexible backend substitution and
    facilitates testing with mock implementations or alternative tools.

Example:
    >>> from r2inspect.adapters import R2PipeAdapter
    >>> from r2inspect.interfaces import BinaryAnalyzerInterface
    >>> import r2pipe
    >>>
    >>> r2 = r2pipe.open("/path/to/binary")
    >>> adapter = R2PipeAdapter(r2)
    >>> assert isinstance(adapter, BinaryAnalyzerInterface)
    >>>
    >>> # Use adapter through the interface
    >>> info = adapter.get_file_info()
    >>> sections = adapter.get_sections()

Benefits:
    - Decouples analyzers from specific r2pipe implementation
    - Enables backend substitution without analyzer changes
    - Facilitates testing with alternative implementations
    - Centralizes r2pipe interaction logic and error handling
    - Provides consistent data validation and sanitization
"""

from .r2pipe_adapter import R2PipeAdapter
from .validation import is_valid_r2_response, sanitize_r2_output, validate_r2_data

__all__ = [
    "R2PipeAdapter",
    "validate_r2_data",
    "sanitize_r2_output",
    "is_valid_r2_response",
]

__version__ = "1.0.0"
__author__ = "Marc Rivero López"
__license__ = "GPLv3"
