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
    BaseAnalyzer: Abstract base class for all analyzers (unified interface)
    HashingStrategy: Abstract base class for hash calculation analyzers (Template Method)
"""

from .base_analyzer import BaseAnalyzer
from .hashing_strategy import HashingStrategy

__all__ = [
    "BaseAnalyzer",
    "HashingStrategy",
]

__version__ = "1.0.0"
__author__ = "Marc Rivero López"
__license__ = "GPLv3"
