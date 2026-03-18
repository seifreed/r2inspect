#!/usr/bin/env python3
"""Protocol interfaces for r2inspect components."""

from .binary_analyzer import (
    AnalysisProvider,
    BinaryAnalyzerInterface,
    ByteAccessProvider,
    CoreQueryProvider,
    DetectionEngineInterface,
    DisassemblyProvider,
    FormatAnalyzerInterface,
    FunctionProvider,
    HashingAnalyzerInterface,
    ImportExportProvider,
    PEFormatProvider,
    SearchProvider,
    SectionProvider,
    StringProvider,
    TextQueryProvider,
)
from .core import (
    AnalyzerBackend,
    ConfigLike,
    FileValidatorLike,
    MagicDetectorLike,
    MagicDetectorProviderLike,
    MemoryMonitorLike,
    R2CommandInterface,
    ResultAggregatorLike,
)
from .pipeline import (
    AnalyzerFactoryLike,
    AnalyzerRegistryLike,
    FileTypeDetectorLike,
    HashCalculatorLike,
    ResultAggregatorFactoryLike,
)
from .runtime import AnalysisRuntimePort, ResultValidationPort

__all__ = [
    "AnalysisProvider",
    "BinaryAnalyzerInterface",
    "ByteAccessProvider",
    "CoreQueryProvider",
    "DetectionEngineInterface",
    "DisassemblyProvider",
    "FormatAnalyzerInterface",
    "FunctionProvider",
    "HashingAnalyzerInterface",
    "ImportExportProvider",
    "PEFormatProvider",
    "SearchProvider",
    "SectionProvider",
    "StringProvider",
    "TextQueryProvider",
    "AnalyzerBackend",
    "ConfigLike",
    "FileValidatorLike",
    "MagicDetectorLike",
    "MagicDetectorProviderLike",
    "MemoryMonitorLike",
    "R2CommandInterface",
    "ResultAggregatorLike",
    "AnalyzerFactoryLike",
    "AnalyzerRegistryLike",
    "FileTypeDetectorLike",
    "HashCalculatorLike",
    "ResultAggregatorFactoryLike",
    "AnalysisRuntimePort",
    "ResultValidationPort",
]

__version__ = "1.0.0"
__author__ = "Marc Rivero López"
__license__ = "GPLv3"
