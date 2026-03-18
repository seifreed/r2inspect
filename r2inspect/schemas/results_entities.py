"""Result entity re-exports for backwards compatibility.

DEPRECATED: Import from domain.entities directly instead.
This module re-exports domain entities for backwards compatibility.
"""

from ..domain.entities import (
    AntiAnalysisResult,
    CryptoResult,
    ExportInfo,
    FileInfo,
    FunctionInfo,
    HashingResult,
    ImportInfo,
    Indicator,
    PackerResult,
    StringInfo,
    YaraMatch,
)

__all__ = [
    "FileInfo",
    "HashingResult",
    "ImportInfo",
    "ExportInfo",
    "YaraMatch",
    "StringInfo",
    "FunctionInfo",
    "AntiAnalysisResult",
    "PackerResult",
    "CryptoResult",
    "Indicator",
]
