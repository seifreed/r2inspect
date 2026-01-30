#!/usr/bin/env python3
"""
r2inspect Schemas

Type-safe result schemas for all r2inspect analyzers using both Pydantic models
and Python dataclasses. This provides validation, IDE support, and seamless
dict <-> model conversion.

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)

Usage:
    # Import Pydantic schemas
    from r2inspect.schemas import HashAnalysisResult, FormatAnalysisResult

    # Create typed result
    result = HashAnalysisResult(
        available=True,
        hash_type="ssdeep",
        hash_value="3:abc:def"
    )

    # Convert dict to model
    from r2inspect.schemas import ResultConverter
    model = ResultConverter.convert_result("ssdeep", result_dict)

    # Convert model to dict
    from r2inspect.schemas import model_to_dict
    data = model_to_dict(result)

    # Import dataclass schemas
    from r2inspect.schemas.results import (
        FileInfo,
        HashingResult,
        SecurityFeatures,
        AnalysisResult,
    )

    # Create typed result with dataclasses
    file_info = FileInfo(name="sample.exe", size=1024)
    result = AnalysisResult(file_info=file_info)

    # Convert to dict
    data = result.to_dict()
"""

# Base schemas
from .base import AnalysisResultBase, FileInfoBase

# Converters
from .converters import ResultConverter, dict_to_model, model_to_dict, safe_convert, validate_result

# Format schemas
from .format import FormatAnalysisResult, SectionInfo, SecurityFeatures

# Hashing schemas
from .hashing import HashAnalysisResult

# Metadata schemas
from .metadata import (
    ExportAnalysisResult,
    ExportInfo,
    FunctionAnalysisResult,
    FunctionInfo,
    ImportAnalysisResult,
    ImportInfo,
    ImportStatistics,
    OverlayAnalysisResult,
    OverlayInfo,
    ResourceAnalysisResult,
    ResourceInfo,
    SectionAnalysisResult,
    StringAnalysisResult,
    StringInfo,
)

# Dataclass-based result schemas
from .results import AnalysisResult, AntiAnalysisResult, CryptoResult
from .results import ExportInfo as ExportInfoDC
from .results import FileInfo
from .results import FunctionInfo as FunctionInfoDC
from .results import HashingResult
from .results import ImportInfo as ImportInfoDC
from .results import Indicator, PackerResult
from .results import SectionInfo as SectionInfoDC
from .results import SecurityFeatures as SecurityFeaturesDC
from .results import StringInfo as StringInfoDC
from .results import YaraMatch, from_dict

# Security schemas
from .security import (
    AuthenticodeAnalysisResult,
    MitigationInfo,
    Recommendation,
    SecurityAnalysisResult,
    SecurityGrade,
    SecurityIssue,
    SecurityScore,
    SeverityLevel,
)

# Auto-register all schemas
# Hashing analyzers
ResultConverter.register_schemas(
    {
        # Fuzzy hashing
        "ssdeep": HashAnalysisResult,
        "tlsh": HashAnalysisResult,
        "impfuzzy": HashAnalysisResult,
        "ccbhash": HashAnalysisResult,
        "simhash": HashAnalysisResult,
        "telfhash": HashAnalysisResult,
        # Format analyzers
        "pe": FormatAnalysisResult,
        "elf": FormatAnalysisResult,
        "macho": FormatAnalysisResult,
        "pe_analyzer": FormatAnalysisResult,
        "elf_analyzer": FormatAnalysisResult,
        "macho_analyzer": FormatAnalysisResult,
        # Security analyzers
        "security": SecurityAnalysisResult,
        "exploit_mitigation": SecurityAnalysisResult,
        "exploit_mitigation_analyzer": SecurityAnalysisResult,
        "mitigations": SecurityAnalysisResult,
        "authenticode": AuthenticodeAnalysisResult,
        "authenticode_analyzer": AuthenticodeAnalysisResult,
        # Metadata analyzers
        "import": ImportAnalysisResult,
        "import_analyzer": ImportAnalysisResult,
        "imports": ImportAnalysisResult,
        "export": ExportAnalysisResult,
        "export_analyzer": ExportAnalysisResult,
        "exports": ExportAnalysisResult,
        "section": SectionAnalysisResult,
        "section_analyzer": SectionAnalysisResult,
        "sections": SectionAnalysisResult,
        "string": StringAnalysisResult,
        "string_analyzer": StringAnalysisResult,
        "strings": StringAnalysisResult,
        "function": FunctionAnalysisResult,
        "function_analyzer": FunctionAnalysisResult,
        "functions": FunctionAnalysisResult,
        "resource": ResourceAnalysisResult,
        "resource_analyzer": ResourceAnalysisResult,
        "resources": ResourceAnalysisResult,
        "overlay": OverlayAnalysisResult,
        "overlay_analyzer": OverlayAnalysisResult,
    }
)


__all__ = [
    # Base (Pydantic)
    "AnalysisResultBase",
    "FileInfoBase",
    # Hashing (Pydantic)
    "HashAnalysisResult",
    # Format (Pydantic)
    "FormatAnalysisResult",
    "SectionInfo",
    "SecurityFeatures",
    # Security (Pydantic)
    "SecurityAnalysisResult",
    "SecurityIssue",
    "SecurityScore",
    "SecurityGrade",
    "SeverityLevel",
    "MitigationInfo",
    "Recommendation",
    "AuthenticodeAnalysisResult",
    # Metadata (Pydantic)
    "ImportAnalysisResult",
    "ImportInfo",
    "ImportStatistics",
    "ExportAnalysisResult",
    "ExportInfo",
    "StringAnalysisResult",
    "StringInfo",
    "FunctionAnalysisResult",
    "FunctionInfo",
    "SectionAnalysisResult",
    "ResourceAnalysisResult",
    "ResourceInfo",
    "OverlayAnalysisResult",
    "OverlayInfo",
    # Converters
    "ResultConverter",
    "dict_to_model",
    "model_to_dict",
    "safe_convert",
    "validate_result",
    # Dataclass-based result schemas
    "AnalysisResult",
    "AntiAnalysisResult",
    "CryptoResult",
    "ExportInfoDC",
    "FileInfo",
    "FunctionInfoDC",
    "HashingResult",
    "ImportInfoDC",
    "Indicator",
    "PackerResult",
    "SectionInfoDC",
    "SecurityFeaturesDC",
    "StringInfoDC",
    "YaraMatch",
    "from_dict",
]


# Version
__version__ = "1.0.0"
