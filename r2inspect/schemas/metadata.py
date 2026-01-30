#!/usr/bin/env python3
"""
Metadata Analyzer Pydantic Schemas

Schemas for metadata analyzers (sections, imports, exports, strings, functions)

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

from typing import Any

from pydantic import BaseModel, Field, field_validator

from .base import AnalysisResultBase

FUNCTION_NAME_DESC = "Function name"


class ImportInfo(BaseModel):
    """
    Information about an imported function.

    Attributes:
        name: Function name
        address: Import address
        ordinal: Import ordinal
        library: Library name
        type: Import type
        category: API category
        risk_score: Risk score (0-100)
        risk_level: Risk level (Minimal, Low, Medium, High, Critical)
        risk_tags: List of risk tags
        description: Function description
    """

    name: str = Field(..., description=FUNCTION_NAME_DESC)

    address: str | None = Field(None, description="Import address (hex)")

    ordinal: int | None = Field(None, ge=0, description="Import ordinal")

    library: str | None = Field(None, description="Library name")

    type: str | None = Field(None, description="Import type")

    category: str | None = Field(None, description="API category")

    risk_score: int = Field(0, ge=0, le=100, description="Risk score (0-100)")

    risk_level: str = Field("Low", description="Risk level")

    risk_tags: list[str] = Field(default_factory=list, description="Risk tags")

    description: str | None = Field(None, description="Function description")


class ImportStatistics(BaseModel):
    """
    Statistics about imports.

    Attributes:
        total_imports: Total number of imports
        unique_libraries: Number of unique libraries
        category_distribution: Distribution by category
        risk_distribution: Distribution by risk level
        library_distribution: Distribution by library
        suspicious_patterns: List of suspicious patterns
    """

    total_imports: int = Field(0, ge=0, description="Total imports")

    unique_libraries: int = Field(0, ge=0, description="Unique libraries")

    category_distribution: dict[str, int] = Field(
        default_factory=dict, description="Category distribution"
    )

    risk_distribution: dict[str, int] = Field(default_factory=dict, description="Risk distribution")

    library_distribution: dict[str, int] = Field(
        default_factory=dict, description="Library distribution"
    )

    suspicious_patterns: list[dict[str, Any]] = Field(
        default_factory=list, description="Suspicious patterns"
    )


class ImportAnalysisResult(AnalysisResultBase):
    """
    Result from import table analysis.

    Attributes:
        imports: List of imported functions
        statistics: Import statistics
        missing_imports: List of potentially missing imports
    """

    imports: list[ImportInfo] = Field(default_factory=list, description="List of imports")

    statistics: ImportStatistics | None = Field(None, description="Import statistics")

    missing_imports: list[str] = Field(
        default_factory=list, description="Potentially missing imports"
    )


class ExportInfo(BaseModel):
    """
    Information about an exported function.

    Attributes:
        name: Function name
        address: Export address
        ordinal: Export ordinal
        type: Export type
        size: Function size
    """

    name: str = Field(..., description=FUNCTION_NAME_DESC)

    address: str | None = Field(None, description="Export address (hex)")

    ordinal: int | None = Field(None, ge=0, description="Export ordinal")

    type: str | None = Field(None, description="Export type")

    size: int | None = Field(None, ge=0, description="Function size")


class ExportAnalysisResult(AnalysisResultBase):
    """
    Result from export table analysis.

    Attributes:
        exports: List of exported functions
        total_exports: Total number of exports
    """

    exports: list[ExportInfo] = Field(default_factory=list, description="List of exports")

    total_exports: int = Field(0, ge=0, description="Total exports")


class StringInfo(BaseModel):
    """
    Information about a string found in binary.

    Attributes:
        value: String value
        address: String address
        length: String length
        type: String type (ascii, unicode, etc.)
        encoding: String encoding
    """

    value: str = Field(..., description="String value")

    address: str | None = Field(None, description="String address (hex)")

    length: int = Field(..., ge=0, description="String length")

    type: str | None = Field(None, description="String type")

    encoding: str | None = Field(None, description="String encoding")


class StringAnalysisResult(AnalysisResultBase):
    """
    Result from string analysis.

    Attributes:
        strings: List of strings found
        suspicious_strings: List of suspicious strings
        decoded_strings: List of decoded strings
        total_strings: Total number of strings
        statistics: String statistics
    """

    strings: list[str] = Field(default_factory=list, description="List of strings")

    suspicious_strings: list[dict[str, Any]] = Field(
        default_factory=list, description="Suspicious strings"
    )

    decoded_strings: list[dict[str, Any]] = Field(
        default_factory=list, description="Decoded strings"
    )

    total_strings: int = Field(0, ge=0, description="Total strings")

    statistics: dict[str, Any | None] = Field(None, description="String statistics")


class FunctionInfo(BaseModel):
    """
    Information about a function.

    Attributes:
        name: Function name
        address: Function address
        size: Function size
        offset: Function offset
        call_refs: Number of call references
        data_refs: Number of data references
        complexity: Cyclomatic complexity
        basic_blocks: Number of basic blocks
    """

    name: str = Field(..., description=FUNCTION_NAME_DESC)

    address: int = Field(..., ge=0, description="Function address")

    size: int = Field(0, ge=0, description="Function size")

    offset: int | None = Field(None, description="Function offset")

    call_refs: int = Field(0, ge=0, description="Call references")

    data_refs: int = Field(0, ge=0, description="Data references")

    complexity: int | None = Field(None, ge=0, description="Cyclomatic complexity")

    basic_blocks: int | None = Field(None, ge=0, description="Basic blocks")


class FunctionAnalysisResult(AnalysisResultBase):
    """
    Result from function analysis.

    Attributes:
        functions: List of functions
        total_functions: Total number of functions
        statistics: Function statistics
    """

    functions: list[FunctionInfo] = Field(default_factory=list, description="List of functions")

    total_functions: int = Field(0, ge=0, description="Total functions")

    statistics: dict[str, Any | None] = Field(None, description="Function statistics")


class SectionAnalysisResult(AnalysisResultBase):
    """
    Result from section analysis.

    Note: Section information is defined in format.py (SectionInfo)
    This is just a wrapper for section-specific analysis.

    Attributes:
        sections: List of section information
        summary: Section summary statistics
    """

    sections: list[dict[str, Any]] = Field(default_factory=list, description="List of sections")

    summary: dict[str, Any | None] = Field(None, description="Section summary")


class ResourceInfo(BaseModel):
    """
    Information about a resource.

    Attributes:
        name: Resource name
        type: Resource type
        size: Resource size
        lang: Resource language
        entropy: Resource entropy
    """

    name: str = Field(..., description="Resource name")

    type: str | None = Field(None, description="Resource type")

    size: int = Field(0, ge=0, description="Resource size")

    lang: str | None = Field(None, description="Resource language")

    entropy: float | None = Field(None, ge=0.0, le=8.0, description="Resource entropy")


class ResourceAnalysisResult(AnalysisResultBase):
    """
    Result from resource analysis.

    Attributes:
        resources: List of resources
        total_resources: Total number of resources
    """

    resources: list[ResourceInfo] = Field(default_factory=list, description="List of resources")

    total_resources: int = Field(0, ge=0, description="Total resources")


class OverlayInfo(BaseModel):
    """
    Information about overlay data.

    Attributes:
        present: Whether overlay is present
        size: Overlay size
        offset: Overlay offset
        entropy: Overlay entropy
        suspicious: Whether overlay is suspicious
    """

    present: bool = Field(False, description="Overlay present")

    size: int | None = Field(None, ge=0, description="Overlay size")

    offset: int | None = Field(None, ge=0, description="Overlay offset")

    entropy: float | None = Field(None, ge=0.0, le=8.0, description="Overlay entropy")

    suspicious: bool = Field(False, description="Suspicious overlay")


class OverlayAnalysisResult(AnalysisResultBase):
    """
    Result from overlay analysis.

    Attributes:
        overlay: Overlay information
    """

    overlay: OverlayInfo | None = Field(None, description="Overlay information")
