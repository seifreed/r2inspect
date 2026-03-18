#!/usr/bin/env python3
"""Metadata analyzer schemas."""

from typing import Any

from pydantic import BaseModel, Field

from .base import AnalysisResultBase

FUNCTION_NAME_DESC = "Function name"


class ImportInfo(BaseModel):
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
    imports: list[ImportInfo] = Field(default_factory=list, description="List of imports")
    statistics: ImportStatistics | None = Field(None, description="Import statistics")
    missing_imports: list[str] = Field(
        default_factory=list, description="Potentially missing imports"
    )


class ExportInfo(BaseModel):
    name: str = Field(..., description=FUNCTION_NAME_DESC)
    address: str | None = Field(None, description="Export address (hex)")
    ordinal: int | None = Field(None, ge=0, description="Export ordinal")
    type: str | None = Field(None, description="Export type")
    size: int | None = Field(None, ge=0, description="Function size")


class ExportAnalysisResult(AnalysisResultBase):
    exports: list[ExportInfo] = Field(default_factory=list, description="List of exports")
    total_exports: int = Field(0, ge=0, description="Total exports")


class StringInfo(BaseModel):
    value: str = Field(..., description="String value")
    address: str | None = Field(None, description="String address (hex)")
    length: int = Field(..., ge=0, description="String length")
    type: str | None = Field(None, description="String type")
    encoding: str | None = Field(None, description="String encoding")


class StringAnalysisResult(AnalysisResultBase):
    strings: list[str] = Field(default_factory=list, description="List of strings")
    suspicious_strings: list[dict[str, Any]] = Field(
        default_factory=list, description="Suspicious strings"
    )
    decoded_strings: list[dict[str, Any]] = Field(
        default_factory=list, description="Decoded strings"
    )
    total_strings: int = Field(0, ge=0, description="Total strings")
    statistics: dict[str, Any | None] = Field(default_factory=dict, description="String statistics")


class FunctionInfo(BaseModel):
    name: str = Field(..., description=FUNCTION_NAME_DESC)
    address: int = Field(..., ge=0, description="Function address")
    size: int = Field(0, ge=0, description="Function size")
    offset: int | None = Field(None, description="Function offset")
    call_refs: int = Field(0, ge=0, description="Call references")
    data_refs: int = Field(0, ge=0, description="Data references")
    complexity: int | None = Field(None, ge=0, description="Cyclomatic complexity")
    basic_blocks: int | None = Field(None, ge=0, description="Basic blocks")


class FunctionAnalysisResult(AnalysisResultBase):
    functions: list[FunctionInfo] = Field(default_factory=list, description="List of functions")
    total_functions: int = Field(0, ge=0, description="Total functions")
    statistics: dict[str, Any | None] = Field(
        default_factory=dict, description="Function statistics"
    )


class SectionAnalysisResult(AnalysisResultBase):
    sections: list[dict[str, Any]] = Field(default_factory=list, description="List of sections")
    summary: dict[str, Any | None] = Field(default_factory=dict, description="Section summary")


class ResourceInfo(BaseModel):
    name: str = Field(..., description="Resource name")
    type: str | None = Field(None, description="Resource type")
    size: int = Field(0, ge=0, description="Resource size")
    lang: str | None = Field(None, description="Resource language")
    entropy: float | None = Field(None, ge=0.0, le=8.0, description="Resource entropy")


class ResourceAnalysisResult(AnalysisResultBase):
    resources: list[ResourceInfo] = Field(default_factory=list, description="List of resources")
    total_resources: int = Field(0, ge=0, description="Total resources")


class OverlayInfo(BaseModel):
    present: bool = Field(False, description="Overlay present")
    size: int | None = Field(None, ge=0, description="Overlay size")
    offset: int | None = Field(None, ge=0, description="Overlay offset")
    entropy: float | None = Field(None, ge=0.0, le=8.0, description="Overlay entropy")
    suspicious: bool = Field(False, description="Suspicious overlay")


class OverlayAnalysisResult(AnalysisResultBase):
    overlay: OverlayInfo | None = Field(None, description="Overlay information")
