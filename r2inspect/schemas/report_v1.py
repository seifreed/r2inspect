"""Stable r2inspect.report/v1 wire models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

SCHEMA_VERSION: Literal["r2inspect.report/v1"] = "r2inspect.report/v1"


class WireModel(BaseModel):
    """Strict base for the versioned wire contract."""

    model_config = ConfigDict(extra="forbid")


class AnalyzerStatus(StrEnum):
    COMPLETED = "completed"
    NOT_DETECTED = "not_detected"
    NOT_APPLICABLE = "not_applicable"
    UNSUPPORTED = "unsupported"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    SKIPPED_BY_PROFILE = "skipped_by_profile"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


class ToolInfoV1(WireModel):
    name: str = "r2inspect"
    version: str
    backend: str = "r2"
    commit: str | None = None
    radare2_version: str | None = None


class AnalysisMetadataV1(WireModel):
    id: str
    profile: str = "standard"
    started_at: datetime
    duration: float = Field(ge=0.0)
    configuration_digest: str | None = None


class SampleInfoV1(WireModel):
    path: str | None = None
    size: int = Field(default=0, ge=0)
    hashes: dict[str, str] = Field(default_factory=dict)
    detected_format: str | None = None
    architecture: str | None = None
    bits: Literal[32, 64] | None = None


class FormatCommonV1(WireModel):
    format: str | None = None
    architecture: str | None = None
    bits: Literal[32, 64] | None = None
    endian: Literal["little", "big"] | None = None
    entry_point: int | None = Field(default=None, ge=0)


class FormatReportV1(WireModel):
    common: FormatCommonV1 = Field(default_factory=FormatCommonV1)
    pe: dict[str, JsonValue] | None = None
    elf: dict[str, JsonValue] | None = None
    macho: dict[str, JsonValue] | None = None


class MitigationV1(WireModel):
    enabled: bool | None
    source: str
    details: dict[str, JsonValue] = Field(default_factory=dict)


class SecurityReportV1(WireModel):
    normalized_mitigations: dict[str, MitigationV1] = Field(default_factory=dict)
    format_specific: dict[str, JsonValue] = Field(default_factory=dict)


class EvidenceV1(WireModel):
    kind: str
    value: JsonValue
    description: str | None = None


class LocationV1(WireModel):
    offset: int | None = Field(default=None, ge=0)
    virtual_address: int | None = Field(default=None, ge=0)
    function: str | None = None
    basic_block: int | None = Field(default=None, ge=0)


class FindingV1(WireModel):
    finding_id: str
    rule_id: str
    title: str
    category: str
    severity: Literal["informational", "low", "medium", "high", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    source_analyzer: str
    method: str
    evidence: list[EvidenceV1] = Field(default_factory=list)
    locations: list[LocationV1] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    attack: list[str] = Field(default_factory=list)
    mbc: list[str] = Field(default_factory=list)


class AnalyzerOutcomeV1(WireModel):
    analyzer_id: str
    status: AnalyzerStatus
    duration: float = Field(default=0.0, ge=0.0)
    error: str | None = None
    warnings: list[str] = Field(default_factory=list)
    metrics: dict[str, JsonValue] = Field(default_factory=dict)


class ReportV1(WireModel):
    schema_version: Literal["r2inspect.report/v1"] = SCHEMA_VERSION
    tool: ToolInfoV1
    analysis: AnalysisMetadataV1
    sample: SampleInfoV1
    format: FormatReportV1 = Field(default_factory=FormatReportV1)
    security: SecurityReportV1 = Field(default_factory=SecurityReportV1)
    findings: list[FindingV1] = Field(default_factory=list)
    artifacts: list[dict[str, JsonValue]] = Field(default_factory=list)
    capabilities: list[dict[str, JsonValue]] = Field(default_factory=list)
    similarity: list[dict[str, JsonValue]] = Field(default_factory=list)
    analyzers: list[AnalyzerOutcomeV1] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    metrics: dict[str, JsonValue] = Field(default_factory=dict)
    extras: dict[str, JsonValue] = Field(default_factory=dict)

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"$id": "https://r2inspect.dev/schemas/r2inspect.report.v1.schema.json"},
    )


__all__ = [
    "SCHEMA_VERSION",
    "AnalysisMetadataV1",
    "AnalyzerOutcomeV1",
    "AnalyzerStatus",
    "EvidenceV1",
    "FindingV1",
    "FormatCommonV1",
    "FormatReportV1",
    "LocationV1",
    "MitigationV1",
    "ReportV1",
    "SampleInfoV1",
    "SecurityReportV1",
    "ToolInfoV1",
]
