#!/usr/bin/env python3
"""Security analyzer schemas."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, ValidationInfo, field_validator

from .base import AnalysisResultBase


class SeverityLevel(StrEnum):
    """Security issue severity levels"""

    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityGrade(StrEnum):
    """Security assessment grades"""

    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"
    UNKNOWN = "Unknown"


class SecurityIssue(BaseModel):
    """Security issue found during analysis."""

    severity: SeverityLevel = Field(..., description="Severity level")

    description: str = Field(..., min_length=1, description="Issue description")

    recommendation: str | None = Field(None, description="Recommended remediation")

    cwe_id: int | None = Field(None, ge=1, description="CWE ID")

    cvss_score: float | None = Field(None, ge=0.0, le=10.0, description="CVSS score (0.0-10.0)")

    @field_validator("description")
    @classmethod
    def validate_description(cls, v: str) -> str:
        """Validate description is not empty"""
        if not v or not v.strip():
            raise ValueError("description cannot be empty")
        return v.strip()


class MitigationInfo(BaseModel):
    """Information about a security mitigation."""

    enabled: bool = Field(..., description="Whether mitigation is enabled")

    description: str = Field(..., description="Mitigation description")

    details: str | None = Field(None, description="Additional details")

    note: str | None = Field(None, description="Additional notes")

    # ASLR-specific
    high_entropy: bool | None = Field(None, description="High entropy ASLR enabled")


class Recommendation(BaseModel):
    """Security recommendation."""

    priority: SeverityLevel = Field(..., description="Priority level")

    mitigation: str = Field(..., description="Mitigation name")

    recommendation: str = Field(..., description="Recommended action")

    impact: str = Field(..., description="Impact description")


class SecurityScore(BaseModel):
    """Security score information."""

    score: int = Field(..., ge=0, description="Numeric score")

    max_score: int = Field(..., ge=0, description="Maximum possible score")

    percentage: float = Field(..., ge=0.0, le=100.0, description="Score as percentage")

    grade: SecurityGrade = Field(..., description="Letter grade")

    @field_validator("max_score")
    @classmethod
    def validate_max_score(cls, v: int, info: ValidationInfo) -> int:
        """Validate max_score is not less than score"""
        if "score" in info.data and v < info.data["score"]:
            raise ValueError("max_score cannot be less than score")
        return v


class SecurityAnalysisResult(AnalysisResultBase):
    """Result from security analyzers."""

    mitigations: dict[str, MitigationInfo] = Field(
        default_factory=dict, description="Dictionary of mitigation information"
    )

    features: dict[str, bool] = Field(
        default_factory=dict, description="Dictionary of security features"
    )

    score: int | None = Field(None, ge=0, le=100, description="Security score (0-100)")

    security_score: SecurityScore | None = Field(None, description="Detailed security score")

    issues: list[SecurityIssue] = Field(default_factory=list, description="Security issues found")

    recommendations: list[Recommendation] = Field(
        default_factory=list, description="Security recommendations"
    )

    vulnerabilities: list[dict[str, Any]] = Field(
        default_factory=list, description="Vulnerabilities found"
    )

    # PE-specific fields
    dll_characteristics: dict[str, Any | None] | None = Field(
        None, description="DLL characteristics (PE)"
    )

    load_config: dict[str, Any | None] | None = Field(None, description="Load configuration (PE)")

    def get_critical_issues(self) -> list[SecurityIssue]:
        """Get all critical severity issues"""
        return [issue for issue in self.issues if issue.severity == SeverityLevel.CRITICAL]

    def get_high_issues(self) -> list[SecurityIssue]:
        """Get all high severity issues"""
        return [issue for issue in self.issues if issue.severity == SeverityLevel.HIGH]

    def get_enabled_mitigations(self) -> list[str]:
        """Get list of enabled mitigation names"""
        return [name for name, info in self.mitigations.items() if info.enabled]

    def get_disabled_mitigations(self) -> list[str]:
        """Get list of disabled mitigation names"""
        return [name for name, info in self.mitigations.items() if not info.enabled]

    def has_mitigation(self, mitigation_name: str) -> bool:
        """Check if a specific mitigation is enabled."""
        info = self.mitigations.get(mitigation_name)
        return info is not None and info.enabled

    def count_issues_by_severity(self) -> dict[str, int]:
        """Count issues by severity level."""
        counts: dict[str, int] = {level.value: 0 for level in SeverityLevel}
        for issue in self.issues:
            counts[issue.severity.value] += 1
        return counts

    def is_secure(self, threshold: int = 70) -> bool:
        """Check if binary meets security threshold."""
        if self.score is None:
            return False
        return self.score >= threshold


class AuthenticodeAnalysisResult(AnalysisResultBase):
    """Result from Authenticode signature analysis."""

    signed: bool = Field(False, description="Whether binary is signed")

    valid: bool | None = Field(None, description="Whether signature is valid")

    signer: str | None = Field(None, description="Signer information")

    timestamp: datetime | None = Field(None, description="Signature timestamp")

    signature_algorithm: str | None = Field(None, description="Signature algorithm")

    digest_algorithm: str | None = Field(None, description="Digest algorithm")

    certificates: list[dict[str, Any]] = Field(
        default_factory=list, description="Certificate chain"
    )
