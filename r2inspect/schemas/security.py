#!/usr/bin/env python3
"""
Security Analyzer Pydantic Schemas

Schemas for security-focused analyzers (exploit mitigation, authenticode, etc.)

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from .base import AnalysisResultBase


class SeverityLevel(str, Enum):
    """Security issue severity levels"""

    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityGrade(str, Enum):
    """Security assessment grades"""

    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"
    UNKNOWN = "Unknown"


class SecurityIssue(BaseModel):
    """
    A security issue found during analysis.

    Attributes:
        severity: Severity level (minimal, low, medium, high, critical)
        description: Human-readable description
        recommendation: Recommended remediation
        cwe_id: Common Weakness Enumeration ID
        cvss_score: CVSS score (0.0-10.0)
    """

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
    """
    Information about a security mitigation.

    Attributes:
        enabled: Whether mitigation is enabled
        description: Human-readable description
        details: Additional details
        note: Additional notes
        high_entropy: High entropy ASLR (for ASLR mitigation)
    """

    enabled: bool = Field(..., description="Whether mitigation is enabled")

    description: str = Field(..., description="Mitigation description")

    details: str | None = Field(None, description="Additional details")

    note: str | None = Field(None, description="Additional notes")

    # ASLR-specific
    high_entropy: bool | None = Field(None, description="High entropy ASLR enabled")


class Recommendation(BaseModel):
    """
    Security recommendation.

    Attributes:
        priority: Priority level (low, medium, high, critical)
        mitigation: Mitigation name
        recommendation: Recommended action
        impact: Impact description
    """

    priority: SeverityLevel = Field(..., description="Priority level")

    mitigation: str = Field(..., description="Mitigation name")

    recommendation: str = Field(..., description="Recommended action")

    impact: str = Field(..., description="Impact description")


class SecurityScore(BaseModel):
    """
    Security score information.

    Attributes:
        score: Numeric score
        max_score: Maximum possible score
        percentage: Score as percentage
        grade: Letter grade (A-F)
    """

    score: int = Field(..., ge=0, description="Numeric score")

    max_score: int = Field(..., ge=0, description="Maximum possible score")

    percentage: float = Field(..., ge=0.0, le=100.0, description="Score as percentage")

    grade: SecurityGrade = Field(..., description="Letter grade")

    @field_validator("max_score")
    @classmethod
    def validate_max_score(cls, v: int, info) -> int:
        """Validate max_score is not less than score"""
        if "score" in info.data and v < info.data["score"]:
            raise ValueError("max_score cannot be less than score")
        return v


class SecurityAnalysisResult(AnalysisResultBase):
    """
    Result from security analyzers (exploit mitigation, etc.).

    Represents comprehensive security analysis including mitigations,
    vulnerabilities, and recommendations.

    Attributes:
        mitigations: Dictionary of mitigation information
        features: Dictionary of security features (bool values)
        score: Security score (0-100)
        security_score: Detailed security score information
        issues: List of security issues found
        recommendations: List of security recommendations
        vulnerabilities: List of vulnerabilities found
        dll_characteristics: DLL characteristics information (PE)
        load_config: Load configuration information (PE)
    """

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
    dll_characteristics: dict[str, Any | None] = Field(None, description="DLL characteristics (PE)")

    load_config: dict[str, Any | None] = Field(None, description="Load configuration (PE)")

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
        """
        Check if a specific mitigation is enabled.

        Args:
            mitigation_name: Name of mitigation to check

        Returns:
            True if mitigation is enabled
        """
        info = self.mitigations.get(mitigation_name)
        return info is not None and info.enabled

    def count_issues_by_severity(self) -> dict[str, int]:
        """
        Count issues by severity level.

        Returns:
            Dictionary mapping severity to count
        """
        counts: dict[str, int] = {level.value: 0 for level in SeverityLevel}
        for issue in self.issues:
            counts[issue.severity.value] += 1
        return counts

    def is_secure(self, threshold: int = 70) -> bool:
        """
        Check if binary meets security threshold.

        Args:
            threshold: Minimum security score (0-100)

        Returns:
            True if score >= threshold
        """
        if self.score is None:
            return False
        return self.score >= threshold


class AuthenticodeAnalysisResult(AnalysisResultBase):
    """
    Result from Authenticode signature analysis.

    Attributes:
        signed: Whether binary is signed
        valid: Whether signature is valid
        signer: Signer information
        timestamp: Signature timestamp
        signature_algorithm: Algorithm used for signature
        digest_algorithm: Algorithm used for digest
        certificates: List of certificates in chain
    """

    signed: bool = Field(False, description="Whether binary is signed")

    valid: bool | None = Field(None, description="Whether signature is valid")

    signer: str | None = Field(None, description="Signer information")

    timestamp: datetime | None = Field(None, description="Signature timestamp")

    signature_algorithm: str | None = Field(None, description="Signature algorithm")

    digest_algorithm: str | None = Field(None, description="Digest algorithm")

    certificates: list[dict[str, Any]] = Field(
        default_factory=list, description="Certificate chain"
    )
