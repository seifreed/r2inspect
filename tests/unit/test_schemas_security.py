#!/usr/bin/env python3
"""Comprehensive tests for r2inspect/schemas/security.py - targeting 100% coverage."""

import pytest
from datetime import datetime
from pydantic import ValidationError

from r2inspect.schemas.security import (
    AuthenticodeAnalysisResult,
    MitigationInfo,
    Recommendation,
    SecurityAnalysisResult,
    SecurityGrade,
    SecurityIssue,
    SecurityScore,
    SeverityLevel,
)


def test_severity_level_enum():
    """Test all SeverityLevel enum values."""
    assert SeverityLevel.MINIMAL == "minimal"
    assert SeverityLevel.LOW == "low"
    assert SeverityLevel.MEDIUM == "medium"
    assert SeverityLevel.HIGH == "high"
    assert SeverityLevel.CRITICAL == "critical"


def test_security_grade_enum():
    """Test all SecurityGrade enum values."""
    assert SecurityGrade.A == "A"
    assert SecurityGrade.B == "B"
    assert SecurityGrade.C == "C"
    assert SecurityGrade.D == "D"
    assert SecurityGrade.F == "F"
    assert SecurityGrade.UNKNOWN == "Unknown"


def test_security_issue_valid():
    """Test SecurityIssue creation with valid data."""
    issue = SecurityIssue(
        severity=SeverityLevel.HIGH,
        description="Buffer overflow detected",
        recommendation="Use safe functions",
        cwe_id=120,
        cvss_score=7.5
    )
    assert issue.severity == SeverityLevel.HIGH
    assert issue.description == "Buffer overflow detected"
    assert issue.recommendation == "Use safe functions"
    assert issue.cwe_id == 120
    assert issue.cvss_score == 7.5


def test_security_issue_description_validation():
    """Test SecurityIssue description validation."""
    # Valid description
    issue = SecurityIssue(severity=SeverityLevel.LOW, description="Valid issue")
    assert issue.description == "Valid issue"
    
    # Description with whitespace gets trimmed
    issue = SecurityIssue(severity=SeverityLevel.LOW, description="  Trimmed  ")
    assert issue.description == "Trimmed"
    
    # Empty description should fail (Pydantic min_length validation)
    with pytest.raises(ValidationError):
        SecurityIssue(severity=SeverityLevel.LOW, description="")
    
    # Whitespace-only description should fail (custom validator)
    with pytest.raises(ValueError, match="description cannot be empty"):
        SecurityIssue(severity=SeverityLevel.LOW, description="   ")


def test_security_issue_optional_fields():
    """Test SecurityIssue with optional fields."""
    issue = SecurityIssue(severity=SeverityLevel.MEDIUM, description="Test")
    assert issue.recommendation is None
    assert issue.cwe_id is None
    assert issue.cvss_score is None


def test_security_issue_cwe_validation():
    """Test SecurityIssue CWE ID validation."""
    # Valid CWE
    issue = SecurityIssue(severity=SeverityLevel.HIGH, description="Test", cwe_id=79)
    assert issue.cwe_id == 79
    
    # CWE must be >= 1
    with pytest.raises(ValidationError):
        SecurityIssue(severity=SeverityLevel.HIGH, description="Test", cwe_id=0)


def test_security_issue_cvss_validation():
    """Test SecurityIssue CVSS score validation."""
    # Valid CVSS scores
    issue1 = SecurityIssue(severity=SeverityLevel.LOW, description="Test", cvss_score=0.0)
    assert issue1.cvss_score == 0.0
    
    issue2 = SecurityIssue(severity=SeverityLevel.CRITICAL, description="Test", cvss_score=10.0)
    assert issue2.cvss_score == 10.0
    
    # CVSS out of range
    with pytest.raises(ValidationError):
        SecurityIssue(severity=SeverityLevel.HIGH, description="Test", cvss_score=10.1)
    
    with pytest.raises(ValidationError):
        SecurityIssue(severity=SeverityLevel.HIGH, description="Test", cvss_score=-0.1)


def test_mitigation_info_basic():
    """Test MitigationInfo creation."""
    mitigation = MitigationInfo(
        enabled=True,
        description="ASLR enabled",
        details="High entropy enabled",
        note="Full protection"
    )
    assert mitigation.enabled is True
    assert mitigation.description == "ASLR enabled"
    assert mitigation.details == "High entropy enabled"
    assert mitigation.note == "Full protection"


def test_mitigation_info_aslr():
    """Test MitigationInfo with ASLR-specific field."""
    mitigation = MitigationInfo(
        enabled=True,
        description="ASLR",
        high_entropy=True
    )
    assert mitigation.high_entropy is True


def test_mitigation_info_optional_fields():
    """Test MitigationInfo with only required fields."""
    mitigation = MitigationInfo(enabled=False, description="DEP disabled")
    assert mitigation.details is None
    assert mitigation.note is None
    assert mitigation.high_entropy is None


def test_recommendation_complete():
    """Test Recommendation with all fields."""
    rec = Recommendation(
        priority=SeverityLevel.HIGH,
        mitigation="ASLR",
        recommendation="Enable ASLR by setting /DYNAMICBASE",
        impact="Prevents reliable exploitation"
    )
    assert rec.priority == SeverityLevel.HIGH
    assert rec.mitigation == "ASLR"
    assert rec.recommendation == "Enable ASLR by setting /DYNAMICBASE"
    assert rec.impact == "Prevents reliable exploitation"


def test_security_score_valid():
    """Test SecurityScore with valid data."""
    score = SecurityScore(
        score=75,
        max_score=100,
        percentage=75.0,
        grade=SecurityGrade.B
    )
    assert score.score == 75
    assert score.max_score == 100
    assert score.percentage == 75.0
    assert score.grade == SecurityGrade.B


def test_security_score_max_score_validation():
    """Test SecurityScore max_score validation."""
    # Valid: max_score >= score
    score = SecurityScore(score=50, max_score=100, percentage=50.0, grade=SecurityGrade.C)
    assert score.max_score == 100
    
    score = SecurityScore(score=50, max_score=50, percentage=100.0, grade=SecurityGrade.A)
    assert score.max_score == 50
    
    # Invalid: max_score < score
    with pytest.raises(ValidationError, match="max_score cannot be less than score"):
        SecurityScore(score=100, max_score=50, percentage=100.0, grade=SecurityGrade.A)


def test_security_score_percentage_bounds():
    """Test SecurityScore percentage validation."""
    # Valid percentages
    score1 = SecurityScore(score=0, max_score=100, percentage=0.0, grade=SecurityGrade.F)
    assert score1.percentage == 0.0
    
    score2 = SecurityScore(score=100, max_score=100, percentage=100.0, grade=SecurityGrade.A)
    assert score2.percentage == 100.0
    
    # Out of bounds
    with pytest.raises(ValidationError):
        SecurityScore(score=50, max_score=100, percentage=150.0, grade=SecurityGrade.A)


def test_security_analysis_result_basic():
    """Test SecurityAnalysisResult creation."""
    result = SecurityAnalysisResult(available=True, score=80)
    assert result.available is True
    assert result.score == 80
    assert result.mitigations == {}
    assert result.features == {}
    assert result.issues == []
    assert result.recommendations == []
    assert result.vulnerabilities == []


def test_security_analysis_result_with_mitigations():
    """Test SecurityAnalysisResult with mitigations."""
    mitigations = {
        "ASLR": MitigationInfo(enabled=True, description="ASLR"),
        "DEP": MitigationInfo(enabled=True, description="DEP"),
        "SafeSEH": MitigationInfo(enabled=False, description="SafeSEH"),
    }
    result = SecurityAnalysisResult(available=True, mitigations=mitigations)
    assert len(result.mitigations) == 3
    assert result.mitigations["ASLR"].enabled is True


def test_security_analysis_result_get_critical_issues():
    """Test get_critical_issues method."""
    issues = [
        SecurityIssue(severity=SeverityLevel.CRITICAL, description="Critical 1"),
        SecurityIssue(severity=SeverityLevel.HIGH, description="High 1"),
        SecurityIssue(severity=SeverityLevel.CRITICAL, description="Critical 2"),
        SecurityIssue(severity=SeverityLevel.LOW, description="Low 1"),
    ]
    result = SecurityAnalysisResult(available=True, issues=issues)
    
    critical = result.get_critical_issues()
    assert len(critical) == 2
    assert all(issue.severity == SeverityLevel.CRITICAL for issue in critical)


def test_security_analysis_result_get_high_issues():
    """Test get_high_issues method."""
    issues = [
        SecurityIssue(severity=SeverityLevel.HIGH, description="High 1"),
        SecurityIssue(severity=SeverityLevel.MEDIUM, description="Medium 1"),
        SecurityIssue(severity=SeverityLevel.HIGH, description="High 2"),
    ]
    result = SecurityAnalysisResult(available=True, issues=issues)
    
    high = result.get_high_issues()
    assert len(high) == 2
    assert all(issue.severity == SeverityLevel.HIGH for issue in high)


def test_security_analysis_result_get_enabled_mitigations():
    """Test get_enabled_mitigations method."""
    mitigations = {
        "ASLR": MitigationInfo(enabled=True, description="ASLR"),
        "DEP": MitigationInfo(enabled=False, description="DEP"),
        "CFG": MitigationInfo(enabled=True, description="CFG"),
    }
    result = SecurityAnalysisResult(available=True, mitigations=mitigations)
    
    enabled = result.get_enabled_mitigations()
    assert len(enabled) == 2
    assert "ASLR" in enabled
    assert "CFG" in enabled
    assert "DEP" not in enabled


def test_security_analysis_result_get_disabled_mitigations():
    """Test get_disabled_mitigations method."""
    mitigations = {
        "ASLR": MitigationInfo(enabled=True, description="ASLR"),
        "DEP": MitigationInfo(enabled=False, description="DEP"),
        "SafeSEH": MitigationInfo(enabled=False, description="SafeSEH"),
    }
    result = SecurityAnalysisResult(available=True, mitigations=mitigations)
    
    disabled = result.get_disabled_mitigations()
    assert len(disabled) == 2
    assert "DEP" in disabled
    assert "SafeSEH" in disabled
    assert "ASLR" not in disabled


def test_security_analysis_result_has_mitigation():
    """Test has_mitigation method."""
    mitigations = {
        "ASLR": MitigationInfo(enabled=True, description="ASLR"),
        "DEP": MitigationInfo(enabled=False, description="DEP"),
    }
    result = SecurityAnalysisResult(available=True, mitigations=mitigations)
    
    # Enabled mitigation
    assert result.has_mitigation("ASLR") is True
    
    # Disabled mitigation
    assert result.has_mitigation("DEP") is False
    
    # Non-existent mitigation
    assert result.has_mitigation("CFG") is False


def test_security_analysis_result_count_issues_by_severity():
    """Test count_issues_by_severity method."""
    issues = [
        SecurityIssue(severity=SeverityLevel.CRITICAL, description="C1"),
        SecurityIssue(severity=SeverityLevel.CRITICAL, description="C2"),
        SecurityIssue(severity=SeverityLevel.HIGH, description="H1"),
        SecurityIssue(severity=SeverityLevel.MEDIUM, description="M1"),
        SecurityIssue(severity=SeverityLevel.LOW, description="L1"),
        SecurityIssue(severity=SeverityLevel.LOW, description="L2"),
        SecurityIssue(severity=SeverityLevel.LOW, description="L3"),
    ]
    result = SecurityAnalysisResult(available=True, issues=issues)
    
    counts = result.count_issues_by_severity()
    assert counts["critical"] == 2
    assert counts["high"] == 1
    assert counts["medium"] == 1
    assert counts["low"] == 3
    assert counts["minimal"] == 0


def test_security_analysis_result_count_issues_empty():
    """Test count_issues_by_severity with no issues."""
    result = SecurityAnalysisResult(available=True)
    
    counts = result.count_issues_by_severity()
    assert all(count == 0 for count in counts.values())


def test_security_analysis_result_is_secure():
    """Test is_secure method."""
    # Secure with default threshold (70)
    result1 = SecurityAnalysisResult(available=True, score=75)
    assert result1.is_secure() is True
    
    # Insecure with default threshold
    result2 = SecurityAnalysisResult(available=True, score=65)
    assert result2.is_secure() is False
    
    # At threshold
    result3 = SecurityAnalysisResult(available=True, score=70)
    assert result3.is_secure() is True
    
    # Custom threshold
    result4 = SecurityAnalysisResult(available=True, score=60)
    assert result4.is_secure(threshold=50) is True
    assert result4.is_secure(threshold=70) is False
    
    # No score
    result5 = SecurityAnalysisResult(available=True)
    assert result5.is_secure() is False


def test_security_analysis_result_score_validation():
    """Test SecurityAnalysisResult score validation."""
    # Valid scores
    result1 = SecurityAnalysisResult(available=True, score=0)
    assert result1.score == 0
    
    result2 = SecurityAnalysisResult(available=True, score=100)
    assert result2.score == 100
    
    # Out of range
    with pytest.raises(ValidationError):
        SecurityAnalysisResult(available=True, score=-1)
    
    with pytest.raises(ValidationError):
        SecurityAnalysisResult(available=True, score=101)


def test_security_analysis_result_pe_fields():
    """Test SecurityAnalysisResult PE-specific fields."""
    dll_chars = {"dynamic_base": True, "nx_compat": True}
    load_config = {"guard_cf": True, "size": 64}
    
    result = SecurityAnalysisResult(
        available=True,
        dll_characteristics=dll_chars,
        load_config=load_config
    )
    
    assert result.dll_characteristics == dll_chars
    assert result.load_config == load_config


def test_security_analysis_result_with_security_score():
    """Test SecurityAnalysisResult with SecurityScore."""
    security_score = SecurityScore(
        score=85,
        max_score=100,
        percentage=85.0,
        grade=SecurityGrade.B
    )
    result = SecurityAnalysisResult(
        available=True,
        score=85,
        security_score=security_score
    )
    
    assert result.security_score.grade == SecurityGrade.B
    assert result.security_score.percentage == 85.0


def test_authenticode_analysis_result_defaults():
    """Test AuthenticodeAnalysisResult default values."""
    result = AuthenticodeAnalysisResult(available=True)
    
    assert result.signed is False
    assert result.valid is None
    assert result.signer is None
    assert result.timestamp is None
    assert result.signature_algorithm is None
    assert result.digest_algorithm is None
    assert result.certificates == []


def test_authenticode_analysis_result_complete():
    """Test AuthenticodeAnalysisResult with all fields."""
    timestamp = datetime(2024, 1, 15, 12, 0, 0)
    certs = [
        {"subject": "CN=Test", "issuer": "CN=Root"},
        {"subject": "CN=Root", "issuer": "CN=Root"}
    ]
    
    result = AuthenticodeAnalysisResult(
        available=True,
        signed=True,
        valid=True,
        signer="Test Signer",
        timestamp=timestamp,
        signature_algorithm="RSA",
        digest_algorithm="SHA256",
        certificates=certs
    )
    
    assert result.signed is True
    assert result.valid is True
    assert result.signer == "Test Signer"
    assert result.timestamp == timestamp
    assert result.signature_algorithm == "RSA"
    assert result.digest_algorithm == "SHA256"
    assert len(result.certificates) == 2


def test_authenticode_analysis_result_signed_but_invalid():
    """Test AuthenticodeAnalysisResult for signed but invalid signature."""
    result = AuthenticodeAnalysisResult(
        available=True,
        signed=True,
        valid=False,
        signer="Untrusted Signer"
    )
    
    assert result.signed is True
    assert result.valid is False
    assert result.signer == "Untrusted Signer"


def test_security_analysis_result_features():
    """Test SecurityAnalysisResult with security features."""
    features = {
        "stack_canary": True,
        "fortify_source": False,
        "relro": True,
        "pie": True,
    }
    result = SecurityAnalysisResult(available=True, features=features)
    
    assert result.features["stack_canary"] is True
    assert result.features["fortify_source"] is False
    assert len(result.features) == 4


def test_security_analysis_result_recommendations():
    """Test SecurityAnalysisResult with recommendations."""
    recs = [
        Recommendation(
            priority=SeverityLevel.HIGH,
            mitigation="ASLR",
            recommendation="Enable ASLR",
            impact="Prevents exploitation"
        ),
        Recommendation(
            priority=SeverityLevel.MEDIUM,
            mitigation="Code Signing",
            recommendation="Sign binary",
            impact="Ensures integrity"
        ),
    ]
    result = SecurityAnalysisResult(available=True, recommendations=recs)
    
    assert len(result.recommendations) == 2
    assert result.recommendations[0].priority == SeverityLevel.HIGH


def test_security_analysis_result_vulnerabilities():
    """Test SecurityAnalysisResult with vulnerabilities."""
    vulns = [
        {"cve": "CVE-2024-1234", "severity": "high"},
        {"cve": "CVE-2024-5678", "severity": "medium"},
    ]
    result = SecurityAnalysisResult(available=True, vulnerabilities=vulns)
    
    assert len(result.vulnerabilities) == 2
    assert result.vulnerabilities[0]["cve"] == "CVE-2024-1234"
