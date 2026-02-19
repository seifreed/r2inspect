from __future__ import annotations

import pytest

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


def test_security_issue_description_strips_whitespace() -> None:
    issue = SecurityIssue(severity=SeverityLevel.LOW, description="  valid description  ")
    assert issue.description == "valid description"


def test_security_issue_description_empty_raises() -> None:
    with pytest.raises(ValueError):
        SecurityIssue(severity=SeverityLevel.LOW, description="")


def test_security_issue_description_whitespace_only_raises() -> None:
    with pytest.raises(ValueError):
        SecurityIssue(severity=SeverityLevel.LOW, description="   ")


def test_security_score_max_less_than_score_raises() -> None:
    with pytest.raises(ValueError):
        SecurityScore(score=80, max_score=50, percentage=80.0, grade=SecurityGrade.A)


def test_security_score_max_equals_score_is_valid() -> None:
    s = SecurityScore(score=50, max_score=50, percentage=100.0, grade=SecurityGrade.A)
    assert s.score == 50
    assert s.max_score == 50


def test_security_score_max_greater_than_score_is_valid() -> None:
    s = SecurityScore(score=30, max_score=100, percentage=30.0, grade=SecurityGrade.F)
    assert s.max_score == 100


def test_get_critical_issues_returns_only_critical() -> None:
    issues = [
        SecurityIssue(severity=SeverityLevel.CRITICAL, description="c1"),
        SecurityIssue(severity=SeverityLevel.HIGH, description="h1"),
        SecurityIssue(severity=SeverityLevel.CRITICAL, description="c2"),
    ]
    result = SecurityAnalysisResult(available=True, issues=issues)
    critical = result.get_critical_issues()
    assert len(critical) == 2
    assert all(i.severity == SeverityLevel.CRITICAL for i in critical)


def test_get_high_issues_returns_only_high() -> None:
    issues = [
        SecurityIssue(severity=SeverityLevel.CRITICAL, description="c1"),
        SecurityIssue(severity=SeverityLevel.HIGH, description="h1"),
        SecurityIssue(severity=SeverityLevel.MEDIUM, description="m1"),
    ]
    result = SecurityAnalysisResult(available=True, issues=issues)
    high = result.get_high_issues()
    assert len(high) == 1
    assert high[0].description == "h1"


def test_get_enabled_mitigations_returns_enabled_names() -> None:
    mitigations = {
        "aslr": MitigationInfo(enabled=True, description="aslr"),
        "dep": MitigationInfo(enabled=False, description="dep"),
        "cfg": MitigationInfo(enabled=True, description="cfg"),
    }
    result = SecurityAnalysisResult(available=True, mitigations=mitigations)
    enabled = result.get_enabled_mitigations()
    assert set(enabled) == {"aslr", "cfg"}


def test_get_disabled_mitigations_returns_disabled_names() -> None:
    mitigations = {
        "aslr": MitigationInfo(enabled=True, description="aslr"),
        "dep": MitigationInfo(enabled=False, description="dep"),
    }
    result = SecurityAnalysisResult(available=True, mitigations=mitigations)
    disabled = result.get_disabled_mitigations()
    assert disabled == ["dep"]


def test_has_mitigation_enabled_returns_true() -> None:
    mitigations = {"aslr": MitigationInfo(enabled=True, description="aslr")}
    result = SecurityAnalysisResult(available=True, mitigations=mitigations)
    assert result.has_mitigation("aslr") is True


def test_has_mitigation_disabled_returns_false() -> None:
    mitigations = {"dep": MitigationInfo(enabled=False, description="dep")}
    result = SecurityAnalysisResult(available=True, mitigations=mitigations)
    assert result.has_mitigation("dep") is False


def test_has_mitigation_missing_returns_false() -> None:
    result = SecurityAnalysisResult(available=True)
    assert result.has_mitigation("nonexistent") is False


def test_count_issues_by_severity_all_levels() -> None:
    issues = [
        SecurityIssue(severity=SeverityLevel.CRITICAL, description="c1"),
        SecurityIssue(severity=SeverityLevel.HIGH, description="h1"),
        SecurityIssue(severity=SeverityLevel.HIGH, description="h2"),
        SecurityIssue(severity=SeverityLevel.MEDIUM, description="m1"),
        SecurityIssue(severity=SeverityLevel.LOW, description="l1"),
    ]
    result = SecurityAnalysisResult(available=True, issues=issues)
    counts = result.count_issues_by_severity()
    assert counts["critical"] == 1
    assert counts["high"] == 2
    assert counts["medium"] == 1
    assert counts["low"] == 1
    assert counts["minimal"] == 0


def test_count_issues_by_severity_empty() -> None:
    result = SecurityAnalysisResult(available=True)
    counts = result.count_issues_by_severity()
    assert all(v == 0 for v in counts.values())


def test_is_secure_above_threshold_returns_true() -> None:
    result = SecurityAnalysisResult(available=True, score=85)
    assert result.is_secure(threshold=70) is True


def test_is_secure_below_threshold_returns_false() -> None:
    result = SecurityAnalysisResult(available=True, score=60)
    assert result.is_secure(threshold=70) is False


def test_is_secure_score_none_returns_false() -> None:
    result = SecurityAnalysisResult(available=True, score=None)
    assert result.is_secure() is False


def test_is_secure_equal_threshold_returns_true() -> None:
    result = SecurityAnalysisResult(available=True, score=70)
    assert result.is_secure(threshold=70) is True


def test_mitigation_info_all_fields() -> None:
    m = MitigationInfo(
        enabled=True,
        description="ASLR enabled",
        details="High entropy",
        note="64-bit",
        high_entropy=True,
    )
    assert m.enabled is True
    assert m.high_entropy is True


def test_security_analysis_result_with_recommendations() -> None:
    rec = Recommendation(
        priority=SeverityLevel.HIGH,
        mitigation="ASLR",
        recommendation="Enable ASLR",
        impact="Reduces exploitability",
    )
    result = SecurityAnalysisResult(available=True, recommendations=[rec])
    assert len(result.recommendations) == 1


def test_authenticode_signed_and_valid() -> None:
    auth = AuthenticodeAnalysisResult(
        available=True,
        signed=True,
        valid=True,
        signer="Test Corp",
    )
    assert auth.signed is True
    assert auth.valid is True
    assert auth.signer == "Test Corp"
