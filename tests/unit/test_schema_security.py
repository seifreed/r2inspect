import pytest

from r2inspect.schemas.security import (
    AuthenticodeAnalysisResult,
    MitigationInfo,
    SecurityAnalysisResult,
    SecurityGrade,
    SecurityIssue,
    SecurityScore,
    SeverityLevel,
)


def test_security_issue_validation():
    issue = SecurityIssue(severity=SeverityLevel.HIGH, description="Issue")
    assert issue.severity == SeverityLevel.HIGH

    with pytest.raises(ValueError):
        SecurityIssue(severity=SeverityLevel.LOW, description=" ")


def test_security_score_validation():
    score = SecurityScore(score=50, max_score=100, percentage=50.0, grade=SecurityGrade.C)
    assert score.grade == SecurityGrade.C

    with pytest.raises(ValueError):
        SecurityScore(score=60, max_score=50, percentage=100.0, grade=SecurityGrade.F)


def test_security_analysis_helpers():
    mitigations = {
        "ASLR": MitigationInfo(enabled=True, description="ASLR"),
        "DEP": MitigationInfo(enabled=False, description="DEP"),
    }
    issues = [
        SecurityIssue(severity=SeverityLevel.CRITICAL, description="critical"),
        SecurityIssue(severity=SeverityLevel.LOW, description="low"),
    ]
    result = SecurityAnalysisResult(available=True, mitigations=mitigations, issues=issues)
    assert result.get_critical_issues()[0].severity == SeverityLevel.CRITICAL
    assert result.get_enabled_mitigations() == ["ASLR"]
    assert result.count_issues_by_severity()["critical"] == 1
    assert result.is_secure() is False


def test_authenticode_defaults():
    result = AuthenticodeAnalysisResult(available=True)
    assert result.signed is False
