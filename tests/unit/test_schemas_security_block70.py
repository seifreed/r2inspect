from __future__ import annotations

import pytest

from r2inspect.schemas.security import (
    AuthenticodeAnalysisResult,
    MitigationInfo,
    SecurityAnalysisResult,
    SecurityIssue,
    SecurityScore,
    SeverityLevel,
)


def test_security_issue_and_score_validators():
    with pytest.raises(ValueError):
        SecurityIssue(severity=SeverityLevel.LOW, description="   ")

    with pytest.raises(ValueError):
        SecurityScore(score=10, max_score=5, percentage=50.0, grade="A")


def test_security_analysis_helpers():
    issues = [
        SecurityIssue(severity=SeverityLevel.CRITICAL, description="crit"),
        SecurityIssue(severity=SeverityLevel.HIGH, description="high"),
    ]
    mitigations = {
        "aslr": MitigationInfo(enabled=True, description="aslr"),
        "dep": MitigationInfo(enabled=False, description="dep"),
    }
    result = SecurityAnalysisResult(
        available=True, issues=issues, mitigations=mitigations, score=75
    )

    assert len(result.get_critical_issues()) == 1
    assert len(result.get_high_issues()) == 1
    assert result.get_enabled_mitigations() == ["aslr"]
    assert result.get_disabled_mitigations() == ["dep"]
    assert result.has_mitigation("aslr") is True
    assert result.has_mitigation("missing") is False
    counts = result.count_issues_by_severity()
    assert counts[SeverityLevel.CRITICAL.value] == 1
    assert result.is_secure() is True

    result.score = None
    assert result.is_secure() is False


def test_authenticode_defaults():
    auth = AuthenticodeAnalysisResult(available=True)
    assert auth.signed is False
    assert auth.certificates == []
