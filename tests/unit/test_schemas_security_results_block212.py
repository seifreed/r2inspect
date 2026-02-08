from __future__ import annotations

from datetime import datetime

import pytest

from r2inspect.schemas.results import (
    AnalysisResult,
    AntiAnalysisResult,
    CryptoResult,
    HashingResult,
    Indicator,
    SecurityFeatures,
    from_dict,
)
from r2inspect.schemas.security import (
    AuthenticodeAnalysisResult,
    MitigationInfo,
    SecurityAnalysisResult,
    SecurityIssue,
    SecurityScore,
    SeverityLevel,
)


def test_security_issue_and_score_validation() -> None:
    issue = SecurityIssue(severity=SeverityLevel.HIGH, description="  bad  ")
    assert issue.description == "bad"
    with pytest.raises(ValueError):
        SecurityIssue(severity=SeverityLevel.LOW, description=" ")

    score = SecurityScore(score=50, max_score=100, percentage=50.0, grade="B")
    assert score.max_score == 100
    with pytest.raises(ValueError):
        SecurityScore(score=60, max_score=50, percentage=50.0, grade="C")


def test_security_analysis_result_helpers() -> None:
    result = SecurityAnalysisResult(available=True)
    result.mitigations = {
        "aslr": MitigationInfo(enabled=True, description="aslr"),
        "dep": MitigationInfo(enabled=False, description="dep"),
    }
    result.issues = [
        SecurityIssue(severity=SeverityLevel.CRITICAL, description="c"),
        SecurityIssue(severity=SeverityLevel.HIGH, description="h"),
    ]
    result.score = 80
    assert len(result.get_critical_issues()) == 1
    assert len(result.get_high_issues()) == 1
    assert result.get_enabled_mitigations() == ["aslr"]
    assert result.get_disabled_mitigations() == ["dep"]
    assert result.has_mitigation("aslr") is True
    counts = result.count_issues_by_severity()
    assert counts["critical"] == 1
    assert counts["high"] == 1
    assert result.is_secure() is True
    assert SecurityAnalysisResult(available=True).is_secure() is False


def test_authenticode_result_basic() -> None:
    auth = AuthenticodeAnalysisResult(available=True, signed=True)
    assert auth.signed is True


def test_results_dataclasses_helpers() -> None:
    hashing = HashingResult(ssdeep="abc")
    assert hashing.has_hash("ssdeep") is True
    assert hashing.has_hash("tlsh") is False

    security = SecurityFeatures(nx=True, relro="full")
    enabled = security.get_enabled_features()
    assert "nx" in enabled
    assert "relro_full" in enabled
    assert 0 < security.security_score() <= 100

    anti = AntiAnalysisResult(anti_debug=True)
    assert anti.has_evasion() is True

    crypto = CryptoResult(algorithms=[{"name": "aes"}])
    assert crypto.has_crypto() is True

    result = AnalysisResult(
        indicators=[Indicator(type="X", description="Y", severity="High")],
        anti_analysis=anti,
    )
    assert result.is_suspicious() is True
    assert len(result.get_high_severity_indicators()) == 1
    summary = result.summary()
    assert summary["high_severity_count"] == 1


def test_from_dict_and_load_helpers() -> None:
    data = {
        "file_info": {"name": "a", "size": 10, "md5": "x"},
        "hashing": {"ssdeep": "abc"},
        "security": {"nx": True, "relro": "partial"},
        "imports": [{"name": "CreateFileA", "library": "KERNEL32.dll"}],
        "exports": [{"name": "exp", "address": "0x1"}],
        "sections": [{"name": ".text", "entropy": 6.0}],
        "strings": ["hello"],
        "yara_matches": [{"rule": "Rule1"}],
        "functions": [{"name": "f", "address": 1}],
        "anti_analysis": {"anti_vm": True},
        "packer": {"is_packed": True, "packer_type": "upx"},
        "crypto": {"algorithms": [{"name": "aes"}]},
        "indicators": [{"type": "Packer", "severity": "High"}],
        "error": "boom",
        "timestamp": datetime.utcnow().isoformat(),
        "execution_time": 1.25,
    }
    result = from_dict(data)
    assert result.file_info.name == "a"
    assert result.hashing.ssdeep == "abc"
    assert result.security.nx is True
    assert result.imports[0].name == "CreateFileA"
    assert result.exports[0].name == "exp"
    assert result.sections[0].name == ".text"
    assert result.strings == ["hello"]
    assert result.yara_matches[0].rule == "Rule1"
    assert result.functions[0].name == "f"
    assert result.anti_analysis.anti_vm is True
    assert result.packer.is_packed is True
    assert result.crypto.algorithms
    assert result.indicators[0].type == "Packer"
    assert result.has_error() is True
    assert result.execution_time == 1.25

    data["timestamp"] = "not-a-date"
    result = from_dict(data)
    assert isinstance(result.timestamp, datetime)

    data["timestamp"] = datetime.utcnow()
    result = from_dict(data)
    assert isinstance(result.timestamp, datetime)
