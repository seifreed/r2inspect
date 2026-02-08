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
    SecurityGrade,
    SecurityIssue,
    SecurityScore,
    SeverityLevel,
)


def test_security_issue_and_score_validation() -> None:
    issue = SecurityIssue(severity=SeverityLevel.LOW, description="  issue  ")
    assert issue.description == "issue"

    with pytest.raises(ValueError):
        SecurityIssue(severity=SeverityLevel.HIGH, description="  ")

    with pytest.raises(ValueError):
        SecurityScore(score=10, max_score=5, percentage=50.0, grade=SecurityGrade.C)


def test_security_analysis_result_helpers() -> None:
    result = SecurityAnalysisResult(
        available=True,
        score=80,
        mitigations={
            "ASLR": MitigationInfo(enabled=True, description="aslr"),
            "DEP": MitigationInfo(enabled=False, description="dep"),
        },
        issues=[
            SecurityIssue(severity=SeverityLevel.CRITICAL, description="c1"),
            SecurityIssue(severity=SeverityLevel.HIGH, description="h1"),
        ],
    )

    assert len(result.get_critical_issues()) == 1
    assert len(result.get_high_issues()) == 1
    assert result.get_enabled_mitigations() == ["ASLR"]
    assert result.get_disabled_mitigations() == ["DEP"]
    assert result.has_mitigation("ASLR") is True
    assert result.has_mitigation("DEP") is False
    counts = result.count_issues_by_severity()
    assert counts["critical"] == 1
    assert result.is_secure(threshold=70) is True

    no_score = SecurityAnalysisResult(available=True)
    assert no_score.is_secure() is False


def test_authenticode_schema_fields() -> None:
    auth = AuthenticodeAnalysisResult(
        available=True,
        signed=True,
        valid=True,
        signer="Test",
        timestamp=datetime(2024, 1, 1),
        signature_algorithm="rsa",
        digest_algorithm="sha256",
    )
    assert auth.signed is True
    assert auth.valid is True
    assert auth.signer == "Test"


def test_results_dataclasses_and_from_dict() -> None:
    hashing = HashingResult(ssdeep="hash")
    assert hashing.has_hash("ssdeep") is True
    assert hashing.has_hash("tlsh") is False

    security = SecurityFeatures(nx=True, relro="partial", high_entropy_va=True)
    assert "nx" in security.get_enabled_features()
    assert "relro_partial" in security.get_enabled_features()
    assert security.security_score() > 0

    anti = AntiAnalysisResult(anti_debug=True, timing_checks=True)
    assert anti.has_evasion() is True

    crypto = CryptoResult(algorithms=[{"name": "AES"}])
    assert crypto.has_crypto() is True

    result = AnalysisResult(
        hashing=hashing,
        security=security,
        anti_analysis=anti,
        crypto=crypto,
        indicators=[Indicator(type="API", description="bad", severity="High")],
    )
    assert result.is_suspicious() is True
    assert len(result.get_high_severity_indicators()) == 1

    data = {
        "file_info": {"name": "sample.bin", "size": 10, "file_type": "ELF"},
        "hashing": {"ssdeep": "hash"},
        "security": {"nx": True, "relro": "full"},
        "imports": [{"name": "read"}],
        "exports": [{"name": "exported"}],
        "sections": [{"name": ".text", "entropy": 5.0}],
        "strings": ["abc"],
        "yara_matches": [{"rule": "rule"}],
        "functions": [{"name": "main"}],
        "anti_analysis": {"anti_debug": True},
        "packer": {"is_packed": True, "packer_type": "UPX"},
        "crypto": {"algorithms": [{"name": "AES"}]},
        "indicators": [{"type": "API", "description": "bad", "severity": "Critical"}],
        "error": None,
        "timestamp": "not-a-date",
        "execution_time": 1.5,
    }
    loaded = from_dict(data)
    assert loaded.file_info.name == "sample.bin"
    assert loaded.security.relro == "full"
    assert loaded.strings == ["abc"]
    assert isinstance(loaded.timestamp, datetime)
    assert loaded.summary()["high_severity_count"] == 1
