from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from r2inspect.schemas.base import AnalysisResultBase, FileInfoBase
from r2inspect.schemas.format import FormatAnalysisResult, SectionInfo
from r2inspect.schemas.hashing import HashAnalysisResult
from r2inspect.schemas.results import (
    AnalysisResult,
    CryptoResult,
    HashingResult,
    Indicator,
    SecurityFeatures,
    from_dict,
)
from r2inspect.schemas.security import (
    SecurityAnalysisResult,
    SecurityGrade,
    SecurityIssue,
    SecurityScore,
    SeverityLevel,
)


def test_base_schema_validation_and_json() -> None:
    with pytest.raises(ValidationError):
        AnalysisResultBase(available=True, execution_time=-1.0)

    base = AnalysisResultBase(available=True, analyzer_name=" PE ")
    assert base.analyzer_name == "pe"
    assert "available" in base.to_json()
    assert base.model_dump_safe()

    file_info = FileInfoBase(file_extension="..EXE")
    assert file_info.file_extension == "exe"


def test_hashing_schema_validations() -> None:
    result = HashAnalysisResult(available=True, hash_type="SSDEEP", method_used="Custom")
    assert result.hash_type == "ssdeep"
    assert result.method_used == "custom"

    with pytest.raises(ValidationError):
        HashAnalysisResult(available=True, hash_type="bad")

    with pytest.raises(ValidationError):
        HashAnalysisResult(available=True, hash_type="ssdeep", file_size=-1)

    with pytest.raises(ValidationError):
        HashAnalysisResult(available=True, hash_type="ssdeep", file_size=11 * 1024 * 1024 * 1024)


def test_format_schema_validations() -> None:
    with pytest.raises(ValidationError):
        SectionInfo(name="")

    with pytest.raises(ValidationError):
        SectionInfo(name=".text", entropy=9.0)

    with pytest.raises(ValidationError):
        FormatAnalysisResult(available=True, format="bad")

    with pytest.raises(ValidationError):
        FormatAnalysisResult(available=True, format="PE32", bits=16)

    with pytest.raises(ValidationError):
        FormatAnalysisResult(available=True, format="PE32", endian="weird")

    result = FormatAnalysisResult(
        available=True,
        format="PE32",
        bits=64,
        sections=[SectionInfo(name=".text", is_executable=True)],
    )
    assert result.is_64bit() is True
    assert result.is_pe() is True


def test_security_schema_methods() -> None:
    with pytest.raises(ValidationError):
        SecurityIssue(severity=SeverityLevel.HIGH, description=" ")

    with pytest.raises(ValidationError):
        SecurityScore(score=5, max_score=4, percentage=100.0, grade=SecurityGrade.A)

    analysis = SecurityAnalysisResult(
        available=True,
        score=85,
        mitigations={
            "aslr": {"enabled": True, "description": "ASLR"},
            "dep": {"enabled": False, "description": "DEP"},
        },
        issues=[
            SecurityIssue(severity=SeverityLevel.CRITICAL, description="issue"),
            SecurityIssue(severity=SeverityLevel.HIGH, description="issue2"),
        ],
    )
    assert analysis.get_critical_issues()
    assert analysis.get_high_issues()
    assert analysis.get_enabled_mitigations() == ["aslr"]
    assert analysis.get_disabled_mitigations() == ["dep"]
    assert analysis.has_mitigation("aslr") is True
    assert analysis.is_secure(threshold=80) is True
    assert analysis.count_issues_by_severity()["critical"] == 1
    analysis.score = None
    assert analysis.is_secure() is False


def test_results_schema_helpers_and_from_dict() -> None:
    hashing = HashingResult(ssdeep="  ", tlsh="abc")
    assert hashing.has_hash("ssdeep") is False
    assert hashing.has_hash("tlsh") is True

    security = SecurityFeatures(nx=True, relro="full")
    assert "nx" in security.get_enabled_features()
    assert "relro_full" in security.get_enabled_features()
    assert security.security_score() > 0

    crypto = CryptoResult(algorithms=[{"name": "AES"}])
    assert crypto.has_crypto() is True

    result = AnalysisResult()
    result.packer.is_packed = True
    result.indicators.append(Indicator(type="Packer", description="packed", severity="High"))
    result.anti_analysis.anti_debug = True
    result.error = "boom"
    summary = result.summary()
    assert summary["is_packed"] is True
    assert result.has_error() is True
    assert result.is_suspicious() is True
    assert result.get_high_severity_indicators()

    parsed = from_dict(
        {
            "file_info": {
                "name": "sample.bin",
                "path": "/tmp/sample.bin",
                "size": 1,
                "md5": "md5",
                "sha1": "sha1",
                "sha256": "sha256",
                "file_type": "PE",
                "architecture": "x86",
                "bits": 32,
                "endian": "little",
                "mime_type": "application/octet-stream",
            },
            "hashing": {
                "ssdeep": "hash",
                "tlsh": "tlsh",
                "imphash": "imp",
                "impfuzzy": "impfuzzy",
                "ccbhash": "ccb",
                "simhash": "sim",
                "telfhash": "telf",
                "rich_hash": "rich",
                "machoc_hash": "machoc",
            },
            "security": {
                "nx": True,
                "pie": True,
                "canary": True,
                "relro": "partial",
                "aslr": True,
                "seh": True,
                "guard_cf": True,
                "authenticode": True,
                "fortify": True,
                "rpath": True,
                "runpath": True,
                "high_entropy_va": True,
            },
            "imports": [{"name": "CreateFileA", "risk_tags": ["fs"]}],
            "exports": [{"name": "ExportedFunc"}],
            "sections": [{"name": ".text", "entropy": 7.2}],
            "strings": ["one", "two"],
            "yara_matches": [{"rule": "rule"}],
            "functions": [{"name": "main"}],
            "anti_analysis": {"anti_debug": True, "timing_checks": True},
            "packer": {"is_packed": True, "packer_type": "UPX"},
            "crypto": {"algorithms": [{"name": "AES"}], "functions": ["aes"]},
            "indicators": [{"type": "Packer", "description": "packed", "severity": "High"}],
            "error": "boom",
            "timestamp": "invalid-time",
            "execution_time": 1.25,
        }
    )
    assert parsed.file_info.name == "sample.bin"
    assert parsed.hashing.ssdeep == "hash"
    assert parsed.security.nx is True
    assert parsed.execution_time == 1.25

    now = datetime.utcnow()
    parsed = from_dict({"timestamp": now})
    assert parsed.timestamp == now
