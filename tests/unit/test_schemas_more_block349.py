from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from r2inspect.schemas import base as base_schema
from r2inspect.schemas import converters
from r2inspect.schemas import format as format_schema
from r2inspect.schemas import hashing, results, security


def test_base_schema_validators_and_dump() -> None:
    result = base_schema.AnalysisResultBase(
        available=True, execution_time=1.2, analyzer_name=" PE "
    )
    assert result.analyzer_name == "pe"
    assert result.model_dump_safe()["available"] is True
    assert "available" in result.to_json()

    with pytest.raises(ValueError):
        base_schema.AnalysisResultBase(available=True, execution_time=-1, analyzer_name="x")

    file_info = base_schema.FileInfoBase(file_extension="..EXE")
    assert file_info.file_extension == "exe"


def test_hashing_schema_validators_and_helpers() -> None:
    good = hashing.HashAnalysisResult(
        available=True, hash_value="abc", hash_type="SSDEEP", method_used="Python_Library"
    )
    assert good.hash_type == "ssdeep"
    assert good.method_used == "python_library"
    assert good.is_valid_hash()

    custom_method = hashing.HashAnalysisResult(
        available=True, hash_value="abc", hash_type="tlsh", method_used="custom"
    )
    assert custom_method.method_used == "custom"

    with pytest.raises(ValueError):
        hashing.HashAnalysisResult(available=True, hash_value="x", hash_type="bad")

    with pytest.raises(ValueError):
        hashing.HashAnalysisResult(available=True, hash_value="x", hash_type="ssdeep", file_size=-1)

    with pytest.raises(ValueError):
        hashing.HashAnalysisResult(
            available=True, hash_value="x", hash_type="ssdeep", file_size=11 * 1024 * 1024 * 1024
        )


def test_format_schema_helpers() -> None:
    section = format_schema.SectionInfo(name=".text", is_executable=True, entropy=7.5)
    assert section.is_suspicious() is False
    assert section.has_permission("x")

    with pytest.raises(ValueError):
        format_schema.SectionInfo(name=" ")

    with pytest.raises(ValueError):
        format_schema.SectionInfo(name=".bad", entropy=9.0)

    features = format_schema.SecurityFeatures(aslr=True, dep=True)
    assert "aslr" in features.get_enabled_features()
    assert features.security_score() > 0

    fmt = format_schema.FormatAnalysisResult(
        available=True,
        format="PE32+",
        bits=64,
        endian="Little",
        sections=[section],
        security_features=features,
    )
    assert fmt.is_pe()
    assert fmt.is_64bit()
    assert fmt.get_executable_sections() == [section]

    with pytest.raises(ValueError):
        format_schema.FormatAnalysisResult(available=True, format="UNKNOWN")

    with pytest.raises(ValueError):
        format_schema.FormatAnalysisResult(available=True, format="PE", bits=16)

    with pytest.raises(ValueError):
        format_schema.FormatAnalysisResult(available=True, format="PE", endian="middle")


def test_security_schema_helpers() -> None:
    issue = security.SecurityIssue(
        severity=security.SeverityLevel.CRITICAL,
        description="Bad",
        recommendation="Fix",
        cwe_id=79,
        cvss_score=9.0,
    )
    assert issue.description == "Bad"

    with pytest.raises(ValueError):
        security.SecurityIssue(
            severity=security.SeverityLevel.LOW,
            description=" ",
        )

    score = security.SecurityScore(
        score=80, max_score=100, percentage=80.0, grade=security.SecurityGrade.A
    )
    assert score.grade == security.SecurityGrade.A

    with pytest.raises(ValueError):
        security.SecurityScore(
            score=90, max_score=80, percentage=90.0, grade=security.SecurityGrade.B
        )

    mitigations = {
        "aslr": security.MitigationInfo(enabled=True, description="ASLR"),
        "dep": security.MitigationInfo(enabled=False, description="DEP"),
    }
    result = security.SecurityAnalysisResult(
        available=True,
        score=75,
        mitigations=mitigations,
        issues=[issue],
    )
    assert result.get_critical_issues() == [issue]
    assert result.get_high_issues() == []
    assert result.get_enabled_mitigations() == ["aslr"]
    assert result.get_disabled_mitigations() == ["dep"]
    assert result.has_mitigation("aslr")
    counts = result.count_issues_by_severity()
    assert counts[security.SeverityLevel.CRITICAL.value] == 1
    assert result.is_secure()

    result.score = None
    assert result.is_secure() is False


def test_results_from_dict_and_helpers() -> None:
    now = datetime.utcnow()
    payload = {
        "file_info": {"name": "a.bin", "size": 123, "md5": "md5", "file_type": "PE"},
        "hashing": {"ssdeep": "3:abc:def", "simhash": "0x1"},
        "security": {"nx": True, "relro": "full", "aslr": True},
        "imports": [{"name": "CreateFileA", "library": "KERNEL32"}],
        "exports": [{"name": "Exported", "address": "0x1"}],
        "sections": [{"name": ".text", "virtual_address": 1}],
        "strings": ["hello"],
        "yara_matches": [{"rule": "Rule", "namespace": "default"}],
        "functions": [{"name": "func", "address": 1}],
        "anti_analysis": {"anti_debug": True},
        "packer": {"is_packed": True, "packer_type": "upx"},
        "crypto": {"algorithms": [{"name": "AES"}]},
        "indicators": [{"type": "Packer", "severity": "High"}],
        "error": None,
        "timestamp": now.isoformat(),
        "execution_time": 1.23,
    }
    result = results.from_dict(payload)
    assert result.file_info.name == "a.bin"
    assert result.hashing.has_hash("ssdeep")
    assert result.security.security_score() > 0
    assert result.sections[0].is_suspicious() is False
    assert result.anti_analysis.has_evasion()
    assert result.packer.is_packed
    assert result.crypto.has_crypto()
    assert result.is_suspicious()
    assert result.get_high_severity_indicators()[0].severity == "High"
    assert result.summary()["file_name"] == "a.bin"
    assert result.to_dict()["execution_time"] == 1.23

    blank = results.from_dict({})
    assert blank.file_info.name == ""
    assert blank.has_error() is False

    results._load_timestamp(blank, {"timestamp": "invalid"})
    results._load_timestamp(blank, {"timestamp": now})
    results._load_execution_time(blank, {})


def test_converters_and_validation_helpers() -> None:
    data = {"available": True, "hash_type": "ssdeep", "hash_value": "abc"}
    model = converters.dict_to_model(data, hashing.HashAnalysisResult)
    assert model.hash_type == "ssdeep"
    assert converters.model_to_dict(model)["hash_value"] == "abc"

    strict_bad = {"available": True, "hash_type": "bad", "hash_value": "abc"}
    with pytest.raises(ValidationError):
        converters.dict_to_model(strict_bad, hashing.HashAnalysisResult, strict=True)

    converted = converters.ResultConverter.convert_results({"bad": strict_bad}, strict=False)
    assert isinstance(converted["bad"], base_schema.AnalysisResultBase)
    assert converted["bad"].analyzer_name == "bad"

    assert converters.safe_convert(None, hashing.HashAnalysisResult) is None
    assert converters.safe_convert(model, hashing.HashAnalysisResult) is model
    assert converters.safe_convert("nope", hashing.HashAnalysisResult) is None
    assert converters.validate_result(model)
