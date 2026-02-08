from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from r2inspect.schemas import converters
from r2inspect.schemas.base import AnalysisResultBase, FileInfoBase
from r2inspect.schemas.format import FormatAnalysisResult, SectionInfo, SecurityFeatures
from r2inspect.schemas.hashing import HashAnalysisResult
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


def test_analysis_result_base_validators_and_dump() -> None:
    result = AnalysisResultBase(available=True, execution_time=1.0, analyzer_name=" PE ")
    assert result.analyzer_name == "pe"
    assert result.model_dump_safe()["available"] is True
    assert '"available":true' in result.to_json()

    with pytest.raises(ValidationError):
        AnalysisResultBase(available=True, execution_time=-1.0)


def test_file_info_base_normalizes_extension() -> None:
    info = FileInfoBase(file_extension="..EXE ")
    assert info.file_extension == "exe"
    assert FileInfoBase(file_extension=None).file_extension is None


def test_hash_analysis_result_validation() -> None:
    result = HashAnalysisResult(
        available=True,
        hash_value="abc",
        hash_type="ssdeep",
        method_used="Python_Library",
        file_size=10,
    )
    assert result.method_used == "python_library"
    assert result.is_valid_hash() is True

    with pytest.raises(ValidationError):
        HashAnalysisResult(available=True, hash_value="x", hash_type="invalid")

    with pytest.raises(ValidationError):
        HashAnalysisResult(available=True, hash_value="x", hash_type="ssdeep", file_size=-1)

    with pytest.raises(ValidationError):
        HashAnalysisResult(
            available=True,
            hash_value="x",
            hash_type="ssdeep",
            file_size=11 * 1024 * 1024 * 1024,
        )


def test_format_analysis_result_and_section_helpers() -> None:
    section = SectionInfo(
        name=".text",
        is_executable=True,
        is_writable=False,
        is_readable=True,
        suspicious_indicators=["packed"],
    )
    assert section.is_suspicious() is True
    assert section.has_permission("x") is True
    assert section.has_permission("w") is False
    assert section.has_permission("unknown") is False

    features = SecurityFeatures(aslr=True, dep=True)
    assert "aslr" in features.get_enabled_features()
    assert features.security_score() > 0

    result = FormatAnalysisResult(
        available=True,
        format="pe32",
        architecture="x86",
        bits=64,
        endian="Le",
        sections=[section],
        security_features=features,
    )
    assert result.is_64bit() is True
    assert result.is_pe() is True
    assert result.is_elf() is False
    assert result.is_macho() is False
    assert result.get_executable_sections() == [section]
    assert result.get_writable_sections() == []
    assert result.get_suspicious_sections() == [section]

    with pytest.raises(ValidationError):
        SectionInfo(name=" ", entropy=1.0)

    with pytest.raises(ValidationError):
        SectionInfo(name=".bad", entropy=9.0)

    with pytest.raises(ValidationError):
        FormatAnalysisResult(available=True, format="bad")

    with pytest.raises(ValidationError):
        FormatAnalysisResult(available=True, format="PE", bits=128)

    with pytest.raises(ValidationError):
        FormatAnalysisResult(available=True, format="PE", endian="middle")


def test_security_schemas_and_helpers() -> None:
    issue = SecurityIssue(severity=SeverityLevel.CRITICAL, description=" bad ")
    assert issue.description == "bad"

    with pytest.raises(ValidationError):
        SecurityIssue(severity=SeverityLevel.LOW, description=" ")

    score = SecurityScore(score=10, max_score=20, percentage=50.0, grade=SecurityGrade.B)
    assert score.grade == SecurityGrade.B

    with pytest.raises(ValidationError):
        SecurityScore(score=10, max_score=5, percentage=50.0, grade=SecurityGrade.B)

    mitigations = {"aslr": MitigationInfo(enabled=True, description="ASLR")}
    result = SecurityAnalysisResult(
        available=True,
        mitigations=mitigations,
        features={"aslr": True},
        score=80,
        issues=[issue],
        recommendations=[
            Recommendation(
                priority=SeverityLevel.HIGH,
                mitigation="DEP",
                recommendation="Enable DEP",
                impact="Prevents code execution",
            )
        ],
    )
    assert result.get_critical_issues() == [issue]
    assert result.get_high_issues() == []
    assert result.get_enabled_mitigations() == ["aslr"]
    assert result.get_disabled_mitigations() == []
    assert result.has_mitigation("aslr") is True
    assert result.count_issues_by_severity()["critical"] == 1
    assert result.is_secure() is True
    assert result.is_secure(threshold=90) is False

    unsigned = AuthenticodeAnalysisResult(available=True, signed=False)
    assert unsigned.signed is False
    assert isinstance(unsigned.timestamp, datetime) or unsigned.timestamp is None


def test_converters_and_safe_convert() -> None:
    data = {"available": True, "hash_type": "ssdeep", "hash_value": "abc"}
    model = converters.dict_to_model(data, HashAnalysisResult)
    assert isinstance(model, HashAnalysisResult)

    invalid = {"available": True, "hash_type": "nope"}
    model_non_strict = converters.dict_to_model(invalid, HashAnalysisResult, strict=False)
    assert isinstance(model_non_strict, HashAnalysisResult)

    with pytest.raises(ValidationError):
        converters.dict_to_model(invalid, HashAnalysisResult, strict=True)

    assert converters.model_to_dict(model)["hash_type"] == "ssdeep"

    converters.ResultConverter.register_schema("ssdeep", HashAnalysisResult)
    schema = converters.ResultConverter.get_schema("ssdeep")
    assert schema is HashAnalysisResult

    converted = converters.ResultConverter.convert_result("ssdeep", data)
    assert isinstance(converted, HashAnalysisResult)
    assert converted.analyzer_name == "ssdeep"

    converted_results = converters.ResultConverter.convert_results(
        {"ok": data, "bad": invalid}, strict=False
    )
    assert "ok" in converted_results
    assert "bad" in converted_results

    listed = converters.ResultConverter.list_registered_schemas()
    assert "ssdeep" in listed

    assert converters.safe_convert(None, HashAnalysisResult) is None
    assert converters.safe_convert(model, HashAnalysisResult) is model
    assert converters.safe_convert(data, HashAnalysisResult) is not None
    assert converters.safe_convert(["not", "a", "dict"], HashAnalysisResult) is None

    invalid_model = HashAnalysisResult.model_construct(available=True, hash_type="nope")
    assert converters.validate_result(invalid_model) is False
