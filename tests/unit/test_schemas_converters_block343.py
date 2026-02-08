from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from r2inspect.schemas.base import AnalysisResultBase, FileInfoBase
from r2inspect.schemas.converters import (
    ResultConverter,
    dict_to_model,
    safe_convert,
    validate_result,
)
from r2inspect.schemas.format import FormatAnalysisResult, SectionInfo, SecurityFeatures
from r2inspect.schemas.hashing import HashAnalysisResult
from r2inspect.schemas.security import (
    AuthenticodeAnalysisResult,
    SecurityAnalysisResult,
    SecurityGrade,
    SecurityIssue,
    SecurityScore,
    SeverityLevel,
)


def test_analysis_result_base_validators_and_dump() -> None:
    result = AnalysisResultBase(available=True, execution_time=0.25, analyzer_name=" PE ")
    assert result.execution_time == 0.25
    assert result.analyzer_name == "pe"

    with pytest.raises(ValidationError):
        AnalysisResultBase(available=True, execution_time=-1.0)

    with pytest.raises(ValueError):
        AnalysisResultBase.validate_execution_time(-1.0)

    assert AnalysisResultBase.validate_analyzer_name(None) is None

    dumped = result.model_dump_safe()
    assert "available" in dumped
    assert "error" not in dumped

    json_payload = result.to_json()
    assert "available" in json_payload


def test_file_info_base_extension_normalization() -> None:
    info = FileInfoBase(file_extension=" .EXE ")
    assert info.file_extension == "exe"

    info = FileInfoBase(file_extension="..tar.gz")
    assert info.file_extension == "tar.gz"

    info = FileInfoBase(file_extension=None)
    assert info.file_extension is None

    assert FileInfoBase.normalize_extension("..Exe") == "exe"


def test_hash_analysis_validators_and_helpers() -> None:
    result = HashAnalysisResult(
        available=True,
        hash_type=" SSDEEP ",
        method_used="python_library",
        file_size=10,
        hash_value="3:abc:def",
    )
    assert result.hash_type == "ssdeep"
    assert result.method_used == "python_library"
    assert result.is_valid_hash() is True

    blank = HashAnalysisResult(
        available=True,
        hash_type="tlsh",
        method_used=None,
        file_size=0,
        hash_value="   ",
    )
    assert blank.is_valid_hash() is False

    with pytest.raises(ValidationError):
        HashAnalysisResult(available=True, hash_type="unknown")

    with pytest.raises(ValidationError):
        HashAnalysisResult(available=True, hash_type="ssdeep", file_size=-1)

    with pytest.raises(ValueError):
        HashAnalysisResult.validate_file_size(-1)

    with pytest.raises(ValidationError):
        HashAnalysisResult(available=True, hash_type="ssdeep", file_size=11 * 1024 * 1024 * 1024)

    custom = HashAnalysisResult(available=True, hash_type="ssdeep", method_used="custom")
    assert custom.method_used == "custom"


def test_section_info_and_security_features() -> None:
    section = SectionInfo(name=" .text ", is_readable=True, is_executable=True)
    assert section.name == ".text"
    assert section.has_permission("r") is True
    assert section.has_permission("w") is False
    assert section.has_permission("x") is True
    assert section.has_permission("z") is False
    assert section.is_suspicious() is False

    section.suspicious_indicators.append("packed")
    assert section.is_suspicious() is True

    with pytest.raises(ValidationError):
        SectionInfo(name=" ")

    with pytest.raises(ValidationError):
        SectionInfo(name=".data", entropy=9.0)

    with pytest.raises(ValueError):
        SectionInfo.validate_entropy(9.0)

    assert SectionInfo.validate_entropy(5.0) == 5.0

    features = SecurityFeatures(aslr=True, dep=True, pie=True)
    enabled = features.get_enabled_features()
    assert "aslr" in enabled
    assert "dep" in enabled
    assert "pie" in enabled
    assert features.security_score() > 0


def test_format_analysis_helpers() -> None:
    section_exec = SectionInfo(name=".text", is_executable=True)
    section_write = SectionInfo(name=".data", is_writable=True)
    section_suspicious = SectionInfo(name=".rsrc", suspicious_indicators=["entropy"])

    result = FormatAnalysisResult(
        available=True,
        format="pe32+",
        bits=64,
        endian="LE",
        sections=[section_exec, section_write, section_suspicious],
    )

    assert result.format == "PE32+"
    assert result.is_64bit() is True
    assert result.is_pe() is True
    assert result.is_elf() is False
    assert result.is_macho() is False
    assert result.get_executable_sections() == [section_exec]
    assert result.get_writable_sections() == [section_write]
    assert result.get_suspicious_sections() == [section_suspicious]

    with pytest.raises(ValidationError):
        FormatAnalysisResult(available=True, format="BAD")

    with pytest.raises(ValidationError):
        FormatAnalysisResult(available=True, format="PE", bits=48)

    with pytest.raises(ValidationError):
        FormatAnalysisResult(available=True, format="ELF", endian="middle")

    assert FormatAnalysisResult.validate_endian(None) is None


def test_security_schema_helpers_and_validators() -> None:
    issue = SecurityIssue(severity=SeverityLevel.CRITICAL, description="  bad  ")
    assert issue.description == "bad"

    with pytest.raises(ValidationError):
        SecurityIssue(severity=SeverityLevel.LOW, description=" ")

    score = SecurityScore(score=80, max_score=100, percentage=80.0, grade=SecurityGrade.A)
    assert score.score == 80

    with pytest.raises(ValidationError):
        SecurityScore(score=80, max_score=40, percentage=50.0, grade=SecurityGrade.C)

    analysis = SecurityAnalysisResult(
        available=True,
        score=75,
        issues=[issue],
        mitigations={
            "aslr": {
                "enabled": True,
                "description": "ASLR",
            },
            "dep": {
                "enabled": False,
                "description": "DEP",
            },
        },
    )

    assert analysis.get_critical_issues() == [issue]
    assert analysis.get_high_issues() == []
    assert analysis.get_enabled_mitigations() == ["aslr"]
    assert analysis.get_disabled_mitigations() == ["dep"]
    assert analysis.has_mitigation("aslr") is True
    assert analysis.has_mitigation("missing") is False
    assert analysis.count_issues_by_severity()[SeverityLevel.CRITICAL.value] == 1
    assert analysis.is_secure(threshold=70) is True

    analysis.score = None
    assert analysis.is_secure() is False

    auth = AuthenticodeAnalysisResult(
        available=True,
        signed=True,
        valid=False,
        signer="Example",
        timestamp=datetime.utcnow(),
        signature_algorithm="sha256",
        digest_algorithm="sha256",
        certificates=[{"subject": "test"}],
    )
    assert auth.signed is True


def test_converters_and_registry(caplog: pytest.LogCaptureFixture) -> None:
    data = {"available": True, "hash_type": "ssdeep", "hash_value": "3:abc:def"}
    model = dict_to_model(data, HashAnalysisResult)
    assert isinstance(model, HashAnalysisResult)

    with pytest.raises(ValidationError):
        dict_to_model({"available": True, "hash_type": "bad"}, HashAnalysisResult, strict=True)

    with caplog.at_level("WARNING"):
        fallback = dict_to_model({"available": True, "hash_type": "bad"}, HashAnalysisResult)
    assert isinstance(fallback, HashAnalysisResult)

    ResultConverter.register_schema("hash", HashAnalysisResult)
    converted = ResultConverter.convert_result("hash", data)
    assert isinstance(converted, HashAnalysisResult)
    assert converted.analyzer_name == "hash"

    results = ResultConverter.convert_results({"hash": data, "bad": {"available": True}})
    assert "hash" in results
    assert "bad" in results

    ResultConverter.register_schema("bad", HashAnalysisResult)
    strict_results = ResultConverter.convert_results(
        {"bad": {"available": True, "hash_type": "bad"}}, strict=True
    )
    assert strict_results == {}

    class ExplodingModel:
        def __init__(self, **_kwargs: object) -> None:
            raise RuntimeError("boom")

    ResultConverter.register_schema("bad2", ExplodingModel)
    non_strict = ResultConverter.convert_results({"bad2": {"available": True}}, strict=False)
    assert "bad2" in non_strict

    listed = ResultConverter.list_registered_schemas()
    assert listed["hash"] == "HashAnalysisResult"

    assert safe_convert(None, HashAnalysisResult) is None
    assert safe_convert(model, HashAnalysisResult) is model
    assert safe_convert(123, HashAnalysisResult) is None

    assert safe_convert({"available": True}, ExplodingModel) is None

    invalid = HashAnalysisResult.model_construct(available=True, hash_type="bad")
    assert validate_result(invalid) is False

    assert validate_result(model) is True
