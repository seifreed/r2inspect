import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from r2inspect.schemas.base import AnalysisResultBase, FileInfoBase
from r2inspect.schemas.converters import (
    ResultConverter,
    dict_to_model,
    model_to_dict,
    safe_convert,
    validate_result,
)
from r2inspect.schemas.format import FormatAnalysisResult, SectionInfo, SecurityFeatures
from r2inspect.schemas.hashing import HashAnalysisResult
from r2inspect.schemas.security import (
    AuthenticodeAnalysisResult,
    MitigationInfo,
    Recommendation,
    SecurityAnalysisResult,
    SecurityIssue,
    SecurityScore,
    SeverityLevel,
)
from r2inspect.security.validators import FileValidator, validate_file_for_analysis


def test_analysis_result_base_and_file_info_validations():
    result = AnalysisResultBase(available=True, execution_time=1.5, analyzer_name=" Pe ")
    assert result.analyzer_name == "pe"
    assert result.model_dump_safe()["available"] is True

    payload = json.loads(result.to_json())
    assert payload["available"] is True

    with pytest.raises(ValueError):
        AnalysisResultBase(available=True, execution_time=-1.0)

    file_info = FileInfoBase(file_extension=".EXE ")
    assert file_info.file_extension == "exe"


def test_hash_analysis_result_validations():
    result = HashAnalysisResult(
        available=True,
        hash_type="SSDeep",
        hash_value="3:abc:def",
        method_used="python_library",
        file_size=1024,
    )
    assert result.hash_type == "ssdeep"
    assert result.is_valid_hash() is True

    result_custom = HashAnalysisResult(
        available=True,
        hash_type="tlsh",
        hash_value="abc",
        method_used="Custom",
    )
    assert result_custom.method_used == "custom"

    with pytest.raises(ValueError):
        HashAnalysisResult(available=True, hash_type="bad", hash_value="x")

    with pytest.raises(ValueError):
        HashAnalysisResult(
            available=True,
            hash_type="ssdeep",
            hash_value="x",
            file_size=11 * 1024 * 1024 * 1024,
        )


def test_format_schema_helpers_and_validations():
    section = SectionInfo(
        name=".text",
        virtual_address=0x1000,
        virtual_size=4096,
        raw_size=4096,
        entropy=5.0,
        permissions="r-x",
        is_executable=True,
        is_readable=True,
        suspicious_indicators=["packed"],
    )
    assert section.is_suspicious() is True
    assert section.has_permission("x") is True

    features = SecurityFeatures(aslr=True, dep=True)
    enabled = features.get_enabled_features()
    assert "aslr" in enabled and "dep" in enabled
    assert features.security_score() > 0

    result = FormatAnalysisResult(
        available=True,
        format="PE32",
        bits=64,
        endian="LE",
        sections=[section],
        security_features=features,
    )
    assert result.is_64bit() is True
    assert result.is_pe() is True
    assert result.get_executable_sections() == [section]
    assert result.get_suspicious_sections() == [section]

    with pytest.raises(ValueError):
        SectionInfo(name=" ", virtual_address=0, virtual_size=0, raw_size=0)

    with pytest.raises(ValueError):
        SectionInfo(name=".bad", virtual_address=0, virtual_size=0, raw_size=0, entropy=9.0)

    with pytest.raises(ValueError):
        FormatAnalysisResult(available=True, format="bad")

    with pytest.raises(ValueError):
        FormatAnalysisResult(available=True, format="PE", bits=16)

    with pytest.raises(ValueError):
        FormatAnalysisResult(available=True, format="PE", endian="middle")


def test_security_schema_helpers():
    issue = SecurityIssue(severity=SeverityLevel.HIGH, description="  issue ")
    assert issue.description == "issue"

    with pytest.raises(ValueError):
        SecurityIssue(severity=SeverityLevel.LOW, description=" ")

    with pytest.raises(ValueError):
        SecurityScore(score=10, max_score=5, percentage=10.0, grade="A")

    score = SecurityScore(score=8, max_score=10, percentage=80.0, grade="B")
    analysis = SecurityAnalysisResult(
        available=True,
        score=80,
        security_score=score,
        issues=[
            SecurityIssue(severity=SeverityLevel.CRITICAL, description="critical"),
            SecurityIssue(severity=SeverityLevel.HIGH, description="high"),
        ],
        mitigations={
            "aslr": MitigationInfo(enabled=True, description="aslr"),
            "dep": MitigationInfo(enabled=False, description="dep"),
        },
        recommendations=[
            Recommendation(
                priority=SeverityLevel.MEDIUM,
                mitigation="aslr",
                recommendation="enable",
                impact="medium",
            )
        ],
    )
    assert analysis.get_critical_issues()[0].severity == SeverityLevel.CRITICAL
    assert analysis.get_high_issues()[0].severity == SeverityLevel.HIGH
    assert analysis.get_enabled_mitigations() == ["aslr"]
    assert analysis.get_disabled_mitigations() == ["dep"]
    assert analysis.has_mitigation("aslr") is True
    assert analysis.count_issues_by_severity()["high"] == 1
    assert analysis.is_secure() is True

    AuthenticodeAnalysisResult(available=True, signed=False)


def test_converters_and_safe_convert():
    ResultConverter._schema_registry.clear()
    ResultConverter.register_schema("ssdeep", HashAnalysisResult)

    schema = ResultConverter.get_schema("SSDEEP")
    assert schema is HashAnalysisResult

    ok = dict_to_model(
        {"available": True, "hash_type": "ssdeep", "hash_value": "x"}, HashAnalysisResult
    )
    assert ok.hash_type == "ssdeep"

    with pytest.raises(ValidationError):
        dict_to_model(
            {"available": True, "hash_type": "bad", "hash_value": "x"},
            HashAnalysisResult,
            strict=True,
        )

    invalid = dict_to_model(
        {"available": True, "hash_type": "bad", "hash_value": "x"},
        HashAnalysisResult,
        strict=False,
    )
    assert invalid.hash_type == "bad"

    as_dict = model_to_dict(ok)
    assert as_dict["hash_type"] == "ssdeep"
    assert validate_result(ok) is True

    converted = ResultConverter.convert_result(
        "ssdeep", {"available": True, "hash_type": "ssdeep", "hash_value": "x"}
    )
    assert isinstance(converted, HashAnalysisResult)

    results = ResultConverter.convert_results(
        {"ssdeep": {"available": True, "hash_type": "bad", "hash_value": "x"}},
        strict=False,
    )
    assert isinstance(results["ssdeep"], HashAnalysisResult)
    assert results["ssdeep"].hash_type == "bad"

    assert safe_convert(None, HashAnalysisResult) is None
    assert safe_convert("nope", HashAnalysisResult, default=ok) is ok
    assert safe_convert(ok, HashAnalysisResult) is ok


def test_security_validators_path_and_yara(tmp_path: Path):
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"data")

    validator = FileValidator(allowed_directory=tmp_path)
    validated = validator.validate_path(str(file_path))
    assert validated == file_path.resolve()

    with pytest.raises(ValueError):
        validator.validate_path("")

    with pytest.raises(ValueError):
        validator.validate_path("bad;name")

    outside = tmp_path.parent / "outside.bin"
    outside.write_bytes(b"x")
    with pytest.raises(ValueError):
        validator.validate_path(str(outside))

    assert validator.sanitize_for_subprocess(validated) == str(validated.absolute())

    with pytest.raises(TypeError):
        validator.sanitize_for_subprocess("not-a-path")

    with pytest.raises(ValueError):
        validator.validate_yara_rule_content("")

    validator.validate_yara_rule_content("rule x { condition: true }")

    with pytest.raises(ValueError):
        validator.validate_yara_rule_content('include "evil"')

    with pytest.raises(ValueError):
        validator.validate_yara_rule_content('import "danger"')

    with pytest.raises(ValueError):
        validator.validate_yara_rule_content("*" * 10001)

    with pytest.raises(ValueError):
        validator.validate_yara_rule_content("a" * 10001)


def test_validate_file_for_analysis(tmp_path: Path):
    file_path = tmp_path / "ok.bin"
    file_path.write_bytes(b"data")

    validated = validate_file_for_analysis(str(file_path), allowed_directory=str(tmp_path))
    assert validated == file_path.resolve()

    empty_path = tmp_path / "empty.bin"
    empty_path.write_bytes(b"")
    with pytest.raises(ValueError):
        validate_file_for_analysis(str(empty_path), allowed_directory=str(tmp_path))

    with pytest.raises(ValueError):
        validate_file_for_analysis(str(file_path), allowed_directory=str(tmp_path), max_size=1)
