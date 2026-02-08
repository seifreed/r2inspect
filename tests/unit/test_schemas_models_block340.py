import json
from datetime import datetime

import pytest
from pydantic import ValidationError

from r2inspect.schemas import base as base_schema
from r2inspect.schemas import converters
from r2inspect.schemas import format as format_schema
from r2inspect.schemas import hashing as hashing_schema
from r2inspect.schemas import metadata as metadata_schema
from r2inspect.schemas import results as results_schema
from r2inspect.schemas import security as security_schema


def test_analysis_result_base_validators_and_dump() -> None:
    result = base_schema.AnalysisResultBase(
        available=True,
        execution_time=1.5,
        analyzer_name=" PE ",
    )
    assert result.analyzer_name == "pe"

    dumped = result.model_dump_safe()
    assert "error" not in dumped
    assert dumped["available"] is True

    text = result.to_json()
    assert json.loads(text)["available"] is True

    with pytest.raises(ValidationError):
        base_schema.AnalysisResultBase(available=True, execution_time=-1)

    with pytest.raises(ValueError):
        base_schema.AnalysisResultBase.validate_execution_time(-1)

    assert base_schema.AnalysisResultBase.validate_analyzer_name(None) is None


def test_file_info_base_extension_normalization() -> None:
    info = base_schema.FileInfoBase(file_extension=" .EXE ")
    assert info.file_extension == "exe"
    assert base_schema.FileInfoBase.normalize_extension(None) is None


def test_hash_analysis_result_validations() -> None:
    result = hashing_schema.HashAnalysisResult(
        available=True,
        hash_type=" SSDeep ",
        hash_value="3:abc:def",
        method_used="Python_Library",
        file_size=1024,
    )
    assert result.hash_type == "ssdeep"
    assert result.method_used == "python_library"
    assert result.is_valid_hash() is True

    result.hash_value = "  "
    assert result.is_valid_hash() is False

    with pytest.raises(ValidationError):
        hashing_schema.HashAnalysisResult(available=True, hash_type="unknown")

    with pytest.raises(ValidationError):
        hashing_schema.HashAnalysisResult(available=True, hash_type="ssdeep", file_size=-1)

    with pytest.raises(ValidationError):
        hashing_schema.HashAnalysisResult(
            available=True, hash_type="ssdeep", file_size=11 * 1024 * 1024 * 1024
        )

    assert hashing_schema.HashAnalysisResult.validate_method_used(None) is None
    assert hashing_schema.HashAnalysisResult.validate_method_used("custom") == "custom"

    with pytest.raises(ValueError):
        hashing_schema.HashAnalysisResult.validate_file_size(-5)


def test_section_info_and_security_features() -> None:
    section = format_schema.SectionInfo(
        name=".text",
        entropy=6.5,
        is_executable=True,
        is_readable=True,
        suspicious_indicators=["packed"],
    )
    assert section.is_suspicious() is True
    assert section.has_permission("x") is True
    assert section.has_permission("w") is False

    with pytest.raises(ValidationError):
        format_schema.SectionInfo(name=" ")

    with pytest.raises(ValidationError):
        format_schema.SectionInfo(name=".bad", entropy=9.0)

    with pytest.raises(ValueError):
        format_schema.SectionInfo.validate_entropy(9.0)

    features = format_schema.SecurityFeatures(aslr=True, dep=True)
    enabled = features.get_enabled_features()
    assert "aslr" in enabled
    assert features.security_score() > 0


def test_format_analysis_result_helpers() -> None:
    sections = [
        format_schema.SectionInfo(name=".text", is_executable=True),
        format_schema.SectionInfo(name=".data", is_writable=True),
    ]
    result = format_schema.FormatAnalysisResult(
        available=True,
        format="pe32+",
        bits=64,
        endian="LE",
        sections=sections,
    )
    assert result.is_64bit() is True
    assert result.is_pe() is True
    assert result.is_elf() is False
    assert result.is_macho() is False
    assert result.get_executable_sections()[0].name == ".text"
    assert result.get_writable_sections()[0].name == ".data"
    assert result.get_suspicious_sections() == []

    assert format_schema.FormatAnalysisResult.validate_endian(None) is None

    with pytest.raises(ValidationError):
        format_schema.FormatAnalysisResult(available=True, format="unknown")

    with pytest.raises(ValidationError):
        format_schema.FormatAnalysisResult(available=True, format="PE", bits=16)

    with pytest.raises(ValidationError):
        format_schema.FormatAnalysisResult(available=True, format="PE", endian="sideways")


def test_security_schema_helpers() -> None:
    issue = security_schema.SecurityIssue(
        severity=security_schema.SeverityLevel.HIGH,
        description=" bad ",
    )
    assert issue.description == "bad"

    with pytest.raises(ValidationError):
        security_schema.SecurityIssue(
            severity=security_schema.SeverityLevel.LOW,
            description=" ",
        )

    with pytest.raises(ValidationError):
        security_schema.SecurityScore(score=5, max_score=3, percentage=50, grade="A")

    score = security_schema.SecurityScore(score=5, max_score=5, percentage=100, grade="A")
    assert score.max_score == 5

    mitigations = {
        "aslr": security_schema.MitigationInfo(enabled=True, description="aslr"),
        "dep": security_schema.MitigationInfo(enabled=False, description="dep"),
    }
    result = security_schema.SecurityAnalysisResult(
        available=True,
        mitigations=mitigations,
        issues=[
            security_schema.SecurityIssue(
                severity=security_schema.SeverityLevel.CRITICAL,
                description="critical",
            ),
            security_schema.SecurityIssue(
                severity=security_schema.SeverityLevel.HIGH,
                description="high",
            ),
        ],
        score=75,
    )

    assert result.get_critical_issues()
    assert result.get_high_issues()
    assert result.get_enabled_mitigations() == ["aslr"]
    assert result.get_disabled_mitigations() == ["dep"]
    assert result.has_mitigation("aslr") is True
    assert result.count_issues_by_severity()["critical"] == 1
    assert result.is_secure() is True
    assert result.is_secure(threshold=80) is False
    assert security_schema.SecurityAnalysisResult(available=True).is_secure() is False


def test_converters_and_validation_helpers() -> None:
    data = {"available": True, "hash_type": "ssdeep", "hash_value": "abc"}
    model = converters.dict_to_model(data, hashing_schema.HashAnalysisResult)
    assert isinstance(model, hashing_schema.HashAnalysisResult)

    with pytest.raises(ValidationError):
        converters.dict_to_model(
            {"available": True, "hash_type": "invalid"},
            hashing_schema.HashAnalysisResult,
            strict=True,
        )

    model = converters.dict_to_model(
        {"available": True, "hash_type": "invalid"},
        hashing_schema.HashAnalysisResult,
        strict=False,
    )
    assert isinstance(model, hashing_schema.HashAnalysisResult)

    converters.ResultConverter.register_schema("ssdeep", hashing_schema.HashAnalysisResult)
    assert converters.ResultConverter.get_schema("ssdeep") is hashing_schema.HashAnalysisResult
    assert converters.ResultConverter.list_registered_schemas()["ssdeep"] == "HashAnalysisResult"

    converted = converters.ResultConverter.convert_result("ssdeep", data)
    assert converted.analyzer_name == "ssdeep"

    converters.ResultConverter.register_schema("bad", hashing_schema.HashAnalysisResult)
    converted_many = converters.ResultConverter.convert_results(
        {
            "ssdeep": data,
            "bad": {"available": True, "hash_type": "invalid"},
        },
        strict=True,
    )
    assert isinstance(converted_many["ssdeep"], hashing_schema.HashAnalysisResult)
    assert "bad" not in converted_many

    safe = converters.safe_convert(None, hashing_schema.HashAnalysisResult, default=None)
    assert safe is None

    safe = converters.safe_convert("bad", hashing_schema.HashAnalysisResult, default=None)
    assert safe is None

    safe = converters.safe_convert(data, hashing_schema.HashAnalysisResult, default=None)
    assert isinstance(safe, hashing_schema.HashAnalysisResult)
    assert converters.safe_convert(safe, hashing_schema.HashAnalysisResult) is safe

    assert converters.validate_result(safe) is True

    invalid = hashing_schema.HashAnalysisResult.model_construct(available=True, hash_type="invalid")
    assert converters.validate_result(invalid) is False

    class BoomModel:
        def __init__(self, **_kwargs: object) -> None:
            raise TypeError("boom")

    converters.ResultConverter.register_schema("boom", BoomModel)  # type: ignore[arg-type]
    converted = converters.ResultConverter.convert_results(
        {"boom": {"available": True}}, strict=False
    )
    assert converted["boom"] == {"available": True}

    assert (
        converters.safe_convert(
            {"available": True}, BoomModel, default="fallback"  # type: ignore[arg-type]
        )
        == "fallback"
    )


def test_results_dataclasses_from_dict_and_summary() -> None:
    data = {
        "file_info": {
            "name": "sample.exe",
            "path": "/tmp/sample.exe",
            "size": 123,
            "md5": "aa",
            "sha1": "bb",
            "sha256": "cc",
            "file_type": "PE",
        },
        "hashing": {"ssdeep": "hash"},
        "security": {"nx": True, "relro": "full"},
        "imports": [{"name": "CreateFile", "library": "KERNEL32"}],
        "exports": [{"name": "Exported"}],
        "sections": [{"name": ".text", "is_executable": True, "suspicious_indicators": ["x"]}],
        "strings": ["hello"],
        "yara_matches": [{"rule": "RuleA"}],
        "functions": [{"name": "f1", "address": 1}],
        "anti_analysis": {"anti_debug": True},
        "packer": {"is_packed": True, "packer_type": "upx"},
        "crypto": {"algorithms": [{"name": "aes"}]},
        "indicators": [{"type": "Packer", "severity": "High"}],
        "error": "",
        "timestamp": datetime.utcnow().isoformat(),
        "execution_time": 1.0,
    }

    result = results_schema.from_dict(data)
    assert result.file_info.name == "sample.exe"
    assert result.hashing.has_hash("ssdeep") is True
    assert result.security.security_score() > 0
    assert result.has_error() is True
    assert result.is_suspicious() is True
    assert result.get_high_severity_indicators()

    summary = result.summary()
    assert summary["file_name"] == "sample.exe"
    assert summary["is_packed"] is True

    roundtrip = results_schema.AnalysisResult(
        file_info=results_schema.FileInfo(name="file"),
        imports=[results_schema.ImportInfo(name="imp")],
        yara_matches=[results_schema.YaraMatch(rule="rule")],
    ).to_dict()
    assert roundtrip["file_info"]["name"] == "file"
    assert roundtrip["imports"][0]["name"] == "imp"

    invalid_ts = data.copy()
    invalid_ts["timestamp"] = "bad timestamp"
    result_bad_ts = results_schema.from_dict(invalid_ts)
    assert isinstance(result_bad_ts.timestamp, datetime)

    empty_result = results_schema.from_dict({})
    assert empty_result.file_info.name == ""

    dt = datetime.utcnow()
    result_dt = results_schema.from_dict({"timestamp": dt})
    assert result_dt.timestamp == dt

    security_features = results_schema.SecurityFeatures(relro="full", nx=True)
    assert "relro_full" in security_features.get_enabled_features()
    assert security_features.security_score() > 0
    assert results_schema.SecurityFeatures(relro="partial", aslr=True).security_score() > 0

    section = results_schema.SectionInfo(name=".text", suspicious_indicators=["x"])
    assert section.is_suspicious()
    assert section.to_dict()["name"] == ".text"
    assert results_schema.ExportInfo(name="exp").to_dict()["name"] == "exp"
    assert results_schema.StringInfo(value="s").to_dict()["value"] == "s"
    assert results_schema.FunctionInfo(name="f").to_dict()["name"] == "f"
    assert results_schema.PackerResult(is_packed=True).to_dict()["is_packed"] is True
    assert results_schema.CryptoResult(algorithms=[{"name": "aes"}]).has_crypto() is True
    assert results_schema.Indicator(type="Packer").to_dict()["type"] == "Packer"


def test_metadata_schema_instantiation() -> None:
    imp = metadata_schema.ImportInfo(name="CreateFile")
    exp = metadata_schema.ExportInfo(name="Exported")
    func = metadata_schema.FunctionInfo(name="func", address=1)
    res = metadata_schema.ResourceInfo(name="res")

    assert imp.name == "CreateFile"
    assert exp.name == "Exported"
    assert func.address == 1
    assert res.name == "res"

    analysis = metadata_schema.ImportAnalysisResult(available=True, imports=[imp])
    assert analysis.imports[0].name == "CreateFile"
