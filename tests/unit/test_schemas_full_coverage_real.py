from __future__ import annotations

import json
from datetime import datetime

import pytest
from pydantic import ValidationError

from r2inspect.schemas import results as results_module
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
    SecurityGrade,
    SecurityIssue,
    SecurityScore,
    SeverityLevel,
)


def test_base_models_and_validators() -> None:
    result = AnalysisResultBase(available=True, execution_time=1.0, analyzer_name=" PE ")
    assert result.analyzer_name == "pe"
    assert json.loads(result.to_json())["available"] is True
    assert result.model_dump_safe()["available"] is True

    with pytest.raises(ValidationError):
        AnalysisResultBase(available=True, execution_time=-1.0)

    with pytest.raises(ValueError):
        AnalysisResultBase.validate_execution_time(-1.0)

    assert AnalysisResultBase.validate_analyzer_name(None) is None

    info = FileInfoBase(file_extension=" .EXE ")
    assert info.file_extension == "exe"
    assert FileInfoBase.normalize_extension(None) is None


def test_converter_registry_and_model_to_dict() -> None:
    ResultConverter.register_schema("hash", HashAnalysisResult)
    schemas = ResultConverter.list_registered_schemas()
    assert "hash" in schemas

    data = {"available": True, "hash_type": "ssdeep", "hash_value": "abc"}
    model = ResultConverter.convert_result("hash", data)
    assert model.hash_type == "ssdeep"

    data_dict = model_to_dict(model)
    assert data_dict["hash_type"] == "ssdeep"

    with pytest.raises(ValidationError):
        dict_to_model({"available": True, "hash_type": "bad"}, HashAnalysisResult, strict=True)

    assert safe_convert(None, HashAnalysisResult) is None
    assert safe_convert(model, HashAnalysisResult) is model
    assert safe_convert({"available": True, "hash_type": "ssdeep"}, HashAnalysisResult)
    assert safe_convert("bad", HashAnalysisResult) is None
    assert safe_convert({"available": True}, HashAnalysisResult)

    class _BadModel:
        def __init__(self) -> None:
            self.ok = True

    assert safe_convert({"x": 1}, _BadModel) is None

    converted = ResultConverter.convert_results({"hash": data, "unknown": {"available": True}})
    assert "hash" in converted
    assert "unknown" in converted

    converted_strict = ResultConverter.convert_results({"hash": {"available": True}}, strict=True)
    assert "hash" not in converted_strict

    bad_model = HashAnalysisResult.model_construct(available=True)
    assert validate_result(bad_model) is False

    class _ExplodingModel:
        def __init__(self, **_kwargs: object) -> None:
            raise TypeError("boom")

    ResultConverter.register_schema("explode", _ExplodingModel)  # type: ignore[arg-type]
    exploded = ResultConverter.convert_results({"explode": {"available": True}}, strict=False)
    assert exploded["explode"] == {"available": True}
    assert validate_result(model) is True


def test_format_and_hashing_schemas() -> None:
    section = SectionInfo(
        name=".text",
        entropy=1.2,
        is_executable=True,
        suspicious_indicators=["x"],
        is_writable=False,
    )
    assert section.is_suspicious() is True
    assert section.has_permission("x") is True

    features = SecurityFeatures(aslr=True, dep=True)
    assert "aslr" in features.get_enabled_features()
    assert features.security_score() > 0

    fmt = FormatAnalysisResult(
        available=True,
        format="PE32",
        bits=64,
        endian="LE",
        sections=[section],
        security_features=features,
    )
    assert fmt.get_executable_sections()
    assert fmt.get_writable_sections() == []
    assert fmt.get_suspicious_sections()
    assert fmt.is_64bit() is True
    assert fmt.is_pe() is True
    assert fmt.is_elf() is False
    assert fmt.is_macho() is False

    hash_result = HashAnalysisResult(
        available=True,
        hash_type="ssdeep",
        hash_value="3:abc:def",
        method_used="R2PIPE",
        file_size=1024,
    )
    assert hash_result.is_valid_hash() is True
    assert HashAnalysisResult.validate_method_used(None) is None

    with pytest.raises(ValidationError):
        HashAnalysisResult(available=True, hash_type="bad")

    with pytest.raises(ValidationError):
        HashAnalysisResult(available=True, hash_type="ssdeep", file_size=-1)

    with pytest.raises(ValueError):
        SectionInfo.validate_entropy(9.0)

    assert FormatAnalysisResult.validate_endian(None) is None

    with pytest.raises(ValueError):
        HashAnalysisResult.validate_file_size(-1)

    with pytest.raises(ValueError):
        SectionInfo.validate_name(" ")

    with pytest.raises(ValueError):
        FormatAnalysisResult.validate_format("BAD")

    with pytest.raises(ValueError):
        FormatAnalysisResult.validate_bits(128)

    with pytest.raises(ValueError):
        FormatAnalysisResult.validate_endian("middle")

    assert HashAnalysisResult.validate_method_used("CustomMethod") == "custommethod"

    with pytest.raises(ValueError):
        HashAnalysisResult.validate_file_size(10 * 1024 * 1024 * 1024 + 1)


def test_security_schema_helpers() -> None:
    issue = SecurityIssue(severity=SeverityLevel.HIGH, description="test")
    mitigation = MitigationInfo(enabled=True, description="mit")
    recommendation = Recommendation(
        priority=SeverityLevel.LOW,
        mitigation="aslr",
        recommendation="enable",
        impact="low",
    )
    score = SecurityScore(score=5, max_score=10, percentage=50.0, grade=SecurityGrade.B)
    auth = AuthenticodeAnalysisResult(available=True, signed=True, signer="ACME")

    result = SecurityAnalysisResult(
        available=True,
        mitigations={"aslr": mitigation},
        issues=[issue],
        recommendations=[recommendation],
        score=75,
        security_score=score,
        vulnerabilities=[{"id": "CVE"}],
    )
    assert result.get_high_issues()
    assert result.get_critical_issues() == []
    assert result.get_enabled_mitigations() == ["aslr"]
    assert result.get_disabled_mitigations() == []
    assert result.has_mitigation("aslr") is True
    assert result.count_issues_by_severity()["high"] == 1
    assert result.is_secure() is True
    assert auth.signed is True

    with pytest.raises(ValidationError):
        SecurityScore(score=10, max_score=5, percentage=50.0, grade=SecurityGrade.C)

    with pytest.raises(ValidationError):
        SecurityIssue(severity=SeverityLevel.LOW, description=" ")

    no_score = SecurityAnalysisResult(available=True)
    assert no_score.is_secure() is False


def test_results_dataclasses_and_loaders() -> None:
    analysis = results_module.AnalysisResult()
    analysis.error = "boom"
    analysis.timestamp = datetime.utcnow()
    analysis.execution_time = 0.1
    analysis.file_info = results_module.FileInfo(name="sample", size=1)
    analysis.security = results_module.SecurityFeatures(aslr=True, relro="partial")
    analysis.hashing = results_module.HashingResult(ssdeep="x")
    analysis.sections = [results_module.SectionInfo(name=".text", suspicious_indicators=["x"])]
    analysis.imports = [results_module.ImportInfo(name="VirtualAlloc")]
    analysis.exports = [results_module.ExportInfo(name="export")]
    analysis.yara_matches = [results_module.YaraMatch(rule="r1")]
    analysis.strings = [results_module.StringInfo(value="abc")]
    analysis.functions = [results_module.FunctionInfo(name="f1")]
    analysis.anti_analysis = results_module.AntiAnalysisResult(anti_debug=True)
    analysis.packer = results_module.PackerResult(is_packed=True, packer_type="upx")
    analysis.crypto = results_module.CryptoResult(algorithms=[{"name": "AES"}])
    analysis.indicators = [results_module.Indicator(severity="High")]

    assert analysis.sections[0].is_suspicious() is True
    assert analysis.strings[0].to_dict()["value"] == "abc"

    assert analysis.has_error() is True
    assert analysis.is_suspicious() is True
    assert analysis.get_high_severity_indicators()
    assert analysis.summary()["has_evasion"] is True
    assert analysis.to_dict()["file_info"]["name"] == "sample"

    input_data = {
        "file_info": {"name": "sample", "size": 1},
        "hashing": {"ssdeep": "x"},
        "security": {"aslr": True},
        "imports": [{"name": "VirtualAlloc"}],
        "exports": [{"name": "export"}],
        "sections": [{"name": ".text", "suspicious_indicators": ["x"]}],
        "strings": [{"value": "abc"}],
        "yara_matches": [{"rule": "r1"}],
        "functions": [{"name": "f1"}],
        "anti_analysis": {"anti_debug": True},
        "packer": {"is_packed": True},
        "crypto": {"algorithms": [{"name": "AES"}]},
        "indicators": [{"severity": "critical"}],
        "error": "boom",
        "timestamp": datetime.utcnow().isoformat(),
        "execution_time": 0.2,
    }
    parsed = results_module.from_dict(input_data)
    assert parsed.file_info.name == "sample"
    assert parsed.security.aslr is True

    no_ts = results_module.AnalysisResult()
    before = no_ts.timestamp
    results_module._load_timestamp(no_ts, {"timestamp": None})
    assert no_ts.timestamp == before

    hasher = results_module.HashingResult(ssdeep="abc")
    assert hasher.has_hash("ssdeep") is True
    assert hasher.has_hash("tlsh") is False

    security = results_module.SecurityFeatures(relro="partial", aslr=True)
    enabled = security.get_enabled_features()
    assert "relro_partial" in enabled
    assert "aslr" in enabled
    security.relro = "full"
    assert security.security_score() > 0

    empty_result = results_module.AnalysisResult()
    results_module._load_file_info(empty_result, {})
    results_module._load_hashing(empty_result, {})
    results_module._load_security(empty_result, {})
    results_module._load_imports(empty_result, {})
    results_module._load_exports(empty_result, {})
    results_module._load_sections(empty_result, {})
    results_module._load_yara_matches(empty_result, {})
    results_module._load_functions(empty_result, {})
    results_module._load_anti_analysis(empty_result, {})
    results_module._load_packer(empty_result, {})
    results_module._load_crypto(empty_result, {})
    results_module._load_indicators(empty_result, {})

    invalid_ts = results_module.AnalysisResult()
    results_module._load_timestamp(invalid_ts, {"timestamp": "bad"})
    results_module._load_timestamp(invalid_ts, {"timestamp": datetime.utcnow()})
