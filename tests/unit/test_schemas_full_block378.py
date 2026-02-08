from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from r2inspect.schemas import (
    AnalysisResultBase,
    FileInfoBase,
    FormatAnalysisResult,
    HashAnalysisResult,
    ResultConverter,
)
from r2inspect.schemas import SectionInfo as SectionInfoModel
from r2inspect.schemas import SecurityAnalysisResult
from r2inspect.schemas import SecurityFeatures as SecurityFeaturesModel
from r2inspect.schemas import (
    SecurityIssue,
    SecurityScore,
    SeverityLevel,
    dict_to_model,
    model_to_dict,
    safe_convert,
    validate_result,
)
from r2inspect.schemas.results import (
    AnalysisResult,
    AntiAnalysisResult,
    CryptoResult,
    FileInfo,
    HashingResult,
    Indicator,
    PackerResult,
    SectionInfo,
    SecurityFeatures,
    YaraMatch,
    _load_timestamp,
    from_dict,
)


def test_base_schema_validators() -> None:
    result = AnalysisResultBase(available=True, execution_time=1.2, analyzer_name=" Pe ")
    assert result.analyzer_name == "pe"
    assert result.model_dump_safe()["available"] is True
    assert "available" in result.to_json()

    with pytest.raises(ValueError):
        AnalysisResultBase(available=True, execution_time=-1)
    with pytest.raises(ValueError):
        AnalysisResultBase.validate_execution_time(-0.1)

    assert AnalysisResultBase(available=True, analyzer_name=None).analyzer_name is None

    info = FileInfoBase(file_extension="....TXT ")
    assert info.file_extension == "txt"
    assert FileInfoBase().file_extension is None
    assert FileInfoBase.normalize_extension(None) is None


def test_hash_schema_validators() -> None:
    result = HashAnalysisResult(
        available=True,
        hash_value="3:abc:def",
        hash_type="SSDEEP",
        method_used="Python_Library",
        file_size=10,
    )
    assert result.hash_type == "ssdeep"
    assert result.method_used == "python_library"
    assert result.is_valid_hash() is True

    with pytest.raises(ValueError):
        HashAnalysisResult(available=True, hash_type="bad")

    with pytest.raises(ValueError):
        HashAnalysisResult(available=True, hash_type="ssdeep", file_size=11 * 1024 * 1024 * 1024)

    with pytest.raises(ValueError):
        HashAnalysisResult(available=True, hash_type="ssdeep", file_size=-1)
    assert HashAnalysisResult.validate_method_used(None) is None
    with pytest.raises(ValueError):
        HashAnalysisResult.validate_file_size(-1)

    custom = HashAnalysisResult(
        available=True, hash_type="tlsh", method_used="custom_method", hash_value="x"
    )
    assert custom.method_used == "custom_method"
    assert HashAnalysisResult(available=True, hash_type="ssdeep").method_used is None


def test_format_schema_helpers() -> None:
    section = SectionInfoModel(
        name=".text",
        is_executable=True,
        is_writable=False,
        is_readable=True,
        suspicious_indicators=["packed"],
    )
    assert section.is_suspicious() is True
    assert section.has_permission("x") is True
    assert section.has_permission("w") is False
    assert section.has_permission("z") is False

    with pytest.raises(ValueError):
        SectionInfoModel(name=" ")

    with pytest.raises(ValueError):
        SectionInfoModel(name="ok", entropy=9.0)

    with pytest.raises(ValueError):
        SectionInfoModel(name="ok", entropy=-1.0)
    with pytest.raises(ValueError):
        SectionInfoModel.validate_entropy(9.0)
    assert SectionInfoModel.validate_entropy(1.0) == 1.0

    features = SecurityFeaturesModel(aslr=True, dep=True)
    assert features.get_enabled_features() == ["aslr", "dep"]
    assert features.security_score() > 0

    fmt = FormatAnalysisResult(available=True, format="pe32", sections=[section], bits=64)
    assert fmt.is_pe() is True
    assert fmt.is_64bit() is True
    assert fmt.get_executable_sections() == [section]
    assert fmt.get_suspicious_sections() == [section]
    assert fmt.get_writable_sections() == []

    with pytest.raises(ValueError):
        FormatAnalysisResult(available=True, format="unknown")

    with pytest.raises(ValueError):
        FormatAnalysisResult(available=True, format="ELF", bits=16)

    with pytest.raises(ValueError):
        FormatAnalysisResult(available=True, format="ELF", endian="middle")

    macho = FormatAnalysisResult(available=True, format="macho", endian="le")
    assert macho.is_macho() is True
    assert FormatAnalysisResult(available=True, format="elf").is_elf() is True
    assert FormatAnalysisResult(available=True, format="elf", endian=None).endian is None


def test_security_schema_helpers() -> None:
    with pytest.raises(ValueError):
        SecurityIssue(severity=SeverityLevel.LOW, description=" ")

    with pytest.raises(ValueError):
        SecurityScore(score=10, max_score=5, percentage=50, grade="A")

    ok_score = SecurityScore(score=5, max_score=10, percentage=50, grade="A")
    assert ok_score.max_score == 10

    critical_issue = SecurityIssue(severity=SeverityLevel.CRITICAL, description="x")
    high_issue = SecurityIssue(severity=SeverityLevel.HIGH, description="y")
    result = SecurityAnalysisResult(
        available=True,
        issues=[critical_issue, high_issue],
        mitigations={
            "aslr": {"enabled": True, "description": "ASLR"},
            "dep": {"enabled": False, "description": "DEP"},
        },
        score=75,
    )
    assert result.get_critical_issues() == [critical_issue]
    assert result.get_high_issues() == [high_issue]
    assert result.get_enabled_mitigations() == ["aslr"]
    assert result.get_disabled_mitigations() == ["dep"]
    assert result.has_mitigation("aslr") is True
    counts = result.count_issues_by_severity()
    assert counts["critical"] == 1
    assert result.is_secure() is True
    assert SecurityAnalysisResult(available=True).is_secure() is False


def test_converters_and_registry() -> None:
    data = {"available": True, "hash_type": "ssdeep", "hash_value": "abc"}
    model = dict_to_model(data, HashAnalysisResult)
    assert isinstance(model, HashAnalysisResult)
    assert model_to_dict(model)["hash_type"] == "ssdeep"

    bad_data = {"available": True, "hash_type": "bad"}
    relaxed = dict_to_model(bad_data, HashAnalysisResult, strict=False)
    assert relaxed.hash_type == "bad"
    with pytest.raises(ValidationError):
        dict_to_model(bad_data, HashAnalysisResult, strict=True)

    ResultConverter.register_schema("custom", HashAnalysisResult)
    converted = ResultConverter.convert_result("custom", data)
    assert converted.analyzer_name == "custom"

    class _Broken:
        def __init__(self, **_kwargs: object) -> None:
            raise TypeError("nope")

    ResultConverter.register_schema("broken", _Broken)  # type: ignore[arg-type]
    converted_results = ResultConverter.convert_results(
        {"broken": {"available": True}}, strict=False
    )
    assert converted_results["broken"] == {"available": True}

    assert safe_convert(None, HashAnalysisResult) is None
    assert safe_convert(model, HashAnalysisResult) is model
    assert safe_convert({"available": True}, HashAnalysisResult) is not None
    assert safe_convert("bad", HashAnalysisResult) is None

    valid = HashAnalysisResult(available=True, hash_type="ssdeep", hash_value="x")
    assert validate_result(valid) is True
    invalid = HashAnalysisResult.model_construct(available=True, hash_type="bad")
    assert validate_result(invalid) is False

    assert "ssdeep" in ResultConverter.list_registered_schemas()

    class _BadModel:
        def __init__(self, **_kwargs: object) -> None:
            raise RuntimeError("boom")

    assert safe_convert({"available": True}, _BadModel) is None


def test_results_dataclasses_and_from_dict() -> None:
    hashing = HashingResult(ssdeep="a", tlsh="b")
    assert hashing.has_hash("ssdeep") is True
    assert hashing.has_hash("missing") is False
    assert hashing.to_dict()["ssdeep"] == "a"

    security = SecurityFeatures(nx=True, relro="partial")
    enabled = security.get_enabled_features()
    assert "nx" in enabled
    assert "relro_partial" in enabled
    assert security.security_score() > 0
    assert security.to_dict()["nx"] is True
    assert SecurityFeatures(relro="full").security_score() > 0

    section = SectionInfo(name=".text", suspicious_indicators=["x"])
    assert section.is_suspicious() is True
    assert section.to_dict()["name"] == ".text"

    anti = AntiAnalysisResult(anti_debug=True)
    assert anti.has_evasion() is True
    assert anti.to_dict()["anti_debug"] is True

    packer = PackerResult(is_packed=True, packer_type="upx")
    crypto = CryptoResult(algorithms=[{"name": "aes"}])
    indicator = Indicator(type="Packer", description="x", severity="High")
    yara = YaraMatch(rule="rule", namespace="ns")
    file_info = FileInfo(name="f", md5="m", file_type="pe")
    assert file_info.to_dict()["md5"] == "m"
    assert yara.to_dict()["rule"] == "rule"
    assert indicator.to_dict()["severity"] == "High"

    from r2inspect.schemas.results import ExportInfo, FunctionInfo, ImportInfo, StringInfo

    import_info = ImportInfo(name="imp", library="lib")
    export_info = ExportInfo(name="exp", address="0x1")
    string_info = StringInfo(value="s", length=1)
    func_info = FunctionInfo(name="f", address=1)
    assert import_info.to_dict()["name"] == "imp"
    assert export_info.to_dict()["name"] == "exp"
    assert string_info.to_dict()["value"] == "s"
    assert func_info.to_dict()["address"] == 1

    result = AnalysisResult(
        file_info=file_info,
        hashing=hashing,
        security=security,
        anti_analysis=anti,
        packer=packer,
        crypto=crypto,
        indicators=[indicator],
        yara_matches=[yara],
        imports=[import_info],
        exports=[export_info],
        strings=[string_info.value],
        functions=[func_info],
        sections=[section],
    )
    summary = result.summary()
    assert summary["file_name"] == "f"
    assert result.is_suspicious() is True
    assert result.get_high_severity_indicators() == [indicator]
    assert result.to_dict()["file_info"]["name"] == "f"

    data = {
        "file_info": {"name": "file", "size": 1, "md5": "m"},
        "hashing": {"ssdeep": "x"},
        "security": {"nx": True},
        "imports": [{"name": "imp"}],
        "exports": [{"name": "exp"}],
        "sections": [{"name": ".text"}],
        "strings": ["s1"],
        "yara_matches": [{"rule": "r"}],
        "functions": [{"name": "f", "address": 1}],
        "anti_analysis": {"anti_vm": True},
        "packer": {"is_packed": True, "packer_type": "x"},
        "crypto": {"algorithms": [{"name": "aes"}]},
        "indicators": [{"type": "Packer", "description": "d", "severity": "Low"}],
        "error": "err",
        "timestamp": datetime.utcnow().isoformat(),
        "execution_time": 1.0,
    }
    loaded = from_dict(data)
    assert loaded.file_info.name == "file"
    assert loaded.hashing.ssdeep == "x"
    assert loaded.security.nx is True
    assert loaded.imports[0].name == "imp"
    assert loaded.exports[0].name == "exp"
    assert loaded.sections[0].name == ".text"
    assert loaded.strings == ["s1"]
    assert loaded.yara_matches[0].rule == "r"
    assert loaded.functions[0].name == "f"
    assert loaded.anti_analysis.anti_vm is True
    assert loaded.packer.is_packed is True
    assert loaded.crypto.has_crypto() is True
    assert loaded.indicators[0].type == "Packer"
    assert loaded.error == "err"
    assert loaded.execution_time == 1.0

    invalid_ts = AnalysisResult()
    _load_timestamp(invalid_ts, {"timestamp": "not-a-timestamp"})
    assert isinstance(invalid_ts.timestamp, datetime)

    ts_holder = AnalysisResult()
    now = datetime.utcnow()
    _load_timestamp(ts_holder, {"timestamp": now})
    assert ts_holder.timestamp == now

    empty = from_dict({})
    assert empty.has_error() is False
    assert empty.is_suspicious() is False
