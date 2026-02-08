from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from r2inspect.schemas import converters
from r2inspect.schemas.base import AnalysisResultBase, FileInfoBase
from r2inspect.schemas.format import FormatAnalysisResult, SectionInfo, SecurityFeatures
from r2inspect.schemas.hashing import HashAnalysisResult


def test_analysis_result_base_validators() -> None:
    result = AnalysisResultBase(available=True, execution_time=0.1, analyzer_name=" PE ")
    assert result.analyzer_name == "pe"
    assert result.model_dump_safe()["available"] is True
    assert '"available":true' in result.to_json()

    with pytest.raises(ValueError):
        AnalysisResultBase(available=True, execution_time=-1)


def test_file_info_base_normalizes_extension() -> None:
    info = FileInfoBase(file_extension=".EXE ")
    assert info.file_extension == "exe"


def test_hash_analysis_result_validation() -> None:
    result = HashAnalysisResult(
        available=True,
        hash_type="SSDEEP",
        hash_value="3:abc:def",
        method_used="CustomMethod",
        file_size=1024,
    )
    assert result.hash_type == "ssdeep"
    assert result.method_used == "custommethod"
    assert result.is_valid_hash() is True

    with pytest.raises(ValueError):
        HashAnalysisResult(available=True, hash_type="bad", hash_value="x")

    with pytest.raises(ValueError):
        HashAnalysisResult(
            available=True, hash_type="ssdeep", hash_value="x", file_size=11 * 1024**3
        )


def test_converters_strict_and_non_strict() -> None:
    data = {"available": True, "hash_type": "invalid", "hash_value": "x"}
    with pytest.raises(ValidationError):
        converters.dict_to_model(data, HashAnalysisResult, strict=True)

    model = converters.dict_to_model(data, HashAnalysisResult, strict=False)
    assert isinstance(model, HashAnalysisResult)
    assert model.hash_type == "invalid"

    converted = converters.model_to_dict(model)
    assert converted["hash_type"] == "invalid"


def test_result_converter_registry_and_conversion() -> None:
    class DummyResult(BaseModel):
        available: bool
        analyzer_name: str | None = None

    class FailingResult(BaseModel):
        def __init__(self, **kwargs):
            raise RuntimeError("boom")

    converters.ResultConverter.register_schema("dummy", DummyResult)
    converters.ResultConverter.register_schema("boom", FailingResult)
    assert converters.ResultConverter.get_schema("DUMMY") is DummyResult
    assert converters.ResultConverter.list_registered_schemas()["dummy"] == "DummyResult"

    result = converters.ResultConverter.convert_result("dummy", {"available": True})
    assert isinstance(result, DummyResult)
    assert result.analyzer_name == "dummy"

    results = converters.ResultConverter.convert_results(
        {"dummy": {"available": True}, "boom": {"available": True}},
        strict=False,
    )
    assert isinstance(results["dummy"], DummyResult)
    assert results["boom"] == {"available": True}


def test_safe_convert_and_validate_result() -> None:
    default_model = HashAnalysisResult(available=True, hash_type="ssdeep", hash_value="x")
    assert converters.safe_convert(None, HashAnalysisResult, default=default_model) is default_model
    assert converters.safe_convert(default_model, HashAnalysisResult) is default_model
    assert converters.safe_convert(123, HashAnalysisResult, default=None) is None

    invalid = HashAnalysisResult.model_construct(
        available=True, hash_type="invalid", hash_value="x"
    )
    assert converters.validate_result(default_model) is True
    assert converters.validate_result(invalid) is False


def test_format_schema_helpers_and_validation() -> None:
    section = SectionInfo(name=" .text ", is_executable=True, is_writable=False, is_readable=True)
    assert section.name == ".text"
    assert section.is_suspicious() is False
    assert section.has_permission("r") is True
    assert section.has_permission("w") is False
    assert section.has_permission("x") is True
    assert section.has_permission("z") is False

    with pytest.raises(ValueError):
        SectionInfo(name=" ")
    with pytest.raises(ValueError):
        SectionInfo(name="name", entropy=9.0)

    features = SecurityFeatures(aslr=True, dep=True, nx=False)
    enabled = features.get_enabled_features()
    assert "aslr" in enabled
    assert features.security_score() >= 0

    fmt = FormatAnalysisResult(
        available=True,
        format="PE32+",
        bits=64,
        endian="LE",
        sections=[section],
        security_features=features,
    )
    assert fmt.is_pe() is True
    assert fmt.is_64bit() is True
    assert fmt.is_elf() is False
    assert fmt.is_macho() is False
    assert fmt.get_executable_sections() == [section]
    assert fmt.get_writable_sections() == []
    assert fmt.get_suspicious_sections() == []

    with pytest.raises(ValueError):
        FormatAnalysisResult(available=True, format="UNKNOWN")
    with pytest.raises(ValueError):
        FormatAnalysisResult(available=True, format="PE", bits=16)
    with pytest.raises(ValueError):
        FormatAnalysisResult(available=True, format="PE", endian="middle")
