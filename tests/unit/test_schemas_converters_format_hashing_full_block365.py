import builtins
import json
import sys

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


def test_analysis_result_base_validation_and_dump():
    result = AnalysisResultBase(available=True, execution_time=1.25, analyzer_name="PE")
    assert result.analyzer_name == "pe"
    dumped = result.model_dump_safe()
    assert dumped["available"] is True
    assert "error" not in dumped
    json_text = result.to_json()
    parsed = json.loads(json_text)
    assert parsed["available"] is True


def test_analysis_result_base_negative_execution_time_raises():
    with pytest.raises(ValueError):
        AnalysisResultBase(available=True, execution_time=-1.0)


def test_file_info_base_extension_normalization():
    info = FileInfoBase(file_extension=".Pe ")
    assert info.file_extension == "pe"


def test_hash_analysis_validators_and_helpers():
    result = HashAnalysisResult(
        available=True,
        hash_type="SSDEEP",
        hash_value="3:abc:def",
        method_used="python_library",
        file_size=123,
    )
    assert result.hash_type == "ssdeep"
    assert result.method_used == "python_library"
    assert result.is_valid_hash() is True

    with pytest.raises(ValueError):
        HashAnalysisResult(available=True, hash_type="invalid", hash_value="x")

    with pytest.raises(ValueError):
        HashAnalysisResult(available=True, hash_type="ssdeep", file_size=20 * 1024 * 1024 * 1024)

    custom_method = HashAnalysisResult(
        available=True, hash_type="tlsh", method_used="custom_method"
    )
    assert custom_method.method_used == "custom_method"


def test_section_info_and_security_features_helpers():
    section = SectionInfo(name=".text", is_executable=True, is_readable=True)
    assert section.has_permission("x") is True
    assert section.has_permission("w") is False
    assert section.is_suspicious() is False

    section.suspicious_indicators.append("packed")
    assert section.is_suspicious() is True

    with pytest.raises(ValueError):
        SectionInfo(name=" ")

    with pytest.raises(ValueError):
        SectionInfo(name=".data", entropy=9.0)

    features = SecurityFeatures(aslr=True, dep=True)
    enabled = features.get_enabled_features()
    assert "aslr" in enabled
    assert features.security_score() > 0


def test_format_analysis_result_helpers_and_validators():
    sections = [
        SectionInfo(name=".text", is_executable=True),
        SectionInfo(name=".data", is_writable=True),
    ]
    result = FormatAnalysisResult(
        available=True,
        format="PE32+",
        bits=64,
        endian="LE",
        sections=sections,
    )
    assert result.is_64bit() is True
    assert result.is_pe() is True
    assert result.is_elf() is False
    assert result.is_macho() is False
    assert len(result.get_executable_sections()) == 1
    assert len(result.get_writable_sections()) == 1

    with pytest.raises(ValueError):
        FormatAnalysisResult(available=True, format="UNKNOWN")

    with pytest.raises(ValueError):
        FormatAnalysisResult(available=True, format="PE", bits=16)

    with pytest.raises(ValueError):
        FormatAnalysisResult(available=True, format="PE", endian="middle")


def test_converters_and_safe_convert_paths():
    data = {
        "available": True,
        "hash_type": "invalid",
        "hash_value": "3:abc:def",
    }
    model = dict_to_model(data, HashAnalysisResult, strict=False)
    assert isinstance(model, HashAnalysisResult)
    assert model.hash_type == "invalid"

    with pytest.raises(ValidationError):
        dict_to_model(data, HashAnalysisResult, strict=True)

    dumped = model_to_dict(model)
    assert dumped["hash_type"] == "invalid"

    ResultConverter.register_schema("hash", HashAnalysisResult)
    converted = ResultConverter.convert_result("hash", {"available": True, "hash_type": "ssdeep"})
    assert isinstance(converted, HashAnalysisResult)

    converted_results = ResultConverter.convert_results(
        {"hash": {"available": True, "hash_type": "invalid"}},
        strict=False,
    )
    assert "hash" in converted_results

    strict_results = ResultConverter.convert_results(
        {"hash": {"available": True, "hash_type": "invalid"}},
        strict=True,
    )
    assert "hash" not in strict_results

    assert safe_convert(None, HashAnalysisResult) is None
    assert safe_convert(model, HashAnalysisResult) is model
    assert safe_convert({"available": True, "hash_type": "ssdeep"}, HashAnalysisResult)
    assert safe_convert("not-a-dict", HashAnalysisResult) is None


def test_validate_result_success_and_failure():
    valid = HashAnalysisResult(available=True, hash_type="ssdeep")
    assert validate_result(valid) is True

    invalid = HashAnalysisResult.model_construct(available=True, hash_type="invalid")
    assert validate_result(invalid) is False
