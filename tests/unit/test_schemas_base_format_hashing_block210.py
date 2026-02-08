from __future__ import annotations

from datetime import datetime

import pytest

from r2inspect.schemas.base import AnalysisResultBase, FileInfoBase
from r2inspect.schemas.format import FormatAnalysisResult, SectionInfo, SecurityFeatures
from r2inspect.schemas.hashing import HashAnalysisResult


def test_analysis_result_base_validators_and_dump() -> None:
    result = AnalysisResultBase(
        available=True,
        execution_time=1.5,
        analyzer_name="  PE  ",
    )
    assert result.analyzer_name == "pe"
    assert result.execution_time == 1.5
    assert isinstance(result.timestamp, datetime)
    dumped = result.model_dump_safe()
    assert dumped["available"] is True
    assert "error" not in dumped
    json_out = result.to_json()
    assert '"available"' in json_out


def test_analysis_result_base_negative_execution_time() -> None:
    with pytest.raises(ValueError):
        AnalysisResultBase(available=True, execution_time=-0.1)


def test_file_info_base_extension_normalization() -> None:
    info = FileInfoBase(file_extension=".EXE ")
    assert info.file_extension == "exe"
    assert FileInfoBase(file_extension=None).file_extension is None


def test_section_info_validation_and_helpers() -> None:
    section = SectionInfo(
        name=" .text ",
        entropy=6.0,
        is_executable=True,
        is_readable=True,
    )
    assert section.name == ".text"
    assert section.has_permission("x") is True
    assert section.has_permission("r") is True
    assert section.has_permission("w") is False
    assert section.is_suspicious() is False
    section.suspicious_indicators.append("packed")
    assert section.is_suspicious() is True

    with pytest.raises(ValueError):
        SectionInfo(name="  ", entropy=1.0)
    with pytest.raises(ValueError):
        SectionInfo(name="ok", entropy=9.1)


def test_security_features_helpers() -> None:
    features = SecurityFeatures(aslr=True, dep=True, nx=True, relro=False)
    enabled = features.get_enabled_features()
    assert "aslr" in enabled
    assert "dep" in enabled
    assert "nx" in enabled
    score = features.security_score()
    assert 0 < score <= 100


def test_format_analysis_result_helpers() -> None:
    sections = [
        SectionInfo(name=".text", is_executable=True),
        SectionInfo(name=".data", is_writable=True),
        SectionInfo(name=".rsrc", suspicious_indicators=["x"]),
    ]
    result = FormatAnalysisResult(
        available=True,
        format="pe32+",
        bits=64,
        endian="le",
        sections=sections,
    )
    assert result.format == "PE32+"
    assert result.is_64bit() is True
    assert result.is_pe() is True
    assert result.is_elf() is False
    assert result.is_macho() is False
    assert len(result.get_executable_sections()) == 1
    assert len(result.get_writable_sections()) == 1
    assert len(result.get_suspicious_sections()) == 1

    with pytest.raises(ValueError):
        FormatAnalysisResult(available=True, format="unknown")
    with pytest.raises(ValueError):
        FormatAnalysisResult(available=True, format="PE", bits=16)
    with pytest.raises(ValueError):
        FormatAnalysisResult(available=True, format="PE", endian="middle")


def test_hash_analysis_result_validations() -> None:
    result = HashAnalysisResult(
        available=True,
        hash_value="3:abc:def",
        hash_type="SSDEEP",
        method_used="PYTHON_LIBRARY",
        file_size=1024,
    )
    assert result.hash_type == "ssdeep"
    assert result.method_used == "python_library"
    assert result.is_valid_hash() is True
    assert HashAnalysisResult(available=True, hash_type="tlsh").is_valid_hash() is False

    with pytest.raises(ValueError):
        HashAnalysisResult(available=True, hash_type="nope")
    with pytest.raises(ValueError):
        HashAnalysisResult(available=True, hash_type="ssdeep", file_size=11 * 1024 * 1024 * 1024)
