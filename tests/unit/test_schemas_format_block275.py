from __future__ import annotations

import pytest
from pydantic import ValidationError

from r2inspect.schemas.format import FormatAnalysisResult, SectionInfo, SecurityFeatures


@pytest.mark.unit
def test_section_info_validation_and_helpers() -> None:
    section = SectionInfo(
        name=".text",
        is_executable=True,
        is_readable=True,
        suspicious_indicators=["packed"],
    )
    assert section.is_suspicious() is True
    assert section.has_permission("x") is True
    assert section.has_permission("w") is False

    with pytest.raises(ValidationError):
        SectionInfo(name=" ")

    with pytest.raises(ValidationError):
        SectionInfo(name=".data", entropy=9.0)


@pytest.mark.unit
def test_security_features_score_and_list() -> None:
    features = SecurityFeatures(aslr=True, dep=True)
    enabled = features.get_enabled_features()
    assert "aslr" in enabled
    assert features.security_score() > 0


@pytest.mark.unit
def test_format_analysis_validation_and_helpers() -> None:
    section = SectionInfo(name=".text", is_executable=True)
    result = FormatAnalysisResult(
        available=True,
        format="PE",
        bits=64,
        endian="LE",
        sections=[section],
    )
    assert result.is_pe() is True
    assert result.is_elf() is False
    assert result.is_macho() is False
    assert result.is_64bit() is True
    assert result.get_executable_sections() == [section]

    with pytest.raises(ValidationError):
        FormatAnalysisResult(available=True, format="UNKNOWN")

    with pytest.raises(ValidationError):
        FormatAnalysisResult(available=True, format="PE", bits=16)

    with pytest.raises(ValidationError):
        FormatAnalysisResult(available=True, format="PE", endian="middle")
