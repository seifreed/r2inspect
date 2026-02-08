from __future__ import annotations

import pytest

from r2inspect.schemas.format import FormatAnalysisResult, SectionInfo


def test_section_info_validators_and_helpers():
    with pytest.raises(ValueError):
        SectionInfo(name="   ")

    with pytest.raises(ValueError):
        SectionInfo(name=".text", entropy=9.0)

    section = SectionInfo(
        name=".text",
        is_executable=True,
        is_readable=True,
        suspicious_indicators=["packed"],
    )
    assert section.is_suspicious() is True
    assert section.has_permission("x") is True
    assert section.has_permission("w") is False


def test_format_analysis_validators_and_queries():
    with pytest.raises(ValueError):
        FormatAnalysisResult(available=True, format="unknown")

    with pytest.raises(ValueError):
        FormatAnalysisResult(available=True, format="PE", bits=16)

    with pytest.raises(ValueError):
        FormatAnalysisResult(available=True, format="ELF", endian="middle")

    result = FormatAnalysisResult(
        available=True,
        format="pe32+",
        bits=64,
        endian="LE",
        sections=[
            SectionInfo(name=".text", is_executable=True),
            SectionInfo(name=".data", is_writable=True),
            SectionInfo(name=".rdata"),
        ],
    )
    assert result.format == "PE32+"
    assert result.endian == "le"
    assert result.is_pe() is True
    assert result.is_elf() is False
    assert result.is_macho() is False
    assert result.is_64bit() is True

    assert len(result.get_executable_sections()) == 1
    assert len(result.get_writable_sections()) == 1
    assert len(result.get_suspicious_sections()) == 0
