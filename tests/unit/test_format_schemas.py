"""Comprehensive tests for r2inspect/schemas/format.py"""

import pytest
from pydantic import ValidationError

from r2inspect.schemas.format import (
    FormatAnalysisResult,
    SectionInfo,
    SecurityFeatures,
)


def test_section_info_creation():
    section = SectionInfo(
        name=".text",
        virtual_address=0x1000,
        virtual_size=0x2000,
        raw_size=0x1800,
        entropy=6.5,
        permissions="r-x",
        is_executable=True,
        is_readable=True,
        is_writable=False,
    )
    assert section.name == ".text"
    assert section.entropy == 6.5


def test_section_info_name_required():
    with pytest.raises(ValidationError):
        SectionInfo(name="")


def test_section_info_name_whitespace():
    with pytest.raises(ValidationError):
        SectionInfo(name="   ")


def test_section_info_name_strip():
    section = SectionInfo(name="  .text  ")
    assert section.name == ".text"


def test_section_info_defaults():
    section = SectionInfo(name=".text")
    assert section.virtual_address == 0
    assert section.virtual_size == 0
    assert section.is_executable is False
    assert section.suspicious_indicators == []


def test_section_info_entropy_valid():
    section = SectionInfo(name=".text", entropy=7.5)
    assert section.entropy == 7.5


def test_section_info_entropy_min():
    section = SectionInfo(name=".text", entropy=0.0)
    assert section.entropy == 0.0


def test_section_info_entropy_max():
    section = SectionInfo(name=".text", entropy=8.0)
    assert section.entropy == 8.0


def test_section_info_entropy_negative():
    with pytest.raises(ValidationError):
        SectionInfo(name=".text", entropy=-1.0)


def test_section_info_entropy_too_high():
    with pytest.raises(ValidationError):
        SectionInfo(name=".text", entropy=8.1)


def test_section_info_entropy_none():
    section = SectionInfo(name=".text", entropy=None)
    assert section.entropy is None


def test_section_info_is_suspicious():
    section = SectionInfo(
        name=".text", suspicious_indicators=["high_entropy"]
    )
    assert section.is_suspicious() is True


def test_section_info_not_suspicious():
    section = SectionInfo(name=".text")
    assert section.is_suspicious() is False


def test_section_info_has_permission_read():
    section = SectionInfo(name=".text", is_readable=True)
    assert section.has_permission("r") is True


def test_section_info_has_permission_write():
    section = SectionInfo(name=".data", is_writable=True)
    assert section.has_permission("w") is True


def test_section_info_has_permission_execute():
    section = SectionInfo(name=".text", is_executable=True)
    assert section.has_permission("x") is True


def test_section_info_has_permission_case_insensitive():
    section = SectionInfo(name=".text", is_executable=True)
    assert section.has_permission("X") is True


def test_section_info_has_permission_not_found():
    section = SectionInfo(name=".text")
    assert section.has_permission("r") is False


def test_section_info_has_permission_unknown():
    section = SectionInfo(name=".text")
    assert section.has_permission("z") is False


def test_section_info_to_dict():
    section = SectionInfo(name=".text", virtual_address=0x1000)
    result = section.to_dict()
    assert isinstance(result, dict)
    assert result["name"] == ".text"


def test_security_features_defaults():
    features = SecurityFeatures()
    assert features.aslr is False
    assert features.nx is False
    assert features.pie is False


def test_security_features_creation():
    features = SecurityFeatures(
        aslr=True,
        dep=True,
        nx=True,
        stack_canary=True,
        pie=True,
        relro="full",
    )
    assert features.aslr is True
    assert features.nx is True
    assert features.relro == "full"


def test_security_features_get_enabled_features():
    features = SecurityFeatures(aslr=True, nx=True, pie=True)
    enabled = features.get_enabled_features()
    assert "aslr" in enabled
    assert "nx" in enabled
    assert "pie" in enabled


def test_security_features_get_enabled_features_none():
    features = SecurityFeatures()
    enabled = features.get_enabled_features()
    assert len(enabled) == 0


def test_security_features_get_enabled_features_relro_full():
    features = SecurityFeatures(relro="full")
    enabled = features.get_enabled_features()
    assert "relro_full" in enabled


def test_security_features_get_enabled_features_relro_partial():
    features = SecurityFeatures(relro="partial")
    enabled = features.get_enabled_features()
    assert "relro_partial" in enabled


def test_security_features_get_enabled_features_relro_bool():
    features = SecurityFeatures(relro=True)
    enabled = features.get_enabled_features()
    assert "relro" in enabled


def test_security_features_security_score():
    features = SecurityFeatures(
        nx=True, pie=True, canary=True, aslr=True
    )
    score = features.security_score()
    assert score == 60


def test_security_features_security_score_max():
    features = SecurityFeatures(
        nx=True,
        pie=True,
        canary=True,
        aslr=True,
        guard_cf=True,
        seh=True,
        authenticode=True,
        fortify=True,
        high_entropy_va=True,
        relro="full",
    )
    score = features.security_score()
    assert score <= 100


def test_security_features_security_score_zero():
    features = SecurityFeatures()
    score = features.security_score()
    assert score == 0


def test_security_features_security_score_relro_full():
    features = SecurityFeatures(relro="full")
    score = features.security_score()
    assert score == 5


def test_security_features_security_score_relro_partial():
    features = SecurityFeatures(relro="partial")
    score = features.security_score()
    assert score == 2


def test_security_features_to_dict():
    features = SecurityFeatures(aslr=True, nx=True)
    result = features.to_dict()
    assert isinstance(result, dict)
    assert result["aslr"] is True


def test_format_analysis_result_creation():
    result = FormatAnalysisResult(
        available=True, format="PE", architecture="x64", bits=64
    )
    assert result.format == "PE"
    assert result.bits == 64


def test_format_analysis_result_pe():
    result = FormatAnalysisResult(available=True, format="PE")
    assert result.format == "PE"


def test_format_analysis_result_elf():
    result = FormatAnalysisResult(available=True, format="ELF")
    assert result.format == "ELF"


def test_format_analysis_result_macho():
    result = FormatAnalysisResult(available=True, format="Mach-O")
    assert result.format == "MACH-O"


def test_format_analysis_result_pe32():
    result = FormatAnalysisResult(available=True, format="PE32")
    assert result.format == "PE32"


def test_format_analysis_result_pe32_plus():
    result = FormatAnalysisResult(available=True, format="PE32+")
    assert result.format == "PE32+"


def test_format_analysis_result_invalid_format():
    with pytest.raises(ValidationError):
        FormatAnalysisResult(available=True, format="INVALID")


def test_format_analysis_result_format_case_insensitive():
    result = FormatAnalysisResult(available=True, format="pe")
    assert result.format == "PE"


def test_format_analysis_result_bits_32():
    result = FormatAnalysisResult(available=True, format="PE", bits=32)
    assert result.bits == 32


def test_format_analysis_result_bits_64():
    result = FormatAnalysisResult(available=True, format="PE", bits=64)
    assert result.bits == 64


def test_format_analysis_result_bits_invalid():
    with pytest.raises(ValidationError):
        FormatAnalysisResult(available=True, format="PE", bits=16)


def test_format_analysis_result_endian_little():
    result = FormatAnalysisResult(
        available=True, format="PE", endian="little"
    )
    assert result.endian == "little"


def test_format_analysis_result_endian_big():
    result = FormatAnalysisResult(available=True, format="ELF", endian="big")
    assert result.endian == "big"


def test_format_analysis_result_endian_le():
    result = FormatAnalysisResult(available=True, format="PE", endian="le")
    assert result.endian == "le"


def test_format_analysis_result_endian_be():
    result = FormatAnalysisResult(available=True, format="ELF", endian="be")
    assert result.endian == "be"


def test_format_analysis_result_endian_invalid():
    with pytest.raises(ValidationError):
        FormatAnalysisResult(available=True, format="PE", endian="invalid")


def test_format_analysis_result_with_sections():
    section1 = SectionInfo(name=".text", is_executable=True)
    section2 = SectionInfo(name=".data", is_writable=True)
    result = FormatAnalysisResult(
        available=True, format="PE", sections=[section1, section2]
    )
    assert len(result.sections) == 2


def test_format_analysis_result_with_security_features():
    security = SecurityFeatures(aslr=True, nx=True)
    result = FormatAnalysisResult(
        available=True, format="PE", security_features=security
    )
    assert result.security_features.aslr is True


def test_format_analysis_result_get_executable_sections():
    section1 = SectionInfo(name=".text", is_executable=True)
    section2 = SectionInfo(name=".data", is_writable=True)
    result = FormatAnalysisResult(
        available=True, format="PE", sections=[section1, section2]
    )
    executable = result.get_executable_sections()
    assert len(executable) == 1
    assert executable[0].name == ".text"


def test_format_analysis_result_get_writable_sections():
    section1 = SectionInfo(name=".text", is_executable=True)
    section2 = SectionInfo(name=".data", is_writable=True)
    result = FormatAnalysisResult(
        available=True, format="PE", sections=[section1, section2]
    )
    writable = result.get_writable_sections()
    assert len(writable) == 1
    assert writable[0].name == ".data"


def test_format_analysis_result_get_suspicious_sections():
    section1 = SectionInfo(name=".text")
    section2 = SectionInfo(
        name=".packed", suspicious_indicators=["high_entropy"]
    )
    result = FormatAnalysisResult(
        available=True, format="PE", sections=[section1, section2]
    )
    suspicious = result.get_suspicious_sections()
    assert len(suspicious) == 1
    assert suspicious[0].name == ".packed"


def test_format_analysis_result_is_64bit():
    result = FormatAnalysisResult(available=True, format="PE", bits=64)
    assert result.is_64bit() is True


def test_format_analysis_result_is_not_64bit():
    result = FormatAnalysisResult(available=True, format="PE", bits=32)
    assert result.is_64bit() is False


def test_format_analysis_result_is_pe():
    result = FormatAnalysisResult(available=True, format="PE")
    assert result.is_pe() is True


def test_format_analysis_result_is_pe_pe32():
    result = FormatAnalysisResult(available=True, format="PE32")
    assert result.is_pe() is True


def test_format_analysis_result_is_not_pe():
    result = FormatAnalysisResult(available=True, format="ELF")
    assert result.is_pe() is False


def test_format_analysis_result_is_elf():
    result = FormatAnalysisResult(available=True, format="ELF")
    assert result.is_elf() is True


def test_format_analysis_result_is_elf_elf64():
    result = FormatAnalysisResult(available=True, format="ELF64")
    assert result.is_elf() is True


def test_format_analysis_result_is_not_elf():
    result = FormatAnalysisResult(available=True, format="PE")
    assert result.is_elf() is False


def test_format_analysis_result_is_macho():
    result = FormatAnalysisResult(available=True, format="MACH-O")
    assert result.is_macho() is True


def test_format_analysis_result_is_macho_variant():
    result = FormatAnalysisResult(available=True, format="MACH-O64")
    assert result.is_macho() is True


def test_format_analysis_result_is_not_macho():
    result = FormatAnalysisResult(available=True, format="PE")
    assert result.is_macho() is False


def test_format_analysis_result_all_fields():
    security = SecurityFeatures(aslr=True, nx=True)
    section = SectionInfo(name=".text", is_executable=True)
    result = FormatAnalysisResult(
        available=True,
        format="PE",
        architecture="x64",
        bits=64,
        endian="little",
        machine="AMD64",
        type="exe",
        entry_point=0x1000,
        image_base=0x400000,
        sections=[section],
        security_features=security,
        compile_time="2024-01-01",
        compiler="MSVC",
        subsystem="Windows GUI",
        is_dll=False,
        is_executable=True,
    )
    assert result.format == "PE"
    assert result.architecture == "x64"
    assert result.entry_point == 0x1000


def test_format_analysis_result_serialization():
    result = FormatAnalysisResult(available=True, format="PE", bits=64)
    data = result.model_dump()
    assert data["format"] == "PE"
    assert data["bits"] == 64


def test_section_info_negative_sizes():
    with pytest.raises(ValidationError):
        SectionInfo(name=".text", virtual_address=-1)


def test_section_info_permissions_all():
    section = SectionInfo(
        name=".text", is_readable=True, is_writable=True, is_executable=True
    )
    assert section.has_permission("r") is True
    assert section.has_permission("w") is True
    assert section.has_permission("x") is True


def test_section_info_entropy_validation_edge_cases():
    section = SectionInfo(name=".text", entropy=None)
    assert section.entropy is None


def test_format_analysis_result_endian_none():
    result = FormatAnalysisResult(available=True, format="PE", endian=None)
    assert result.endian is None
