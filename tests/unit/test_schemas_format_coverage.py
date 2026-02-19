"""Coverage tests for r2inspect/schemas/format.py"""

import pytest
from pydantic import ValidationError

from r2inspect.schemas.format import FormatAnalysisResult, SectionInfo, SecurityFeatures


# SectionInfo tests

def test_section_info_valid_name():
    section = SectionInfo(name=".text")
    assert section.name == ".text"


def test_section_info_name_stripped():
    section = SectionInfo(name="  .data  ")
    assert section.name == ".data"


def test_section_info_empty_name_raises():
    with pytest.raises(ValidationError):
        SectionInfo(name="")


def test_section_info_whitespace_name_raises():
    with pytest.raises(ValidationError):
        SectionInfo(name="   ")


def test_section_info_entropy_none():
    section = SectionInfo(name=".text", entropy=None)
    assert section.entropy is None


def test_section_info_entropy_valid():
    section = SectionInfo(name=".text", entropy=7.5)
    assert section.entropy == 7.5


def test_section_info_entropy_zero():
    section = SectionInfo(name=".text", entropy=0.0)
    assert section.entropy == 0.0


def test_section_info_entropy_max():
    section = SectionInfo(name=".text", entropy=8.0)
    assert section.entropy == 8.0


def test_section_info_entropy_invalid_negative():
    with pytest.raises(ValidationError):
        SectionInfo(name=".text", entropy=-0.1)


def test_section_info_entropy_invalid_above_max():
    with pytest.raises(ValidationError):
        SectionInfo(name=".text", entropy=8.1)


def test_section_info_is_suspicious_false():
    section = SectionInfo(name=".text", suspicious_indicators=[])
    assert section.is_suspicious() is False


def test_section_info_is_suspicious_true():
    section = SectionInfo(name=".text", suspicious_indicators=["high_entropy"])
    assert section.is_suspicious() is True


def test_section_info_has_permission_readable():
    section = SectionInfo(name=".text", is_readable=True)
    assert section.has_permission("r") is True


def test_section_info_has_permission_writable():
    section = SectionInfo(name=".data", is_writable=True)
    assert section.has_permission("w") is True


def test_section_info_has_permission_executable():
    section = SectionInfo(name=".text", is_executable=True)
    assert section.has_permission("x") is True


def test_section_info_has_permission_false():
    section = SectionInfo(name=".text", is_readable=False, is_writable=False, is_executable=False)
    assert section.has_permission("r") is False
    assert section.has_permission("w") is False
    assert section.has_permission("x") is False


def test_section_info_has_permission_unknown_returns_false():
    section = SectionInfo(name=".text")
    assert section.has_permission("z") is False


def test_section_info_has_permission_case_insensitive():
    section = SectionInfo(name=".text", is_readable=True)
    assert section.has_permission("R") is True


def test_section_info_to_dict():
    section = SectionInfo(name=".text", virtual_address=0x1000, entropy=6.5)
    d = section.to_dict()
    assert isinstance(d, dict)
    assert d["name"] == ".text"
    assert d["virtual_address"] == 0x1000
    assert d["entropy"] == 6.5


# SecurityFeatures tests

def test_security_features_defaults():
    features = SecurityFeatures()
    assert features.aslr is False
    assert features.nx is False
    assert features.pie is False


def test_security_features_get_enabled_empty():
    features = SecurityFeatures()
    enabled = features.get_enabled_features()
    assert enabled == []


def test_security_features_get_enabled_bool_features():
    features = SecurityFeatures(aslr=True, nx=True, pie=True)
    enabled = features.get_enabled_features()
    assert "aslr" in enabled
    assert "nx" in enabled
    assert "pie" in enabled


def test_security_features_get_enabled_relro_partial():
    features = SecurityFeatures(relro="partial")
    enabled = features.get_enabled_features()
    assert "relro_partial" in enabled


def test_security_features_get_enabled_relro_full():
    features = SecurityFeatures(relro="full")
    enabled = features.get_enabled_features()
    assert "relro_full" in enabled


def test_security_features_get_enabled_relro_true():
    features = SecurityFeatures(relro=True)
    enabled = features.get_enabled_features()
    assert "relro" in enabled


def test_security_features_get_enabled_relro_false():
    features = SecurityFeatures(relro=False)
    enabled = features.get_enabled_features()
    assert "relro" not in enabled
    assert "relro_full" not in enabled
    assert "relro_partial" not in enabled


def test_security_features_security_score_zero():
    features = SecurityFeatures()
    assert features.security_score() == 0


def test_security_features_security_score_with_features():
    features = SecurityFeatures(nx=True, pie=True, canary=True, aslr=True)
    score = features.security_score()
    assert score >= 60  # 15+15+15+15


def test_security_features_security_score_relro_full():
    features = SecurityFeatures(relro="full")
    score = features.security_score()
    assert score == 5


def test_security_features_security_score_relro_partial():
    features = SecurityFeatures(relro="partial")
    score = features.security_score()
    assert score == 2


def test_security_features_security_score_relro_true():
    features = SecurityFeatures(relro=True)
    score = features.security_score()
    assert score == 2


def test_security_features_security_score_capped_at_100():
    features = SecurityFeatures(
        nx=True, pie=True, canary=True, aslr=True,
        guard_cf=True, seh=True, authenticode=True,
        fortify=True, high_entropy_va=True, relro="full"
    )
    score = features.security_score()
    assert score <= 100


def test_security_features_to_dict():
    features = SecurityFeatures(aslr=True, nx=True)
    d = features.to_dict()
    assert isinstance(d, dict)
    assert d["aslr"] is True
    assert d["nx"] is True


# FormatAnalysisResult tests

def test_format_analysis_result_valid_pe():
    result = FormatAnalysisResult(available=True, format="PE32")
    assert result.format == "PE32"
    assert result.is_pe() is True
    assert result.is_elf() is False
    assert result.is_macho() is False


def test_format_analysis_result_valid_elf():
    result = FormatAnalysisResult(available=True, format="ELF64")
    assert result.format == "ELF64"
    assert result.is_elf() is True
    assert result.is_pe() is False


def test_format_analysis_result_valid_macho():
    result = FormatAnalysisResult(available=True, format="MACH-O")
    assert result.format == "MACH-O"
    assert result.is_macho() is True


def test_format_analysis_result_format_normalized():
    result = FormatAnalysisResult(available=True, format="pe32")
    assert result.format == "PE32"


def test_format_analysis_result_invalid_format():
    with pytest.raises(ValidationError):
        FormatAnalysisResult(available=True, format="UNKNOWN")


def test_format_analysis_result_valid_bits_32():
    result = FormatAnalysisResult(available=True, format="PE32", bits=32)
    assert result.bits == 32
    assert result.is_64bit() is False


def test_format_analysis_result_valid_bits_64():
    result = FormatAnalysisResult(available=True, format="PE32+", bits=64)
    assert result.bits == 64
    assert result.is_64bit() is True


def test_format_analysis_result_invalid_bits():
    with pytest.raises(ValidationError):
        FormatAnalysisResult(available=True, format="PE", bits=16)


def test_format_analysis_result_bits_none():
    result = FormatAnalysisResult(available=True, format="PE", bits=None)
    assert result.bits is None
    assert result.is_64bit() is False


def test_format_analysis_result_endian_little():
    result = FormatAnalysisResult(available=True, format="PE", endian="little")
    assert result.endian == "little"


def test_format_analysis_result_endian_le():
    result = FormatAnalysisResult(available=True, format="PE", endian="LE")
    assert result.endian == "le"


def test_format_analysis_result_endian_big():
    result = FormatAnalysisResult(available=True, format="ELF", endian="big")
    assert result.endian == "big"


def test_format_analysis_result_endian_be():
    result = FormatAnalysisResult(available=True, format="ELF", endian="be")
    assert result.endian == "be"


def test_format_analysis_result_invalid_endian():
    with pytest.raises(ValidationError):
        FormatAnalysisResult(available=True, format="PE", endian="middle")


def test_format_analysis_result_endian_none():
    result = FormatAnalysisResult(available=True, format="PE", endian=None)
    assert result.endian is None


def test_format_analysis_result_get_executable_sections():
    s1 = SectionInfo(name=".text", is_executable=True)
    s2 = SectionInfo(name=".data", is_executable=False)
    result = FormatAnalysisResult(available=True, format="PE", sections=[s1, s2])
    exec_sections = result.get_executable_sections()
    assert len(exec_sections) == 1
    assert exec_sections[0].name == ".text"


def test_format_analysis_result_get_writable_sections():
    s1 = SectionInfo(name=".text", is_writable=False)
    s2 = SectionInfo(name=".data", is_writable=True)
    result = FormatAnalysisResult(available=True, format="PE", sections=[s1, s2])
    writable = result.get_writable_sections()
    assert len(writable) == 1
    assert writable[0].name == ".data"


def test_format_analysis_result_get_suspicious_sections():
    s1 = SectionInfo(name=".text", suspicious_indicators=["packed"])
    s2 = SectionInfo(name=".data", suspicious_indicators=[])
    result = FormatAnalysisResult(available=True, format="PE", sections=[s1, s2])
    suspicious = result.get_suspicious_sections()
    assert len(suspicious) == 1
    assert suspicious[0].name == ".text"


def test_format_analysis_result_get_sections_empty():
    result = FormatAnalysisResult(available=True, format="ELF")
    assert result.get_executable_sections() == []
    assert result.get_writable_sections() == []
    assert result.get_suspicious_sections() == []


def test_format_analysis_result_macho_variants():
    for fmt in ("MACH-O32", "MACH-O64", "MACHO"):
        result = FormatAnalysisResult(available=True, format=fmt)
        assert result.is_macho() is True


def test_format_analysis_result_elf_variants():
    for fmt in ("ELF", "ELF32", "ELF64"):
        result = FormatAnalysisResult(available=True, format=fmt)
        assert result.is_elf() is True


# Test for validate_entropy validator directly (line 49)

def test_validate_entropy_validator_raises_for_negative():
    """Direct call to validate_entropy raises ValueError for out-of-range values."""
    import pytest
    with pytest.raises(ValueError, match="Entropy must be between"):
        SectionInfo.validate_entropy(-1.0)


def test_validate_entropy_validator_raises_for_above_max():
    """Direct call to validate_entropy raises ValueError for values above 8.0."""
    import pytest
    with pytest.raises(ValueError, match="Entropy must be between"):
        SectionInfo.validate_entropy(9.0)
