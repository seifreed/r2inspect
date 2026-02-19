#!/usr/bin/env python3
"""Branch-path tests for r2inspect/schemas/format.py.

Missing lines targeted:
40-42 (SectionInfo.validate_name), 48-50 (validate_entropy),
54 (is_suspicious), 58 (has_permission), 63, 67 (to_dict),
93-103 (SecurityFeatures.get_enabled_features),
107-130 (security_score), 134 (SecurityFeatures.to_dict),
176-191 (FormatAnalysisResult.validate_format / validate_bits / validate_endian),
197-210 (validate_endian branches), 214-238 (result methods).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from r2inspect.schemas.format import (
    FormatAnalysisResult,
    SectionInfo,
    SecurityFeatures,
)


# ---------------------------------------------------------------------------
# SectionInfo.validate_name – lines 40-42
# ---------------------------------------------------------------------------


def test_section_info_name_stripped_on_creation():
    s = SectionInfo(name="  .text  ")
    assert s.name == ".text"


def test_section_info_empty_name_raises():
    with pytest.raises(ValidationError):
        SectionInfo(name="")


def test_section_info_whitespace_only_name_raises():
    with pytest.raises(ValidationError):
        SectionInfo(name="   ")


# ---------------------------------------------------------------------------
# SectionInfo.validate_entropy – lines 48-50
# ---------------------------------------------------------------------------


def test_section_info_entropy_valid_boundary_zero():
    s = SectionInfo(name=".text", entropy=0.0)
    assert s.entropy == 0.0


def test_section_info_entropy_valid_boundary_eight():
    s = SectionInfo(name=".text", entropy=8.0)
    assert s.entropy == 8.0


def test_section_info_entropy_none_accepted():
    s = SectionInfo(name=".text", entropy=None)
    assert s.entropy is None


def test_section_info_entropy_out_of_range_raises():
    with pytest.raises(ValidationError):
        SectionInfo(name=".text", entropy=8.1)


def test_section_info_entropy_negative_raises():
    with pytest.raises(ValidationError):
        SectionInfo(name=".text", entropy=-0.1)


# ---------------------------------------------------------------------------
# SectionInfo.is_suspicious – line 54 (True branch)
# ---------------------------------------------------------------------------


def test_section_info_is_suspicious_returns_true():
    s = SectionInfo(name=".upx0", suspicious_indicators=["packed", "high_entropy"])
    assert s.is_suspicious() is True


def test_section_info_is_suspicious_returns_false():
    s = SectionInfo(name=".text")
    assert s.is_suspicious() is False


# ---------------------------------------------------------------------------
# SectionInfo.has_permission – line 58 (True returns)
# ---------------------------------------------------------------------------


def test_section_info_has_permission_read():
    s = SectionInfo(name=".rodata", is_readable=True)
    assert s.has_permission("r") is True


def test_section_info_has_permission_write():
    s = SectionInfo(name=".data", is_writable=True)
    assert s.has_permission("w") is True


def test_section_info_has_permission_execute():
    s = SectionInfo(name=".text", is_executable=True)
    assert s.has_permission("x") is True


def test_section_info_has_permission_unknown_returns_false():
    s = SectionInfo(name=".text", is_executable=True)
    assert s.has_permission("z") is False


def test_section_info_has_permission_case_insensitive():
    s = SectionInfo(name=".text", is_executable=True)
    assert s.has_permission("X") is True


# ---------------------------------------------------------------------------
# SectionInfo.to_dict – line 67
# ---------------------------------------------------------------------------


def test_section_info_to_dict_returns_dict():
    s = SectionInfo(name=".text", virtual_address=0x1000, is_executable=True)
    d = s.to_dict()
    assert isinstance(d, dict)
    assert d["name"] == ".text"
    assert d["is_executable"] is True


# ---------------------------------------------------------------------------
# SecurityFeatures.get_enabled_features – lines 93-103
# ---------------------------------------------------------------------------


def test_security_features_get_enabled_features_empty():
    sf = SecurityFeatures()
    assert sf.get_enabled_features() == []


def test_security_features_get_enabled_features_aslr_dep():
    sf = SecurityFeatures(aslr=True, dep=True)
    enabled = sf.get_enabled_features()
    assert "aslr" in enabled
    assert "dep" in enabled


def test_security_features_get_enabled_features_relro_full():
    sf = SecurityFeatures(relro="full")
    enabled = sf.get_enabled_features()
    assert "relro_full" in enabled


def test_security_features_get_enabled_features_relro_partial():
    sf = SecurityFeatures(relro="partial")
    enabled = sf.get_enabled_features()
    assert "relro_partial" in enabled


def test_security_features_get_enabled_features_relro_true():
    sf = SecurityFeatures(relro=True)
    enabled = sf.get_enabled_features()
    assert "relro" in enabled


def test_security_features_get_enabled_features_relro_false_excluded():
    sf = SecurityFeatures(relro=False)
    enabled = sf.get_enabled_features()
    assert "relro" not in enabled
    assert "relro_full" not in enabled


def test_security_features_get_enabled_features_pie_canary():
    sf = SecurityFeatures(pie=True, canary=True)
    enabled = sf.get_enabled_features()
    assert "pie" in enabled
    assert "canary" in enabled


# ---------------------------------------------------------------------------
# SecurityFeatures.security_score – lines 107-130
# ---------------------------------------------------------------------------


def test_security_score_zero_when_all_false():
    sf = SecurityFeatures()
    assert sf.security_score() == 0


def test_security_score_full_suite():
    sf = SecurityFeatures(
        nx=True, pie=True, canary=True, aslr=True,
        guard_cf=True, seh=True, authenticode=True, fortify=True, high_entropy_va=True,
    )
    score = sf.security_score()
    assert score > 0
    assert score <= 100


def test_security_score_relro_full_adds_points():
    sf_full = SecurityFeatures(relro="full")
    sf_partial = SecurityFeatures(relro="partial")
    sf_none = SecurityFeatures()
    assert sf_full.security_score() > sf_partial.security_score() > sf_none.security_score()


def test_security_score_relro_true_same_as_partial():
    sf_bool = SecurityFeatures(relro=True)
    sf_partial = SecurityFeatures(relro="partial")
    assert sf_bool.security_score() == sf_partial.security_score()


def test_security_score_capped_at_100():
    sf = SecurityFeatures(
        nx=True, pie=True, canary=True, aslr=True, stack_canary=True,
        guard_cf=True, seh=True, authenticode=True, fortify=True, high_entropy_va=True,
        relro="full", dep=True, rpath=False,
    )
    assert sf.security_score() <= 100


# ---------------------------------------------------------------------------
# SecurityFeatures.to_dict – line 134
# ---------------------------------------------------------------------------


def test_security_features_to_dict_returns_dict():
    sf = SecurityFeatures(aslr=True, nx=True)
    d = sf.to_dict()
    assert isinstance(d, dict)
    assert d["aslr"] is True
    assert d["nx"] is True


# ---------------------------------------------------------------------------
# FormatAnalysisResult.validate_format – lines 176-191
# ---------------------------------------------------------------------------


def test_format_analysis_result_pe_normalized():
    r = FormatAnalysisResult(available=True, format="pe")
    assert r.format == "PE"


def test_format_analysis_result_pe32_normalized():
    r = FormatAnalysisResult(available=True, format="pe32")
    assert r.format == "PE32"


def test_format_analysis_result_pe32plus_normalized():
    r = FormatAnalysisResult(available=True, format="PE32+")
    assert r.format == "PE32+"


def test_format_analysis_result_elf_normalized():
    r = FormatAnalysisResult(available=True, format="ELF64")
    assert r.format == "ELF64"


def test_format_analysis_result_macho_accepted():
    r = FormatAnalysisResult(available=True, format="MACH-O")
    assert r.format == "MACH-O"


def test_format_analysis_result_invalid_format_raises():
    with pytest.raises(ValidationError):
        FormatAnalysisResult(available=True, format="WASM")


# ---------------------------------------------------------------------------
# FormatAnalysisResult.validate_bits – lines 197-199
# ---------------------------------------------------------------------------


def test_format_analysis_result_bits_32():
    r = FormatAnalysisResult(available=True, format="PE", bits=32)
    assert r.bits == 32


def test_format_analysis_result_bits_64():
    r = FormatAnalysisResult(available=True, format="ELF", bits=64)
    assert r.bits == 64


def test_format_analysis_result_bits_invalid_raises():
    with pytest.raises(ValidationError):
        FormatAnalysisResult(available=True, format="PE", bits=16)


def test_format_analysis_result_bits_none_accepted():
    r = FormatAnalysisResult(available=True, format="PE", bits=None)
    assert r.bits is None


# ---------------------------------------------------------------------------
# FormatAnalysisResult.validate_endian – lines 201-210
# ---------------------------------------------------------------------------


def test_format_analysis_result_endian_little():
    r = FormatAnalysisResult(available=True, format="PE", endian="little")
    assert r.endian == "little"


def test_format_analysis_result_endian_big():
    r = FormatAnalysisResult(available=True, format="ELF", endian="BIG")
    assert r.endian == "big"


def test_format_analysis_result_endian_le():
    r = FormatAnalysisResult(available=True, format="PE", endian="LE")
    assert r.endian == "le"


def test_format_analysis_result_endian_be():
    r = FormatAnalysisResult(available=True, format="ELF", endian="be")
    assert r.endian == "be"


def test_format_analysis_result_endian_invalid_raises():
    with pytest.raises(ValidationError):
        FormatAnalysisResult(available=True, format="PE", endian="middle")


def test_format_analysis_result_endian_none_accepted():
    r = FormatAnalysisResult(available=True, format="PE", endian=None)
    assert r.endian is None


# ---------------------------------------------------------------------------
# FormatAnalysisResult section-query methods – lines 214-238
# ---------------------------------------------------------------------------


def _make_result(**kwargs):
    defaults = {"available": True, "format": "PE"}
    defaults.update(kwargs)
    return FormatAnalysisResult(**defaults)


def test_get_executable_sections_filters_correctly():
    r = _make_result(
        sections=[
            SectionInfo(name=".text", is_executable=True),
            SectionInfo(name=".data", is_executable=False),
        ]
    )
    execs = r.get_executable_sections()
    assert len(execs) == 1
    assert execs[0].name == ".text"


def test_get_writable_sections_filters_correctly():
    r = _make_result(
        sections=[
            SectionInfo(name=".data", is_writable=True),
            SectionInfo(name=".text", is_writable=False),
        ]
    )
    writable = r.get_writable_sections()
    assert len(writable) == 1
    assert writable[0].name == ".data"


def test_get_suspicious_sections_filters_correctly():
    r = _make_result(
        sections=[
            SectionInfo(name=".upx0", suspicious_indicators=["packed"]),
            SectionInfo(name=".text"),
        ]
    )
    suspicious = r.get_suspicious_sections()
    assert len(suspicious) == 1
    assert suspicious[0].name == ".upx0"


def test_get_executable_sections_empty_when_none():
    r = _make_result(sections=[SectionInfo(name=".data", is_executable=False)])
    assert r.get_executable_sections() == []


def test_is_64bit_true():
    r = _make_result(bits=64)
    assert r.is_64bit() is True


def test_is_64bit_false_for_32():
    r = _make_result(bits=32)
    assert r.is_64bit() is False


def test_is_pe_true():
    r = _make_result(format="PE")
    assert r.is_pe() is True


def test_is_pe_true_pe32():
    r = _make_result(format="PE32")
    assert r.is_pe() is True


def test_is_pe_false_for_elf():
    r = _make_result(format="ELF")
    assert r.is_pe() is False


def test_is_elf_true():
    r = _make_result(format="ELF")
    assert r.is_elf() is True


def test_is_elf_false_for_pe():
    r = _make_result(format="PE")
    assert r.is_elf() is False


def test_is_macho_true():
    r = _make_result(format="MACH-O")
    assert r.is_macho() is True


def test_is_macho_false_for_pe():
    r = _make_result(format="PE")
    assert r.is_macho() is False
