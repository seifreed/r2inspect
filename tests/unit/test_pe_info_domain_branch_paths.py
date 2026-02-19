#!/usr/bin/env python3
"""Branch path tests for r2inspect/modules/pe_info_domain.py covering missing lines."""

from __future__ import annotations

import pytest

from r2inspect.modules.pe_info_domain import (
    PE32_PLUS,
    apply_optional_header_info,
    build_subsystem_info,
    characteristics_from_bin,
    characteristics_from_header,
    compute_entry_point,
    determine_pe_file_type,
    determine_pe_format,
    normalize_pe_format,
    normalize_resource_entries,
    parse_version_info_text,
)


# ---------------------------------------------------------------------------
# determine_pe_file_type() - lines 16, 21, 24, 25, 27
# ---------------------------------------------------------------------------


def test_determine_pe_file_type_non_pe_class_returns_directly():
    """determine_pe_file_type returns class immediately when not PE/Unknown (line 16)."""
    result = determine_pe_file_type({"class": "ELF"}, None, None)
    assert result == "ELF"


def test_determine_pe_file_type_dll_from_description():
    """determine_pe_file_type returns DLL when file_desc contains dll (line 21)."""
    result = determine_pe_file_type({"class": "PE32"}, None, "Dynamic Link Library DLL")
    assert result == "DLL"


def test_determine_pe_file_type_exe_from_description():
    """determine_pe_file_type returns EXE when file_desc contains executable (line 24)."""
    result = determine_pe_file_type({"class": "PE32"}, None, "PE32 executable")
    assert result == "EXE"


def test_determine_pe_file_type_sys_from_driver_description():
    """determine_pe_file_type returns SYS when file_desc contains driver (line 25)."""
    result = determine_pe_file_type({"class": "PE32"}, None, "kernel driver")
    assert result == "SYS"


def test_determine_pe_file_type_sys_from_sys_description():
    """determine_pe_file_type returns SYS when file_desc contains sys."""
    result = determine_pe_file_type({"class": "PE32"}, None, "sys file")
    assert result == "SYS"


def test_determine_pe_file_type_fallback_to_class():
    """determine_pe_file_type falls back to class when no useful description (line 27)."""
    result = determine_pe_file_type({"class": "PE32"}, None, None)
    assert result == "PE32"


def test_determine_pe_file_type_unknown_class_no_desc():
    """determine_pe_file_type returns class for Unknown with no file_desc."""
    result = determine_pe_file_type({"class": "Unknown"}, None, None)
    assert result == "Unknown"


def test_determine_pe_file_type_pe32plus_dll():
    """determine_pe_file_type handles PE32+ class with dll description."""
    result = determine_pe_file_type({"class": PE32_PLUS}, None, "DLL module")
    assert result == "DLL"


# ---------------------------------------------------------------------------
# determine_pe_format() - lines 33, 37, 41-48
# ---------------------------------------------------------------------------


def test_determine_pe_format_returns_known_format():
    """determine_pe_format returns format directly when known and not Unknown (line 33)."""
    result = determine_pe_format({"format": "PE32+"}, None)
    assert result == "PE32+"


def test_determine_pe_format_32bit_from_bits():
    """determine_pe_format returns PE32 for 32-bit binary (line 37)."""
    result = determine_pe_format({"format": "Unknown", "bits": 32}, None)
    assert result == "PE32"


def test_determine_pe_format_64bit_from_bits():
    """determine_pe_format returns PE32+ for 64-bit binary (line 41)."""
    result = determine_pe_format({"format": "Unknown", "bits": 64}, None)
    assert result == PE32_PLUS


def test_determine_pe_format_from_pe_header_magic_pe32():
    """determine_pe_format returns PE32 from optional_header Magic 0x10B (line 44-45)."""
    pe_header = {"optional_header": {"Magic": 0x10B}}
    result = determine_pe_format({"format": "Unknown", "bits": 0}, pe_header)
    assert result == "PE32"


def test_determine_pe_format_from_pe_header_magic_pe32plus():
    """determine_pe_format returns PE32+ from optional_header Magic 0x20B (line 46-47)."""
    pe_header = {"optional_header": {"Magic": 0x20B}}
    result = determine_pe_format({"format": "Unknown", "bits": 0}, pe_header)
    assert result == PE32_PLUS


def test_determine_pe_format_fallback_to_pe():
    """determine_pe_format returns PE as fallback (line 48)."""
    result = determine_pe_format({"format": "Unknown", "bits": 0}, None)
    assert result == "PE"


# ---------------------------------------------------------------------------
# normalize_pe_format() - lines 54, 58
# ---------------------------------------------------------------------------


def test_normalize_pe_format_empty_string_returns_pe():
    """normalize_pe_format returns PE for empty string (line 54)."""
    result = normalize_pe_format("")
    assert result == "PE"


def test_normalize_pe_format_unknown_returns_pe():
    """normalize_pe_format returns PE for Unknown (line 54)."""
    result = normalize_pe_format("Unknown")
    assert result == "PE"


def test_normalize_pe_format_pe32_returns_pe():
    """normalize_pe_format returns PE for PE32 (line 57)."""
    result = normalize_pe_format("PE32")
    assert result == "PE"


def test_normalize_pe_format_non_pe_format_returned_as_is():
    """normalize_pe_format returns non-PE format unchanged (line 58)."""
    result = normalize_pe_format("ELF")
    assert result == "ELF"


# ---------------------------------------------------------------------------
# compute_entry_point() - lines 64, 76
# ---------------------------------------------------------------------------


def test_compute_entry_point_from_baddr_boffset():
    """compute_entry_point uses baddr + boffset when both present (line 64)."""
    result = compute_entry_point({"baddr": 0x400000, "boffset": 0x1000}, None)
    assert result == 0x401000


def test_compute_entry_point_from_entry_info():
    """compute_entry_point prefers vaddr from entry_info when present (line 76)."""
    entry_info = [{"vaddr": 0x402000}]
    result = compute_entry_point({"baddr": 0x400000, "boffset": 0x1000}, entry_info)
    assert result == 0x402000


def test_compute_entry_point_fallback_zero():
    """compute_entry_point returns 0 when no baddr and no entry_info."""
    result = compute_entry_point({}, None)
    assert result == 0


# ---------------------------------------------------------------------------
# apply_optional_header_info() - lines 76, 94, 98
# ---------------------------------------------------------------------------


def test_apply_optional_header_info_no_pe_header_returns_unchanged():
    """apply_optional_header_info returns info unchanged when pe_header is None."""
    info = {"image_base": 0x400000}
    result = apply_optional_header_info(info, None)
    assert result == info


def test_apply_optional_header_info_with_image_base():
    """apply_optional_header_info updates image_base from optional_header."""
    info = {"image_base": 0}
    pe_header = {"optional_header": {"ImageBase": 0x400000}}
    result = apply_optional_header_info(info, pe_header)
    assert result["image_base"] == 0x400000


def test_apply_optional_header_info_with_entry_rva():
    """apply_optional_header_info computes entry_point from AddressOfEntryPoint."""
    info = {"image_base": 0x400000}
    pe_header = {"optional_header": {"ImageBase": 0x400000, "AddressOfEntryPoint": 0x1000}}
    result = apply_optional_header_info(info, pe_header)
    assert result["entry_point"] == 0x401000


def test_apply_optional_header_info_zero_image_base_not_updated():
    """apply_optional_header_info skips zero ImageBase."""
    info = {"image_base": 0x400000}
    pe_header = {"optional_header": {"ImageBase": 0}}
    result = apply_optional_header_info(info, pe_header)
    assert result["image_base"] == 0x400000


# ---------------------------------------------------------------------------
# characteristics_from_header() - lines 94, 98
# ---------------------------------------------------------------------------


def test_characteristics_from_header_none_returns_none():
    """characteristics_from_header returns None for None input."""
    result = characteristics_from_header(None)
    assert result is None


def test_characteristics_from_header_non_int_characteristics_returns_none():
    """characteristics_from_header returns None if Characteristics is not int (line 98)."""
    pe_header = {"file_header": {"Characteristics": "0x2000"}}
    result = characteristics_from_header(pe_header)
    assert result is None


def test_characteristics_from_header_dll_flag():
    """characteristics_from_header detects DLL flag (0x2000)."""
    pe_header = {"file_header": {"Characteristics": 0x2002}}
    result = characteristics_from_header(pe_header)
    assert result is not None
    assert result["is_dll"] is True
    assert result["is_executable"] is True


def test_characteristics_from_header_exe_only():
    """characteristics_from_header detects executable without DLL flag."""
    pe_header = {"file_header": {"Characteristics": 0x0002}}
    result = characteristics_from_header(pe_header)
    assert result["is_dll"] is False
    assert result["is_executable"] is True


def test_characteristics_from_header_missing_characteristics():
    """characteristics_from_header handles missing Characteristics key."""
    pe_header = {"file_header": {}}
    result = characteristics_from_header(pe_header)
    assert result is not None
    assert result["is_dll"] is False
    assert result["is_executable"] is False


# ---------------------------------------------------------------------------
# normalize_resource_entries() - lines 106-113
# ---------------------------------------------------------------------------


def test_normalize_resource_entries_empty_list():
    """normalize_resource_entries returns empty list for empty input."""
    result = normalize_resource_entries([])
    assert result == []


def test_normalize_resource_entries_with_data():
    """normalize_resource_entries extracts name, type, size, lang from each resource."""
    resources = [
        {"name": "ICON", "type": "RT_ICON", "size": 1024, "lang": "en-US"},
        {"name": "MANIFEST", "type": "RT_MANIFEST", "size": 512, "lang": "neutral"},
    ]
    result = normalize_resource_entries(resources)
    assert len(result) == 2
    assert result[0]["name"] == "ICON"
    assert result[0]["type"] == "RT_ICON"
    assert result[1]["size"] == 512


def test_normalize_resource_entries_uses_defaults():
    """normalize_resource_entries uses Unknown defaults for missing keys."""
    result = normalize_resource_entries([{}])
    assert result[0]["name"] == "Unknown"
    assert result[0]["type"] == "Unknown"
    assert result[0]["size"] == 0
    assert result[0]["lang"] == "Unknown"


# ---------------------------------------------------------------------------
# parse_version_info_text() - lines 118-123
# ---------------------------------------------------------------------------


def test_parse_version_info_text_basic():
    """parse_version_info_text parses key=value lines."""
    version_text = "ProductName=MyApp\nFileVersion=1.0.0.0\nCompanyName=ACME"
    result = parse_version_info_text(version_text)
    assert result["ProductName"] == "MyApp"
    assert result["FileVersion"] == "1.0.0.0"
    assert result["CompanyName"] == "ACME"


def test_parse_version_info_text_ignores_lines_without_equals():
    """parse_version_info_text skips lines without = sign."""
    version_text = "no equals here\nkey=value\nanother line"
    result = parse_version_info_text(version_text)
    assert len(result) == 1
    assert result["key"] == "value"


def test_parse_version_info_text_value_with_equals():
    """parse_version_info_text handles values containing = characters."""
    version_text = "URL=http://example.com?a=b&c=d"
    result = parse_version_info_text(version_text)
    assert result["URL"] == "http://example.com?a=b&c=d"


def test_parse_version_info_text_empty_string():
    """parse_version_info_text returns empty dict for empty string."""
    result = parse_version_info_text("")
    assert result == {}


# ---------------------------------------------------------------------------
# characteristics_from_bin() - lines 127-142
# ---------------------------------------------------------------------------


def test_characteristics_from_bin_dll_from_type():
    """characteristics_from_bin detects DLL from type field (line 131-132)."""
    result = characteristics_from_bin({"type": "dll", "class": ""}, None)
    assert result["is_dll"] is True


def test_characteristics_from_bin_dll_from_class():
    """characteristics_from_bin detects DLL from class field (line 133)."""
    result = characteristics_from_bin({"type": "", "class": "dll"}, None)
    assert result["is_dll"] is True


def test_characteristics_from_bin_dll_from_dynamic_library():
    """characteristics_from_bin detects DLL from dynamic library in type (line 134)."""
    result = characteristics_from_bin({"type": "dynamic library", "class": ""}, None)
    assert result["is_dll"] is True


def test_characteristics_from_bin_dll_from_path():
    """characteristics_from_bin detects DLL from .dll file extension (line 135)."""
    result = characteristics_from_bin({"type": "", "class": ""}, "/system32/kernel32.dll")
    assert result["is_dll"] is True


def test_characteristics_from_bin_exe_from_path():
    """characteristics_from_bin detects EXE from .exe extension (line 139)."""
    result = characteristics_from_bin({"type": "", "class": ""}, "C:/Windows/cmd.exe")
    assert result["is_dll"] is False
    assert result["is_executable"] is True


def test_characteristics_from_bin_executable_from_type():
    """characteristics_from_bin detects executable from type field."""
    result = characteristics_from_bin({"type": "executable", "class": ""}, None)
    assert result["is_executable"] is True


def test_characteristics_from_bin_none_path():
    """characteristics_from_bin handles None filepath (line 129)."""
    result = characteristics_from_bin({"type": "pe executable", "class": ""}, None)
    assert isinstance(result, dict)
    assert "is_dll" in result
    assert "is_executable" in result


# ---------------------------------------------------------------------------
# build_subsystem_info() - lines 149, 153
# ---------------------------------------------------------------------------


def test_build_subsystem_info_console():
    """build_subsystem_info sets gui_app=False for console subsystem (line 149)."""
    result = build_subsystem_info("Windows CUI console")
    assert result["subsystem"] == "Windows CUI console"
    assert result["gui_app"] is False


def test_build_subsystem_info_windows_gui():
    """build_subsystem_info sets gui_app=True for windows GUI subsystem (line 151)."""
    result = build_subsystem_info("Windows GUI")
    assert result["gui_app"] is True


def test_build_subsystem_info_unknown_subsystem():
    """build_subsystem_info sets gui_app=None for unrecognized subsystem (line 153)."""
    result = build_subsystem_info("EFI Application")
    assert result["gui_app"] is None
    assert result["subsystem"] == "EFI Application"


def test_build_subsystem_info_native():
    """build_subsystem_info returns gui_app=None for Native subsystem."""
    result = build_subsystem_info("Native")
    assert result["gui_app"] is None
