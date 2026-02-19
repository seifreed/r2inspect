#!/usr/bin/env python3
"""Branch-path tests for r2inspect/modules/compiler_domain.py.

Targets lines missing from coverage snapshot:
26, 32, 43, 45, 47, 49, 51, 53, 55, 57, 63-71, 80-84, 92-95,
99-106, 110-114, 118-122, 126-132, 165, 183, 199, 222.
"""

from __future__ import annotations

import pytest

from r2inspect.modules.compiler_domain import (
    _check_import_signatures,
    _check_section_signatures,
    _check_string_signatures,
    _check_symbol_signatures,
    calculate_compiler_score,
    detect_clang_version,
    detect_gcc_version,
    detect_go_version,
    detect_msvc_version,
    detect_rust_version,
    detection_method,
    extract_import_names,
    extract_section_names,
    extract_symbol_names,
    map_msvc_version_from_rich,
    parse_strings_output,
)


# ---------------------------------------------------------------------------
# calculate_compiler_score – line 26 (return 0.0 when max_score == 0)
# ---------------------------------------------------------------------------


def test_calculate_compiler_score_no_keys_returns_zero():
    result = calculate_compiler_score({}, [], [], [], [])
    assert result == 0.0


def test_calculate_compiler_score_returns_capped_one():
    sigs = {"strings": ["x"], "imports": ["x"], "sections": ["x"], "symbols": ["x"]}
    result = calculate_compiler_score(sigs, ["x"], ["x"], ["x"], ["x"])
    assert result <= 1.0


# ---------------------------------------------------------------------------
# detection_method – lines 32, 43, 45, 47, 49, 51, 53, 55, 57
# ---------------------------------------------------------------------------


def test_detection_method_high_confidence_score():
    result = detection_method("Unknown", 0.85)
    assert "High confidence" in result


def test_detection_method_medium_confidence_score():
    result = detection_method("Unknown", 0.65)
    assert "Medium confidence" in result


def test_detection_method_low_confidence_score():
    result = detection_method("Unknown", 0.3)
    assert "Low confidence" in result


def test_detection_method_dotnet_branch():
    result = detection_method("DotNet", 0.9)
    assert "CLR metadata analysis" in result


def test_detection_method_autoit_branch():
    result = detection_method("AutoIt", 0.9)
    assert "AU3 signature and string analysis" in result


def test_detection_method_nsis_branch():
    result = detection_method("NSIS", 0.9)
    assert "Installer signature analysis" in result


def test_detection_method_innosetup_branch():
    result = detection_method("InnoSetup", 0.9)
    assert "Installer signature analysis" in result


def test_detection_method_pyinstaller_branch():
    result = detection_method("PyInstaller", 0.9)
    assert "Python runtime detection" in result


def test_detection_method_cx_freeze_branch():
    result = detection_method("cx_Freeze", 0.9)
    assert "Python runtime detection" in result


def test_detection_method_nim_branch():
    result = detection_method("Nim", 0.9)
    assert "Nim runtime and symbol analysis" in result


def test_detection_method_zig_branch():
    result = detection_method("Zig", 0.9)
    assert "Modern compiler signature analysis" in result


def test_detection_method_swift_branch():
    result = detection_method("Swift", 0.9)
    assert "Modern compiler signature analysis" in result


def test_detection_method_tinycc_branch():
    result = detection_method("TinyCC", 0.9)
    assert "Modern compiler signature analysis" in result


def test_detection_method_nodejs_branch():
    result = detection_method("NodeJS", 0.9)
    assert "Node.js runtime detection" in result


def test_detection_method_fasm_branch():
    result = detection_method("FASM", 0.9)
    assert "Assembly tool signature" in result


# ---------------------------------------------------------------------------
# map_msvc_version_from_rich – lines 63-71
# ---------------------------------------------------------------------------


def test_map_msvc_version_contains_2019():
    assert map_msvc_version_from_rich("MSVC 2019") == "Visual Studio 2019"


def test_map_msvc_version_contains_2022():
    assert map_msvc_version_from_rich("MSVC 2022") == "Visual Studio 2022"


def test_map_msvc_version_contains_1900():
    assert map_msvc_version_from_rich("MSVC 1900") == "Visual Studio 2015"


def test_map_msvc_version_contains_1910():
    assert map_msvc_version_from_rich("MSVC 1910") == "Visual Studio 2017"


def test_map_msvc_version_unknown_returns_generic():
    result = map_msvc_version_from_rich("MSVC 9999")
    assert "Rich Header" in result


# ---------------------------------------------------------------------------
# detect_msvc_version – lines 80-84 (regex string match)
# ---------------------------------------------------------------------------


def test_detect_msvc_version_import_lookup_hit():
    versions = {"msvcp140.dll": "Visual Studio 2015"}
    assert detect_msvc_version([], ["msvcp140.dll"], versions) == "Visual Studio 2015"


def test_detect_msvc_version_string_regex_hit():
    strings = ["Microsoft Visual C++ Runtime 9.0 build"]
    result = detect_msvc_version(strings, [], {})
    assert result.startswith("Visual Studio")


def test_detect_msvc_version_no_match_returns_unknown():
    assert detect_msvc_version(["no info"], ["nothing"], {}) == "Unknown"


# ---------------------------------------------------------------------------
# detect_gcc_version – lines 92-95 (GNU fallback pattern)
# ---------------------------------------------------------------------------


def test_detect_gcc_version_gcc_pattern():
    strings = ["Compiled with GCC 9.3.0 on Linux"]
    result = detect_gcc_version(strings)
    assert result.startswith("GCC")
    assert "." in result


def test_detect_gcc_version_gnu_fallback_pattern():
    strings = ["GNU 8.4 toolchain"]
    result = detect_gcc_version(strings)
    assert result == "GCC 8.4"


def test_detect_gcc_version_empty_returns_unknown():
    assert detect_gcc_version([]) == "Unknown"


def test_detect_gcc_version_no_match_returns_unknown():
    assert detect_gcc_version(["no version here"]) == "Unknown"


# ---------------------------------------------------------------------------
# detect_clang_version – lines 99-106
# ---------------------------------------------------------------------------


def test_detect_clang_version_full_version():
    strings = ["clang version 9.0.0 (https://llvm.org)"]
    result = detect_clang_version(strings)
    assert result.startswith("Clang")
    assert "." in result


def test_detect_clang_version_apple_clang():
    strings = ["Apple clang 9.3 (macOS)"]
    result = detect_clang_version(strings)
    assert result.startswith("Apple Clang")
    assert "." in result


def test_detect_clang_version_no_match_returns_unknown():
    assert detect_clang_version(["no match"]) == "Unknown"


def test_detect_clang_version_empty_returns_unknown():
    assert detect_clang_version([]) == "Unknown"


# ---------------------------------------------------------------------------
# detect_go_version – lines 110-114
# ---------------------------------------------------------------------------


def test_detect_go_version_finds_version():
    strings = ["go1.20.3 built with standard toolchain"]
    result = detect_go_version(strings)
    assert result == "Go 1.20.3"


def test_detect_go_version_no_match_returns_unknown():
    assert detect_go_version(["no match"]) == "Unknown"


def test_detect_go_version_empty_returns_unknown():
    assert detect_go_version([]) == "Unknown"


# ---------------------------------------------------------------------------
# detect_rust_version – lines 118-122
# ---------------------------------------------------------------------------


def test_detect_rust_version_finds_version():
    strings = ["rustc 1.70.0 (90c541806 2023-05-31)"]
    result = detect_rust_version(strings)
    assert result == "Rust 1.70.0"


def test_detect_rust_version_no_match_returns_unknown():
    assert detect_rust_version(["no match"]) == "Unknown"


def test_detect_rust_version_empty_returns_unknown():
    assert detect_rust_version([]) == "Unknown"


# ---------------------------------------------------------------------------
# parse_strings_output – lines 126-132
# ---------------------------------------------------------------------------


def test_parse_strings_output_extracts_fifth_field():
    output = "0x00401000 4 5 type actual string content"
    result = parse_strings_output(output)
    assert result == ["actual string content"]


def test_parse_strings_output_multiple_lines():
    output = "0x00401000 4 5 t hello\n0x00402000 3 6 t world"
    result = parse_strings_output(output)
    assert len(result) == 2
    assert "hello" in result
    assert "world" in result


def test_parse_strings_output_skips_short_lines():
    output = "short\nalso short\n0x00401000 4 5 t valid string"
    result = parse_strings_output(output)
    assert result == ["valid string"]


def test_parse_strings_output_empty_input():
    assert parse_strings_output("") == []


def test_parse_strings_output_only_whitespace():
    assert parse_strings_output("   \n\t\n   ") == []


# ---------------------------------------------------------------------------
# _check_string_signatures – line 165 (early return when "strings" absent)
# ---------------------------------------------------------------------------


def test_check_string_signatures_missing_key_returns_zeros():
    score, max_score = _check_string_signatures({}, ["anything"])
    assert score == 0.0
    assert max_score == 0.0


def test_check_string_signatures_with_match():
    sigs = {"strings": ["hello"]}
    score, max_score = _check_string_signatures(sigs, ["hello world"])
    assert score > 0.0
    assert max_score == 3.0


# ---------------------------------------------------------------------------
# _check_import_signatures – line 183 (early return when "imports" absent)
# ---------------------------------------------------------------------------


def test_check_import_signatures_missing_key_returns_zeros():
    score, max_score = _check_import_signatures({}, ["kernel32.dll"])
    assert score == 0.0
    assert max_score == 0.0


def test_check_import_signatures_with_match():
    sigs = {"imports": ["kernel32"]}
    score, max_score = _check_import_signatures(sigs, ["kernel32.dll"])
    assert score > 0.0
    assert max_score == 2.0


# ---------------------------------------------------------------------------
# _check_section_signatures – line 199 (early return when "sections" absent)
# ---------------------------------------------------------------------------


def test_check_section_signatures_missing_key_returns_zeros():
    score, max_score = _check_section_signatures({}, [".text"])
    assert score == 0.0
    assert max_score == 0.0


def test_check_section_signatures_with_match():
    sigs = {"sections": [".text"]}
    score, max_score = _check_section_signatures(sigs, [".text", ".data"])
    assert score > 0.0
    assert max_score == 1.0


# ---------------------------------------------------------------------------
# _check_symbol_signatures – line 222 (score increment on symbol match)
# ---------------------------------------------------------------------------


def test_check_symbol_signatures_missing_key_returns_zeros():
    score, max_score = _check_symbol_signatures({}, ["main"])
    assert score == 0.0
    assert max_score == 0.0


def test_check_symbol_signatures_with_match():
    sigs = {"symbols": ["main"]}
    score, max_score = _check_symbol_signatures(sigs, ["main", "_start"])
    assert score > 0.0
    assert max_score == 1.0


def test_check_symbol_signatures_no_match():
    sigs = {"symbols": ["nomatch"]}
    score, max_score = _check_symbol_signatures(sigs, ["main", "_start"])
    assert score == 0.0
    assert max_score == 1.0


# ---------------------------------------------------------------------------
# extract_* helpers – round-trip smoke tests
# ---------------------------------------------------------------------------


def test_extract_import_names_lib_and_name_fields():
    imports = [{"libname": "kernel32.dll", "name": "CreateFileA"}, {"name": "ReadFile"}]
    result = extract_import_names(imports)
    assert "kernel32.dll" in result
    assert "CreateFileA" in result
    assert "ReadFile" in result


def test_extract_section_names_skips_non_dict():
    sections = [{"name": ".text"}, "invalid", {"other": "x"}]
    result = extract_section_names(sections)
    assert result == [".text"]


def test_extract_symbol_names_skips_non_dict():
    symbols = [{"name": "main"}, None, {"other": "x"}]
    result = extract_symbol_names(symbols)
    assert result == ["main"]
