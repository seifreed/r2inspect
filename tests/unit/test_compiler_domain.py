#!/usr/bin/env python3
"""Comprehensive tests for compiler_domain module."""

from r2inspect.modules.compiler_domain import (
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


def test_calculate_compiler_score_all_match():
    signatures = {
        "strings": ["test"],
        "imports": ["kernel32.dll"],
        "sections": [".text"],
        "symbols": ["main"],
    }
    strings_data = ["test pattern"]
    imports_data = ["kernel32.dll"]
    sections_data = [".text"]
    symbols_data = ["main"]
    score = calculate_compiler_score(signatures, strings_data, imports_data, sections_data, symbols_data)
    assert score > 0.0
    assert score <= 1.0


def test_calculate_compiler_score_no_match():
    signatures = {
        "strings": ["nomatch"],
        "imports": ["nomatch.dll"],
        "sections": [".nomatch"],
        "symbols": ["nomatch"],
    }
    strings_data = ["different"]
    imports_data = ["different.dll"]
    sections_data = [".different"]
    symbols_data = ["different"]
    score = calculate_compiler_score(signatures, strings_data, imports_data, sections_data, symbols_data)
    assert score == 0.0


def test_calculate_compiler_score_partial_match():
    signatures = {
        "strings": ["test"],
        "imports": ["kernel32.dll"],
    }
    strings_data = ["test pattern"]
    imports_data = ["other.dll"]
    sections_data = []
    symbols_data = []
    score = calculate_compiler_score(signatures, strings_data, imports_data, sections_data, symbols_data)
    assert 0.0 < score < 1.0


def test_calculate_compiler_score_empty_signatures():
    signatures = {}
    score = calculate_compiler_score(signatures, [], [], [], [])
    assert score == 0.0


def test_calculate_compiler_score_empty_data():
    signatures = {"strings": ["test"]}
    score = calculate_compiler_score(signatures, [], [], [], [])
    assert score == 0.0


def test_calculate_compiler_score_string_only():
    signatures = {"strings": ["Microsoft.*Visual.*C"]}
    strings_data = ["Microsoft Visual C++ 2019"]
    score = calculate_compiler_score(signatures, strings_data, [], [], [])
    assert score > 0.0


def test_calculate_compiler_score_import_only():
    signatures = {"imports": ["msvcr120.dll"]}
    imports_data = ["msvcr120.dll", "kernel32.dll"]
    score = calculate_compiler_score(signatures, [], imports_data, [], [])
    assert score > 0.0


def test_calculate_compiler_score_section_only():
    signatures = {"sections": [".text"]}
    sections_data = [".text", ".data"]
    score = calculate_compiler_score(signatures, [], [], sections_data, [])
    assert score > 0.0


def test_calculate_compiler_score_symbol_only():
    signatures = {"symbols": ["_start"]}
    symbols_data = ["_start", "main"]
    score = calculate_compiler_score(signatures, [], [], [], symbols_data)
    assert score > 0.0


def test_detection_method_high_confidence():
    result = detection_method("MSVC", 0.9)
    assert "High confidence" in result
    assert "Runtime library analysis" in result


def test_detection_method_medium_confidence():
    result = detection_method("GCC", 0.7)
    assert "Medium confidence" in result
    assert "Symbol and section analysis" in result


def test_detection_method_low_confidence():
    result = detection_method("Clang", 0.4)
    assert "Low confidence" in result


def test_detection_method_msvc():
    result = detection_method("MSVC", 0.8)
    assert "Runtime library analysis" in result


def test_detection_method_gcc():
    result = detection_method("GCC", 0.8)
    assert "Symbol and section analysis" in result


def test_detection_method_clang():
    result = detection_method("Clang", 0.8)
    assert "Symbol and section analysis" in result


def test_detection_method_dotnet():
    result = detection_method("DotNet", 0.8)
    assert "CLR metadata analysis" in result


def test_detection_method_autoit():
    result = detection_method("AutoIt", 0.8)
    assert "AU3 signature and string analysis" in result


def test_detection_method_nsis():
    result = detection_method("NSIS", 0.8)
    assert "Installer signature analysis" in result


def test_detection_method_innosetup():
    result = detection_method("InnoSetup", 0.8)
    assert "Installer signature analysis" in result


def test_detection_method_pyinstaller():
    result = detection_method("PyInstaller", 0.8)
    assert "Python runtime detection" in result


def test_detection_method_cx_freeze():
    result = detection_method("cx_Freeze", 0.8)
    assert "Python runtime detection" in result


def test_detection_method_nim():
    result = detection_method("Nim", 0.8)
    assert "Nim runtime and symbol analysis" in result


def test_detection_method_zig():
    result = detection_method("Zig", 0.8)
    assert "Modern compiler signature analysis" in result


def test_detection_method_swift():
    result = detection_method("Swift", 0.8)
    assert "Modern compiler signature analysis" in result


def test_detection_method_tinycc():
    result = detection_method("TinyCC", 0.8)
    assert "Modern compiler signature analysis" in result


def test_detection_method_nodejs():
    result = detection_method("NodeJS", 0.8)
    assert "Node.js runtime detection" in result


def test_detection_method_fasm():
    result = detection_method("FASM", 0.8)
    assert "Assembly tool signature" in result


def test_detection_method_unknown():
    result = detection_method("Unknown", 0.8)
    assert "High confidence" in result


def test_map_msvc_version_from_rich_2019():
    result = map_msvc_version_from_rich("MSVC 2019")
    assert result == "Visual Studio 2019"


def test_map_msvc_version_from_rich_2022():
    result = map_msvc_version_from_rich("MSVC 2022")
    assert result == "Visual Studio 2022"


def test_map_msvc_version_from_rich_1900():
    result = map_msvc_version_from_rich("MSVC 1900")
    assert result == "Visual Studio 2015"


def test_map_msvc_version_from_rich_1910():
    result = map_msvc_version_from_rich("MSVC 1910")
    assert result == "Visual Studio 2017"


def test_map_msvc_version_from_rich_unknown():
    result = map_msvc_version_from_rich("MSVC 1800")
    assert "Rich Header" in result


def test_detect_msvc_version_from_imports():
    versions = {"msvcr120.dll": "Visual Studio 2013"}
    result = detect_msvc_version([], ["msvcr120.dll"], versions)
    assert result == "Visual Studio 2013"


def test_detect_msvc_version_from_strings():
    strings = ["Microsoft Visual C++ 14.0"]
    result = detect_msvc_version(strings, [], {})
    assert "Visual Studio" in result
    assert "14.0" in result


def test_detect_msvc_version_unknown():
    result = detect_msvc_version([], [], {})
    assert result == "Unknown"


def test_detect_gcc_version_full():
    strings = ["GCC 9.3.0"]
    result = detect_gcc_version(strings)
    assert result == "GCC 9.3.0"


def test_detect_gcc_version_short():
    strings = ["GNU 8.2"]
    result = detect_gcc_version(strings)
    assert result == "GCC 8.2"


def test_detect_gcc_version_unknown():
    result = detect_gcc_version([])
    assert result == "Unknown"


def test_detect_clang_version_full():
    strings = ["clang version 12.0.1"]
    result = detect_clang_version(strings)
    assert result == "Clang 12.0.1"


def test_detect_clang_version_apple():
    strings = ["Apple clang 13.0"]
    result = detect_clang_version(strings)
    assert result == "Apple Clang 13.0"


def test_detect_clang_version_unknown():
    result = detect_clang_version([])
    assert result == "Unknown"


def test_detect_go_version():
    strings = ["go1.18.1"]
    result = detect_go_version(strings)
    assert result == "Go 1.18.1"


def test_detect_go_version_unknown():
    result = detect_go_version([])
    assert result == "Unknown"


def test_detect_rust_version():
    strings = ["rustc 1.62.0"]
    result = detect_rust_version(strings)
    assert result == "Rust 1.62.0"


def test_detect_rust_version_unknown():
    result = detect_rust_version([])
    assert result == "Unknown"


def test_parse_strings_output_valid():
    output = "0x00401000 4 5 test string\n0x00402000 3 4 another one"
    result = parse_strings_output(output)
    assert len(result) == 2
    assert "test string" in result
    assert "another one" in result


def test_parse_strings_output_empty():
    result = parse_strings_output("")
    assert result == []


def test_parse_strings_output_invalid_lines():
    output = "invalid line\nshort"
    result = parse_strings_output(output)
    assert result == []


def test_parse_strings_output_whitespace():
    output = "   \n\n   \n"
    result = parse_strings_output(output)
    assert result == []


def test_extract_import_names_with_libname():
    imports = [{"libname": "kernel32.dll"}, {"libname": "user32.dll"}]
    result = extract_import_names(imports)
    assert "kernel32.dll" in result
    assert "user32.dll" in result


def test_extract_import_names_with_name():
    imports = [{"name": "CreateFileA"}, {"name": "ReadFile"}]
    result = extract_import_names(imports)
    assert "CreateFileA" in result
    assert "ReadFile" in result


def test_extract_import_names_mixed():
    imports = [{"libname": "kernel32.dll", "name": "CreateFileA"}, {"name": "ReadFile"}]
    result = extract_import_names(imports)
    assert "kernel32.dll" in result
    assert "CreateFileA" in result
    assert "ReadFile" in result


def test_extract_import_names_empty():
    result = extract_import_names([])
    assert result == []


def test_extract_import_names_no_keys():
    imports = [{"other": "value"}]
    result = extract_import_names(imports)
    assert result == []


def test_extract_section_names_valid():
    sections = [{"name": ".text"}, {"name": ".data"}, {"name": ".rdata"}]
    result = extract_section_names(sections)
    assert ".text" in result
    assert ".data" in result
    assert ".rdata" in result


def test_extract_section_names_empty():
    result = extract_section_names([])
    assert result == []


def test_extract_section_names_no_name():
    sections = [{"other": "value"}]
    result = extract_section_names(sections)
    assert result == []


def test_extract_section_names_mixed():
    sections = [{"name": ".text"}, {"other": "value"}, {"name": ".data"}]
    result = extract_section_names(sections)
    assert ".text" in result
    assert ".data" in result
    assert len(result) == 2


def test_extract_symbol_names_valid():
    symbols = [{"name": "main"}, {"name": "_start"}, {"name": "printf"}]
    result = extract_symbol_names(symbols)
    assert "main" in result
    assert "_start" in result
    assert "printf" in result


def test_extract_symbol_names_empty():
    result = extract_symbol_names([])
    assert result == []


def test_extract_symbol_names_no_name():
    symbols = [{"other": "value"}]
    result = extract_symbol_names(symbols)
    assert result == []


def test_extract_symbol_names_mixed():
    symbols = [{"name": "main"}, {"other": "value"}, {"name": "printf"}]
    result = extract_symbol_names(symbols)
    assert "main" in result
    assert "printf" in result
    assert len(result) == 2


def test_calculate_compiler_score_multiple_strings():
    signatures = {"strings": ["test", "pattern", "match"]}
    strings_data = ["test data", "pattern here", "match found"]
    score = calculate_compiler_score(signatures, strings_data, [], [], [])
    assert score > 0.0


def test_calculate_compiler_score_case_insensitive():
    signatures = {"strings": ["test"]}
    strings_data = ["TEST PATTERN"]
    score = calculate_compiler_score(signatures, strings_data, [], [], [])
    assert score > 0.0


def test_calculate_compiler_score_partial_string_match():
    signatures = {"imports": ["kernel32"]}
    imports_data = ["kernel32.dll"]
    score = calculate_compiler_score(signatures, [], imports_data, [], [])
    assert score > 0.0


def test_detection_method_contains_multiple_parts():
    result = detection_method("MSVC", 0.85)
    parts = result.split("|")
    assert len(parts) >= 2


def test_detect_msvc_version_priority():
    versions = {"msvcr120.dll": "Visual Studio 2013"}
    strings = ["Microsoft Visual C++ 19.0"]
    result = detect_msvc_version(strings, ["msvcr120.dll"], versions)
    assert result == "Visual Studio 2013"


def test_detect_gcc_version_case_insensitive():
    strings = ["gcc 10.2.0"]
    result = detect_gcc_version(strings)
    assert "GCC" in result


def test_detect_clang_version_case_insensitive():
    strings = ["CLANG 11.0.1"]
    result = detect_clang_version(strings)
    assert "Clang" in result


def test_detect_go_version_case_insensitive():
    strings = ["GO1.17.3"]
    result = detect_go_version(strings)
    assert "Go" in result


def test_detect_rust_version_case_insensitive():
    strings = ["RUSTC 1.60.0"]
    result = detect_rust_version(strings)
    assert "Rust" in result
