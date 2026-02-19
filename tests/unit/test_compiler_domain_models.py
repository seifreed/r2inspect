#!/usr/bin/env python3
"""Tests for compiler_domain module."""

import pytest
from r2inspect.modules.compiler_domain import (
    calculate_compiler_score,
    detection_method,
    map_msvc_version_from_rich,
    detect_msvc_version,
    detect_gcc_version,
    detect_clang_version,
    detect_go_version,
    detect_rust_version,
    parse_strings_output,
    extract_import_names,
    extract_section_names,
    extract_symbol_names,
)


class TestCalculateCompilerScore:
    """Tests for calculate_compiler_score function."""

    def test_calculate_compiler_score_empty_data(self):
        """Test with empty data."""
        signatures = {}
        result = calculate_compiler_score(signatures, [], [], [], [])
        assert result == 0.0

    def test_calculate_compiler_score_no_signatures(self):
        """Test with no matching signatures."""
        signatures = {
            "strings": ["pattern1", "pattern2"],
            "imports": ["import1"],
            "sections": ["section1"],
            "symbols": ["symbol1"],
        }
        result = calculate_compiler_score(signatures, [], [], [], [])
        assert result == 0.0

    def test_calculate_compiler_score_perfect_match(self):
        """Test with perfect matching data."""
        signatures = {
            "strings": ["test"],
            "imports": ["kernel32"],
            "sections": [".text"],
            "symbols": ["main"],
        }
        strings = ["test string here"]
        imports = ["kernel32.dll"]
        sections = [".text"]
        symbols = ["main"]
        result = calculate_compiler_score(signatures, strings, imports, sections, symbols)
        assert result > 0.5

    def test_calculate_compiler_score_range(self):
        """Test that score is between 0 and 1."""
        signatures = {
            "strings": ["pattern1", "pattern2"],
            "imports": ["import1"],
            "sections": ["section1"],
            "symbols": ["symbol1"],
        }
        strings = ["pattern1"]
        imports = ["import1"]
        sections = ["section1"]
        symbols = ["symbol1"]
        result = calculate_compiler_score(signatures, strings, imports, sections, symbols)
        assert 0.0 <= result <= 1.0

    def test_calculate_compiler_score_partial_match(self):
        """Test with partial matching data."""
        signatures = {
            "strings": ["test"],
        }
        strings = ["test"]
        result = calculate_compiler_score(signatures, strings, [], [], [])
        assert 0.0 < result < 1.0


class TestDetectionMethod:
    """Tests for detection_method function."""

    def test_detection_method_high_confidence(self):
        """Test high confidence detection."""
        result = detection_method("MSVC", 0.9)
        assert "High confidence" in result

    def test_detection_method_medium_confidence(self):
        """Test medium confidence detection."""
        result = detection_method("MSVC", 0.7)
        assert "Medium confidence" in result

    def test_detection_method_low_confidence(self):
        """Test low confidence detection."""
        result = detection_method("MSVC", 0.4)
        assert "Low confidence" in result

    def test_detection_method_msvc(self):
        """Test MSVC-specific detection methods."""
        result = detection_method("MSVC", 0.9)
        assert "Runtime library analysis" in result

    def test_detection_method_gcc(self):
        """Test GCC-specific detection methods."""
        result = detection_method("GCC", 0.9)
        assert "Symbol and section analysis" in result

    def test_detection_method_clang(self):
        """Test Clang-specific detection methods."""
        result = detection_method("Clang", 0.9)
        assert "Symbol and section analysis" in result

    def test_detection_method_dotnet(self):
        """Test DotNet-specific detection methods."""
        result = detection_method("DotNet", 0.9)
        assert "CLR metadata analysis" in result

    def test_detection_method_autoit(self):
        """Test AutoIt-specific detection methods."""
        result = detection_method("AutoIt", 0.9)
        assert "AU3 signature" in result

    def test_detection_method_nsis(self):
        """Test NSIS-specific detection methods."""
        result = detection_method("NSIS", 0.9)
        assert "Installer signature" in result

    def test_detection_method_innosetup(self):
        """Test InnoSetup-specific detection methods."""
        result = detection_method("InnoSetup", 0.9)
        assert "Installer signature" in result

    def test_detection_method_pyinstaller(self):
        """Test PyInstaller-specific detection methods."""
        result = detection_method("PyInstaller", 0.9)
        assert "Python runtime" in result

    def test_detection_method_cx_freeze(self):
        """Test cx_Freeze-specific detection methods."""
        result = detection_method("cx_Freeze", 0.9)
        assert "Python runtime" in result

    def test_detection_method_nim(self):
        """Test Nim-specific detection methods."""
        result = detection_method("Nim", 0.9)
        assert "Nim runtime" in result

    def test_detection_method_zig(self):
        """Test Zig-specific detection methods."""
        result = detection_method("Zig", 0.9)
        assert "Modern compiler" in result

    def test_detection_method_swift(self):
        """Test Swift-specific detection methods."""
        result = detection_method("Swift", 0.9)
        assert "Modern compiler" in result

    def test_detection_method_nodejs(self):
        """Test NodeJS-specific detection methods."""
        result = detection_method("NodeJS", 0.9)
        assert "Node.js runtime" in result

    def test_detection_method_fasm(self):
        """Test FASM-specific detection methods."""
        result = detection_method("FASM", 0.9)
        assert "Assembly tool" in result

    def test_detection_method_format(self):
        """Test that result includes pipe separator."""
        result = detection_method("MSVC", 0.9)
        assert "|" in result


class TestMapMsvcVersionFromRich:
    """Tests for map_msvc_version_from_rich function."""

    def test_map_msvc_2019(self):
        """Test mapping Visual Studio 2019."""
        result = map_msvc_version_from_rich("2019")
        assert "2019" in result

    def test_map_msvc_2022(self):
        """Test mapping Visual Studio 2022."""
        result = map_msvc_version_from_rich("2022")
        assert "2022" in result

    def test_map_msvc_1900(self):
        """Test mapping Visual Studio 2015."""
        result = map_msvc_version_from_rich("1900")
        assert "2015" in result

    def test_map_msvc_1910(self):
        """Test mapping Visual Studio 2017."""
        result = map_msvc_version_from_rich("1910")
        assert "2017" in result

    def test_map_msvc_unknown(self):
        """Test unknown version returns generic string."""
        result = map_msvc_version_from_rich("unknown")
        assert "Visual Studio" in result
        assert "Rich Header" in result

    def test_map_msvc_empty(self):
        """Test empty string."""
        result = map_msvc_version_from_rich("")
        assert "Visual Studio" in result


class TestDetectMsvcVersion:
    """Tests for detect_msvc_version function."""

    def test_detect_msvc_version_from_imports(self):
        """Test detecting MSVC version from imports."""
        strings = []
        imports = ["msvcrt140"]
        versions = {"msvcrt140": "Visual Studio 2015"}
        result = detect_msvc_version(strings, imports, versions)
        assert "Visual Studio 2015" in result

    def test_detect_msvc_version_from_strings(self):
        """Test detecting MSVC version from strings."""
        strings = ["Microsoft Visual C++ 14.0"]
        imports = []
        versions = {}
        result = detect_msvc_version(strings, imports, versions)
        assert "Visual Studio" in result

    def test_detect_msvc_version_no_match(self):
        """Test when no version is detected."""
        strings = ["some random string"]
        imports = ["other.dll"]
        versions = {}
        result = detect_msvc_version(strings, imports, versions)
        assert "Unknown" in result

    def test_detect_msvc_version_priority(self):
        """Test that imports have priority over strings."""
        strings = ["Microsoft Visual C++ 12.0"]
        imports = ["msvcrt140"]
        versions = {"msvcrt140": "Visual Studio 2015"}
        result = detect_msvc_version(strings, imports, versions)
        assert "2015" in result


class TestDetectGccVersion:
    """Tests for detect_gcc_version function."""

    def test_detect_gcc_version_full_version(self):
        """Test detecting GCC with full version."""
        strings = ["GCC 9.3.0"]
        result = detect_gcc_version(strings)
        assert "9.3.0" in result

    def test_detect_gcc_version_partial_version(self):
        """Test detecting GCC with partial version."""
        strings = ["GNU C Library 2.31"]
        result = detect_gcc_version(strings)
        assert "2.31" in result

    def test_detect_gcc_version_no_match(self):
        """Test when GCC is not found."""
        strings = ["some other string"]
        result = detect_gcc_version(strings)
        assert "Unknown" in result

    def test_detect_gcc_version_empty_list(self):
        """Test with empty string list."""
        result = detect_gcc_version([])
        assert "Unknown" in result

    def test_detect_gcc_version_case_insensitive(self):
        """Test case insensitive matching."""
        strings = ["gcc 10.2.0"]
        result = detect_gcc_version(strings)
        assert "10.2.0" in result


class TestDetectClangVersion:
    """Tests for detect_clang_version function."""

    def test_detect_clang_version_full(self):
        """Test detecting Clang with full version."""
        strings = ["clang 12.0.1"]
        result = detect_clang_version(strings)
        assert "12.0.1" in result

    def test_detect_clang_version_apple(self):
        """Test detecting Apple Clang."""
        strings = ["Apple clang 13.0"]
        result = detect_clang_version(strings)
        assert "13.0" in result

    def test_detect_clang_version_no_match(self):
        """Test when Clang is not found."""
        strings = ["some random string"]
        result = detect_clang_version(strings)
        assert "Unknown" in result

    def test_detect_clang_version_empty_list(self):
        """Test with empty string list."""
        result = detect_clang_version([])
        assert "Unknown" in result


class TestDetectGoVersion:
    """Tests for detect_go_version function."""

    def test_detect_go_version_standard(self):
        """Test detecting Go version."""
        strings = ["go1.16.3"]
        result = detect_go_version(strings)
        assert "1.16.3" in result

    def test_detect_go_version_no_match(self):
        """Test when Go is not found."""
        strings = ["some random string"]
        result = detect_go_version(strings)
        assert "Unknown" in result

    def test_detect_go_version_empty_list(self):
        """Test with empty string list."""
        result = detect_go_version([])
        assert "Unknown" in result


class TestDetectRustVersion:
    """Tests for detect_rust_version function."""

    def test_detect_rust_version_standard(self):
        """Test detecting Rust version."""
        strings = ["rustc 1.52.1"]
        result = detect_rust_version(strings)
        assert "1.52.1" in result

    def test_detect_rust_version_no_match(self):
        """Test when Rust is not found."""
        strings = ["some random string"]
        result = detect_rust_version(strings)
        assert "Unknown" in result

    def test_detect_rust_version_empty_list(self):
        """Test with empty string list."""
        result = detect_rust_version([])
        assert "Unknown" in result


class TestParseStringsOutput:
    """Tests for parse_strings_output function."""

    def test_parse_strings_output_empty(self):
        """Test parsing empty output."""
        result = parse_strings_output("")
        assert result == []

    def test_parse_strings_output_single_line(self):
        """Test parsing single line."""
        output = "   4 0x1000 8 /bin/bash"
        result = parse_strings_output(output)
        assert "/bin/bash" in result

    def test_parse_strings_output_multiple_lines(self):
        """Test parsing multiple lines."""
        output = "   4 0x1000 8 /bin/bash\n   6 0x2000 10 /usr/lib/libc"
        result = parse_strings_output(output)
        assert len(result) == 2
        assert "/bin/bash" in result
        assert "/usr/lib/libc" in result

    def test_parse_strings_output_insufficient_columns(self):
        """Test lines with insufficient columns are skipped."""
        output = "   4 0x1000\n   6 0x2000 10 /usr/lib"
        result = parse_strings_output(output)
        assert "/usr/lib" in result

    def test_parse_strings_output_empty_lines(self):
        """Test empty lines are ignored."""
        output = "   4 0x1000 8 /bin/bash\n\n   6 0x2000 10 /usr/lib"
        result = parse_strings_output(output)
        assert len(result) == 2

    def test_parse_strings_output_whitespace_handling(self):
        """Test whitespace handling in output."""
        output = "   4   0x1000   8   /bin/bash"
        result = parse_strings_output(output)
        assert "/bin/bash" in result


class TestExtractImportNames:
    """Tests for extract_import_names function."""

    def test_extract_import_names_empty(self):
        """Test with empty list."""
        result = extract_import_names([])
        assert result == []

    def test_extract_import_names_with_libname(self):
        """Test extracting libname field."""
        imports = [{"libname": "kernel32.dll"}]
        result = extract_import_names(imports)
        assert "kernel32.dll" in result

    def test_extract_import_names_with_name(self):
        """Test extracting name field."""
        imports = [{"name": "GetProcAddress"}]
        result = extract_import_names(imports)
        assert "GetProcAddress" in result

    def test_extract_import_names_both_fields(self):
        """Test extracting both fields from single entry."""
        imports = [{"libname": "kernel32.dll", "name": "GetProcAddress"}]
        result = extract_import_names(imports)
        assert "kernel32.dll" in result
        assert "GetProcAddress" in result

    def test_extract_import_names_multiple_entries(self):
        """Test with multiple import entries."""
        imports = [
            {"libname": "kernel32.dll"},
            {"name": "GetProcAddress"},
            {"libname": "ntdll.dll", "name": "NtCreateFile"},
        ]
        result = extract_import_names(imports)
        assert len(result) == 4
        assert "kernel32.dll" in result
        assert "GetProcAddress" in result
        assert "ntdll.dll" in result
        assert "NtCreateFile" in result

    def test_extract_import_names_skip_invalid(self):
        """Test that entries without fields are skipped."""
        imports = [
            {"libname": "kernel32.dll"},
            {"other_field": "value"},
        ]
        result = extract_import_names(imports)
        assert len(result) == 1
        assert "kernel32.dll" in result


class TestExtractSectionNames:
    """Tests for extract_section_names function."""

    def test_extract_section_names_empty(self):
        """Test with empty list."""
        result = extract_section_names([])
        assert result == []

    def test_extract_section_names_valid(self):
        """Test extracting section names."""
        sections = [{"name": ".text"}, {"name": ".data"}, {"name": ".bss"}]
        result = extract_section_names(sections)
        assert ".text" in result
        assert ".data" in result
        assert ".bss" in result

    def test_extract_section_names_skip_non_dict(self):
        """Test that non-dict entries are skipped."""
        sections = [
            {"name": ".text"},
            "invalid string",
            {"name": ".data"},
        ]
        result = extract_section_names(sections)
        assert len(result) == 2

    def test_extract_section_names_skip_missing_name(self):
        """Test that entries without name field are skipped."""
        sections = [
            {"name": ".text"},
            {"other_field": "value"},
            {"name": ".data"},
        ]
        result = extract_section_names(sections)
        assert len(result) == 2

    def test_extract_section_names_case_sensitive(self):
        """Test that names are preserved as-is."""
        sections = [{"name": ".TEXT"}, {"name": ".Data"}]
        result = extract_section_names(sections)
        assert ".TEXT" in result
        assert ".Data" in result


class TestExtractSymbolNames:
    """Tests for extract_symbol_names function."""

    def test_extract_symbol_names_empty(self):
        """Test with empty list."""
        result = extract_symbol_names([])
        assert result == []

    def test_extract_symbol_names_valid(self):
        """Test extracting symbol names."""
        symbols = [{"name": "main"}, {"name": "printf"}, {"name": "malloc"}]
        result = extract_symbol_names(symbols)
        assert "main" in result
        assert "printf" in result
        assert "malloc" in result

    def test_extract_symbol_names_skip_non_dict(self):
        """Test that non-dict entries are skipped."""
        symbols = [
            {"name": "main"},
            123,
            {"name": "printf"},
        ]
        result = extract_symbol_names(symbols)
        assert len(result) == 2

    def test_extract_symbol_names_skip_missing_name(self):
        """Test that entries without name field are skipped."""
        symbols = [
            {"name": "main"},
            {"address": 0x1000},
            {"name": "printf"},
        ]
        result = extract_symbol_names(symbols)
        assert len(result) == 2

    def test_extract_symbol_names_case_sensitive(self):
        """Test that names are preserved as-is."""
        symbols = [{"name": "Main"}, {"name": "PRINTF"}]
        result = extract_symbol_names(symbols)
        assert "Main" in result
        assert "PRINTF" in result

    def test_extract_symbol_names_with_decorations(self):
        """Test symbol names with C++ decorations."""
        symbols = [
            {"name": "_ZN3std4vecIiE3newEv"},
            {"name": "??0MyClass@@QEAA@XZ"},
        ]
        result = extract_symbol_names(symbols)
        assert "_ZN3std4vecIiE3newEv" in result
        assert "??0MyClass@@QEAA@XZ" in result
