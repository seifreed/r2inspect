#!/usr/bin/env python3
"""Comprehensive tests for elf_analyzer - remaining coverage."""

from unittest.mock import MagicMock, Mock, patch

from r2inspect.modules.elf_analyzer import ELFAnalyzer


def test_analyze_complete_workflow():
    """Test analyze method complete workflow."""
    adapter = MagicMock()
    adapter.get_file_info.return_value = {
        "bin": {
            "arch": "x86",
            "machine": "AMD64",
            "bits": 64,
            "endian": "little",
            "class": "ELF64",
            "format": "elf",
            "baddr": 0x400000,
        }
    }
    
    analyzer = ELFAnalyzer(adapter)
    
    with patch.object(analyzer, '_get_compilation_info', return_value={"compiler": "gcc"}):
        with patch.object(analyzer, '_get_section_info', return_value=[]):
            with patch.object(analyzer, '_get_program_headers', return_value=[]):
                with patch.object(analyzer, 'get_security_features', return_value={}):
                    result = analyzer.analyze()
                    assert result["architecture"] == "x86"
                    assert result["bits"] == 64


def test_get_elf_headers_complete():
    """Test _get_elf_headers extracts all fields."""
    adapter = MagicMock()
    adapter.get_file_info.return_value = {
        "bin": {
            "arch": "arm",
            "machine": "ARM",
            "bits": 32,
            "endian": "big",
            "class": "ELF32",
            "format": "elf",
            "baddr": 0x8000,
        }
    }
    
    analyzer = ELFAnalyzer(adapter)
    result = analyzer._get_elf_headers()
    
    assert result["architecture"] == "arm"
    assert result["machine"] == "ARM"
    assert result["bits"] == 32
    assert result["endian"] == "big"
    assert result["type"] == "ELF32"
    assert result["format"] == "elf"
    assert result["entry_point"] == 0x8000


def test_get_elf_headers_missing_bin_info():
    """Test _get_elf_headers with missing bin info."""
    adapter = MagicMock()
    adapter.get_file_info.return_value = {}
    
    analyzer = ELFAnalyzer(adapter)
    result = analyzer._get_elf_headers()
    
    assert result == {}


def test_get_compilation_info_complete():
    """Test _get_compilation_info combines all sources."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    with patch.object(analyzer, '_extract_comment_section', return_value={"compiler": "gcc"}):
        with patch.object(analyzer, '_extract_dwarf_info', return_value={"compile_time": "2020"}):
            with patch.object(analyzer, '_extract_build_id', return_value="abc123"):
                result = analyzer._get_compilation_info()
                assert result["compiler"] == "gcc"
                assert result["compile_time"] == "2020"
                assert result["build_id"] == "abc123"


def test_get_compilation_info_with_estimate():
    """Test _get_compilation_info uses estimate when no compile time."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    with patch.object(analyzer, '_extract_comment_section', return_value={}):
        with patch.object(analyzer, '_extract_dwarf_info', return_value={}):
            with patch.object(analyzer, '_extract_build_id', return_value=None):
                with patch.object(analyzer, '_estimate_compile_time', return_value=""):
                    result = analyzer._get_compilation_info()
                    assert result["compile_time"] == ""


def test_extract_comment_section_with_data():
    """Test _extract_comment_section extracts and parses data."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    sections = [{"name": ".comment", "vaddr": 0x1000, "size": 100}]
    comment_data = "GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0"
    
    with patch.object(analyzer, '_cmd_list', return_value=sections):
        with patch.object(analyzer, '_read_section', return_value=comment_data):
            with patch.object(analyzer, '_parse_comment_compiler_info', return_value={"compiler": "gcc", "version": "9.3.0"}):
                result = analyzer._extract_comment_section()
                assert result["comment"] == comment_data.strip()
                assert result["compiler"] == "gcc"


def test_extract_comment_section_no_section():
    """Test _extract_comment_section with no .comment section."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    sections = [{"name": ".text", "vaddr": 0x1000, "size": 100}]
    
    with patch.object(analyzer, '_cmd_list', return_value=sections):
        result = analyzer._extract_comment_section()
        assert result == {}


def test_extract_comment_section_no_data():
    """Test _extract_comment_section with no data read."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    sections = [{"name": ".comment", "vaddr": 0x1000, "size": 100}]
    
    with patch.object(analyzer, '_cmd_list', return_value=sections):
        with patch.object(analyzer, '_read_section', return_value=None):
            result = analyzer._extract_comment_section()
            assert result == {}


def test_extract_dwarf_info_with_data():
    """Test _extract_dwarf_info extracts debug info."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    debug_output = """DW_AT_producer: GNU C17 9.3.0
DW_AT_compile_time: 2020-01-01
Other debug info"""
    
    with patch.object(analyzer, '_cmd', return_value=debug_output):
        with patch.object(analyzer, '_parse_dwarf_info', return_value={"producer": "GNU C17", "version": "9.3.0"}):
            result = analyzer._extract_dwarf_info()
            assert "producer" in result


def test_extract_dwarf_info_no_debug():
    """Test _extract_dwarf_info with no debug info."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    with patch.object(analyzer, '_cmd', return_value="No debug info"):
        result = analyzer._extract_dwarf_info()
        assert result == {}


def test_extract_build_id_with_section():
    """Test _extract_build_id extracts build ID."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    sections = [{"name": ".note.gnu.build-id", "vaddr": 0x1000, "size": 100}]
    build_id_data = "04 00 00 00 14 00 00 00 03 00 00 00 47 4e 55 00 ab cd ef 12 34 56 78 90"
    
    with patch.object(analyzer, '_cmd_list', return_value=sections):
        with patch.object(analyzer, '_read_section', return_value=build_id_data):
            with patch.object(analyzer, '_parse_build_id_data', return_value="abcdef1234567890"):
                result = analyzer._extract_build_id()
                assert result == "abcdef1234567890"


def test_extract_build_id_no_section():
    """Test _extract_build_id with no build-id section."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    sections = [{"name": ".text", "vaddr": 0x1000, "size": 100}]
    
    with patch.object(analyzer, '_cmd_list', return_value=sections):
        result = analyzer._extract_build_id()
        assert result is None


def test_get_section_info_with_sections():
    """Test _get_section_info extracts sections."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    sections_info = [
        {"name": ".text", "type": "PROGBITS", "flags": "rx", "size": 1000, "vaddr": 0x1000, "paddr": 0x1000},
        {"name": ".data", "type": "PROGBITS", "flags": "rw", "size": 500, "vaddr": 0x2000, "paddr": 0x2000},
    ]
    
    with patch.object(analyzer, '_cmd_list', return_value=sections_info):
        result = analyzer._get_section_info()
        assert len(result) == 2
        assert result[0]["name"] == ".text"
        assert result[1]["name"] == ".data"


def test_get_section_info_no_sections():
    """Test _get_section_info with no sections."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    with patch.object(analyzer, '_cmd_list', return_value=None):
        result = analyzer._get_section_info()
        assert result == []


def test_get_program_headers_with_headers():
    """Test _get_program_headers extracts headers."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    headers_info = [
        {"type": "LOAD", "flags": "r-x", "offset": 0, "vaddr": 0x400000, "paddr": 0x400000, "filesz": 1000, "memsz": 1000},
        {"type": "LOAD", "flags": "rw-", "offset": 0x1000, "vaddr": 0x600000, "paddr": 0x600000, "filesz": 500, "memsz": 1000},
    ]
    
    with patch('r2inspect.modules.elf_analyzer.get_elf_headers', return_value=headers_info):
        result = analyzer._get_program_headers()
        assert len(result) == 2
        assert result[0]["type"] == "LOAD"
        assert result[1]["memsz"] == 1000


def test_get_program_headers_no_headers():
    """Test _get_program_headers with no headers."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    with patch('r2inspect.modules.elf_analyzer.get_elf_headers', return_value=None):
        result = analyzer._get_program_headers()
        assert result == []


def test_read_section_with_psz_command():
    """Test _read_section with psz command."""
    adapter = MagicMock()
    adapter.read_bytes.return_value = b"Test string\x00extra"
    
    analyzer = ELFAnalyzer(adapter)
    section = {"vaddr": 0x1000, "size": 100}
    
    result = analyzer._read_section(section, "psz")
    assert result == "Test string"


def test_read_section_with_px_command():
    """Test _read_section with px command."""
    adapter = MagicMock()
    adapter.read_bytes.return_value = b"\x01\x02\x03\x04"
    
    analyzer = ELFAnalyzer(adapter)
    section = {"vaddr": 0x1000, "size": 4}
    
    result = analyzer._read_section(section, "px")
    assert result == "01 02 03 04"


def test_read_section_with_other_command():
    """Test _read_section with other command."""
    adapter = MagicMock()
    adapter.read_bytes.return_value = b"Test data"
    
    analyzer = ELFAnalyzer(adapter)
    section = {"vaddr": 0x1000, "size": 9}
    
    result = analyzer._read_section(section, "other")
    assert result == "Test data"


def test_read_section_no_vaddr():
    """Test _read_section with no vaddr."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    section = {"vaddr": 0, "size": 100}
    
    result = analyzer._read_section(section, "psz")
    assert result is None


def test_read_section_no_size():
    """Test _read_section with no size."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    section = {"vaddr": 0x1000, "size": 0}
    
    result = analyzer._read_section(section, "psz")
    assert result is None


def test_read_section_adapter_no_read_bytes():
    """Test _read_section with adapter without read_bytes."""
    adapter = Mock(spec=[])
    analyzer = ELFAnalyzer(Mock())
    analyzer.adapter = adapter
    section = {"vaddr": 0x1000, "size": 100}
    
    result = analyzer._read_section(section, "psz")
    assert result is None


def test_parse_comment_compiler_info():
    """Test _parse_comment_compiler_info delegates correctly."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    comment_data = "GCC: (Ubuntu) 9.3.0"
    
    with patch('r2inspect.modules.elf_analyzer.parse_comment_compiler_info', return_value={"compiler": "gcc"}):
        result = analyzer._parse_comment_compiler_info(comment_data)
        assert result == {"compiler": "gcc"}


def test_parse_dwarf_info():
    """Test _parse_dwarf_info delegates correctly."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    dwarf_lines = ["DW_AT_producer: GNU C", "DW_AT_compile_time: 2020"]
    
    with patch('r2inspect.modules.elf_analyzer.parse_dwarf_info', return_value={"producer": "GNU C"}):
        result = analyzer._parse_dwarf_info(dwarf_lines)
        assert result == {"producer": "GNU C"}


def test_parse_dwarf_producer():
    """Test _parse_dwarf_producer delegates correctly."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    line = "DW_AT_producer: GNU C17 9.3.0"
    
    with patch('r2inspect.modules.elf_analyzer.parse_dwarf_producer', return_value={"producer": "GNU C17"}):
        result = analyzer._parse_dwarf_producer(line)
        assert result == {"producer": "GNU C17"}


def test_parse_dwarf_compile_time():
    """Test _parse_dwarf_compile_time delegates correctly."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    line = "DW_AT_compile_time: 2020-01-01"
    
    with patch('r2inspect.modules.elf_analyzer.parse_dwarf_compile_time', return_value="2020-01-01"):
        result = analyzer._parse_dwarf_compile_time(line)
        assert result == "2020-01-01"


def test_parse_build_id_data():
    """Test _parse_build_id_data delegates correctly."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    build_id_data = "ab cd ef 12"
    
    with patch('r2inspect.modules.elf_analyzer.parse_build_id_data', return_value="abcdef12"):
        result = analyzer._parse_build_id_data(build_id_data)
        assert result == "abcdef12"


def test_get_security_features():
    """Test get_security_features delegates correctly."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    with patch('r2inspect.modules.elf_analyzer._get_security_features', return_value={"NX": True, "PIE": True}):
        result = analyzer.get_security_features()
        assert result == {"NX": True, "PIE": True}


def test_extract_comment_section_exception():
    """Test _extract_comment_section handles exception."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    with patch.object(analyzer, '_cmd_list', side_effect=Exception("Test error")):
        result = analyzer._extract_comment_section()
        assert result == {}


def test_extract_dwarf_info_exception():
    """Test _extract_dwarf_info handles exception."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    with patch.object(analyzer, '_cmd', side_effect=Exception("Test error")):
        result = analyzer._extract_dwarf_info()
        assert result == {}


def test_extract_build_id_exception():
    """Test _extract_build_id handles exception."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    with patch.object(analyzer, '_cmd_list', side_effect=Exception("Test error")):
        result = analyzer._extract_build_id()
        assert result is None


def test_supports_format_case_insensitive():
    """Test supports_format is case insensitive."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    assert analyzer.supports_format("elf") is True
    assert analyzer.supports_format("Elf32") is True
    assert analyzer.supports_format("ELF64") is True
    assert analyzer.supports_format("elf64") is True


def test_get_section_info_with_defaults():
    """Test _get_section_info handles missing fields."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    sections_info = [
        {"name": ".text"},
        {},
    ]
    
    with patch.object(analyzer, '_cmd_list', return_value=sections_info):
        result = analyzer._get_section_info()
        assert len(result) == 2
        assert result[0]["name"] == ".text"
        assert result[0]["type"] == "Unknown"
        assert result[1]["name"] == "Unknown"


def test_get_program_headers_with_defaults():
    """Test _get_program_headers handles missing fields."""
    adapter = MagicMock()
    analyzer = ELFAnalyzer(adapter)
    
    headers_info = [
        {"type": "LOAD"},
        {},
    ]
    
    with patch('r2inspect.modules.elf_analyzer.get_elf_headers', return_value=headers_info):
        result = analyzer._get_program_headers()
        assert len(result) == 2
        assert result[0]["type"] == "LOAD"
        assert result[0]["flags"] == ""
        assert result[1]["type"] == "Unknown"
