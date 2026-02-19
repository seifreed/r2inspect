#!/usr/bin/env python3
"""Extra coverage tests for elf_analyzer module."""

import pytest
from unittest.mock import MagicMock, patch
from r2inspect.modules.elf_analyzer import ELFAnalyzer


class FakeAdapter:
    def __init__(self):
        self.file_info = {"bin": {"arch": "x86", "bits": 64}}
    
    def get_file_info(self):
        return self.file_info


def test_elf_analyzer_init():
    adapter = FakeAdapter()
    analyzer = ELFAnalyzer(adapter, config=None)
    assert analyzer.adapter is adapter


def test_get_category():
    adapter = FakeAdapter()
    analyzer = ELFAnalyzer(adapter)
    assert analyzer.get_category() == "format"


def test_get_description():
    adapter = FakeAdapter()
    analyzer = ELFAnalyzer(adapter)
    assert "ELF" in analyzer.get_description()


def test_supports_format():
    adapter = FakeAdapter()
    analyzer = ELFAnalyzer(adapter)
    assert analyzer.supports_format("ELF") is True
    assert analyzer.supports_format("ELF32") is True
    assert analyzer.supports_format("ELF64") is True
    assert analyzer.supports_format("PE") is False


def test_get_elf_headers():
    adapter = FakeAdapter()
    analyzer = ELFAnalyzer(adapter)
    result = analyzer._get_elf_headers()
    assert "architecture" in result


def test_get_elf_headers_error():
    adapter = FakeAdapter()
    adapter.get_file_info = MagicMock(side_effect=Exception("test"))
    analyzer = ELFAnalyzer(adapter)
    result = analyzer._get_elf_headers()
    assert result == {}


def test_extract_comment_section():
    adapter = FakeAdapter()
    analyzer = ELFAnalyzer(adapter)
    with patch.object(analyzer, '_cmd_list', return_value=[]):
        result = analyzer._extract_comment_section()
        assert result == {}


def test_extract_dwarf_info():
    adapter = FakeAdapter()
    analyzer = ELFAnalyzer(adapter)
    with patch.object(analyzer, '_cmd', return_value="No debug info"):
        result = analyzer._extract_dwarf_info()
        assert result == {}


def test_extract_build_id():
    adapter = FakeAdapter()
    analyzer = ELFAnalyzer(adapter)
    with patch.object(analyzer, '_cmd_list', return_value=[]):
        result = analyzer._extract_build_id()
        assert result is None


def test_estimate_compile_time():
    adapter = FakeAdapter()
    analyzer = ELFAnalyzer(adapter)
    result = analyzer._estimate_compile_time()
    assert result == ""


def test_get_section_info():
    adapter = FakeAdapter()
    analyzer = ELFAnalyzer(adapter)
    with patch.object(analyzer, '_cmd_list', return_value=[]):
        result = analyzer._get_section_info()
        assert isinstance(result, list)


def test_get_section_info_error():
    adapter = FakeAdapter()
    analyzer = ELFAnalyzer(adapter)
    with patch.object(analyzer, '_cmd_list', side_effect=Exception("test")):
        result = analyzer._get_section_info()
        assert result == []


def test_get_program_headers():
    adapter = FakeAdapter()
    analyzer = ELFAnalyzer(adapter)
    with patch('r2inspect.modules.elf_analyzer.get_elf_headers', return_value=[]):
        result = analyzer._get_program_headers()
        assert isinstance(result, list)


def test_get_program_headers_error():
    adapter = FakeAdapter()
    analyzer = ELFAnalyzer(adapter)
    with patch('r2inspect.modules.elf_analyzer.get_elf_headers', side_effect=Exception("test")):
        result = analyzer._get_program_headers()
        assert result == []


def test_read_section_none():
    adapter = FakeAdapter()
    analyzer = ELFAnalyzer(adapter)
    result = analyzer._read_section(None, "psz")
    assert result is None


def test_read_section_no_adapter():
    adapter = None
    analyzer = ELFAnalyzer(FakeAdapter())
    analyzer.adapter = None
    result = analyzer._read_section({"vaddr": 0x1000, "size": 100}, "psz")
    assert result is None


def test_get_compilation_info_error():
    adapter = FakeAdapter()
    analyzer = ELFAnalyzer(adapter)
    with patch.object(analyzer, '_extract_comment_section', side_effect=Exception("test")):
        result = analyzer._get_compilation_info()
        assert isinstance(result, dict)
