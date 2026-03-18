#!/usr/bin/env python3
"""Extra coverage tests for elf_analyzer module.

No unittest.mock, no MagicMock, no patch. Real objects and plain adapters only.
"""

import pytest
from r2inspect.modules.elf_analyzer import ELFAnalyzer


class FakeAdapter:
    """Adapter returning controlled responses via cmd/cmdj."""

    def __init__(self, file_info=None, cmd_responses=None, cmdj_responses=None):
        self._file_info = file_info or {"bin": {"arch": "x86", "bits": 64}}
        self._cmd_responses = cmd_responses or {}
        self._cmdj_responses = cmdj_responses or {}

    def get_file_info(self):
        return self._file_info

    def cmd(self, command):
        return self._cmd_responses.get(command, "")

    def cmdj(self, command, default=None):
        return self._cmdj_responses.get(command, default)


class ErrorFileInfoAdapter(FakeAdapter):
    """Adapter whose get_file_info raises."""

    def get_file_info(self):
        raise Exception("test error")


class ErrorCmdAdapter(FakeAdapter):
    """Adapter whose cmd/cmdj always raise."""

    def cmd(self, command):
        raise Exception("test error")

    def cmdj(self, command, default=None):
        raise Exception("test error")


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
    adapter = ErrorFileInfoAdapter()
    analyzer = ELFAnalyzer(adapter)
    result = analyzer._get_elf_headers()
    assert result == {}


def test_extract_comment_section():
    adapter = FakeAdapter()
    analyzer = ELFAnalyzer(adapter)
    result = analyzer._extract_comment_section()
    assert isinstance(result, dict)


def test_extract_dwarf_info():
    adapter = FakeAdapter()
    analyzer = ELFAnalyzer(adapter)
    result = analyzer._extract_dwarf_info()
    assert isinstance(result, dict)


def test_extract_build_id():
    adapter = FakeAdapter()
    analyzer = ELFAnalyzer(adapter)
    result = analyzer._extract_build_id()
    # Returns None or a string depending on adapter responses.
    assert result is None or isinstance(result, str)


def test_estimate_compile_time():
    adapter = FakeAdapter()
    analyzer = ELFAnalyzer(adapter)
    result = analyzer._estimate_compile_time()
    assert result == ""


def test_get_section_info():
    adapter = FakeAdapter()
    analyzer = ELFAnalyzer(adapter)
    result = analyzer._get_section_info()
    assert isinstance(result, list)


def test_get_section_info_error():
    adapter = ErrorCmdAdapter()
    analyzer = ELFAnalyzer(adapter)
    result = analyzer._get_section_info()
    assert result == []


def test_get_program_headers():
    adapter = FakeAdapter()
    analyzer = ELFAnalyzer(adapter)
    result = analyzer._get_program_headers()
    assert isinstance(result, list)


def test_get_program_headers_error():
    adapter = ErrorCmdAdapter()
    analyzer = ELFAnalyzer(adapter)
    result = analyzer._get_program_headers()
    assert result == []


def test_read_section_none():
    adapter = FakeAdapter()
    analyzer = ELFAnalyzer(adapter)
    result = analyzer._read_section(None, "psz")
    assert result is None


def test_read_section_no_adapter():
    adapter = FakeAdapter()
    analyzer = ELFAnalyzer(adapter)
    analyzer.adapter = None
    result = analyzer._read_section({"vaddr": 0x1000, "size": 100}, "psz")
    assert result is None


def test_get_compilation_info_error():
    """Test _get_compilation_info with adapter that raises on cmd/cmdj."""
    adapter = ErrorCmdAdapter()
    analyzer = ELFAnalyzer(adapter)
    result = analyzer._get_compilation_info()
    assert isinstance(result, dict)
