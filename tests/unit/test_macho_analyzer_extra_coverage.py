#!/usr/bin/env python3
"""Extra coverage tests for macho_analyzer module."""

import pytest
from unittest.mock import MagicMock, patch
from r2inspect.modules.macho_analyzer import MachOAnalyzer


class FakeAdapter:
    pass


def test_macho_analyzer_init():
    adapter = FakeAdapter()
    analyzer = MachOAnalyzer(adapter, config=None)
    assert analyzer.adapter is adapter


def test_get_category():
    adapter = FakeAdapter()
    analyzer = MachOAnalyzer(adapter)
    assert analyzer.get_category() == "format"


def test_get_description():
    adapter = FakeAdapter()
    analyzer = MachOAnalyzer(adapter)
    assert "Mach-O" in analyzer.get_description()


def test_supports_format():
    adapter = FakeAdapter()
    analyzer = MachOAnalyzer(adapter)
    assert analyzer.supports_format("MACH0") is True
    assert analyzer.supports_format("MACHO") is True
    assert analyzer.supports_format("MACH-O") is True
    assert analyzer.supports_format("PE") is False


def test_get_macho_headers():
    adapter = FakeAdapter()
    analyzer = MachOAnalyzer(adapter)
    with patch.object(analyzer, '_cmdj', return_value={}):
        result = analyzer._get_macho_headers()
        assert isinstance(result, dict)


def test_get_macho_headers_error():
    adapter = FakeAdapter()
    analyzer = MachOAnalyzer(adapter)
    with patch.object(analyzer, '_cmdj', side_effect=Exception("test")):
        result = analyzer._get_macho_headers()
        assert result == {}


def test_extract_build_version():
    adapter = FakeAdapter()
    analyzer = MachOAnalyzer(adapter)
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', return_value=[]):
        result = analyzer._extract_build_version()
        assert isinstance(result, dict)


def test_extract_version_min():
    adapter = FakeAdapter()
    analyzer = MachOAnalyzer(adapter)
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', return_value=[]):
        result = analyzer._extract_version_min()
        assert isinstance(result, dict)


def test_extract_dylib_info():
    adapter = FakeAdapter()
    analyzer = MachOAnalyzer(adapter)
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', return_value=[]):
        result = analyzer._extract_dylib_info()
        assert isinstance(result, dict)


def test_extract_uuid():
    adapter = FakeAdapter()
    analyzer = MachOAnalyzer(adapter)
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', return_value=[]):
        result = analyzer._extract_uuid()
        assert result is None


def test_extract_uuid_error():
    adapter = FakeAdapter()
    analyzer = MachOAnalyzer(adapter)
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', side_effect=Exception("test")):
        result = analyzer._extract_uuid()
        assert result is None


def test_estimate_from_sdk_version():
    adapter = FakeAdapter()
    analyzer = MachOAnalyzer(adapter)
    with patch('r2inspect.modules.macho_analyzer.estimate_from_sdk_version', return_value="2020"):
        result = analyzer._estimate_from_sdk_version("14.0")
        assert result == "2020"


def test_estimate_from_sdk_version_error():
    adapter = FakeAdapter()
    analyzer = MachOAnalyzer(adapter)
    with patch('r2inspect.modules.macho_analyzer.estimate_from_sdk_version', side_effect=Exception("test")):
        result = analyzer._estimate_from_sdk_version("14.0")
        assert result is None


def test_estimate_compile_time():
    adapter = FakeAdapter()
    analyzer = MachOAnalyzer(adapter)
    result = analyzer._estimate_compile_time()
    assert result == ""


def test_get_load_commands():
    adapter = FakeAdapter()
    analyzer = MachOAnalyzer(adapter)
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', return_value=[]):
        with patch('r2inspect.modules.macho_analyzer.build_load_commands', return_value=[]):
            result = analyzer._get_load_commands()
            assert isinstance(result, list)


def test_get_load_commands_error():
    adapter = FakeAdapter()
    analyzer = MachOAnalyzer(adapter)
    with patch('r2inspect.modules.macho_analyzer.get_macho_headers', side_effect=Exception("test")):
        result = analyzer._get_load_commands()
        assert result == []


def test_get_section_info():
    adapter = FakeAdapter()
    analyzer = MachOAnalyzer(adapter)
    analyzer.adapter = None
    with patch('r2inspect.modules.macho_analyzer.build_sections', return_value=[]):
        result = analyzer._get_section_info()
        assert isinstance(result, list)


def test_get_section_info_error():
    adapter = FakeAdapter()
    analyzer = MachOAnalyzer(adapter)
    with patch('r2inspect.modules.macho_analyzer.build_sections', side_effect=Exception("test")):
        result = analyzer._get_section_info()
        assert result == []


def test_get_compilation_info_error():
    adapter = FakeAdapter()
    analyzer = MachOAnalyzer(adapter)
    with patch.object(analyzer, '_extract_build_version', side_effect=Exception("test")):
        result = analyzer._get_compilation_info()
        assert isinstance(result, dict)
