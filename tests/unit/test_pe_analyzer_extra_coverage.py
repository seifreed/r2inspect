#!/usr/bin/env python3
"""Extra coverage tests for pe_analyzer module."""

import pytest
from unittest.mock import MagicMock, patch
from r2inspect.modules.pe_analyzer import PEAnalyzer


class FakeAdapter:
    pass


def test_pe_analyzer_init():
    adapter = FakeAdapter()
    analyzer = PEAnalyzer(adapter, config=None, filepath="/tmp/test.exe")
    assert analyzer.adapter is adapter
    assert str(analyzer.filepath) == "/tmp/test.exe"


def test_get_category():
    adapter = FakeAdapter()
    analyzer = PEAnalyzer(adapter)
    assert analyzer.get_category() == "format"


def test_get_description():
    adapter = FakeAdapter()
    analyzer = PEAnalyzer(adapter)
    assert "PE" in analyzer.get_description()


def test_supports_format():
    adapter = FakeAdapter()
    analyzer = PEAnalyzer(adapter)
    assert analyzer.supports_format("PE") is True
    assert analyzer.supports_format("PE32") is True
    assert analyzer.supports_format("PE32+") is True
    assert analyzer.supports_format("DLL") is True
    assert analyzer.supports_format("EXE") is True
    assert analyzer.supports_format("ELF") is False


def test_analyze():
    adapter = FakeAdapter()
    analyzer = PEAnalyzer(adapter, filepath="/tmp/test.exe")
    
    with patch('r2inspect.modules.pe_analyzer._get_pe_headers_info', return_value={}):
        with patch('r2inspect.modules.pe_analyzer._get_file_characteristics', return_value={}):
            with patch('r2inspect.modules.pe_analyzer._get_compilation_info', return_value={}):
                with patch.object(analyzer, 'get_security_features', return_value={}):
                    with patch('r2inspect.modules.pe_analyzer._get_subsystem_info', return_value={}):
                        with patch.object(analyzer, 'calculate_imphash', return_value="abc123"):
                            result = analyzer.analyze()
                            assert "imphash" in result


def test_get_security_features():
    adapter = FakeAdapter()
    analyzer = PEAnalyzer(adapter)
    
    with patch('r2inspect.modules.pe_analyzer._get_security_features', return_value={"ASLR": True}):
        result = analyzer.get_security_features()
        assert result == {"ASLR": True}


def test_get_resource_info():
    adapter = FakeAdapter()
    analyzer = PEAnalyzer(adapter)
    
    with patch('r2inspect.modules.pe_analyzer._get_resource_info', return_value=[]):
        result = analyzer.get_resource_info()
        assert isinstance(result, list)


def test_get_version_info():
    adapter = FakeAdapter()
    analyzer = PEAnalyzer(adapter)
    
    with patch('r2inspect.modules.pe_analyzer._get_version_info', return_value={}):
        result = analyzer.get_version_info()
        assert isinstance(result, dict)


def test_calculate_imphash():
    adapter = FakeAdapter()
    analyzer = PEAnalyzer(adapter)
    
    with patch('r2inspect.modules.pe_analyzer._calculate_imphash', return_value="abc123def456"):
        result = analyzer.calculate_imphash()
        assert result == "abc123def456"


def test_determine_pe_format():
    adapter = FakeAdapter()
    analyzer = PEAnalyzer(adapter)
    
    with patch('r2inspect.modules.pe_analyzer._determine_pe_format', return_value="PE32"):
        result = analyzer._determine_pe_format({"bits": 32}, None)
        assert result == "PE32"
