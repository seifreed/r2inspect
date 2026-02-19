#!/usr/bin/env python3
"""Extra coverage tests for import_analyzer module."""

import pytest
from unittest.mock import MagicMock, patch
from r2inspect.modules.import_analyzer import ImportAnalyzer


class FakeAdapter:
    pass


def test_import_analyzer_init():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter, config=None)
    assert analyzer.adapter is adapter


def test_get_category():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    assert analyzer.get_category() == "metadata"


def test_get_description():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    assert "import" in analyzer.get_description().lower()


def test_supports_format():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    assert analyzer.supports_format("PE") is True
    assert analyzer.supports_format("PE32") is True
    assert analyzer.supports_format("DLL") is True
    assert analyzer.supports_format("ELF") is False


def test_get_risk_level():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    assert analyzer._get_risk_level(80) == "HIGH"
    assert analyzer._get_risk_level(50) == "MEDIUM"
    assert analyzer._get_risk_level(20) == "LOW"


def test_count_suspicious_indicators():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    result_data = {
        "api_analysis": {"suspicious_apis": ["a", "b"]},
        "obfuscation": {"indicators": ["c"]},
        "anomalies": {"count": 2}
    }
    count = analyzer._count_suspicious_indicators(result_data)
    assert count == 5


def test_get_imports():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    with patch.object(analyzer, '_cmdj', return_value=[{"name": "CreateFileA"}]):
        with patch.object(analyzer, '_analyze_import', return_value={"name": "CreateFileA"}):
            result = analyzer.get_imports()
            assert len(result) == 1


def test_get_imports_error():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    with patch.object(analyzer, '_cmdj', side_effect=Exception("test")):
        result = analyzer.get_imports()
        assert result == []


def test_analyze_import():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    imp = {"name": "CreateFileA", "plt": 0x1000, "libname": "kernel32.dll"}
    with patch.object(analyzer, '_calculate_risk_score', return_value={"risk_score": 50, "risk_level": "MEDIUM", "risk_tags": []}):
        result = analyzer._analyze_import(imp)
        assert result["name"] == "CreateFileA"


def test_analyze_import_error():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    imp = {"name": "CreateFileA"}
    with patch.object(analyzer, '_calculate_risk_score', side_effect=Exception("test")):
        result = analyzer._analyze_import(imp)
        assert "error" in result


def test_get_function_description():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    desc = analyzer._get_function_description("CreateFileA")
    assert "file" in desc.lower()


def test_get_import_statistics():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    with patch.object(analyzer, 'get_imports', return_value=[]):
        result = analyzer.get_import_statistics()
        assert result["total_imports"] == 0


def test_get_missing_imports():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    analyzer.adapter = None
    with patch.object(analyzer, '_cmdj', return_value=[]):
        with patch.object(analyzer, 'get_imports', return_value=[]):
            result = analyzer.get_missing_imports()
            assert isinstance(result, list)


def test_get_missing_imports_error():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    with patch.object(analyzer, 'get_imports', side_effect=Exception("test")):
        result = analyzer.get_missing_imports()
        assert result == []


def test_is_candidate_api_string():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    assert analyzer._is_candidate_api_string("CreateFileA", []) is True
    assert analyzer._is_candidate_api_string("abc", []) is False
    assert analyzer._is_candidate_api_string("CreateFileA", ["CreateFileA"]) is False


def test_matches_known_api():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    result = analyzer._matches_known_api("CreateFileA")
    assert isinstance(result, bool)


def test_analyze_api_usage():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    imports = [{"name": "CreateFileA", "category": "File"}]
    with patch('r2inspect.modules.import_analyzer.categorize_apis', return_value={}):
        with patch('r2inspect.modules.import_analyzer.assess_api_risk', return_value=([], 0)):
            result = analyzer.analyze_api_usage(imports)
            assert "categories" in result


def test_analyze_api_usage_empty():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    result = analyzer.analyze_api_usage([])
    assert result["risk_score"] == 0


def test_analyze_api_usage_error():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    with patch('r2inspect.modules.import_analyzer.categorize_apis', side_effect=Exception("test")):
        result = analyzer.analyze_api_usage([{"name": "test"}])
        assert result["risk_score"] == 0


def test_detect_api_obfuscation():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    imports = [{"name": "GetProcAddress"}]
    result = analyzer.detect_api_obfuscation(imports)
    assert result["detected"] is True


def test_detect_api_obfuscation_error():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    result = analyzer.detect_api_obfuscation(None)
    assert result["detected"] is False


def test_analyze_dll_dependencies():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    dlls = ["kernel32.dll", "user32.dll"]
    result = analyzer.analyze_dll_dependencies(dlls)
    assert "common_dlls" in result


def test_analyze_dll_dependencies_empty():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    result = analyzer.analyze_dll_dependencies([])
    assert result["common_dlls"] == []


def test_analyze_dll_dependencies_error():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    with patch('collections.Counter', side_effect=Exception("test")):
        result = analyzer.analyze_dll_dependencies(["test.dll"])
        assert result["common_dlls"] == []


def test_detect_import_anomalies_no_imports():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    result = analyzer.detect_import_anomalies([])
    assert result["count"] > 0


def test_detect_import_anomalies_error():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    result = analyzer.detect_import_anomalies(None)
    assert result["count"] >= 0


def test_check_import_forwarding():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    with patch.object(analyzer, '_cmdj', return_value=[]):
        result = analyzer.check_import_forwarding()
        assert result["detected"] is False


def test_check_import_forwarding_error():
    adapter = FakeAdapter()
    analyzer = ImportAnalyzer(adapter)
    with patch.object(analyzer, '_cmdj', side_effect=Exception("test")):
        result = analyzer.check_import_forwarding()
        assert result["detected"] is False
