#!/usr/bin/env python3
"""Comprehensive tests for import_analyzer.py - focusing on real analysis without mocks."""

from unittest.mock import MagicMock

from r2inspect.modules.import_analyzer import ImportAnalyzer


class MinimalAdapter:
    """Minimal test adapter for import analysis."""
    
    def __init__(self):
        self.commands = {}
        self.json_commands = {}
        
    def cmd(self, command):
        return self.commands.get(command, "")
    
    def cmdj(self, command, default=None):
        return self.json_commands.get(command, default)


def test_import_analyzer_initialization():
    """Test ImportAnalyzer initialization."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    assert analyzer.adapter is adapter
    assert analyzer.api_categories is not None


def test_import_analyzer_initialization_with_config():
    """Test ImportAnalyzer initialization with config."""
    adapter = MinimalAdapter()
    config = MagicMock()
    analyzer = ImportAnalyzer(adapter, config=config)
    
    assert analyzer.config is config


def test_get_category():
    """Test get_category returns metadata."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    assert analyzer.get_category() == "metadata"


def test_get_description():
    """Test get_description returns description."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    desc = analyzer.get_description()
    assert isinstance(desc, str)
    assert len(desc) > 0


def test_supports_format_pe():
    """Test supports_format for PE files."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    assert analyzer.supports_format("PE") is True
    assert analyzer.supports_format("PE32") is True
    assert analyzer.supports_format("PE32+") is True
    assert analyzer.supports_format("DLL") is True
    assert analyzer.supports_format("EXE") is True


def test_supports_format_non_pe():
    """Test supports_format for non-PE files."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    assert analyzer.supports_format("ELF") is False
    assert analyzer.supports_format("MACHO") is False
    assert analyzer.supports_format("UNKNOWN") is False


def test_get_imports_empty():
    """Test get_imports with no imports."""
    adapter = MinimalAdapter()
    adapter.json_commands["iij"] = []
    analyzer = ImportAnalyzer(adapter)
    
    result = analyzer.get_imports()
    assert isinstance(result, list)
    assert len(result) == 0


def test_get_imports_basic():
    """Test get_imports with basic imports."""
    adapter = MinimalAdapter()
    imports = [
        {"name": "CreateFile", "plt": 0x1000, "libname": "kernel32.dll"},
        {"name": "printf", "plt": 0x2000, "libname": "msvcrt.dll"},
    ]
    adapter.json_commands["iij"] = imports
    analyzer = ImportAnalyzer(adapter)
    
    result = analyzer.get_imports()
    assert len(result) == 2
    assert result[0]["name"] == "CreateFile"
    assert result[1]["name"] == "printf"


def test_get_imports_error_handling():
    """Test get_imports handles errors gracefully."""
    adapter = MinimalAdapter()
    
    def raise_error(cmd, default=None):
        raise Exception("Test error")
    
    adapter.cmdj = raise_error
    analyzer = ImportAnalyzer(adapter)
    
    result = analyzer.get_imports()
    assert isinstance(result, list)
    assert len(result) == 0


def test_analyze_import_basic():
    """Test _analyze_import with basic import."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    imp = {
        "name": "CreateFile",
        "plt": 0x1000,
        "libname": "kernel32.dll",
        "ordinal": 0,
        "type": "FUNC",
    }
    
    result = analyzer._analyze_import(imp)
    
    assert result["name"] == "CreateFile"
    assert result["address"] == "0x1000"
    assert result["library"] == "kernel32.dll"
    assert "risk_score" in result
    assert "category" in result


def test_analyze_import_with_ordinal():
    """Test _analyze_import with ordinal import."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    imp = {
        "name": "",
        "plt": 0x1000,
        "libname": "unknown.dll",
        "ordinal": 123,
        "type": "FUNC",
    }
    
    result = analyzer._analyze_import(imp)
    
    assert result["name"] == ""
    assert result["ordinal"] == 123


def test_analyze_import_error_handling():
    """Test _analyze_import handles errors."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    imp = {}
    
    result = analyzer._analyze_import(imp)
    assert "name" in result


def test_calculate_risk_score_low_risk():
    """Test _calculate_risk_score for low risk API."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    result = analyzer._calculate_risk_score("printf")
    
    assert result["risk_score"] >= 0
    assert "risk_level" in result
    assert "risk_tags" in result


def test_calculate_risk_score_high_risk():
    """Test _calculate_risk_score for high risk API."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    result = analyzer._calculate_risk_score("CreateRemoteThread")
    
    assert result["risk_score"] >= 80
    assert result["risk_level"] in ["Critical", "High"]


def test_get_function_description():
    """Test _get_function_description returns descriptions."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    assert len(analyzer._get_function_description("CreateProcess")) > 0
    assert len(analyzer._get_function_description("VirtualAlloc")) > 0
    assert analyzer._get_function_description("UnknownFunc") == ""


def test_get_import_statistics_empty():
    """Test get_import_statistics with no imports."""
    adapter = MinimalAdapter()
    adapter.json_commands["iij"] = []
    analyzer = ImportAnalyzer(adapter)
    
    result = analyzer.get_import_statistics()
    
    assert result["total_imports"] == 0
    assert result["unique_libraries"] == 0


def test_get_import_statistics_basic():
    """Test get_import_statistics with imports."""
    adapter = MinimalAdapter()
    imports = [
        {"name": "CreateFile", "plt": 0x1000, "libname": "kernel32.dll"},
        {"name": "CreateProcess", "plt": 0x2000, "libname": "kernel32.dll"},
        {"name": "printf", "plt": 0x3000, "libname": "msvcrt.dll"},
    ]
    adapter.json_commands["iij"] = imports
    analyzer = ImportAnalyzer(adapter)
    
    result = analyzer.get_import_statistics()
    
    assert result["total_imports"] == 3
    assert result["unique_libraries"] == 2
    assert "category_distribution" in result
    assert "risk_distribution" in result


def test_get_import_statistics_error():
    """Test get_import_statistics handles errors."""
    adapter = MinimalAdapter()
    
    def raise_error(cmd, default=None):
        raise Exception("Test error")
    
    adapter.cmdj = raise_error
    analyzer = ImportAnalyzer(adapter)
    
    result = analyzer.get_import_statistics()
    assert result["total_imports"] == 0


def test_get_missing_imports_basic():
    """Test get_missing_imports detection."""
    adapter = MinimalAdapter()
    imports = [
        {"name": "CreateFile", "plt": 0x1000, "libname": "kernel32.dll"},
    ]
    strings = [
        {"string": "CreateProcess"},
        {"string": "Hello World"},
    ]
    adapter.json_commands["iij"] = imports
    adapter.json_commands["izj"] = strings
    analyzer = ImportAnalyzer(adapter)
    
    result = analyzer.get_missing_imports()
    
    assert isinstance(result, list)


def test_get_missing_imports_error():
    """Test get_missing_imports handles errors."""
    adapter = MinimalAdapter()
    
    def raise_error(cmd, default=None):
        raise Exception("Test error")
    
    adapter.cmdj = raise_error
    analyzer = ImportAnalyzer(adapter)
    
    result = analyzer.get_missing_imports()
    assert isinstance(result, list)


def test_is_candidate_api_string():
    """Test _is_candidate_api_string filtering."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    imported = ["CreateFile"]
    
    assert analyzer._is_candidate_api_string("CreateProcess", imported) is True
    assert analyzer._is_candidate_api_string("CreateFile", imported) is False
    assert analyzer._is_candidate_api_string("abc", imported) is False
    assert analyzer._is_candidate_api_string("ALLCAPS", imported) is False


def test_matches_known_api():
    """Test _matches_known_api detection."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    assert analyzer._matches_known_api("CreateProcess") is True
    assert analyzer._matches_known_api("UnknownAPI") is False


def test_analyze_api_usage_empty():
    """Test analyze_api_usage with empty imports."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    result = analyzer.analyze_api_usage([])
    
    assert result["categories"] == {}
    assert result["suspicious_apis"] == []
    assert result["risk_score"] == 0


def test_analyze_api_usage_basic():
    """Test analyze_api_usage with imports."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    imports = [
        {"name": "CreateFile", "category": "File"},
        {"name": "CreateProcess", "category": "Process"},
    ]
    
    result = analyzer.analyze_api_usage(imports)
    
    assert "categories" in result
    assert "risk_score" in result
    assert result["risk_score"] >= 0
    assert result["risk_score"] <= 100


def test_analyze_api_usage_error():
    """Test analyze_api_usage handles errors."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    result = analyzer.analyze_api_usage(None)
    assert result["categories"] == {}


def test_detect_api_obfuscation_empty():
    """Test detect_api_obfuscation with empty imports."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    result = analyzer.detect_api_obfuscation([])
    
    assert result["detected"] is True
    assert len(result["indicators"]) > 0
    assert result["score"] > 0


def test_detect_api_obfuscation_getprocaddress():
    """Test detect_api_obfuscation detects GetProcAddress."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    imports = [
        {"name": "GetProcAddress"},
    ]
    
    result = analyzer.detect_api_obfuscation(imports)
    
    assert result["detected"] is True
    assert len(result["indicators"]) > 0
    assert result["score"] > 0


def test_detect_api_obfuscation_loadlibrary():
    """Test detect_api_obfuscation detects LoadLibrary."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    imports = [
        {"name": "LoadLibraryA"},
    ]
    
    result = analyzer.detect_api_obfuscation(imports)
    
    assert result["detected"] is True


def test_detect_api_obfuscation_few_imports():
    """Test detect_api_obfuscation detects few imports."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    imports = [
        {"name": "func1"},
        {"name": "func2"},
    ]
    
    result = analyzer.detect_api_obfuscation(imports)
    
    assert result["detected"] is True


def test_detect_api_obfuscation_ordinal_only():
    """Test detect_api_obfuscation detects ordinal imports."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    imports = [
        {"name": "", "ordinal": 123},
        {"name": "", "ordinal": 456},
    ]
    
    result = analyzer.detect_api_obfuscation(imports)
    
    assert result["detected"] is True


def test_detect_api_obfuscation_error():
    """Test detect_api_obfuscation handles errors."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    result = analyzer.detect_api_obfuscation(None)
    assert result["detected"] is False


def test_analyze_dll_dependencies_empty():
    """Test analyze_dll_dependencies with empty list."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    result = analyzer.analyze_dll_dependencies([])
    
    assert result["common_dlls"] == []
    assert result["suspicious_dlls"] == []


def test_analyze_dll_dependencies_common():
    """Test analyze_dll_dependencies with common DLLs."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    dlls = ["kernel32.dll", "user32.dll", "msvcrt.dll"]
    
    result = analyzer.analyze_dll_dependencies(dlls)
    
    assert len(result["common_dlls"]) == 3
    assert "analysis" in result


def test_analyze_dll_dependencies_suspicious():
    """Test analyze_dll_dependencies with suspicious DLLs."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    dlls = ["psapi.dll", "dbghelp.dll"]
    
    result = analyzer.analyze_dll_dependencies(dlls)
    
    assert len(result["suspicious_dlls"]) == 2


def test_analyze_dll_dependencies_mixed():
    """Test analyze_dll_dependencies with mixed DLLs."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    dlls = ["kernel32.dll", "psapi.dll", "unknown.dll"]
    
    result = analyzer.analyze_dll_dependencies(dlls)
    
    assert len(result["common_dlls"]) >= 1
    assert len(result["suspicious_dlls"]) >= 1
    assert result["analysis"]["total_dlls"] == 3


def test_analyze_dll_dependencies_error():
    """Test analyze_dll_dependencies handles errors."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    result = analyzer.analyze_dll_dependencies(None)
    assert result["common_dlls"] == []


def test_detect_import_anomalies_no_imports():
    """Test detect_import_anomalies with no imports."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    result = analyzer.detect_import_anomalies([])
    
    assert result["count"] > 0
    assert len(result["anomalies"]) > 0


def test_detect_import_anomalies_duplicates():
    """Test detect_import_anomalies detects duplicates."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    imports = [
        {"name": "CreateFile"},
        {"name": "CreateFile"},
    ]
    
    result = analyzer.detect_import_anomalies(imports)
    
    assert result["count"] > 0


def test_detect_import_anomalies_excessive():
    """Test detect_import_anomalies detects excessive imports."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    imports = [{"name": f"func{i}"} for i in range(501)]
    
    result = analyzer.detect_import_anomalies(imports)
    
    assert result["count"] > 0


def test_detect_import_anomalies_error():
    """Test detect_import_anomalies handles errors."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    result = analyzer.detect_import_anomalies([])
    assert result["count"] >= 0


def test_check_import_forwarding_basic():
    """Test check_import_forwarding detection."""
    adapter = MinimalAdapter()
    adapter.json_commands["izj"] = []
    analyzer = ImportAnalyzer(adapter)
    
    result = analyzer.check_import_forwarding()
    
    assert result["detected"] is False
    assert result["forwards"] == []


def test_check_import_forwarding_error():
    """Test check_import_forwarding handles errors."""
    adapter = MinimalAdapter()
    
    def raise_error(cmd, default=None):
        raise Exception("Test error")
    
    adapter.cmdj = raise_error
    analyzer = ImportAnalyzer(adapter)
    
    result = analyzer.check_import_forwarding()
    assert result["detected"] is False


def test_get_risk_level():
    """Test _get_risk_level classification."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    assert analyzer._get_risk_level(80) == "HIGH"
    assert analyzer._get_risk_level(50) == "MEDIUM"
    assert analyzer._get_risk_level(30) == "LOW"


def test_count_suspicious_indicators():
    """Test _count_suspicious_indicators calculation."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    result = {
        "api_analysis": {"suspicious_apis": ["api1", "api2"]},
        "obfuscation": {"indicators": ["ind1"]},
        "anomalies": {"count": 2},
    }
    
    count = analyzer._count_suspicious_indicators(result)
    assert count == 5


def test_analyze_complete_flow():
    """Test complete analyze flow."""
    adapter = MinimalAdapter()
    imports = [
        {"name": "CreateFile", "plt": 0x1000, "libname": "kernel32.dll"},
        {"name": "CreateProcess", "plt": 0x2000, "libname": "kernel32.dll"},
    ]
    adapter.json_commands["iij"] = imports
    adapter.json_commands["izj"] = []
    
    analyzer = ImportAnalyzer(adapter)
    result = analyzer.analyze()
    
    assert "total_imports" in result
    assert "total_dlls" in result
    assert "api_analysis" in result
    assert "obfuscation" in result
    assert "dll_analysis" in result
    assert "statistics" in result


def test_analyze_error_handling():
    """Test analyze handles errors."""
    adapter = MinimalAdapter()
    
    def raise_error(cmd, default=None):
        raise Exception("Test error")
    
    adapter.cmdj = raise_error
    analyzer = ImportAnalyzer(adapter)
    
    result = analyzer.analyze()
    assert "error" in result


def test_import_analyzer_api_categories_initialized():
    """Test that API categories are properly initialized."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    assert hasattr(analyzer, 'api_categories')
    assert isinstance(analyzer.api_categories, dict)
    assert len(analyzer.api_categories) > 0


def test_import_analyzer_risk_categories_initialized():
    """Test that risk categories are properly initialized."""
    adapter = MinimalAdapter()
    analyzer = ImportAnalyzer(adapter)
    
    assert hasattr(analyzer, '_risk_categories')
    assert isinstance(analyzer._risk_categories, dict)
    assert len(analyzer._risk_categories) > 0
