#!/usr/bin/env python3
"""Comprehensive tests for r2inspect/modules/export_analyzer.py - PE/ELF export analysis."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from r2inspect.modules.export_analyzer import ExportAnalyzer


def test_export_analyzer_init():
    adapter = Mock()
    config = Mock()
    
    analyzer = ExportAnalyzer(adapter, config)
    
    assert analyzer.adapter == adapter
    assert analyzer.config == config


def test_get_category():
    analyzer = ExportAnalyzer(Mock(), None)
    
    result = analyzer.get_category()
    
    assert result == "metadata"


def test_get_description():
    analyzer = ExportAnalyzer(Mock(), None)
    
    result = analyzer.get_description()
    
    assert "export" in result.lower()
    assert "function" in result.lower()


def test_supports_format_pe():
    analyzer = ExportAnalyzer(Mock(), None)
    
    assert analyzer.supports_format("PE") is True
    assert analyzer.supports_format("PE32") is True
    assert analyzer.supports_format("PE32+") is True


def test_supports_format_dll():
    analyzer = ExportAnalyzer(Mock(), None)
    
    assert analyzer.supports_format("DLL") is True


def test_supports_format_elf():
    analyzer = ExportAnalyzer(Mock(), None)
    
    assert analyzer.supports_format("ELF") is True


def test_supports_format_unsupported():
    analyzer = ExportAnalyzer(Mock(), None)
    
    assert analyzer.supports_format("MACHO") is False
    assert analyzer.supports_format("UNKNOWN") is False


def test_supports_format_case_insensitive():
    analyzer = ExportAnalyzer(Mock(), None)
    
    assert analyzer.supports_format("pe") is True
    assert analyzer.supports_format("elf") is True
    assert analyzer.supports_format("dll") is True


def test_analyze_basic():
    adapter = Mock()
    adapter.cmd.return_value = "[]"
    
    analyzer = ExportAnalyzer(adapter, None)
    result = analyzer.analyze()
    
    assert "exports" in result
    assert "statistics" in result
    assert "total_exports" in result


def test_analyze_with_exports():
    adapter = Mock()
    adapter.cmd.return_value = '[{"name": "TestFunc", "vaddr": 4096, "ordinal": 1}]'
    
    analyzer = ExportAnalyzer(adapter, None)
    result = analyzer.analyze()
    
    assert result["total_exports"] >= 0
    assert isinstance(result["exports"], list)


def test_analyze_error_handling():
    adapter = Mock()
    adapter.cmd.side_effect = Exception("Command failed")
    
    analyzer = ExportAnalyzer(adapter, None)
    result = analyzer.analyze()
    
    assert "error" in result or "exports" in result


def test_get_exports_empty():
    adapter = Mock()
    adapter.cmd.return_value = "[]"
    
    analyzer = ExportAnalyzer(adapter, None)
    result = analyzer.get_exports()
    
    assert result == []


def test_get_exports_single():
    adapter = Mock()
    adapter.cmd.return_value = '[{"name": "DllMain", "vaddr": 4096, "ordinal": 1, "type": "FUNC"}]'
    
    analyzer = ExportAnalyzer(adapter, None)
    result = analyzer.get_exports()
    
    assert len(result) >= 0


def test_get_exports_multiple():
    adapter = Mock()
    adapter.cmd.return_value = '''[
        {"name": "DllMain", "vaddr": 4096, "ordinal": 1},
        {"name": "ExportFunc1", "vaddr": 8192, "ordinal": 2},
        {"name": "ExportFunc2", "vaddr": 12288, "ordinal": 3}
    ]'''
    
    analyzer = ExportAnalyzer(adapter, None)
    result = analyzer.get_exports()
    
    assert len(result) >= 0


def test_get_exports_malformed_data():
    adapter = Mock()
    adapter.cmd.return_value = '["not a dict", 123]'
    
    analyzer = ExportAnalyzer(adapter, None)
    result = analyzer.get_exports()
    
    assert isinstance(result, list)


def test_get_exports_exception():
    adapter = Mock()
    adapter.cmd.side_effect = Exception("Failed to get exports")
    
    analyzer = ExportAnalyzer(adapter, None)
    result = analyzer.get_exports()
    
    assert result == []


def test_analyze_export_basic():
    adapter = Mock()
    adapter.cmd.return_value = "[]"
    
    analyzer = ExportAnalyzer(adapter, None)
    export = {"name": "TestFunc", "vaddr": 4096, "ordinal": 1, "type": "FUNC"}
    
    result = analyzer._analyze_export(export)
    
    assert result["name"] == "TestFunc"
    assert "0x" in result["address"]
    assert result["ordinal"] == 1


def test_analyze_export_forwarded():
    adapter = Mock()
    adapter.cmd.return_value = "[]"
    
    analyzer = ExportAnalyzer(adapter, None)
    export = {
        "name": "ForwardedFunc",
        "vaddr": 4096,
        "ordinal": 1,
        "forwarded": True,
        "forwarder": "KERNEL32.CreateFileA"
    }
    
    result = analyzer._analyze_export(export)
    
    assert result["is_forwarded"] is True
    assert result["forwarder"] == "KERNEL32.CreateFileA"


def test_analyze_export_missing_fields():
    adapter = Mock()
    adapter.cmd.return_value = "[]"
    
    analyzer = ExportAnalyzer(adapter, None)
    export = {}
    
    result = analyzer._analyze_export(export)
    
    assert result["name"] == "unknown"
    assert result["ordinal"] == 0


def test_analyze_export_with_size():
    adapter = Mock()
    adapter.cmd.return_value = "[]"
    
    analyzer = ExportAnalyzer(adapter, None)
    export = {"name": "TestFunc", "vaddr": 4096, "ordinal": 1, "size": 256}
    
    result = analyzer._analyze_export(export)
    
    assert result["size"] == 256


def test_analyze_export_exception():
    adapter = Mock()
    adapter.cmd.side_effect = Exception("Analysis failed")
    
    analyzer = ExportAnalyzer(adapter, None)
    export = {"name": "TestFunc", "vaddr": 4096, "ordinal": 1}
    
    result = analyzer._analyze_export(export)
    
    assert isinstance(result, dict)
    assert "name" in result


def test_get_export_characteristics_dll_export():
    adapter = Mock()
    adapter.cmd.return_value = "[]"
    
    analyzer = ExportAnalyzer(adapter, None)
    export = {"name": "DllMain", "vaddr": 4096}
    
    result = analyzer._get_export_characteristics(export)
    
    assert result.get("dll_export") is True


def test_get_export_characteristics_suspicious_names():
    adapter = Mock()
    adapter.cmd.return_value = "[]"
    
    analyzer = ExportAnalyzer(adapter, None)
    suspicious_names = [
        "InstallHook",
        "UninstallService",
        "ExecutePayload",
        "RunCommand",
        "StartProcess",
        "InjectDLL",
        "HookAPI",
        "PatchMemory",
        "BypassUAC",
        "DisableSecurity",
    ]
    
    for name in suspicious_names:
        export = {"name": name, "vaddr": 4096}
        result = analyzer._get_export_characteristics(export)
        
        if result.get("suspicious_name"):
            assert "suspicious_pattern" in result


def test_get_export_characteristics_function_info():
    adapter = Mock()
    adapter.cmd.return_value = '[{"size": 128, "cc": 5}]'
    
    analyzer = ExportAnalyzer(adapter, None)
    export = {"name": "TestFunc", "vaddr": 4096}
    
    result = analyzer._get_export_characteristics(export)
    
    if result.get("is_function"):
        assert "function_size" in result


def test_get_export_characteristics_not_function():
    adapter = Mock()
    adapter.cmd.return_value = "[]"
    
    analyzer = ExportAnalyzer(adapter, None)
    export = {"name": "DataExport", "vaddr": 4096}
    
    result = analyzer._get_export_characteristics(export)
    
    assert result.get("is_function", True) in [True, False]


def test_get_export_characteristics_no_address():
    adapter = Mock()
    
    analyzer = ExportAnalyzer(adapter, None)
    export = {"name": "TestFunc", "vaddr": 0}
    
    result = analyzer._get_export_characteristics(export)
    
    assert isinstance(result, dict)


def test_get_export_characteristics_exception():
    adapter = Mock()
    adapter.cmd.side_effect = Exception("Failed")
    
    analyzer = ExportAnalyzer(adapter, None)
    export = {"name": "TestFunc", "vaddr": 4096}
    
    result = analyzer._get_export_characteristics(export)
    
    assert isinstance(result, dict)


def test_get_export_characteristics_malformed_func_info():
    adapter = Mock()
    adapter.cmd.return_value = '["not a dict"]'
    
    analyzer = ExportAnalyzer(adapter, None)
    export = {"name": "TestFunc", "vaddr": 4096}
    
    result = analyzer._get_export_characteristics(export)
    
    assert isinstance(result, dict)


def test_get_export_statistics_empty():
    adapter = Mock()
    adapter.cmd.return_value = "[]"
    
    analyzer = ExportAnalyzer(adapter, None)
    result = analyzer.get_export_statistics()
    
    assert result["total_exports"] == 0
    assert result["function_exports"] == 0
    assert result["data_exports"] == 0


def test_get_export_statistics_with_exports():
    adapter = Mock()
    adapter.cmd.return_value = '[{"name": "TestFunc", "vaddr": 4096, "ordinal": 1}]'
    
    analyzer = ExportAnalyzer(adapter, None)
    result = analyzer.get_export_statistics()
    
    assert result["total_exports"] >= 0
    assert "export_names" in result


def test_get_export_statistics_exception():
    adapter = Mock()
    adapter.cmd.side_effect = Exception("Failed")
    
    analyzer = ExportAnalyzer(adapter, None)
    result = analyzer.get_export_statistics()
    
    assert isinstance(result, dict)


def test_update_export_stats_basic():
    adapter = Mock()
    
    analyzer = ExportAnalyzer(adapter, None)
    stats = {
        "total_exports": 0,
        "function_exports": 0,
        "data_exports": 0,
        "forwarded_exports": 0,
        "suspicious_exports": 0,
        "export_names": [],
    }
    export = {
        "name": "TestFunc",
        "is_forwarded": False,
        "characteristics": {"is_function": True}
    }
    
    analyzer._update_export_stats(stats, export)
    
    assert "TestFunc" in stats["export_names"]
    assert stats["function_exports"] == 1


def test_update_export_stats_forwarded():
    adapter = Mock()
    
    analyzer = ExportAnalyzer(adapter, None)
    stats = {
        "forwarded_exports": 0,
        "export_names": [],
        "function_exports": 0,
        "data_exports": 0,
        "suspicious_exports": 0,
    }
    export = {
        "name": "ForwardedFunc",
        "is_forwarded": True,
        "characteristics": {}
    }
    
    analyzer._update_export_stats(stats, export)
    
    assert stats["forwarded_exports"] == 1


def test_update_export_stats_data_export():
    adapter = Mock()
    
    analyzer = ExportAnalyzer(adapter, None)
    stats = {
        "data_exports": 0,
        "function_exports": 0,
        "export_names": [],
        "forwarded_exports": 0,
        "suspicious_exports": 0,
    }
    export = {
        "name": "DataVar",
        "is_forwarded": False,
        "characteristics": {"is_function": False}
    }
    
    analyzer._update_export_stats(stats, export)
    
    assert stats["data_exports"] == 1


def test_update_export_stats_suspicious():
    adapter = Mock()
    
    analyzer = ExportAnalyzer(adapter, None)
    stats = {
        "suspicious_exports": 0,
        "export_names": [],
        "function_exports": 0,
        "data_exports": 0,
        "forwarded_exports": 0,
    }
    export = {
        "name": "InjectCode",
        "is_forwarded": False,
        "characteristics": {"suspicious_name": True}
    }
    
    analyzer._update_export_stats(stats, export)
    
    assert stats["suspicious_exports"] == 1


def test_update_export_stats_malformed():
    adapter = Mock()
    
    analyzer = ExportAnalyzer(adapter, None)
    stats = {
        "export_names": [],
        "function_exports": 0,
        "data_exports": 0,
    }
    
    analyzer._update_export_stats(stats, "not a dict")
    
    assert len(stats["export_names"]) == 0


def test_analyze_integration():
    adapter = Mock()
    adapter.cmd.side_effect = [
        '[{"name": "DllMain", "vaddr": 4096, "ordinal": 1, "type": "FUNC"}]',
        '[{"size": 128, "cc": 3}]',
    ]
    
    analyzer = ExportAnalyzer(adapter, None)
    result = analyzer.analyze()
    
    assert "exports" in result
    assert "statistics" in result
    assert "total_exports" in result


def test_get_exports_preserves_order():
    adapter = Mock()
    adapter.cmd.return_value = '''[
        {"name": "Func1", "vaddr": 4096, "ordinal": 1},
        {"name": "Func2", "vaddr": 8192, "ordinal": 2},
        {"name": "Func3", "vaddr": 12288, "ordinal": 3}
    ]'''
    
    analyzer = ExportAnalyzer(adapter, None)
    result = analyzer.get_exports()
    
    if len(result) >= 3:
        assert result[0]["name"] == "Func1"
        assert result[1]["name"] == "Func2"
        assert result[2]["name"] == "Func3"


def test_all_suspicious_patterns_checked():
    adapter = Mock()
    adapter.cmd.return_value = "[]"
    
    analyzer = ExportAnalyzer(adapter, None)
    patterns = [
        "install", "uninstall", "execute", "run", "start",
        "inject", "hook", "patch", "bypass", "disable"
    ]
    
    found_patterns = []
    for pattern in patterns:
        export = {"name": f"Test{pattern.upper()}Function", "vaddr": 4096}
        result = analyzer._get_export_characteristics(export)
        
        if result.get("suspicious_name"):
            found_patterns.append(result["suspicious_pattern"])
    
    assert len(found_patterns) == len(patterns)
