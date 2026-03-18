#!/usr/bin/env python3
"""Comprehensive tests for r2inspect/modules/export_analyzer.py - PE/ELF export analysis.

All tests use a real StubAdapter (no mocks, no monkeypatch, no @patch).
The adapter exposes get_exports() and get_function_info(addr) which are the
two r2 dispatch routes used by ExportAnalyzer via _cmd_list("iEj") and
_cmd_list("afij @ <addr>").
"""

from __future__ import annotations

from typing import Any

import pytest

from r2inspect.modules.export_analyzer import ExportAnalyzer


# ---------------------------------------------------------------------------
# Stub adapter -- routes through real r2_command_dispatch logic
# ---------------------------------------------------------------------------


class StubAdapter:
    """Fake adapter providing get_exports() and get_function_info(addr).

    Responses are fully deterministic and consumed without side-effects.
    """

    def __init__(
        self,
        exports: list[Any] | None = None,
        func_info_map: dict[int, list[Any]] | None = None,
        *,
        raise_on_exports: bool = False,
        raise_on_func_info: bool = False,
    ) -> None:
        self._exports = exports if exports is not None else []
        self._func_info_map = func_info_map or {}
        self._raise_on_exports = raise_on_exports
        self._raise_on_func_info = raise_on_func_info

    def get_exports(self) -> list[Any]:
        if self._raise_on_exports:
            raise RuntimeError("exports unavailable")
        return self._exports

    def get_function_info(self, address: int) -> list[Any]:
        if self._raise_on_func_info:
            raise RuntimeError("func info unavailable")
        return self._func_info_map.get(address, [])


def _make(
    exports: list[Any] | None = None,
    func_info_map: dict[int, list[Any]] | None = None,
    *,
    raise_on_exports: bool = False,
    raise_on_func_info: bool = False,
) -> ExportAnalyzer:
    adapter = StubAdapter(
        exports=exports,
        func_info_map=func_info_map,
        raise_on_exports=raise_on_exports,
        raise_on_func_info=raise_on_func_info,
    )
    return ExportAnalyzer(adapter=adapter, config=None)


# ---------------------------------------------------------------------------
# __init__ / basic properties
# ---------------------------------------------------------------------------


def test_export_analyzer_init():
    adapter = StubAdapter()
    analyzer = ExportAnalyzer(adapter, None)
    assert analyzer.adapter is adapter
    assert analyzer.config is None


def test_get_category():
    analyzer = _make()
    assert analyzer.get_category() == "metadata"


def test_get_description():
    analyzer = _make()
    result = analyzer.get_description()
    assert "export" in result.lower()
    assert "function" in result.lower()


# ---------------------------------------------------------------------------
# supports_format
# ---------------------------------------------------------------------------


def test_supports_format_pe():
    analyzer = _make()
    assert analyzer.supports_format("PE") is True
    assert analyzer.supports_format("PE32") is True
    assert analyzer.supports_format("PE32+") is True


def test_supports_format_dll():
    analyzer = _make()
    assert analyzer.supports_format("DLL") is True


def test_supports_format_elf():
    analyzer = _make()
    assert analyzer.supports_format("ELF") is True


def test_supports_format_unsupported():
    analyzer = _make()
    assert analyzer.supports_format("MACHO") is False
    assert analyzer.supports_format("UNKNOWN") is False


def test_supports_format_case_insensitive():
    analyzer = _make()
    assert analyzer.supports_format("pe") is True
    assert analyzer.supports_format("elf") is True
    assert analyzer.supports_format("dll") is True


# ---------------------------------------------------------------------------
# analyze() — full pipeline
# ---------------------------------------------------------------------------


def test_analyze_basic():
    analyzer = _make(exports=[])
    result = analyzer.analyze()

    assert "exports" in result
    assert "statistics" in result
    assert "total_exports" in result
    assert result["total_exports"] == 0


def test_analyze_with_exports():
    exports = [{"name": "TestFunc", "vaddr": 4096, "ordinal": 1}]
    analyzer = _make(exports=exports)
    result = analyzer.analyze()

    assert result["total_exports"] == 1
    assert isinstance(result["exports"], list)
    assert len(result["exports"]) == 1


def test_analyze_error_handling():
    analyzer = _make(raise_on_exports=True)
    result = analyzer.analyze()

    # Error path: exports fail, result still returned with defaults
    assert "exports" in result or "error" in result


# ---------------------------------------------------------------------------
# get_exports()
# ---------------------------------------------------------------------------


def test_get_exports_empty():
    analyzer = _make(exports=[])
    result = analyzer.get_exports()
    assert result == []


def test_get_exports_single():
    exports = [{"name": "DllMain", "vaddr": 4096, "ordinal": 1, "type": "FUNC"}]
    analyzer = _make(exports=exports)
    result = analyzer.get_exports()
    assert len(result) == 1
    assert result[0]["name"] == "DllMain"


def test_get_exports_multiple():
    exports = [
        {"name": "DllMain", "vaddr": 4096, "ordinal": 1},
        {"name": "ExportFunc1", "vaddr": 8192, "ordinal": 2},
        {"name": "ExportFunc2", "vaddr": 12288, "ordinal": 3},
    ]
    analyzer = _make(exports=exports)
    result = analyzer.get_exports()
    assert len(result) == 3


def test_get_exports_malformed_data():
    # Non-dict entries are skipped by the analyzer
    exports = ["not a dict", 123, {"name": "Valid", "vaddr": 0}]
    analyzer = _make(exports=exports)
    result = analyzer.get_exports()
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["name"] == "Valid"


def test_get_exports_exception():
    analyzer = _make(raise_on_exports=True)
    result = analyzer.get_exports()
    assert result == []


# ---------------------------------------------------------------------------
# _analyze_export()
# ---------------------------------------------------------------------------


def test_analyze_export_basic():
    analyzer = _make()
    export = {"name": "TestFunc", "vaddr": 4096, "ordinal": 1, "type": "FUNC"}
    result = analyzer._analyze_export(export)

    assert result["name"] == "TestFunc"
    assert "0x" in result["address"]
    assert result["ordinal"] == 1


def test_analyze_export_forwarded():
    analyzer = _make()
    export = {
        "name": "ForwardedFunc",
        "vaddr": 4096,
        "ordinal": 1,
        "forwarded": True,
        "forwarder": "KERNEL32.CreateFileA",
    }
    result = analyzer._analyze_export(export)

    assert result["is_forwarded"] is True
    assert result["forwarder"] == "KERNEL32.CreateFileA"


def test_analyze_export_missing_fields():
    analyzer = _make()
    export: dict[str, Any] = {}
    result = analyzer._analyze_export(export)

    assert result["name"] == "unknown"
    assert result["ordinal"] == 0


def test_analyze_export_with_size():
    analyzer = _make()
    export = {"name": "TestFunc", "vaddr": 4096, "ordinal": 1, "size": 256}
    result = analyzer._analyze_export(export)

    assert result["size"] == 256


def test_analyze_export_exception():
    """When _get_export_characteristics raises, _analyze_export catches and records error."""
    analyzer = _make(raise_on_func_info=True)

    # Force characteristics to raise by replacing the method
    def _raise(exp: Any) -> dict[str, Any]:
        raise RuntimeError("Analysis failed")

    analyzer._get_export_characteristics = _raise  # type: ignore[method-assign]
    export = {"name": "TestFunc", "vaddr": 4096, "ordinal": 1}
    result = analyzer._analyze_export(export)

    assert isinstance(result, dict)
    assert result["name"] == "TestFunc"
    assert "error" in result


# ---------------------------------------------------------------------------
# _get_export_characteristics()
# ---------------------------------------------------------------------------


def test_get_export_characteristics_dll_export():
    analyzer = _make()
    export = {"name": "DllMain", "vaddr": 0}
    result = analyzer._get_export_characteristics(export)
    assert result.get("dll_export") is True


def test_get_export_characteristics_suspicious_names():
    analyzer = _make()
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
        export = {"name": name, "vaddr": 0}
        result = analyzer._get_export_characteristics(export)
        assert result.get("suspicious_name") is True, f"{name} should be suspicious"
        assert "suspicious_pattern" in result


def test_get_export_characteristics_function_info():
    func_info = [{"size": 128, "cc": 5}]
    analyzer = _make(func_info_map={4096: func_info})
    export = {"name": "TestFunc", "vaddr": 4096}
    result = analyzer._get_export_characteristics(export)

    assert result.get("is_function") is True
    assert result.get("function_size") == 128
    assert result.get("complexity") == 5


def test_get_export_characteristics_not_function():
    # No function info returned -> is_function = False
    analyzer = _make(func_info_map={})
    export = {"name": "DataExport", "vaddr": 4096}
    result = analyzer._get_export_characteristics(export)

    assert result.get("is_function") is False


def test_get_export_characteristics_no_address():
    # vaddr == 0 means the function info branch is skipped
    analyzer = _make()
    export = {"name": "TestFunc", "vaddr": 0}
    result = analyzer._get_export_characteristics(export)
    assert isinstance(result, dict)
    # No is_function key set when vaddr is 0
    assert "is_function" not in result


def test_get_export_characteristics_exception():
    analyzer = _make(raise_on_func_info=True)
    export = {"name": "TestFunc", "vaddr": 4096}
    result = analyzer._get_export_characteristics(export)
    # Exception is caught internally, returns partial dict
    assert isinstance(result, dict)


def test_get_export_characteristics_malformed_func_info():
    # Non-dict element in function info list
    analyzer = _make(func_info_map={4096: ["not a dict"]})
    export = {"name": "TestFunc", "vaddr": 4096}
    result = analyzer._get_export_characteristics(export)
    assert isinstance(result, dict)
    assert result.get("is_function") is False


# ---------------------------------------------------------------------------
# get_export_statistics()
# ---------------------------------------------------------------------------


def test_get_export_statistics_empty():
    analyzer = _make(exports=[])
    result = analyzer.get_export_statistics()

    assert result["total_exports"] == 0
    assert result["function_exports"] == 0
    assert result["data_exports"] == 0


def test_get_export_statistics_with_exports():
    exports = [{"name": "TestFunc", "vaddr": 4096, "ordinal": 1}]
    analyzer = _make(exports=exports)
    result = analyzer.get_export_statistics()

    assert result["total_exports"] == 1
    assert "export_names" in result
    assert "TestFunc" in result["export_names"]


def test_get_export_statistics_exception():
    analyzer = _make(raise_on_exports=True)
    result = analyzer.get_export_statistics()
    assert isinstance(result, dict)
    assert result["total_exports"] == 0


# ---------------------------------------------------------------------------
# _update_export_stats()
# ---------------------------------------------------------------------------


def _make_stats() -> dict[str, Any]:
    return {
        "total_exports": 0,
        "function_exports": 0,
        "data_exports": 0,
        "forwarded_exports": 0,
        "suspicious_exports": 0,
        "export_names": [],
    }


def test_update_export_stats_basic():
    analyzer = _make()
    stats = _make_stats()
    export = {
        "name": "TestFunc",
        "is_forwarded": False,
        "characteristics": {"is_function": True},
    }

    analyzer._update_export_stats(stats, export)

    assert "TestFunc" in stats["export_names"]
    assert stats["function_exports"] == 1


def test_update_export_stats_forwarded():
    analyzer = _make()
    stats = _make_stats()
    export = {
        "name": "ForwardedFunc",
        "is_forwarded": True,
        "characteristics": {},
    }

    analyzer._update_export_stats(stats, export)

    assert stats["forwarded_exports"] == 1
    assert stats["data_exports"] == 0


def test_update_export_stats_data_export():
    analyzer = _make()
    stats = _make_stats()
    export = {
        "name": "DataVar",
        "is_forwarded": False,
        "characteristics": {"is_function": False},
    }

    analyzer._update_export_stats(stats, export)

    assert stats["data_exports"] == 1


def test_update_export_stats_suspicious():
    analyzer = _make()
    stats = _make_stats()
    export = {
        "name": "InjectCode",
        "is_forwarded": False,
        "characteristics": {"suspicious_name": True},
    }

    analyzer._update_export_stats(stats, export)

    assert stats["suspicious_exports"] == 1


def test_update_export_stats_malformed():
    analyzer = _make()
    stats = _make_stats()

    analyzer._update_export_stats(stats, "not a dict")

    assert len(stats["export_names"]) == 0


# ---------------------------------------------------------------------------
# Integration / ordering
# ---------------------------------------------------------------------------


def test_analyze_integration():
    exports = [{"name": "DllMain", "vaddr": 4096, "ordinal": 1, "type": "FUNC"}]
    func_info = {4096: [{"size": 128, "cc": 3}]}
    analyzer = _make(exports=exports, func_info_map=func_info)
    result = analyzer.analyze()

    assert "exports" in result
    assert "statistics" in result
    assert "total_exports" in result
    assert result["total_exports"] == 1
    # Verify function characteristics were resolved
    exp = result["exports"][0]
    assert exp["characteristics"].get("is_function") is True
    assert exp["characteristics"].get("function_size") == 128


def test_get_exports_preserves_order():
    exports = [
        {"name": "Func1", "vaddr": 4096, "ordinal": 1},
        {"name": "Func2", "vaddr": 8192, "ordinal": 2},
        {"name": "Func3", "vaddr": 12288, "ordinal": 3},
    ]
    analyzer = _make(exports=exports)
    result = analyzer.get_exports()

    assert len(result) == 3
    assert result[0]["name"] == "Func1"
    assert result[1]["name"] == "Func2"
    assert result[2]["name"] == "Func3"


def test_all_suspicious_patterns_checked():
    analyzer = _make()
    patterns = [
        "install",
        "uninstall",
        "execute",
        "run",
        "start",
        "inject",
        "hook",
        "patch",
        "bypass",
        "disable",
    ]

    found_patterns = []
    for pattern in patterns:
        export = {"name": f"Test{pattern.upper()}Function", "vaddr": 0}
        result = analyzer._get_export_characteristics(export)
        assert result.get("suspicious_name") is True, f"Pattern '{pattern}' not detected"
        found_patterns.append(result["suspicious_pattern"])

    assert len(found_patterns) == len(patterns)
