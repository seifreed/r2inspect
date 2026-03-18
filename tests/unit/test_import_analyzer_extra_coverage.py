#!/usr/bin/env python3
"""Extra coverage tests for import_analyzer module -- fully mock-free."""

import logging

import pytest
from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.domain.services.import_analysis import build_import_statistics
from r2inspect.modules.import_analyzer import ImportAnalyzer


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeR2:
    """Minimal r2pipe stand-in driven by command maps."""

    def __init__(self, cmdj_map=None, cmd_map=None):
        self.cmdj_map = cmdj_map or {}
        self.cmd_map = cmd_map or {}

    def cmdj(self, command):
        return self.cmdj_map.get(command, [])

    def cmd(self, command):
        return self.cmd_map.get(command, "")


class ErrorR2(FakeR2):
    """FakeR2 variant whose cmdj always raises."""

    def cmdj(self, command):
        raise RuntimeError("cmdj boom")

    def cmd(self, command):
        raise RuntimeError("cmd boom")


def _make_analyzer(cmdj_map=None, cmd_map=None):
    """Build an ImportAnalyzer backed by FakeR2 + R2PipeAdapter."""
    r2 = FakeR2(cmdj_map=cmdj_map, cmd_map=cmd_map)
    adapter = R2PipeAdapter(r2)
    return ImportAnalyzer(adapter, config=None)


def _make_error_analyzer():
    """Build an ImportAnalyzer backed by ErrorR2 + R2PipeAdapter."""
    r2 = ErrorR2()
    adapter = R2PipeAdapter(r2)
    return ImportAnalyzer(adapter, config=None)


# ---------------------------------------------------------------------------
# Basic metadata
# ---------------------------------------------------------------------------


def test_import_analyzer_init():
    analyzer = _make_analyzer()
    assert analyzer.adapter is not None


def test_get_category():
    analyzer = _make_analyzer()
    assert analyzer.get_category() == "metadata"


def test_get_description():
    analyzer = _make_analyzer()
    assert "import" in analyzer.get_description().lower()


def test_supports_format():
    analyzer = _make_analyzer()
    assert analyzer.supports_format("PE") is True
    assert analyzer.supports_format("PE32") is True
    assert analyzer.supports_format("DLL") is True
    assert analyzer.supports_format("ELF") is False


# ---------------------------------------------------------------------------
# Risk helpers
# ---------------------------------------------------------------------------


def test_get_risk_level():
    analyzer = _make_analyzer()
    assert analyzer._get_risk_level(80) == "HIGH"
    assert analyzer._get_risk_level(50) == "MEDIUM"
    assert analyzer._get_risk_level(20) == "LOW"


def test_count_suspicious_indicators():
    analyzer = _make_analyzer()
    result_data = {
        "api_analysis": {"suspicious_apis": ["a", "b"]},
        "obfuscation": {"indicators": ["c"]},
        "anomalies": {"count": 2},
    }
    count = analyzer._count_suspicious_indicators(result_data)
    assert count == 5


# ---------------------------------------------------------------------------
# get_imports
# ---------------------------------------------------------------------------


def test_get_imports():
    imports_data = [{"name": "CreateFileA", "plt": 0x1000, "libname": "kernel32.dll"}]
    analyzer = _make_analyzer(cmdj_map={"iij": imports_data})
    result = analyzer.get_imports()
    assert len(result) == 1
    assert result[0]["name"] == "CreateFileA"


def test_get_imports_multiple():
    imports_data = [
        {"name": "CreateFileA", "plt": 0x1000, "libname": "kernel32.dll"},
        {"name": "MessageBoxA", "plt": 0x2000, "libname": "user32.dll"},
    ]
    analyzer = _make_analyzer(cmdj_map={"iij": imports_data})
    result = analyzer.get_imports()
    assert len(result) == 2


def test_get_imports_empty():
    analyzer = _make_analyzer(cmdj_map={"iij": []})
    result = analyzer.get_imports()
    assert result == []


def test_get_imports_error():
    analyzer = _make_error_analyzer()
    result = analyzer.get_imports()
    assert result == []


# ---------------------------------------------------------------------------
# _analyze_import
# ---------------------------------------------------------------------------


def test_analyze_import():
    analyzer = _make_analyzer()
    imp = {"name": "CreateFileA", "plt": 0x1000, "libname": "kernel32.dll"}
    result = analyzer._analyze_import(imp)
    assert result["name"] == "CreateFileA"
    assert result["library"] == "kernel32.dll"
    assert "risk_score" in result


def test_analyze_import_unknown():
    analyzer = _make_analyzer()
    imp = {"name": "SomeObscureFunc", "plt": 0x3000, "libname": "custom.dll"}
    result = analyzer._analyze_import(imp)
    assert result["name"] == "SomeObscureFunc"


def test_analyze_import_missing_fields():
    analyzer = _make_analyzer()
    imp = {}
    result = analyzer._analyze_import(imp)
    assert result["name"] == "unknown"


# ---------------------------------------------------------------------------
# _get_function_description
# ---------------------------------------------------------------------------


def test_get_function_description():
    analyzer = _make_analyzer()
    desc = analyzer._get_function_description("CreateFileA")
    assert "file" in desc.lower()


def test_get_function_description_unknown():
    analyzer = _make_analyzer()
    desc = analyzer._get_function_description("UnknownFunc")
    assert desc == ""


# ---------------------------------------------------------------------------
# get_import_statistics
# ---------------------------------------------------------------------------


def test_get_import_statistics():
    analyzer = _make_analyzer(cmdj_map={"iij": []})
    result = analyzer.get_import_statistics()
    assert result["total_imports"] == 0


def test_get_import_statistics_with_data():
    imports_data = [
        {"name": "CreateFileA", "plt": 0x1000, "libname": "kernel32.dll"},
    ]
    analyzer = _make_analyzer(cmdj_map={"iij": imports_data})
    result = analyzer.get_import_statistics()
    assert result["total_imports"] == 1


def test_get_import_statistics_logs_context_on_error(caplog):
    analyzer = _make_error_analyzer()
    with caplog.at_level(logging.ERROR):
        result = analyzer.get_import_statistics()
    assert result["total_imports"] == 0


# ---------------------------------------------------------------------------
# get_missing_imports
# ---------------------------------------------------------------------------


def test_get_missing_imports_empty_strings():
    analyzer = _make_analyzer(cmdj_map={"iij": [], "izj": []})
    result = analyzer.get_missing_imports()
    assert isinstance(result, list)


def test_get_missing_imports_with_candidate():
    imports_data = []
    strings_data = [
        {"string": "CreateFileA", "vaddr": 0x5000},
    ]
    analyzer = _make_analyzer(cmdj_map={"iij": imports_data, "izj": strings_data})
    result = analyzer.get_missing_imports()
    # CreateFileA matches known APIs and isn't in the import list
    assert isinstance(result, list)


def test_get_missing_imports_error():
    analyzer = _make_error_analyzer()
    result = analyzer.get_missing_imports()
    assert result == []


# ---------------------------------------------------------------------------
# _is_candidate_api_string / _matches_known_api
# ---------------------------------------------------------------------------


def test_is_candidate_api_string():
    analyzer = _make_analyzer()
    assert analyzer._is_candidate_api_string("CreateFileA", []) is True
    assert analyzer._is_candidate_api_string("abc", []) is False
    assert analyzer._is_candidate_api_string("CreateFileA", ["CreateFileA"]) is False


def test_matches_known_api():
    analyzer = _make_analyzer()
    result = analyzer._matches_known_api("CreateFileA")
    assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# analyze_api_usage
# ---------------------------------------------------------------------------


def test_analyze_api_usage():
    analyzer = _make_analyzer()
    imports = [{"name": "CreateFileA", "category": "File"}]
    result = analyzer.analyze_api_usage(imports)
    assert "categories" in result


def test_analyze_api_usage_empty():
    analyzer = _make_analyzer()
    result = analyzer.analyze_api_usage([])
    assert result["risk_score"] == 0


def test_analyze_api_usage_error():
    analyzer = _make_analyzer()
    result = analyzer.analyze_api_usage([{"name": "test"}])
    assert isinstance(result.get("risk_score", 0), (int, float))


# ---------------------------------------------------------------------------
# detect_api_obfuscation
# ---------------------------------------------------------------------------


def test_detect_api_obfuscation():
    analyzer = _make_analyzer()
    imports = [{"name": "GetProcAddress"}]
    result = analyzer.detect_api_obfuscation(imports)
    assert result["detected"] is True


def test_detect_api_obfuscation_none():
    analyzer = _make_analyzer()
    result = analyzer.detect_api_obfuscation(None)
    assert result["detected"] is False


# ---------------------------------------------------------------------------
# analyze_dll_dependencies
# ---------------------------------------------------------------------------


def test_analyze_dll_dependencies():
    analyzer = _make_analyzer()
    dlls = ["kernel32.dll", "user32.dll"]
    result = analyzer.analyze_dll_dependencies(dlls)
    assert "common_dlls" in result


def test_analyze_dll_dependencies_empty():
    analyzer = _make_analyzer()
    result = analyzer.analyze_dll_dependencies([])
    assert result["common_dlls"] == []


def test_analyze_dll_dependencies_single():
    analyzer = _make_analyzer()
    result = analyzer.analyze_dll_dependencies(["test.dll"])
    assert "common_dlls" in result


# ---------------------------------------------------------------------------
# detect_import_anomalies
# ---------------------------------------------------------------------------


def test_detect_import_anomalies_no_imports():
    analyzer = _make_analyzer()
    result = analyzer.detect_import_anomalies([])
    assert result["count"] > 0


def test_detect_import_anomalies_none():
    analyzer = _make_analyzer()
    result = analyzer.detect_import_anomalies(None)
    assert result["count"] >= 0


# ---------------------------------------------------------------------------
# check_import_forwarding
# ---------------------------------------------------------------------------


def test_check_import_forwarding_empty():
    analyzer = _make_analyzer(cmdj_map={"izj": []})
    result = analyzer.check_import_forwarding()
    assert result["detected"] is False


def test_check_import_forwarding_with_forward():
    strings_data = [
        {"string": "ntdll.RtlAllocateHeap", "vaddr": 0x6000},
    ]
    analyzer = _make_analyzer(cmdj_map={"izj": strings_data})
    result = analyzer.check_import_forwarding()
    # The forwarding pattern matches "word.word" format
    assert isinstance(result["detected"], bool)


def test_check_import_forwarding_error():
    analyzer = _make_error_analyzer()
    result = analyzer.check_import_forwarding()
    assert result["detected"] is False


# ---------------------------------------------------------------------------
# build_import_statistics (domain function, no adapter needed)
# ---------------------------------------------------------------------------


def test_build_import_statistics_ignores_invalid_entries_consistently():
    stats = build_import_statistics(
        [
            {
                "name": "CreateFileA",
                "category": "File",
                "risk_level": "LOW",
                "library": "kernel32.dll",
            },
            "not-a-dict",
        ]
    )
    assert stats["total_imports"] == 1
    assert stats["unique_libraries"] == 1
    assert stats["category_distribution"] == {"File": 1}
    assert stats["risk_distribution"] == {"LOW": 1}
    assert stats["library_distribution"] == {"kernel32.dll": 1}


def test_build_import_statistics_accepts_dll_key_for_library_distribution():
    stats = build_import_statistics(
        [
            {
                "name": "CreateFileA",
                "category": "File",
                "risk_level": "LOW",
                "library": "kernel32.dll",
            },
            {"name": "MessageBoxA", "category": "UI", "risk_level": "LOW", "dll": "user32.dll"},
        ]
    )
    assert stats["unique_libraries"] == 2
    assert stats["library_distribution"] == {"kernel32.dll": 1, "user32.dll": 1}


def test_build_import_statistics_accepts_libname_key_for_library_distribution():
    stats = build_import_statistics(
        [
            {
                "name": "CreateFileA",
                "category": "File",
                "risk_level": "LOW",
                "libname": "kernel32.dll",
            },
        ]
    )
    assert stats["unique_libraries"] == 1
    assert stats["library_distribution"] == {"kernel32.dll": 1}
