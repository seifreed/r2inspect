#!/usr/bin/env python3
"""Coverage tests for r2inspect/core/inspector_helpers.py"""
from __future__ import annotations

from typing import Any

from r2inspect.core.inspector_helpers import InspectorExecutionMixin
from r2inspect.registry.analyzer_registry import AnalyzerRegistry


# ---------------------------------------------------------------------------
# Minimal concrete subclass for testing
# ---------------------------------------------------------------------------

class FakeResultAggregator:
    def generate_indicators(self, results: dict) -> list:
        return [{"indicator": "test"}]

    def generate_executive_summary(self, results: dict) -> dict:
        return {"summary": "ok"}


class StubInspector(InspectorExecutionMixin):
    """Minimal concrete implementation of InspectorExecutionMixin."""

    def __init__(self):
        self.adapter = None
        self.config = None
        self.filename = "stub_file.bin"
        self.registry = AnalyzerRegistry()
        self._result_aggregator = FakeResultAggregator()


def make_inspector() -> StubInspector:
    return StubInspector()


# ---------------------------------------------------------------------------
# Static helper methods
# ---------------------------------------------------------------------------

def test_as_dict_with_dict_input():
    assert StubInspector._as_dict({"key": "val"}) == {"key": "val"}


def test_as_dict_with_non_dict_returns_empty():
    assert StubInspector._as_dict("string") == {}
    assert StubInspector._as_dict(None) == {}
    assert StubInspector._as_dict([1, 2]) == {}
    assert StubInspector._as_dict(42) == {}


def test_as_bool_dict_with_dict_input():
    result = StubInspector._as_bool_dict({"aslr": 1, "nx": 0, "pie": True})
    assert result["aslr"] is True
    assert result["nx"] is False
    assert result["pie"] is True


def test_as_bool_dict_with_non_dict_returns_empty():
    assert StubInspector._as_bool_dict("not a dict") == {}
    assert StubInspector._as_bool_dict(None) == {}
    assert StubInspector._as_bool_dict([]) == {}


def test_as_bool_dict_converts_keys_to_str():
    result = StubInspector._as_bool_dict({1: True, 2: False})
    assert "1" in result
    assert "2" in result


def test_as_str_with_string_input():
    assert StubInspector._as_str("hello") == "hello"


def test_as_str_with_non_string_returns_default():
    assert StubInspector._as_str(None) == ""
    assert StubInspector._as_str(42) == ""
    assert StubInspector._as_str([]) == ""


def test_as_str_with_custom_default():
    assert StubInspector._as_str(None, default="fallback") == "fallback"


# ---------------------------------------------------------------------------
# _execute_analyzer – analyzer not found
# ---------------------------------------------------------------------------

def test_execute_analyzer_returns_empty_dict_when_not_in_registry():
    inspector = make_inspector()
    result = inspector._execute_analyzer("nonexistent_analyzer_xyz")
    assert result == {}


def test_execute_list_returns_empty_list_when_analyzer_not_found():
    inspector = make_inspector()
    result = inspector._execute_list("nonexistent_xyz")
    assert result == []


def test_execute_dict_returns_empty_dict_when_analyzer_not_found():
    inspector = make_inspector()
    result = inspector._execute_dict("nonexistent_xyz")
    assert result == {}


# ---------------------------------------------------------------------------
# _execute_analyzer – via registered analyzer class
# ---------------------------------------------------------------------------

class FakeAnalyzer:
    def __init__(self, **kwargs):
        self.adapter = kwargs.get("adapter")
        self.config = kwargs.get("config")
        self.filename = kwargs.get("filename")

    def analyze(self) -> dict:
        return {"analyzed": True}

    def detect(self) -> dict:
        return {"detected": True}

    def custom_method(self) -> list:
        return ["a", "b"]

    def method_with_args(self, x: int) -> dict:
        return {"x": x}


def register_fake_analyzer(registry: AnalyzerRegistry, name: str = "fake_analyzer") -> None:
    registry.register(
        name=name,
        analyzer_class=FakeAnalyzer,
        category="detection",
        file_formats={"ANY"},
        required=False,
    )


def test_execute_analyzer_calls_analyze_method():
    inspector = make_inspector()
    register_fake_analyzer(inspector.registry)
    result = inspector._execute_analyzer("fake_analyzer")
    assert result == {"analyzed": True}


def test_execute_analyzer_calls_custom_method():
    inspector = make_inspector()
    register_fake_analyzer(inspector.registry)
    result = inspector._execute_analyzer("fake_analyzer", "custom_method")
    assert result == ["a", "b"]


def test_execute_analyzer_method_not_found_returns_empty():
    inspector = make_inspector()
    register_fake_analyzer(inspector.registry)
    result = inspector._execute_analyzer("fake_analyzer", "nonexistent_method")
    assert result == {}


def test_execute_analyzer_with_args_passed_to_analyze():
    inspector = make_inspector()
    register_fake_analyzer(inspector.registry)
    result = inspector._execute_analyzer("fake_analyzer", "analyze", "arg1")
    # analyze() ignores args but should still return something
    assert isinstance(result, dict)


def test_execute_analyzer_with_kwargs_on_custom_method():
    inspector = make_inspector()
    register_fake_analyzer(inspector.registry)
    result = inspector._execute_analyzer("fake_analyzer", "method_with_args", 7)
    assert result == {"x": 7}


class BrokenAnalyzer:
    def __init__(self, **kwargs):
        pass

    def analyze(self):
        raise RuntimeError("analysis failed")

    def detect(self):
        raise RuntimeError("detection failed")


def test_execute_analyzer_handles_exception_returns_empty():
    inspector = make_inspector()
    inspector.registry.register(
        name="broken_analyzer",
        analyzer_class=BrokenAnalyzer,
        category="detection",
        file_formats={"ANY"},
        required=False,
    )
    result = inspector._execute_analyzer("broken_analyzer")
    assert result == {}


# ---------------------------------------------------------------------------
# _execute_list / _execute_dict
# ---------------------------------------------------------------------------

def test_execute_list_returns_list_from_analyzer():
    inspector = make_inspector()
    register_fake_analyzer(inspector.registry, name="list_analyzer")
    result = inspector._execute_list("list_analyzer", "custom_method")
    assert result == ["a", "b"]


def test_execute_list_converts_non_list_to_empty():
    inspector = make_inspector()
    register_fake_analyzer(inspector.registry, name="dict_as_list_analyzer")
    result = inspector._execute_list("dict_as_list_analyzer", "analyze")
    assert result == []


def test_execute_dict_returns_dict_from_analyzer():
    inspector = make_inspector()
    register_fake_analyzer(inspector.registry, name="dict_analyzer")
    result = inspector._execute_dict("dict_analyzer")
    assert result == {"analyzed": True}


# ---------------------------------------------------------------------------
# Convenience wrapper methods (test they route correctly)
# ---------------------------------------------------------------------------

def test_get_pe_info_returns_empty_when_no_analyzer():
    inspector = make_inspector()
    result = inspector.get_pe_info()
    assert result == {}


def test_get_elf_info_returns_empty_when_no_analyzer():
    inspector = make_inspector()
    result = inspector.get_elf_info()
    assert result == {}


def test_get_macho_info_returns_empty_when_no_analyzer():
    inspector = make_inspector()
    result = inspector.get_macho_info()
    assert result == {}


def test_get_strings_returns_empty_list_when_no_analyzer():
    inspector = make_inspector()
    result = inspector.get_strings()
    assert result == []


def test_get_security_features_returns_empty_when_no_analyzer():
    inspector = make_inspector()
    result = inspector.get_security_features()
    assert result == {}


def test_get_imports_returns_empty_list():
    inspector = make_inspector()
    result = inspector.get_imports()
    assert result == []


def test_get_exports_returns_empty_list():
    inspector = make_inspector()
    result = inspector.get_exports()
    assert result == []


def test_get_sections_returns_empty_list():
    inspector = make_inspector()
    result = inspector.get_sections()
    assert result == []


def test_detect_packer_returns_empty_when_no_analyzer():
    inspector = make_inspector()
    result = inspector.detect_packer()
    assert result == {}


def test_detect_crypto_returns_error_dict_when_no_analyzer():
    inspector = make_inspector()
    result = inspector.detect_crypto()
    assert isinstance(result, dict)
    # Either empty or the error fallback
    assert "algorithms" in result or result == {} or "error" in result


def test_detect_anti_analysis_returns_empty():
    inspector = make_inspector()
    result = inspector.detect_anti_analysis()
    assert result == {}


def test_detect_compiler_returns_empty():
    inspector = make_inspector()
    result = inspector.detect_compiler()
    assert result == {}


def test_run_yara_rules_returns_empty_list():
    inspector = make_inspector()
    result = inspector.run_yara_rules()
    assert result == []


def test_search_xor_returns_empty_list():
    inspector = make_inspector()
    result = inspector.search_xor("DEADBEEF")
    assert result == []


def test_analyze_functions_returns_empty():
    inspector = make_inspector()
    result = inspector.analyze_functions()
    assert result == {}


def test_analyze_ssdeep_returns_empty():
    inspector = make_inspector()
    assert inspector.analyze_ssdeep() == {}


def test_analyze_tlsh_returns_empty():
    inspector = make_inspector()
    assert inspector.analyze_tlsh() == {}


def test_analyze_telfhash_returns_empty():
    inspector = make_inspector()
    assert inspector.analyze_telfhash() == {}


def test_analyze_rich_header_returns_empty():
    inspector = make_inspector()
    assert inspector.analyze_rich_header() == {}


def test_analyze_impfuzzy_returns_empty():
    inspector = make_inspector()
    assert inspector.analyze_impfuzzy() == {}


def test_analyze_ccbhash_returns_empty():
    inspector = make_inspector()
    assert inspector.analyze_ccbhash() == {}


def test_analyze_binlex_returns_empty():
    inspector = make_inspector()
    assert inspector.analyze_binlex() == {}


def test_analyze_binbloom_returns_empty():
    inspector = make_inspector()
    assert inspector.analyze_binbloom() == {}


def test_analyze_simhash_returns_empty():
    inspector = make_inspector()
    assert inspector.analyze_simhash() == {}


def test_analyze_bindiff_returns_empty():
    inspector = make_inspector()
    assert inspector.analyze_bindiff() == {}


# ---------------------------------------------------------------------------
# generate_indicators / generate_executive_summary
# ---------------------------------------------------------------------------

def test_generate_indicators_returns_list():
    inspector = make_inspector()
    result = inspector.generate_indicators({"some": "data"})
    assert isinstance(result, list)


def test_generate_executive_summary_returns_dict():
    inspector = make_inspector()
    result = inspector.generate_executive_summary({"some": "data"})
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# _execute_with_progress / _execute_without_progress
# ---------------------------------------------------------------------------

class FakePipeline:
    def execute_with_progress(self, callback, options):
        return {"progress_result": True}

    def execute(self, options, parallel=False):
        return {"execute_result": True}


def test_execute_with_progress_returns_dict():
    inspector = make_inspector()
    result = inspector._execute_with_progress(FakePipeline(), {}, lambda s: None)
    assert result == {"progress_result": True}


def test_execute_with_progress_returns_empty_on_non_dict():
    class NonDictPipeline:
        def execute_with_progress(self, callback, options):
            return "not a dict"

    inspector = make_inspector()
    result = inspector._execute_with_progress(NonDictPipeline(), {}, lambda s: None)
    assert result == {}


def test_execute_without_progress_returns_dict():
    inspector = make_inspector()
    result = inspector._execute_without_progress(FakePipeline(), {})
    assert result == {"execute_result": True}


def test_execute_without_progress_with_parallel():
    inspector = make_inspector()
    result = inspector._execute_without_progress(FakePipeline(), {}, parallel=True)
    assert result == {"execute_result": True}


# ---------------------------------------------------------------------------
# get_file_info / _detect_file_format (covers lines 115-125)
# ---------------------------------------------------------------------------

def test_get_file_info_returns_dict_with_file_not_found():
    inspector = make_inspector()
    # filename "stub_file.bin" doesn't exist, stage catches internally
    result = inspector.get_file_info()
    assert isinstance(result, dict)


def test_detect_file_format_returns_string():
    inspector = make_inspector()
    result = inspector._detect_file_format()
    assert isinstance(result, str)


def test_detect_file_format_returns_unknown_without_real_file():
    inspector = make_inspector()
    fmt = inspector._detect_file_format()
    # Without a real file, returns "Unknown" or some default
    assert isinstance(fmt, str)


# ---------------------------------------------------------------------------
# detect_crypto with registered analyzer (covers line 168)
# ---------------------------------------------------------------------------

class FakeCryptoAnalyzer:
    def __init__(self, **kwargs):
        pass

    def detect(self) -> dict:
        return {"algorithms": ["AES"], "constants": [0xDEADBEEF]}


def test_detect_crypto_returns_result_when_analyzer_registered():
    inspector = make_inspector()
    inspector.registry.register(
        name="crypto_analyzer",
        analyzer_class=FakeCryptoAnalyzer,
        category="detection",
        file_formats={"ANY"},
        required=False,
    )
    result = inspector.detect_crypto()
    assert isinstance(result, dict)
    assert "algorithms" in result
