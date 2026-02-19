"""Branch-path tests for inspector_helpers.py covering missing lines."""

from __future__ import annotations

from typing import Any

from r2inspect.core.inspector_helpers import InspectorExecutionMixin


# ---------------------------------------------------------------------------
# Minimal support classes (no unittest.mock)
# ---------------------------------------------------------------------------


class NullRegistry:
    """Registry that never finds any analyzer class."""

    def get_analyzer_class(self, name: str) -> None:
        return None


class SingleAnalyzerRegistry:
    """Registry that returns a specific analyzer class by name."""

    def __init__(self, name: str, klass: type) -> None:
        self._name = name
        self._klass = klass

    def get_analyzer_class(self, name: str) -> type | None:
        return self._klass if name == self._name else None


class SimpleAggregator:
    """Minimal result aggregator."""

    def generate_indicators(self, results: dict[str, Any]) -> list[dict[str, Any]]:
        return [{"indicator": "test"}]

    def generate_executive_summary(self, results: dict[str, Any]) -> dict[str, Any]:
        return {"summary": "ok"}


class SimplePipeline:
    """Pipeline stub that records calls."""

    def __init__(self) -> None:
        self.progress_calls: list[str] = []

    def execute_with_progress(
        self, callback: Any, options: dict[str, Any]
    ) -> dict[str, Any]:
        callback("step1")
        return {"pipeline_result": True}

    def execute(self, options: dict[str, Any], *, parallel: bool = False) -> dict[str, Any]:
        return {"pipeline_result": True, "parallel": parallel}


class AlwaysAnalyzeClass:
    """Analyzer that can be constructed with adapter kwarg and returns a dict."""

    def __init__(self, adapter: Any = None, **kwargs: Any) -> None:
        self.adapter = adapter

    def analyze(self) -> dict[str, Any]:
        return {"status": "analyzed"}

    def custom_method(self) -> dict[str, Any]:
        return {"status": "custom"}

    def method_with_args(self, arg1: str, arg2: int = 0) -> dict[str, Any]:
        return {"arg1": arg1, "arg2": arg2}

    def raising_method(self) -> None:
        raise RuntimeError("method error")


class RaisingAnalyzerClass:
    """Analyzer whose constructor raises."""

    def __init__(self, adapter: Any = None, **kwargs: Any) -> None:
        raise RuntimeError("constructor failure")


# ---------------------------------------------------------------------------
# Concrete subclass of InspectorExecutionMixin for testing
# ---------------------------------------------------------------------------


class ConcreteHelper(InspectorExecutionMixin):
    """Concrete helper that satisfies all required attributes."""

    def __init__(
        self,
        registry: Any = None,
        aggregator: Any = None,
        adapter: Any = None,
        filename: str = "test_nonexistent_12345.bin",
    ) -> None:
        self.adapter = adapter
        self.config = None
        self.filename = filename
        self.registry = registry if registry is not None else NullRegistry()
        self._result_aggregator = aggregator if aggregator is not None else SimpleAggregator()


# ---------------------------------------------------------------------------
# _as_dict  (line 42)
# ---------------------------------------------------------------------------


def test_as_dict_returns_dict_unchanged():
    result = ConcreteHelper._as_dict({"a": 1, "b": 2})
    assert result == {"a": 1, "b": 2}


def test_as_dict_returns_empty_for_non_dict():
    assert ConcreteHelper._as_dict([1, 2]) == {}
    assert ConcreteHelper._as_dict(None) == {}
    assert ConcreteHelper._as_dict("string") == {}


# ---------------------------------------------------------------------------
# _as_bool_dict  (lines 46-48)
# ---------------------------------------------------------------------------


def test_as_bool_dict_converts_values():
    result = ConcreteHelper._as_bool_dict({"x": 1, "y": 0, "z": "yes"})
    assert result == {"x": True, "y": False, "z": True}


def test_as_bool_dict_returns_empty_for_non_dict():
    assert ConcreteHelper._as_bool_dict(None) == {}
    assert ConcreteHelper._as_bool_dict([]) == {}


# ---------------------------------------------------------------------------
# _as_str  (line 52)
# ---------------------------------------------------------------------------


def test_as_str_returns_string_value():
    assert ConcreteHelper._as_str("hello") == "hello"


def test_as_str_returns_default_for_non_string():
    assert ConcreteHelper._as_str(42, "fallback") == "fallback"
    assert ConcreteHelper._as_str(None) == ""


# ---------------------------------------------------------------------------
# _execute_with_progress  (line 30)
# ---------------------------------------------------------------------------


def test_execute_with_progress_calls_pipeline_and_returns_dict():
    pipeline = SimplePipeline()
    helper = ConcreteHelper()
    called: list[str] = []
    result = helper._execute_with_progress(pipeline, {}, called.append)
    assert result == {"pipeline_result": True}
    assert called == ["step1"]


# ---------------------------------------------------------------------------
# _execute_without_progress  (line 38)
# ---------------------------------------------------------------------------


def test_execute_without_progress_calls_pipeline_and_returns_dict():
    pipeline = SimplePipeline()
    helper = ConcreteHelper()
    result = helper._execute_without_progress(pipeline, {})
    assert result == {"pipeline_result": True, "parallel": False}


def test_execute_without_progress_parallel_flag():
    pipeline = SimplePipeline()
    helper = ConcreteHelper()
    result = helper._execute_without_progress(pipeline, {}, parallel=True)
    assert result["parallel"] is True


# ---------------------------------------------------------------------------
# _execute_analyzer  (lines 61-87)
# ---------------------------------------------------------------------------


def test_execute_analyzer_returns_empty_dict_when_analyzer_not_found():
    """Registry returns None; lines 62-64 hit."""
    helper = ConcreteHelper(registry=NullRegistry())
    result = helper._execute_analyzer("nonexistent_analyzer")
    assert result == {}


def test_execute_analyzer_calls_analyze_method():
    """Registry returns class; default analyze path (line 83)."""
    registry = SingleAnalyzerRegistry("my_analyzer", AlwaysAnalyzeClass)
    helper = ConcreteHelper(registry=registry)
    result = helper._execute_analyzer("my_analyzer")
    assert result == {"status": "analyzed"}


def test_execute_analyzer_calls_named_method():
    """Non-default method_name path (lines 73-80 true branch when method exists)."""
    registry = SingleAnalyzerRegistry("my_analyzer", AlwaysAnalyzeClass)
    helper = ConcreteHelper(registry=registry)
    result = helper._execute_analyzer("my_analyzer", "custom_method")
    assert result == {"status": "custom"}


def test_execute_analyzer_returns_empty_when_method_not_found():
    """method_name set but not present on analyzer (lines 75-79)."""
    registry = SingleAnalyzerRegistry("my_analyzer", AlwaysAnalyzeClass)
    helper = ConcreteHelper(registry=registry)
    result = helper._execute_analyzer("my_analyzer", "nonexistent_method")
    assert result == {}


def test_execute_analyzer_passes_args_to_analyze():
    """args present → analyzer.analyze(*args) path (lines 81-82)."""
    registry = SingleAnalyzerRegistry("my_analyzer", AlwaysAnalyzeClass)
    helper = ConcreteHelper(registry=registry)
    result = helper._execute_analyzer("my_analyzer", "method_with_args", "hello", arg2=5)
    assert result == {"arg1": "hello", "arg2": 5}


def test_execute_analyzer_exception_returns_empty():
    """Constructor or execution raises; lines 85-87 hit."""
    registry = SingleAnalyzerRegistry("bad_analyzer", RaisingAnalyzerClass)
    helper = ConcreteHelper(registry=registry)
    result = helper._execute_analyzer("bad_analyzer")
    assert result == {}


# ---------------------------------------------------------------------------
# _execute_list  (lines 96-97)
# ---------------------------------------------------------------------------


def test_execute_list_returns_list_when_analyzer_returns_list():

    class ListAnalyzer:
        def __init__(self, adapter: Any = None, **kwargs: Any) -> None:
            pass

        def analyze(self) -> list[str]:
            return ["a", "b", "c"]

    registry = SingleAnalyzerRegistry("list_analyzer", ListAnalyzer)
    helper = ConcreteHelper(registry=registry)
    result = helper._execute_list("list_analyzer")
    assert result == ["a", "b", "c"]


def test_execute_list_returns_empty_list_when_non_list_returned():
    registry = SingleAnalyzerRegistry("my_analyzer", AlwaysAnalyzeClass)
    helper = ConcreteHelper(registry=registry)
    result = helper._execute_list("my_analyzer")
    assert result == []


# ---------------------------------------------------------------------------
# _execute_dict  (line 106)
# ---------------------------------------------------------------------------


def test_execute_dict_returns_dict():
    registry = SingleAnalyzerRegistry("my_analyzer", AlwaysAnalyzeClass)
    helper = ConcreteHelper(registry=registry)
    result = helper._execute_dict("my_analyzer")
    assert result == {"status": "analyzed"}


def test_execute_dict_returns_empty_when_not_found():
    helper = ConcreteHelper(registry=NullRegistry())
    result = helper._execute_dict("not_found")
    assert result == {}


# ---------------------------------------------------------------------------
# get_file_info  (lines 115-118)
# ---------------------------------------------------------------------------


def test_get_file_info_returns_dict():
    """FileInfoStage may fail for non-existent file, but get_file_info still returns a dict."""

    class MinimalAdapter:
        def get_file_info(self) -> dict[str, Any]:
            return {}

    helper = ConcreteHelper(adapter=MinimalAdapter())
    result = helper.get_file_info()
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# _detect_file_format  (lines 121-125)
# ---------------------------------------------------------------------------


def test_detect_file_format_returns_string():
    """_detect_file_format always returns a string."""

    class MinimalAdapter:
        def get_file_info(self) -> dict[str, Any]:
            return {}

    helper = ConcreteHelper(adapter=MinimalAdapter())
    result = helper._detect_file_format()
    assert isinstance(result, str)


# ---------------------------------------------------------------------------
# All delegation methods (lines 128-217)
# ---------------------------------------------------------------------------


def test_get_pe_info_returns_dict():
    helper = ConcreteHelper()
    assert isinstance(helper.get_pe_info(), dict)


def test_get_elf_info_returns_dict():
    helper = ConcreteHelper()
    assert isinstance(helper.get_elf_info(), dict)


def test_get_macho_info_returns_dict():
    helper = ConcreteHelper()
    assert isinstance(helper.get_macho_info(), dict)


def test_get_strings_returns_list():
    helper = ConcreteHelper()
    assert isinstance(helper.get_strings(), list)


def test_get_security_features_returns_dict():
    helper = ConcreteHelper()
    assert isinstance(helper.get_security_features(), dict)


def test_get_imports_returns_list():
    helper = ConcreteHelper()
    assert isinstance(helper.get_imports(), list)


def test_get_exports_returns_list():
    helper = ConcreteHelper()
    assert isinstance(helper.get_exports(), list)


def test_get_sections_returns_list():
    helper = ConcreteHelper()
    assert isinstance(helper.get_sections(), list)


def test_detect_packer_returns_dict():
    helper = ConcreteHelper()
    assert isinstance(helper.detect_packer(), dict)


def test_detect_crypto_returns_dict():
    helper = ConcreteHelper()
    result = helper.detect_crypto()
    assert isinstance(result, dict)


def test_detect_crypto_with_analyzer_not_found():
    """detect_crypto returns fallback with error when analyzer not found (lines 165-168)."""
    helper = ConcreteHelper()
    result = helper.detect_crypto()
    assert isinstance(result, dict)


def test_detect_anti_analysis_returns_dict():
    helper = ConcreteHelper()
    assert isinstance(helper.detect_anti_analysis(), dict)


def test_detect_compiler_returns_dict():
    helper = ConcreteHelper()
    assert isinstance(helper.detect_compiler(), dict)


def test_run_yara_rules_returns_list():
    helper = ConcreteHelper()
    assert isinstance(helper.run_yara_rules(), list)


def test_run_yara_rules_with_path_returns_list():
    helper = ConcreteHelper()
    assert isinstance(helper.run_yara_rules("/some/path"), list)


def test_search_xor_returns_list():
    helper = ConcreteHelper()
    assert isinstance(helper.search_xor("test"), list)


def test_analyze_functions_returns_dict():
    helper = ConcreteHelper()
    assert isinstance(helper.analyze_functions(), dict)


def test_analyze_ssdeep_returns_dict():
    helper = ConcreteHelper()
    assert isinstance(helper.analyze_ssdeep(), dict)


def test_analyze_tlsh_returns_dict():
    helper = ConcreteHelper()
    assert isinstance(helper.analyze_tlsh(), dict)


def test_analyze_telfhash_returns_dict():
    helper = ConcreteHelper()
    assert isinstance(helper.analyze_telfhash(), dict)


def test_analyze_rich_header_returns_dict():
    helper = ConcreteHelper()
    assert isinstance(helper.analyze_rich_header(), dict)


def test_analyze_impfuzzy_returns_dict():
    helper = ConcreteHelper()
    assert isinstance(helper.analyze_impfuzzy(), dict)


def test_analyze_ccbhash_returns_dict():
    helper = ConcreteHelper()
    assert isinstance(helper.analyze_ccbhash(), dict)


def test_analyze_binlex_returns_dict():
    helper = ConcreteHelper()
    assert isinstance(helper.analyze_binlex(), dict)


def test_analyze_binbloom_returns_dict():
    helper = ConcreteHelper()
    assert isinstance(helper.analyze_binbloom(), dict)


def test_analyze_simhash_returns_dict():
    helper = ConcreteHelper()
    assert isinstance(helper.analyze_simhash(), dict)


def test_analyze_bindiff_returns_dict():
    helper = ConcreteHelper()
    assert isinstance(helper.analyze_bindiff(), dict)


# ---------------------------------------------------------------------------
# generate_indicators  (lines 183-184)
# ---------------------------------------------------------------------------


def test_generate_indicators_returns_list():
    helper = ConcreteHelper(aggregator=SimpleAggregator())
    result = helper.generate_indicators({"data": "test"})
    assert isinstance(result, list)


def test_generate_indicators_returns_empty_when_aggregator_returns_non_list():

    class BadAggregator:
        def generate_indicators(self, results: dict[str, Any]) -> str:
            return "not_a_list"

    helper = ConcreteHelper(aggregator=BadAggregator())
    result = helper.generate_indicators({})
    assert result == []


# ---------------------------------------------------------------------------
# generate_executive_summary  (lines 220-221)
# ---------------------------------------------------------------------------


def test_generate_executive_summary_returns_dict():
    helper = ConcreteHelper(aggregator=SimpleAggregator())
    result = helper.generate_executive_summary({"data": "test"})
    assert isinstance(result, dict)
    assert result == {"summary": "ok"}


def test_generate_executive_summary_returns_empty_for_non_dict():

    class NonDictAggregator:
        def generate_executive_summary(self, results: dict[str, Any]) -> list[str]:
            return ["not", "a", "dict"]

    helper = ConcreteHelper(aggregator=NonDictAggregator())
    result = helper.generate_executive_summary({})
    assert result == {}
