#!/usr/bin/env python3
"""Comprehensive tests for inspector_helpers.py execution mixin -- mock-free."""

from typing import Any

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.config import Config
from r2inspect.core.inspector import InspectorExecutionMixin
from r2inspect.core.result_aggregator import ResultAggregator
from r2inspect.pipeline.analysis_pipeline import AnalysisPipeline
from r2inspect.pipeline.stage_models import AnalysisStage
from r2inspect.registry.analyzer_registry import AnalyzerRegistry
from r2inspect.registry.categories import AnalyzerCategory
from r2inspect.abstractions.base_analyzer import BaseAnalyzer


# ---------------------------------------------------------------------------
# FakeR2 -- lightweight stand-in for an r2pipe session
# ---------------------------------------------------------------------------


class FakeR2:
    def __init__(self, cmdj_map=None, cmd_map=None):
        self.cmdj_map = cmdj_map or {}
        self.cmd_map = cmd_map or {}

    def cmdj(self, command):
        return self.cmdj_map.get(command, {})

    def cmd(self, command):
        return self.cmd_map.get(command, "")


# ---------------------------------------------------------------------------
# Tiny real analyzers used to populate the registry in tests
# ---------------------------------------------------------------------------


class _DictAnalyzer(BaseAnalyzer):
    """Analyzer whose analyze() returns a fixed dict."""

    _result: dict[str, Any] = {}

    def analyze(self) -> dict[str, Any]:
        return self._result


class _ListAnalyzer(BaseAnalyzer):
    """Analyzer with an analyze() that returns a list."""

    _result: list[Any] = []

    def analyze(self) -> Any:
        return self._result


class _MultiMethodAnalyzer(BaseAnalyzer):
    """Analyzer exposing several named methods for dispatch testing."""

    _analyze_result: dict[str, Any] = {"data": "result"}
    _custom_result: dict[str, Any] = {"custom": "data"}

    def analyze(self) -> dict[str, Any]:
        return self._analyze_result

    def custom_method(self) -> dict[str, Any]:
        return self._custom_result


class _ArgEchoAnalyzer(BaseAnalyzer):
    """Analyzer whose analyze() echoes back positional and keyword args."""

    def analyze(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return {"args": list(args), "kwargs": kwargs}


class _ExplodingAnalyzer(BaseAnalyzer):
    """Analyzer that always raises on construction body (but not __init__)."""

    def analyze(self) -> dict[str, Any]:
        raise RuntimeError("boom")


class _StringAnalyzer(BaseAnalyzer):
    """Analyzer with extract_strings and search_xor methods."""

    def analyze(self) -> dict[str, Any]:
        return {}

    def extract_strings(self) -> list[str]:
        return ["string1", "string2"]

    def search_xor(self, search_string: str) -> list[dict[str, Any]]:
        return [{"offset": 100, "pattern": search_string}]


class _SecurityAnalyzer(BaseAnalyzer):
    """Analyzer with get_security_features method."""

    def analyze(self) -> dict[str, Any]:
        return {}

    def get_security_features(self) -> dict[str, Any]:
        return {"aslr": True, "dep": False}


class _ImportAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict[str, Any]:
        return {}

    def get_imports(self) -> list[dict[str, Any]]:
        return [{"name": "kernel32.dll"}]


class _ExportAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict[str, Any]:
        return {}

    def get_exports(self) -> list[dict[str, Any]]:
        return [{"name": "DllMain"}]


class _SectionAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict[str, Any]:
        return {}

    def analyze_sections(self) -> list[dict[str, Any]]:
        return [{"name": ".text"}]


class _PackerDetector(BaseAnalyzer):
    def analyze(self) -> dict[str, Any]:
        return {}

    def detect(self) -> dict[str, Any]:
        return {"is_packed": True}


class _CryptoAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict[str, Any]:
        return {}

    def detect(self) -> dict[str, Any]:
        return {"algorithms": ["AES"]}


class _AntiAnalysis(BaseAnalyzer):
    def analyze(self) -> dict[str, Any]:
        return {}

    def detect(self) -> dict[str, Any]:
        return {"anti_debug": True}


class _CompilerDetector(BaseAnalyzer):
    def analyze(self) -> dict[str, Any]:
        return {}

    def detect_compiler(self) -> dict[str, Any]:
        return {"compiler": "MSVC"}


class _YaraAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict[str, Any]:
        return {}

    def scan(self, rules_path=None) -> list[dict[str, Any]]:
        if rules_path:
            return [{"rule": "custom"}]
        return [{"rule": "malware"}]


class _FunctionAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict[str, Any]:
        return {}

    def analyze_functions(self) -> dict[str, Any]:
        return {"count": 10}


class _SimilarityAnalyzer(BaseAnalyzer):
    """Generic similarity analyzer that returns a dict from analyze()."""

    _name: str = "similarity"

    def analyze(self) -> dict[str, Any]:
        return {"hash": "abc123", "type": self._name}


# ---------------------------------------------------------------------------
# Helpers to build a real TestInspector backed by FakeR2 + real registry
# ---------------------------------------------------------------------------


def _make_registry(**name_to_class: type) -> AnalyzerRegistry:
    """Build a small AnalyzerRegistry populated with the given analyzers."""
    registry = AnalyzerRegistry(lazy_loading=False)
    for name, cls in name_to_class.items():
        registry.register(name=name, analyzer_class=cls, category=AnalyzerCategory.DETECTION)
    return registry


def _make_inspector(
    registry: AnalyzerRegistry | None = None,
    cmdj_map: dict | None = None,
    cmd_map: dict | None = None,
) -> InspectorExecutionMixin:
    """Create a concrete InspectorExecutionMixin wired to real collaborators."""
    fake_r2 = FakeR2(cmdj_map=cmdj_map, cmd_map=cmd_map)
    adapter = R2PipeAdapter(fake_r2)
    config = Config()

    class _TestInspector(InspectorExecutionMixin):
        pass

    inspector = _TestInspector.__new__(_TestInspector)
    inspector.adapter = adapter
    inspector.config = config
    inspector.filename = "test.bin"
    inspector.registry = registry or AnalyzerRegistry(lazy_loading=False)
    inspector._result_aggregator = ResultAggregator()
    return inspector


# ---------------------------------------------------------------------------
# A simple real pipeline stage for progress/execution tests
# ---------------------------------------------------------------------------


class _FixedResultStage(AnalysisStage):
    """Stage that merges a fixed dict into the pipeline context results."""

    def __init__(self, name: str, result: dict[str, Any]):
        super().__init__(name=name)
        self._result = result

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        results = context.setdefault("results", {})
        results.update(self._result)
        return context


class _NonDictStage(AnalysisStage):
    """Stage whose _execute returns a non-dict to exercise fallback."""

    def __init__(self, name: str):
        super().__init__(name=name)

    def _execute(self, _context: dict[str, Any]) -> dict[str, Any]:
        # The pipeline itself always returns a dict, but we can make the
        # results sub-key hold something unexpected.
        return {"results": {}}


# ===================================================================
# Pipeline execution tests
# ===================================================================


def test_execute_with_progress_returns_dict():
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_FixedResultStage("s1", {"result": "data"}))

    inspector = _make_inspector()
    progress_messages: list[str] = []
    result = inspector._execute_with_progress(
        pipeline, {}, lambda s, *_a: progress_messages.append(str(s))
    )
    assert isinstance(result, dict)
    # Pipeline wraps results under "results" key in the context
    results = result.get("results", result)
    assert results.get("result") == "data"


def test_execute_with_progress_empty_pipeline():
    """An empty pipeline should return a dict (possibly empty)."""
    pipeline = AnalysisPipeline()
    inspector = _make_inspector()
    result = inspector._execute_with_progress(pipeline, {}, lambda *_a: None)
    assert isinstance(result, dict)


def test_execute_without_progress_returns_dict():
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_FixedResultStage("s1", {"result": "data"}))

    inspector = _make_inspector()
    result = inspector._execute_without_progress(pipeline, {})
    assert isinstance(result, dict)
    results = result.get("results", result)
    assert results.get("result") == "data"


def test_execute_without_progress_with_parallel():
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_FixedResultStage("s1", {"result": "data"}))

    inspector = _make_inspector()
    result = inspector._execute_without_progress(pipeline, {}, parallel=True)
    assert isinstance(result, dict)
    results = result.get("results", result)
    assert results.get("result") == "data"


def test_execute_without_progress_empty_pipeline():
    pipeline = AnalysisPipeline()
    inspector = _make_inspector()
    result = inspector._execute_without_progress(pipeline, {})
    assert isinstance(result, dict)


# ===================================================================
# Static helper tests (_as_dict, _as_bool_dict, _as_str)
# ===================================================================


def test_as_dict_with_dict():
    result = InspectorExecutionMixin._as_dict({"key": "value"})
    assert result == {"key": "value"}


def test_as_dict_with_non_dict():
    assert InspectorExecutionMixin._as_dict("string") == {}
    assert InspectorExecutionMixin._as_dict(123) == {}
    assert InspectorExecutionMixin._as_dict(None) == {}
    assert InspectorExecutionMixin._as_dict([1, 2, 3]) == {}


def test_as_bool_dict_with_dict():
    input_data = {"key1": 1, "key2": 0, "key3": True, "key4": False, "key5": "string"}
    result = InspectorExecutionMixin._as_bool_dict(input_data)
    assert result == {"key1": True, "key2": False, "key3": True, "key4": False, "key5": True}


def test_as_bool_dict_with_mixed_keys():
    input_data = {1: True, "str": False, 3.14: 1}
    result = InspectorExecutionMixin._as_bool_dict(input_data)
    assert result == {"1": True, "str": False, "3.14": True}


def test_as_bool_dict_with_non_dict():
    assert InspectorExecutionMixin._as_bool_dict("string") == {}
    assert InspectorExecutionMixin._as_bool_dict(123) == {}
    assert InspectorExecutionMixin._as_bool_dict(None) == {}


def test_as_str_with_string():
    result = InspectorExecutionMixin._as_str("test")
    assert result == "test"


def test_as_str_with_non_string():
    assert InspectorExecutionMixin._as_str(123) == ""
    assert InspectorExecutionMixin._as_str(None) == ""
    assert InspectorExecutionMixin._as_str([1, 2]) == ""


def test_as_str_with_custom_default():
    assert InspectorExecutionMixin._as_str(123, default="custom") == "custom"
    assert InspectorExecutionMixin._as_str(None, default="N/A") == "N/A"


# ===================================================================
# _execute_analyzer dispatch tests
# ===================================================================


def test_execute_analyzer_not_found():
    inspector = _make_inspector()
    result = inspector._execute_analyzer("nonexistent_analyzer")
    assert result == {}


def test_execute_analyzer_default_method():
    registry = _make_registry(test_analyzer=_MultiMethodAnalyzer)
    inspector = _make_inspector(registry=registry)

    result = inspector._execute_analyzer("test_analyzer")
    assert result == {"data": "result"}


def test_execute_analyzer_custom_method():
    registry = _make_registry(test_analyzer=_MultiMethodAnalyzer)
    inspector = _make_inspector(registry=registry)

    result = inspector._execute_analyzer("test_analyzer", "custom_method")
    assert result == {"custom": "data"}


def test_execute_analyzer_method_not_found():
    registry = _make_registry(test_analyzer=_DictAnalyzer)
    inspector = _make_inspector(registry=registry)

    result = inspector._execute_analyzer("test_analyzer", "missing_method")
    assert result == {}


def test_execute_analyzer_with_args():
    registry = _make_registry(test_analyzer=_ArgEchoAnalyzer)
    inspector = _make_inspector(registry=registry)

    result = inspector._execute_analyzer("test_analyzer", "analyze", "arg1", "arg2")
    assert result["args"] == ["arg1", "arg2"]


def test_execute_analyzer_with_kwargs():
    registry = _make_registry(test_analyzer=_ArgEchoAnalyzer)
    inspector = _make_inspector(registry=registry)

    result = inspector._execute_analyzer("test_analyzer", "analyze", key="value")
    assert result["kwargs"] == {"key": "value"}


def test_execute_analyzer_raises_exception():
    registry = _make_registry(test_analyzer=_ExplodingAnalyzer)
    inspector = _make_inspector(registry=registry)

    result = inspector._execute_analyzer("test_analyzer")
    assert result == {}


# ===================================================================
# _execute_list / _execute_dict
# ===================================================================


def test_execute_list_returns_list():
    class _LA(_ListAnalyzer):
        _result = ["item1", "item2"]

    registry = _make_registry(test_analyzer=_LA)
    inspector = _make_inspector(registry=registry)

    result = inspector._execute_list("test_analyzer")
    assert result == ["item1", "item2"]


def test_execute_list_converts_non_list():
    class _DA(_DictAnalyzer):
        _result = {"not": "list"}

    registry = _make_registry(test_analyzer=_DA)
    inspector = _make_inspector(registry=registry)

    result = inspector._execute_list("test_analyzer")
    assert result == []


def test_execute_dict_returns_dict():
    class _DA(_DictAnalyzer):
        _result = {"key": "value"}

    registry = _make_registry(test_analyzer=_DA)
    inspector = _make_inspector(registry=registry)

    result = inspector._execute_dict("test_analyzer")
    assert result == {"key": "value"}


def test_execute_dict_converts_non_dict():
    class _LA(_ListAnalyzer):
        _result = ["not", "dict"]

    registry = _make_registry(test_analyzer=_LA)
    inspector = _make_inspector(registry=registry)

    result = inspector._execute_dict("test_analyzer")
    assert result == {}


# ===================================================================
# Stage-backed query methods (get_file_info, _detect_file_format)
# ===================================================================


def test_get_file_info():
    inspector = _make_inspector(
        cmdj_map={"ij": {"core": {"size": 1024, "file": "test.bin"}}},
    )
    result = inspector.get_file_info()
    assert isinstance(result, dict)


def test_detect_file_format():
    inspector = _make_inspector(
        cmdj_map={"ij": {"bin": {"bintype": "pe", "arch": "x86"}}},
    )
    result = inspector._detect_file_format()
    assert isinstance(result, str)


# ===================================================================
# High-level convenience methods backed by real analyzers
# ===================================================================


def test_get_pe_info():
    class _PE(_DictAnalyzer):
        _result = {"pe_type": "PE32"}

    registry = _make_registry(pe_analyzer=_PE)
    inspector = _make_inspector(registry=registry)

    result = inspector.get_pe_info()
    assert isinstance(result, dict)


def test_get_elf_info():
    class _ELF(_DictAnalyzer):
        _result = {"elf_type": "ELF64"}

    registry = _make_registry(elf_analyzer=_ELF)
    inspector = _make_inspector(registry=registry)

    result = inspector.get_elf_info()
    assert isinstance(result, dict)


def test_get_macho_info():
    class _Macho(_DictAnalyzer):
        _result = {"macho_type": "Mach-O"}

    registry = _make_registry(macho_analyzer=_Macho)
    inspector = _make_inspector(registry=registry)

    result = inspector.get_macho_info()
    assert isinstance(result, dict)


def test_get_strings():
    registry = _make_registry(string_analyzer=_StringAnalyzer)
    inspector = _make_inspector(registry=registry)

    result = inspector.get_strings()
    assert result == ["string1", "string2"]


def test_get_security_features():
    registry = _make_registry(pe_analyzer=_SecurityAnalyzer)
    inspector = _make_inspector(registry=registry)

    result = inspector.get_security_features()
    assert result == {"aslr": True, "dep": False}


def test_get_imports():
    registry = _make_registry(import_analyzer=_ImportAnalyzer)
    inspector = _make_inspector(registry=registry)

    result = inspector.get_imports()
    assert result == [{"name": "kernel32.dll"}]


def test_get_exports():
    registry = _make_registry(export_analyzer=_ExportAnalyzer)
    inspector = _make_inspector(registry=registry)

    result = inspector.get_exports()
    assert result == [{"name": "DllMain"}]


def test_get_sections():
    registry = _make_registry(section_analyzer=_SectionAnalyzer)
    inspector = _make_inspector(registry=registry)

    result = inspector.get_sections()
    assert result == [{"name": ".text"}]


def test_detect_packer():
    registry = _make_registry(packer_detector=_PackerDetector)
    inspector = _make_inspector(registry=registry)

    result = inspector.detect_packer()
    assert result == {"is_packed": True}


def test_detect_crypto():
    registry = _make_registry(crypto_analyzer=_CryptoAnalyzer)
    inspector = _make_inspector(registry=registry)

    result = inspector.detect_crypto()
    assert "algorithms" in result


def test_detect_crypto_analyzer_not_found():
    inspector = _make_inspector()  # empty registry
    result = inspector.detect_crypto()
    assert result.get("error") == "Analyzer not found"


def test_detect_anti_analysis():
    registry = _make_registry(anti_analysis=_AntiAnalysis)
    inspector = _make_inspector(registry=registry)

    result = inspector.detect_anti_analysis()
    assert result == {"anti_debug": True}


def test_detect_compiler():
    registry = _make_registry(compiler_detector=_CompilerDetector)
    inspector = _make_inspector(registry=registry)

    result = inspector.detect_compiler()
    assert result == {"compiler": "MSVC"}


def test_run_yara_rules():
    registry = _make_registry(yara_analyzer=_YaraAnalyzer)
    inspector = _make_inspector(registry=registry)

    result = inspector.run_yara_rules()
    assert result == [{"rule": "malware"}]


def test_run_yara_rules_with_custom_path():
    registry = _make_registry(yara_analyzer=_YaraAnalyzer)
    inspector = _make_inspector(registry=registry)

    result = inspector.run_yara_rules("/path/to/rules")
    assert result == [{"rule": "custom"}]


def test_search_xor():
    registry = _make_registry(string_analyzer=_StringAnalyzer)
    inspector = _make_inspector(registry=registry)

    result = inspector.search_xor("test")
    assert len(result) == 1
    assert result[0]["offset"] == 100
    assert result[0]["pattern"] == "test"


# ===================================================================
# Indicator / summary helpers (backed by real ResultAggregator)
# ===================================================================


def test_generate_indicators():
    inspector = _make_inspector()
    result = inspector.generate_indicators({"sections": []})
    # Real aggregator returns a list (possibly empty when no indicators match)
    assert isinstance(result, list)


def test_generate_indicators_with_suspicious_data():
    inspector = _make_inspector()
    # Provide analysis results that the real aggregator might flag
    result = inspector.generate_indicators(
        {
            "sections": [{"name": ".text", "entropy": 7.9}],
            "imports": [{"name": "VirtualAlloc"}, {"name": "WriteProcessMemory"}],
        }
    )
    assert isinstance(result, list)


def test_analyze_functions():
    registry = _make_registry(function_analyzer=_FunctionAnalyzer)
    inspector = _make_inspector(registry=registry)

    result = inspector.analyze_functions()
    assert result == {"count": 10}


# ===================================================================
# Similarity analyzers
# ===================================================================


def _make_similarity_class(name: str) -> type:
    """Dynamically build a similarity analyzer class."""

    class _Sim(_SimilarityAnalyzer):
        _name = name

    _Sim.__name__ = f"_Sim_{name}"
    return _Sim


def test_analyze_ssdeep():
    registry = _make_registry(ssdeep=_make_similarity_class("ssdeep"))
    inspector = _make_inspector(registry=registry)
    result = inspector.analyze_ssdeep()
    assert isinstance(result, dict)
    assert result.get("type") == "ssdeep"


def test_analyze_tlsh():
    registry = _make_registry(tlsh=_make_similarity_class("tlsh"))
    inspector = _make_inspector(registry=registry)
    result = inspector.analyze_tlsh()
    assert isinstance(result, dict)
    assert result.get("type") == "tlsh"


def test_analyze_telfhash():
    registry = _make_registry(telfhash=_make_similarity_class("telfhash"))
    inspector = _make_inspector(registry=registry)
    result = inspector.analyze_telfhash()
    assert isinstance(result, dict)


def test_analyze_rich_header():
    registry = _make_registry(rich_header=_make_similarity_class("rich_header"))
    inspector = _make_inspector(registry=registry)
    result = inspector.analyze_rich_header()
    assert isinstance(result, dict)


def test_analyze_impfuzzy():
    registry = _make_registry(impfuzzy=_make_similarity_class("impfuzzy"))
    inspector = _make_inspector(registry=registry)
    result = inspector.analyze_impfuzzy()
    assert isinstance(result, dict)


def test_analyze_ccbhash():
    registry = _make_registry(ccbhash=_make_similarity_class("ccbhash"))
    inspector = _make_inspector(registry=registry)
    result = inspector.analyze_ccbhash()
    assert isinstance(result, dict)


def test_analyze_binlex():
    registry = _make_registry(binlex=_make_similarity_class("binlex"))
    inspector = _make_inspector(registry=registry)
    result = inspector.analyze_binlex()
    assert isinstance(result, dict)


def test_analyze_binbloom():
    registry = _make_registry(binbloom=_make_similarity_class("binbloom"))
    inspector = _make_inspector(registry=registry)
    result = inspector.analyze_binbloom()
    assert isinstance(result, dict)


def test_analyze_simhash():
    registry = _make_registry(simhash=_make_similarity_class("simhash"))
    inspector = _make_inspector(registry=registry)
    result = inspector.analyze_simhash()
    assert isinstance(result, dict)


def test_analyze_bindiff():
    registry = _make_registry(bindiff=_make_similarity_class("bindiff"))
    inspector = _make_inspector(registry=registry)
    result = inspector.analyze_bindiff()
    assert isinstance(result, dict)


# ===================================================================
# Executive summary (real ResultAggregator)
# ===================================================================


def test_generate_executive_summary():
    inspector = _make_inspector()
    result = inspector.generate_executive_summary({"analysis": "results"})
    assert isinstance(result, dict)


def test_generate_executive_summary_with_empty_results():
    inspector = _make_inspector()
    result = inspector.generate_executive_summary({})
    assert isinstance(result, dict)
