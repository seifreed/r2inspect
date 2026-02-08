from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.core.inspector_helpers import InspectorExecutionMixin
from r2inspect.core.result_aggregator import ResultAggregator
from r2inspect.factory import create_inspector
from r2inspect.registry.analyzer_registry import AnalyzerRegistry


def _sample_path() -> Path:
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")
    return sample


class _BareInspector(InspectorExecutionMixin):
    def __init__(self) -> None:
        self.adapter = None
        self.config = None
        self.filename = "missing"
        self.registry = AnalyzerRegistry()
        self._result_aggregator = ResultAggregator()


@pytest.mark.unit
def test_inspector_helpers_type_coercions() -> None:
    assert InspectorExecutionMixin._as_dict({"a": 1}) == {"a": 1}
    assert InspectorExecutionMixin._as_dict("nope") == {}
    assert InspectorExecutionMixin._as_bool_dict({"a": 1, "b": 0}) == {"a": True, "b": False}
    assert InspectorExecutionMixin._as_bool_dict("nope") == {}
    assert InspectorExecutionMixin._as_str("ok", default="x") == "ok"
    assert InspectorExecutionMixin._as_str(1, default="x") == "x"


@pytest.mark.unit
def test_inspector_helpers_analyzer_not_found_branch() -> None:
    inspector = _BareInspector()
    assert inspector.detect_crypto()["error"] == "Analyzer not found"


@pytest.mark.unit
def test_inspector_helpers_real_methods() -> None:
    sample = _sample_path()
    with create_inspector(str(sample)) as inspector:
        assert inspector.get_file_info()
        assert isinstance(inspector.get_pe_info(), dict)
        assert isinstance(inspector.get_strings(), list)
        assert isinstance(inspector.get_security_features(), dict)
        assert isinstance(inspector.get_imports(), list)
        assert isinstance(inspector.get_exports(), list)
        assert isinstance(inspector.get_sections(), list)

        assert isinstance(inspector.detect_packer(), dict)
        assert isinstance(inspector.detect_anti_analysis(), dict)
        assert isinstance(inspector.detect_compiler(), dict)
        assert isinstance(inspector.detect_crypto(), dict)

        assert isinstance(inspector.run_yara_rules(), list)
        assert isinstance(inspector.search_xor("test"), list)
        assert isinstance(inspector.analyze_functions(), dict)
        assert isinstance(inspector.analyze_ssdeep(), dict)
        assert isinstance(inspector.analyze_tlsh(), dict)
        assert isinstance(inspector.analyze_telfhash(), dict)
        assert isinstance(inspector.analyze_rich_header(), dict)
        assert isinstance(inspector.analyze_impfuzzy(), dict)
        assert isinstance(inspector.analyze_ccbhash(), dict)
        assert isinstance(inspector.analyze_binlex(), dict)
        assert isinstance(inspector.analyze_binbloom(), dict)
        assert isinstance(inspector.analyze_simhash(), dict)
        assert isinstance(inspector.analyze_bindiff(), dict)

        analysis = inspector.analyze()
        indicators = inspector.generate_indicators(analysis)
        assert isinstance(indicators, list)
        summary = inspector.generate_executive_summary(analysis)
        assert isinstance(summary, dict)

        # Exercise analyzer lookup/method missing branch.
        assert inspector._execute_analyzer("missing_analyzer") == {}
        assert inspector._execute_analyzer("pe_analyzer", "missing_method") == {}
        assert inspector._execute_analyzer("string_analyzer", "analyze", "extra") == {}
        assert inspector._detect_file_format() in {"PE", "PE32", "PE32+", "Unknown"}
        assert isinstance(inspector.get_elf_info(), dict)
        assert isinstance(inspector.get_macho_info(), dict)

        progress: list[str] = []

        def _progress(stage: str, *_args: object) -> None:
            progress.append(stage)

        inspector.analyze(progress_callback=_progress)
        assert progress


@pytest.mark.unit
def test_result_aggregator_indicators_and_summary() -> None:
    agg = ResultAggregator()
    results = {
        "file_info": {
            "name": "sample.exe",
            "file_type": "PE",
            "size": 1,
            "md5": "x",
            "sha256": "y",
        },
        "pe_info": {"compilation_timestamp": "now"},
        "security": {"authenticode": False, "aslr": True, "dep": False, "cfg": False},
        "packer": {"is_packed": True, "packer_type": "UPX"},
        "anti_analysis": {"anti_debug": True, "anti_vm": True},
        "imports": [{"name": "VirtualAlloc"}, {"name": "CreateRemoteThread"}],
        "yara_matches": [{"rule": "rule1"}],
        "sections": [{"entropy": 7.5, "name": "UPX0"}],
        "functions": {"count": 2},
        "crypto": {"matches": ["AES"]},
        "rich_header": {
            "available": True,
            "compilers": [{"compiler_name": "MSVC", "build_number": 1}],
        },
    }
    indicators = agg.generate_indicators(results)
    assert indicators

    summary = agg.generate_executive_summary(results)
    assert "file_overview" in summary
    assert summary["file_overview"]["toolset"]

    # Trigger error handling in executive summary.
    bad_summary = agg.generate_executive_summary({"file_info": None})
    assert "error" in bad_summary
