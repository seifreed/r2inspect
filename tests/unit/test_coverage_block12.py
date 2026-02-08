from __future__ import annotations

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.function_analyzer import FunctionAnalyzer

PE_FIXTURE = "samples/fixtures/hello_pe.exe"


def test_function_analyzer_real_fixture() -> None:
    r2 = r2pipe.open(PE_FIXTURE)
    try:
        adapter = R2PipeAdapter(r2)
        analyzer = FunctionAnalyzer(adapter)
        result = analyzer.analyze_functions()
        summary = analyzer.generate_machoc_summary(result)
    finally:
        r2.quit()

    assert "total_functions" in result
    assert "function_stats" in result
    assert "machoc_hashes" in result
    if result["total_functions"] > 0:
        assert result["functions_analyzed"] >= 0
    assert "total_functions_hashed" in summary or "error" in summary


def test_function_analyzer_helpers() -> None:
    r2 = r2pipe.open(PE_FIXTURE)
    try:
        adapter = R2PipeAdapter(r2)
        analyzer = FunctionAnalyzer(adapter)
        functions = analyzer._get_functions()
        if functions:
            func = functions[0]
            func_name = func.get("name", "f")
            analyzer._calculate_cyclomatic_complexity(func)
            analyzer._classify_function_type(func_name, func)
        stats = analyzer._generate_function_stats(functions)
        coverage = analyzer._analyze_function_coverage(functions)
    finally:
        r2.quit()

    assert isinstance(stats, dict)
    assert isinstance(coverage, dict)


def test_function_similarity_and_stats_helpers() -> None:
    analyzer = FunctionAnalyzer(None)
    machoc_hashes = {"f1": "aaa", "f2": "aaa", "f3": "bbb"}
    similarities = analyzer.get_function_similarity(machoc_hashes)
    assert similarities

    summary = analyzer.generate_machoc_summary({"machoc_hashes": machoc_hashes})
    assert summary.get("duplicate_function_groups") == 1
    assert summary.get("total_duplicate_functions") == 2

    assert analyzer._calculate_std_dev([1.0, 2.0, 3.0]) > 0
    assert analyzer._calculate_std_dev([1.0]) == 0.0
