#!/usr/bin/env python3
"""Branch-path tests for r2inspect/pipeline/stages_metadata.py.

Covers missing lines: 28, 34-38, 41, 43-45, 47-49, 51-53, 55-57, 59-62,
64, 74-75, 77-79, 81-82, 88-95, 98, 103, 106, 109, 112.
"""

from __future__ import annotations

from typing import Any

import pytest

from r2inspect.pipeline.stages_metadata import MetadataStage
from r2inspect.registry.analyzer_registry import AnalyzerCategory, AnalyzerRegistry


# ---------------------------------------------------------------------------
# Minimal helpers (plain Python classes - no mocks)
# ---------------------------------------------------------------------------


class _DummyConfig:
    pass


class _DummyAdapter:
    def get_file_info(self) -> dict:
        return {"bin": {"format": "pe"}}


# ---------------------------------------------------------------------------
# Dummy analyzer classes for registry registration
# ---------------------------------------------------------------------------


class _DummySectionAnalyzer:
    def __init__(self, **_kwargs: Any) -> None:
        pass

    def analyze_sections(self) -> list:
        return [{"name": ".text"}, {"name": ".data"}]


class _DummyImportAnalyzer:
    def __init__(self, **_kwargs: Any) -> None:
        pass

    def get_imports(self) -> list:
        return [{"name": "CreateFileA", "library": "kernel32.dll"}]


class _DummyExportAnalyzer:
    def __init__(self, **_kwargs: Any) -> None:
        pass

    def get_exports(self) -> list:
        return [{"name": "main"}]


class _DummyStringAnalyzer:
    def __init__(self, **_kwargs: Any) -> None:
        pass

    def extract_strings(self) -> list:
        return ["hello", "world"]


class _DummyFunctionAnalyzer:
    def __init__(self, **_kwargs: Any) -> None:
        pass

    def analyze_functions(self) -> dict:
        return {"count": 5, "functions": []}


class _RaisingSectionAnalyzer:
    """Analyzer whose analyze_sections raises to test exception path."""

    def __init__(self, **_kwargs: Any) -> None:
        pass

    def analyze_sections(self) -> list:
        raise RuntimeError("simulated section analysis error")


class _RaisingImportAnalyzer:
    """Analyzer whose get_imports raises to test exception path."""

    def __init__(self, **_kwargs: Any) -> None:
        pass

    def get_imports(self) -> list:
        raise RuntimeError("simulated import analysis error")


# ---------------------------------------------------------------------------
# Helper to build a registry with specific analyzers
# ---------------------------------------------------------------------------


def _make_registry(
    sections: type | None = _DummySectionAnalyzer,
    imports: type | None = _DummyImportAnalyzer,
    exports: type | None = _DummyExportAnalyzer,
    strings: type | None = _DummyStringAnalyzer,
    functions: type | None = _DummyFunctionAnalyzer,
) -> AnalyzerRegistry:
    registry = AnalyzerRegistry(lazy_loading=False)
    if sections:
        registry.register("section_analyzer", sections, AnalyzerCategory.METADATA)
    if imports:
        registry.register("import_analyzer", imports, AnalyzerCategory.METADATA)
    if exports:
        registry.register("export_analyzer", exports, AnalyzerCategory.METADATA)
    if strings:
        registry.register("string_analyzer", strings, AnalyzerCategory.METADATA)
    if functions:
        registry.register("function_analyzer", functions, AnalyzerCategory.METADATA)
    return registry


# ---------------------------------------------------------------------------
# MetadataStage.__init__ - lines 28-38
# ---------------------------------------------------------------------------


def test_metadata_stage_init_sets_all_attributes():
    """Instantiating MetadataStage covers all __init__ lines (28-38)."""
    registry = _make_registry()
    adapter = _DummyAdapter()
    config = _DummyConfig()
    options: dict[str, Any] = {"analyze_functions": True}

    stage = MetadataStage(registry, adapter, config, "test.exe", options)

    assert stage.registry is registry
    assert stage.adapter is adapter
    assert stage.config is config
    assert stage.filename == "test.exe"
    assert stage.options is options
    assert stage.name == "metadata"
    assert stage.optional is True
    assert "file_info" in stage.dependencies
    assert "format_detection" in stage.dependencies


# ---------------------------------------------------------------------------
# MetadataStage._execute - lines 41-64: full execution with all analyzers
# ---------------------------------------------------------------------------


def test_metadata_stage_execute_returns_all_sections():
    registry = _make_registry()
    stage = MetadataStage(
        registry, _DummyAdapter(), _DummyConfig(), "test.exe",
        {"analyze_functions": True},
    )
    ctx: dict[str, Any] = {"results": {}}
    result = stage.execute(ctx)

    assert "sections" in result
    assert "imports" in result
    assert "exports" in result
    assert "strings" in result
    assert "functions" in result


def test_metadata_stage_execute_without_analyze_functions():
    """analyze_functions=False skips function analysis; lines 59-62 branch taken False."""
    registry = _make_registry()
    stage = MetadataStage(
        registry, _DummyAdapter(), _DummyConfig(), "test.exe",
        {"analyze_functions": False},
    )
    ctx: dict[str, Any] = {"results": {}}
    result = stage.execute(ctx)

    assert "sections" in result
    assert "functions" not in result


def test_metadata_stage_execute_populates_context_results():
    registry = _make_registry()
    stage = MetadataStage(
        registry, _DummyAdapter(), _DummyConfig(), "test.exe",
        {"analyze_functions": True},
    )
    ctx: dict[str, Any] = {"results": {}}
    stage.execute(ctx)

    assert "sections" in ctx["results"]
    assert "imports" in ctx["results"]


# ---------------------------------------------------------------------------
# MetadataStage._run_analyzer_method - line 79: return None when not registered
# ---------------------------------------------------------------------------


def test_run_analyzer_method_returns_none_when_analyzer_not_registered():
    """No analyzers registered -> get_analyzer_class returns None -> line 79."""
    registry = AnalyzerRegistry(lazy_loading=False)
    stage = MetadataStage(
        registry, _DummyAdapter(), _DummyConfig(), "test.exe",
        {"analyze_functions": False},
    )
    ctx: dict[str, Any] = {"results": {}}
    result = stage._run_analyzer_method(ctx, "nonexistent_analyzer", "some_method", "key")
    assert result is None


def test_execute_with_no_registered_analyzers_returns_empty():
    """No analyzers registered -> all _extract_* return None -> result is {}."""
    registry = AnalyzerRegistry(lazy_loading=False)
    stage = MetadataStage(
        registry, _DummyAdapter(), _DummyConfig(), "test.exe",
        {"analyze_functions": True},
    )
    ctx: dict[str, Any] = {"results": {}}
    result = stage.execute(ctx)
    assert result == {}


# ---------------------------------------------------------------------------
# _run_analyzer_method - lines 92-95: exception path
# ---------------------------------------------------------------------------


def test_run_analyzer_method_exception_path_stores_default_value():
    """Analyzer raises -> exception caught at lines 92-95 -> default returned."""
    registry = _make_registry(sections=_RaisingSectionAnalyzer)
    stage = MetadataStage(
        registry, _DummyAdapter(), _DummyConfig(), "test.exe",
        {"analyze_functions": False},
    )
    ctx: dict[str, Any] = {"results": {}}
    result = stage._run_analyzer_method(
        ctx, "section_analyzer", "analyze_sections", "sections"
    )
    assert result == {"sections": []}
    assert ctx["results"]["sections"] == []


def test_run_analyzer_method_exception_path_for_imports():
    registry = _make_registry(imports=_RaisingImportAnalyzer)
    stage = MetadataStage(
        registry, _DummyAdapter(), _DummyConfig(), "test.exe",
        {"analyze_functions": False},
    )
    ctx: dict[str, Any] = {"results": {}}
    result = stage._run_analyzer_method(
        ctx, "import_analyzer", "get_imports", "imports"
    )
    assert result == {"imports": []}


def test_run_analyzer_method_exception_path_uses_custom_default():
    """When default_value={} is passed, exception path stores {} not []."""
    registry = _make_registry(functions=_RaisingSectionAnalyzer)

    class _RaisingFunctionAnalyzer:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        def analyze_functions(self) -> dict:
            raise RuntimeError("function analysis error")

    registry.register(
        "function_analyzer", _RaisingFunctionAnalyzer, AnalyzerCategory.METADATA
    )
    stage = MetadataStage(
        registry, _DummyAdapter(), _DummyConfig(), "test.exe",
        {"analyze_functions": True},
    )
    ctx: dict[str, Any] = {"results": {}}
    result = stage._run_analyzer_method(
        ctx, "function_analyzer", "analyze_functions", "functions", {}
    )
    assert result == {"functions": {}}


# ---------------------------------------------------------------------------
# Individual _extract_* methods - lines 98, 103, 106, 109, 112
# ---------------------------------------------------------------------------


def test_extract_sections_calls_section_analyzer():
    registry = _make_registry()
    stage = MetadataStage(
        registry, _DummyAdapter(), _DummyConfig(), "test.exe", {}
    )
    ctx: dict[str, Any] = {"results": {}}
    result = stage._extract_sections(ctx)
    assert result is not None
    assert "sections" in result
    assert len(result["sections"]) > 0


def test_extract_imports_calls_import_analyzer():
    registry = _make_registry()
    stage = MetadataStage(
        registry, _DummyAdapter(), _DummyConfig(), "test.exe", {}
    )
    ctx: dict[str, Any] = {"results": {}}
    result = stage._extract_imports(ctx)
    assert result is not None
    assert "imports" in result


def test_extract_exports_calls_export_analyzer():
    registry = _make_registry()
    stage = MetadataStage(
        registry, _DummyAdapter(), _DummyConfig(), "test.exe", {}
    )
    ctx: dict[str, Any] = {"results": {}}
    result = stage._extract_exports(ctx)
    assert result is not None
    assert "exports" in result


def test_extract_strings_calls_string_analyzer():
    registry = _make_registry()
    stage = MetadataStage(
        registry, _DummyAdapter(), _DummyConfig(), "test.exe", {}
    )
    ctx: dict[str, Any] = {"results": {}}
    result = stage._extract_strings(ctx)
    assert result is not None
    assert "strings" in result


def test_extract_functions_calls_function_analyzer():
    registry = _make_registry()
    stage = MetadataStage(
        registry, _DummyAdapter(), _DummyConfig(), "test.exe", {}
    )
    ctx: dict[str, Any] = {"results": {}}
    result = stage._extract_functions(ctx)
    assert result is not None
    assert "functions" in result
    assert isinstance(result["functions"], dict)


def test_extract_sections_returns_none_when_not_registered():
    registry = _make_registry(sections=None)
    stage = MetadataStage(
        registry, _DummyAdapter(), _DummyConfig(), "test.exe", {}
    )
    ctx: dict[str, Any] = {"results": {}}
    assert stage._extract_sections(ctx) is None


def test_extract_imports_returns_none_when_not_registered():
    registry = _make_registry(imports=None)
    stage = MetadataStage(
        registry, _DummyAdapter(), _DummyConfig(), "test.exe", {}
    )
    ctx: dict[str, Any] = {"results": {}}
    assert stage._extract_imports(ctx) is None


def test_extract_exports_returns_none_when_not_registered():
    registry = _make_registry(exports=None)
    stage = MetadataStage(
        registry, _DummyAdapter(), _DummyConfig(), "test.exe", {}
    )
    ctx: dict[str, Any] = {"results": {}}
    assert stage._extract_exports(ctx) is None


def test_extract_strings_returns_none_when_not_registered():
    registry = _make_registry(strings=None)
    stage = MetadataStage(
        registry, _DummyAdapter(), _DummyConfig(), "test.exe", {}
    )
    ctx: dict[str, Any] = {"results": {}}
    assert stage._extract_strings(ctx) is None


def test_extract_functions_returns_none_when_not_registered():
    registry = _make_registry(functions=None)
    stage = MetadataStage(
        registry, _DummyAdapter(), _DummyConfig(), "test.exe", {}
    )
    ctx: dict[str, Any] = {"results": {}}
    assert stage._extract_functions(ctx) is None


# ---------------------------------------------------------------------------
# _run_analyzer_method - line 74-75: default_value=None branch
# ---------------------------------------------------------------------------


def test_run_analyzer_method_defaults_default_value_to_empty_list():
    """When default_value=None is passed, it becomes [] at line 75."""
    registry = _make_registry(sections=_RaisingSectionAnalyzer)
    stage = MetadataStage(
        registry, _DummyAdapter(), _DummyConfig(), "test.exe", {}
    )
    ctx: dict[str, Any] = {"results": {}}
    result = stage._run_analyzer_method(
        ctx, "section_analyzer", "analyze_sections", "sections", None
    )
    assert result == {"sections": []}
