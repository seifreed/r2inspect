"""Branch-path tests for r2inspect/pipeline/stages_hashing.py."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from r2inspect.pipeline.stages_hashing import HashingStage
from r2inspect.registry.analyzer_registry import AnalyzerCategory, AnalyzerRegistry


# ---------------------------------------------------------------------------
# Stub helpers
# ---------------------------------------------------------------------------


class StubConfig:
    """Minimal config stub - no typed_config needed by HashingStage itself."""


class StubAdapter:
    pass


class BasicHashAnalyzer:
    def __init__(self, **kwargs: Any) -> None:
        pass

    def analyze(self) -> dict[str, Any]:
        return {"result": "basic"}


class TLSHAnalyzer:
    def __init__(self, **kwargs: Any) -> None:
        pass

    def analyze_sections(self) -> dict[str, Any]:
        return {"tlsh": "abc"}

    def analyze(self) -> dict[str, Any]:
        return {"result": "tlsh_default"}


class CCBHashAnalyzer:
    def __init__(self, **kwargs: Any) -> None:
        pass

    def analyze_functions(self) -> dict[str, Any]:
        return {"ccb": "def"}

    def analyze(self) -> dict[str, Any]:
        return {"result": "ccb_default"}


class SimhashAnalyzer:
    def __init__(self, **kwargs: Any) -> None:
        pass

    def analyze_detailed(self) -> dict[str, Any]:
        return {"simhash": "ghi"}

    def analyze(self) -> dict[str, Any]:
        return {"result": "simhash_default"}


class RaisingAnalyzer:
    def __init__(self, **kwargs: Any) -> None:
        pass

    def analyze(self) -> dict[str, Any]:
        raise RuntimeError("analyzer intentionally failed")


def make_registry_with(*entries: tuple[str, type, dict | None]) -> AnalyzerRegistry:
    registry = AnalyzerRegistry(lazy_loading=False)
    for name, cls, formats in entries:
        if formats:
            registry.register(name, cls, AnalyzerCategory.HASHING, file_formats=formats)
        else:
            registry.register(name, cls, AnalyzerCategory.HASHING)
    return registry


def make_stage(
    registry: AnalyzerRegistry,
    filename: str = "test.bin",
) -> HashingStage:
    return HashingStage(
        registry=registry,
        adapter=StubAdapter(),
        config=StubConfig(),
        filename=filename,
    )


def make_context(file_format: str = "PE") -> dict[str, Any]:
    return {
        "results": {},
        "metadata": {"file_format": file_format},
        "options": {},
    }


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------


def test_hashing_stage_init_stores_attributes():
    registry = AnalyzerRegistry(lazy_loading=False)
    adapter = StubAdapter()
    config = StubConfig()
    stage = HashingStage(registry=registry, adapter=adapter, config=config, filename="a.bin")
    assert stage.registry is registry
    assert stage.adapter is adapter
    assert stage.config is config
    assert stage.filename == "a.bin"
    assert stage.name == "hashing"
    assert stage.optional is True


def test_hashing_stage_dependencies_include_file_info():
    registry = AnalyzerRegistry(lazy_loading=False)
    stage = HashingStage(registry=registry, adapter=StubAdapter(), config=StubConfig(), filename="x")
    assert "file_info" in stage.dependencies


# ---------------------------------------------------------------------------
# _supports_format
# ---------------------------------------------------------------------------


def test_supports_format_returns_true_when_no_metadata():
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register("nofmt", BasicHashAnalyzer, AnalyzerCategory.HASHING)
    stage = make_stage(registry)
    assert stage._supports_format("nofmt", "PE") is True


def test_supports_format_returns_false_when_format_not_in_metadata():
    registry = make_registry_with(("ssdeep", BasicHashAnalyzer, {"PE"}))
    stage = make_stage(registry)
    assert stage._supports_format("ssdeep", "ELF") is False


def test_supports_format_returns_true_when_format_matches():
    registry = make_registry_with(("ssdeep", BasicHashAnalyzer, {"PE"}))
    stage = make_stage(registry)
    assert stage._supports_format("ssdeep", "PE") is True


# ---------------------------------------------------------------------------
# _run_hashing_analyzer - per-name dispatch
# ---------------------------------------------------------------------------


def test_run_hashing_analyzer_tlsh_uses_analyze_sections():
    registry = make_registry_with(("tlsh", TLSHAnalyzer, None))
    stage = make_stage(registry)
    analyzer = TLSHAnalyzer()
    result = stage._run_hashing_analyzer("tlsh", analyzer)
    assert result == {"tlsh": "abc"}


def test_run_hashing_analyzer_ccbhash_uses_analyze_functions():
    registry = AnalyzerRegistry(lazy_loading=False)
    stage = make_stage(registry)
    analyzer = CCBHashAnalyzer()
    result = stage._run_hashing_analyzer("ccbhash", analyzer)
    assert result == {"ccb": "def"}


def test_run_hashing_analyzer_simhash_uses_analyze_detailed():
    registry = AnalyzerRegistry(lazy_loading=False)
    stage = make_stage(registry)
    analyzer = SimhashAnalyzer()
    result = stage._run_hashing_analyzer("simhash", analyzer)
    assert result == {"simhash": "ghi"}


def test_run_hashing_analyzer_default_uses_analyze():
    registry = AnalyzerRegistry(lazy_loading=False)
    stage = make_stage(registry)
    analyzer = BasicHashAnalyzer()
    result = stage._run_hashing_analyzer("ssdeep", analyzer)
    assert result == {"result": "basic"}


def test_run_hashing_analyzer_tlsh_without_analyze_sections_falls_back_to_analyze():
    """When tlsh analyzer lacks analyze_sections, analyze() is used."""
    registry = AnalyzerRegistry(lazy_loading=False)
    stage = make_stage(registry)
    analyzer = BasicHashAnalyzer()
    result = stage._run_hashing_analyzer("tlsh", analyzer)
    assert result == {"result": "basic"}


# ---------------------------------------------------------------------------
# _store_hashing_result
# ---------------------------------------------------------------------------


def test_store_hashing_result_populates_context_and_results():
    registry = AnalyzerRegistry(lazy_loading=False)
    stage = make_stage(registry)
    context: dict[str, Any] = {"results": {}}
    results: dict[str, Any] = {}
    stage._store_hashing_result(context, results, "ssdeep", {"hash": "abc"})
    assert context["results"]["ssdeep"] == {"hash": "abc"}
    assert results["ssdeep"] == {"hash": "abc"}


# ---------------------------------------------------------------------------
# _execute - full flow
# ---------------------------------------------------------------------------


def test_execute_with_no_hashing_analyzers_returns_empty():
    registry = AnalyzerRegistry(lazy_loading=False)
    stage = make_stage(registry)
    context = make_context()
    result = stage._execute(context)
    assert isinstance(result, dict)
    assert len(result) == 0


def test_execute_with_basic_analyzer_returns_result():
    registry = make_registry_with(("ssdeep", BasicHashAnalyzer, None))
    stage = make_stage(registry)
    context = make_context("PE")
    result = stage._execute(context)
    assert "ssdeep" in result
    assert result["ssdeep"] == {"result": "basic"}


def test_execute_skips_analyzer_when_format_not_supported():
    registry = make_registry_with(("ssdeep", BasicHashAnalyzer, {"PE"}))
    stage = make_stage(registry)
    context = make_context("ELF")
    result = stage._execute(context)
    assert "ssdeep" not in result


def test_execute_catches_analyzer_exception_and_stores_error():
    registry = make_registry_with(("bad_hasher", RaisingAnalyzer, None))
    stage = make_stage(registry)
    context = make_context("PE")
    result = stage._execute(context)
    assert "bad_hasher" not in result
    assert "error" in context["results"].get("bad_hasher", {})


def test_execute_tlsh_analyzer_in_full_flow():
    registry = make_registry_with(("tlsh", TLSHAnalyzer, None))
    stage = make_stage(registry)
    context = make_context("PE")
    result = stage._execute(context)
    assert "tlsh" in result
    assert result["tlsh"] == {"tlsh": "abc"}


def test_execute_multiple_analyzers():
    registry = make_registry_with(
        ("ssdeep", BasicHashAnalyzer, None),
        ("tlsh", TLSHAnalyzer, None),
    )
    stage = make_stage(registry)
    context = make_context("PE")
    result = stage._execute(context)
    assert "ssdeep" in result
    assert "tlsh" in result
