#!/usr/bin/env python3
"""Branch-path tests for r2inspect/pipeline/stages_security.py.

Covers missing lines: 27, 33-36, 39, 41-51, 54-70, 73-88.
Uses real stub classes (no mocks).
"""

from __future__ import annotations

from typing import Any

import pytest

from r2inspect.pipeline.stages_security import SecurityStage
from r2inspect.registry.analyzer_registry import AnalyzerRegistry
from r2inspect.registry.categories import AnalyzerCategory


# ---------------------------------------------------------------------------
# Stub adapter and analyzers
# ---------------------------------------------------------------------------


class MinimalAdapter:
    """Stub adapter satisfying the AnalyzerBackend interface."""

    def get_file_info(self) -> dict[str, Any]:
        return {}

    def get_sections(self) -> list[dict[str, Any]]:
        return []

    def get_symbols(self) -> list[dict[str, Any]]:
        return []

    def get_dynamic_info_text(self) -> str:
        return ""

    def get_headers_json(self) -> list[dict[str, Any]]:
        return []

    def read_bytes(self, addr: int, size: int) -> bytes:
        return b""


class DummyPEAnalyzer:
    """Stub PE analyzer that returns valid security features."""

    def __init__(self, **kwargs: Any) -> None:
        pass

    def get_security_features(self) -> dict[str, Any]:
        return {"nx": True, "aslr": True, "dep": True}


class FailingPEAnalyzer:
    """Stub PE analyzer whose get_security_features always raises."""

    def __init__(self, **kwargs: Any) -> None:
        pass

    def get_security_features(self) -> dict[str, Any]:
        raise RuntimeError("PE security analysis intentionally failed")


class DummyMitigationAnalyzer:
    """Stub mitigation analyzer returning security mitigations."""

    def __init__(self, **kwargs: Any) -> None:
        pass

    def analyze(self) -> dict[str, Any]:
        return {"stack_canary": True, "relro": "full"}


class FailingMitigationAnalyzer:
    """Stub mitigation analyzer whose analyze always raises."""

    def __init__(self, **kwargs: Any) -> None:
        pass

    def analyze(self) -> dict[str, Any]:
        raise RuntimeError("mitigation analysis intentionally failed")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_context(file_format: str = "PE") -> dict[str, Any]:
    return {
        "results": {},
        "metadata": {"file_format": file_format},
    }


def _make_stage(
    registry: AnalyzerRegistry,
    adapter: Any = None,
) -> SecurityStage:
    if adapter is None:
        adapter = MinimalAdapter()
    return SecurityStage(registry, adapter, None, "test_binary")


# ---------------------------------------------------------------------------
# __init__ (lines 27, 33-36)
# ---------------------------------------------------------------------------


def test_security_stage_init_sets_attributes():
    registry = AnalyzerRegistry()
    adapter = MinimalAdapter()
    stage = SecurityStage(registry, adapter, config=None, filename="test.exe")
    assert stage.registry is registry
    assert stage.adapter is adapter
    assert stage.config is None
    assert stage.filename == "test.exe"
    assert stage.name == "security"
    assert stage.optional is True


# ---------------------------------------------------------------------------
# _execute – non-PE format skips PE analysis (lines 39-51)
# ---------------------------------------------------------------------------


def test_execute_elf_format_skips_pe_analysis():
    registry = AnalyzerRegistry()
    stage = _make_stage(registry)
    ctx = _make_context(file_format="ELF")
    result = stage.execute(ctx)
    # No security data set from PE analysis; result may be empty or from mitigations
    assert isinstance(result, dict)


def test_execute_unknown_format_skips_pe_analysis():
    registry = AnalyzerRegistry()
    stage = _make_stage(registry)
    ctx = _make_context(file_format="Unknown")
    result = stage.execute(ctx)
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# _analyze_pe_security – pe_analyzer not registered returns None (line 70)
# ---------------------------------------------------------------------------


def test_analyze_pe_security_no_registered_analyzer_returns_none():
    registry = AnalyzerRegistry()
    stage = _make_stage(registry)
    ctx = _make_context(file_format="PE")
    result = stage._analyze_pe_security(ctx)
    assert result is None


# ---------------------------------------------------------------------------
# _analyze_pe_security – success path (lines 56-65)
# ---------------------------------------------------------------------------


def test_analyze_pe_security_success_populates_context():
    registry = AnalyzerRegistry()
    registry.register("pe_analyzer", analyzer_class=DummyPEAnalyzer, category=AnalyzerCategory.SECURITY)
    stage = _make_stage(registry)
    ctx = _make_context(file_format="PE")

    result = stage._analyze_pe_security(ctx)

    assert result is not None
    assert "security" in result
    assert result["security"]["nx"] is True
    assert ctx["results"]["security"]["aslr"] is True


# ---------------------------------------------------------------------------
# _analyze_pe_security – exception path (lines 66-69)
# ---------------------------------------------------------------------------


def test_analyze_pe_security_exception_stores_error():
    registry = AnalyzerRegistry()
    registry.register("pe_analyzer", analyzer_class=FailingPEAnalyzer, category=AnalyzerCategory.SECURITY)
    stage = _make_stage(registry)
    ctx = _make_context(file_format="PE")

    result = stage._analyze_pe_security(ctx)

    assert result is not None
    assert "security" in result
    assert "error" in result["security"]
    assert "intentionally failed" in result["security"]["error"]


# ---------------------------------------------------------------------------
# _execute – PE format triggers pe analysis (lines 42-45)
# ---------------------------------------------------------------------------


def test_execute_pe_format_calls_pe_security():
    registry = AnalyzerRegistry()
    registry.register("pe_analyzer", analyzer_class=DummyPEAnalyzer, category=AnalyzerCategory.SECURITY)
    stage = _make_stage(registry)
    ctx = _make_context(file_format="PE")

    result = stage.execute(ctx)

    assert "security" in result
    assert result["security"]["nx"] is True


# ---------------------------------------------------------------------------
# _analyze_mitigations – mitigation_class not registered returns None (line 88)
# ---------------------------------------------------------------------------


def test_analyze_mitigations_no_registered_class_returns_none():
    registry = AnalyzerRegistry()
    stage = _make_stage(registry)
    ctx = _make_context()

    result = stage._analyze_mitigations(ctx)
    assert result is None


# ---------------------------------------------------------------------------
# _analyze_mitigations – success path, security key absent (lines 75-83, 87)
# ---------------------------------------------------------------------------


def test_analyze_mitigations_success_no_existing_security_key():
    registry = AnalyzerRegistry()
    registry.register("exploit_mitigation", analyzer_class=DummyMitigationAnalyzer, category=AnalyzerCategory.SECURITY)
    stage = _make_stage(registry)
    ctx = _make_context()
    ctx["results"] = {}  # no existing "security" key

    result = stage._analyze_mitigations(ctx)

    assert result is not None
    assert "security" in result
    assert result["security"]["stack_canary"] is True


# ---------------------------------------------------------------------------
# _analyze_mitigations – success path, security key already exists (lines 80-81)
# ---------------------------------------------------------------------------


def test_analyze_mitigations_merges_into_existing_security():
    registry = AnalyzerRegistry()
    registry.register("exploit_mitigation", analyzer_class=DummyMitigationAnalyzer, category=AnalyzerCategory.SECURITY)
    stage = _make_stage(registry)
    ctx = _make_context(file_format="PE")
    ctx["results"]["security"] = {"nx": True, "aslr": False}

    result = stage._analyze_mitigations(ctx)

    assert result is not None
    assert "security" in result
    assert result["security"]["nx"] is True
    assert result["security"]["stack_canary"] is True


# ---------------------------------------------------------------------------
# _analyze_mitigations – exception path returns None (lines 84-86)
# ---------------------------------------------------------------------------


def test_analyze_mitigations_exception_returns_none():
    registry = AnalyzerRegistry()
    registry.register("exploit_mitigation", analyzer_class=FailingMitigationAnalyzer, category=AnalyzerCategory.SECURITY)
    stage = _make_stage(registry)
    ctx = _make_context()

    result = stage._analyze_mitigations(ctx)
    assert result is None


# ---------------------------------------------------------------------------
# Full execute with both PE analyzer and mitigations registered
# ---------------------------------------------------------------------------


def test_execute_pe_with_mitigations_combined():
    registry = AnalyzerRegistry()
    registry.register("pe_analyzer", analyzer_class=DummyPEAnalyzer, category=AnalyzerCategory.SECURITY)
    registry.register("exploit_mitigation", analyzer_class=DummyMitigationAnalyzer, category=AnalyzerCategory.SECURITY)
    stage = _make_stage(registry)
    ctx = _make_context(file_format="PE")

    result = stage.execute(ctx)

    assert "security" in result
    assert result["security"]["nx"] is True
    assert result["security"]["stack_canary"] is True


def test_execute_non_pe_with_mitigations_only():
    registry = AnalyzerRegistry()
    registry.register("exploit_mitigation", analyzer_class=DummyMitigationAnalyzer, category=AnalyzerCategory.SECURITY)
    stage = _make_stage(registry)
    ctx = _make_context(file_format="ELF")

    result = stage.execute(ctx)

    assert "security" in result
    assert result["security"]["stack_canary"] is True
