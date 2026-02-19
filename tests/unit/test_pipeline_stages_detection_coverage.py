#!/usr/bin/env python3
"""Coverage tests for r2inspect/pipeline/stages_detection.py"""
from __future__ import annotations

from typing import Any

from r2inspect.pipeline.stages_detection import DetectionStage
from r2inspect.registry.analyzer_registry import AnalyzerRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class FakeAdapter:
    pass


class FakeConfig:
    pass


def make_stage(options: dict | None = None, registry: AnalyzerRegistry | None = None) -> DetectionStage:
    if registry is None:
        registry = AnalyzerRegistry()
    return DetectionStage(
        registry=registry,
        adapter=FakeAdapter(),
        config=FakeConfig(),
        filename="test.bin",
        options=options or {},
    )


def make_context() -> dict[str, Any]:
    return {"options": {}, "results": {}, "metadata": {}}


# ---------------------------------------------------------------------------
# Stage metadata
# ---------------------------------------------------------------------------

def test_detection_stage_name_and_description():
    stage = make_stage()
    assert stage.name == "detection"
    assert "detection" in stage.description.lower() or "pattern" in stage.description.lower()


def test_detection_stage_is_optional():
    stage = make_stage()
    assert stage.optional is True


def test_detection_stage_dependencies():
    stage = make_stage()
    assert "format_detection" in stage.dependencies


# ---------------------------------------------------------------------------
# _execute with no analyzers registered returns empty
# ---------------------------------------------------------------------------

def test_execute_with_no_analyzers_returns_empty_dict():
    stage = make_stage(options={"detect_packer": True, "detect_crypto": True})
    context = make_context()
    result = stage._execute(context)
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# _run_analyzer
# ---------------------------------------------------------------------------

def test_run_analyzer_returns_none_when_not_registered():
    stage = make_stage()
    context = make_context()
    result = stage._run_analyzer(context, "nonexistent_xyz", "data")
    assert result is None


class FakeDetector:
    def __init__(self, **kwargs):
        pass

    def detect(self) -> dict:
        return {"detected": True}


def test_run_analyzer_returns_result_when_registered():
    registry = AnalyzerRegistry()
    registry.register(
        name="test_detector",
        analyzer_class=FakeDetector,
        category="detection",
        file_formats={"ANY"},
        required=False,
    )
    stage = make_stage(registry=registry)
    context = make_context()
    result = stage._run_analyzer(context, "test_detector", "test_key")
    assert result is not None
    assert result == {"test_key": {"detected": True}}
    assert context["results"]["test_key"] == {"detected": True}


class BrokenDetector:
    def __init__(self, **kwargs):
        pass

    def detect(self):
        raise RuntimeError("detection failed")


def test_run_analyzer_handles_exception_returns_error_dict():
    registry = AnalyzerRegistry()
    registry.register(
        name="broken_detector",
        analyzer_class=BrokenDetector,
        category="detection",
        file_formats={"ANY"},
        required=False,
    )
    stage = make_stage(registry=registry)
    context = make_context()
    result = stage._run_analyzer(context, "broken_detector", "broken_key")
    assert result is not None
    assert "error" in result["broken_key"]
    assert context["results"]["broken_key"]["error"] != ""


# ---------------------------------------------------------------------------
# _run_packer_detection / _run_crypto_detection / _run_anti_analysis_detection
# ---------------------------------------------------------------------------

def test_run_packer_detection_no_analyzer_returns_none():
    stage = make_stage()
    result = stage._run_packer_detection(make_context())
    assert result is None


def test_run_crypto_detection_no_analyzer_returns_none():
    stage = make_stage()
    result = stage._run_crypto_detection(make_context())
    assert result is None


def test_run_anti_analysis_detection_no_analyzer_returns_none():
    stage = make_stage()
    result = stage._run_anti_analysis_detection(make_context())
    assert result is None


class FakePackerDetector:
    def __init__(self, **kwargs):
        pass

    def detect(self) -> dict:
        return {"packed": False}


def test_run_packer_detection_with_registered_analyzer():
    registry = AnalyzerRegistry()
    registry.register(
        name="packer_detector",
        analyzer_class=FakePackerDetector,
        category="detection",
        file_formats={"ANY"},
        required=False,
    )
    stage = make_stage(registry=registry)
    context = make_context()
    result = stage._run_packer_detection(context)
    assert result == {"packer": {"packed": False}}


class FakeCryptoAnalyzer:
    def __init__(self, **kwargs):
        pass

    def detect(self) -> dict:
        return {"algorithms": []}


def test_run_crypto_detection_with_registered_analyzer():
    registry = AnalyzerRegistry()
    registry.register(
        name="crypto_analyzer",
        analyzer_class=FakeCryptoAnalyzer,
        category="detection",
        file_formats={"ANY"},
        required=False,
    )
    stage = make_stage(registry=registry)
    context = make_context()
    result = stage._run_crypto_detection(context)
    assert result == {"crypto": {"algorithms": []}}


class FakeAntiAnalysis:
    def __init__(self, **kwargs):
        pass

    def detect(self) -> dict:
        return {"techniques": []}


def test_run_anti_analysis_detection_with_registered_analyzer():
    registry = AnalyzerRegistry()
    registry.register(
        name="anti_analysis",
        analyzer_class=FakeAntiAnalysis,
        category="detection",
        file_formats={"ANY"},
        required=False,
    )
    stage = make_stage(registry=registry)
    context = make_context()
    result = stage._run_anti_analysis_detection(context)
    assert result == {"anti_analysis": {"techniques": []}}


# ---------------------------------------------------------------------------
# _run_compiler_detection
# ---------------------------------------------------------------------------

def test_run_compiler_detection_no_analyzer_returns_none():
    stage = make_stage()
    result = stage._run_compiler_detection(make_context())
    assert result is None


class FakeCompilerDetector:
    def __init__(self, **kwargs):
        pass

    def detect_compiler(self) -> dict:
        return {"compiler": "gcc"}


def test_run_compiler_detection_with_registered_analyzer():
    registry = AnalyzerRegistry()
    registry.register(
        name="compiler_detector",
        analyzer_class=FakeCompilerDetector,
        category="detection",
        file_formats={"ANY"},
        required=False,
    )
    stage = make_stage(registry=registry)
    context = make_context()
    result = stage._run_compiler_detection(context)
    assert result == {"compiler": {"compiler": "gcc"}}
    assert context["results"]["compiler"] == {"compiler": "gcc"}


class BrokenCompilerDetector:
    def __init__(self, **kwargs):
        pass

    def detect_compiler(self):
        raise ValueError("compiler detection failed")


def test_run_compiler_detection_handles_exception():
    registry = AnalyzerRegistry()
    registry.register(
        name="compiler_detector",
        analyzer_class=BrokenCompilerDetector,
        category="detection",
        file_formats={"ANY"},
        required=False,
    )
    stage = make_stage(registry=registry)
    context = make_context()
    result = stage._run_compiler_detection(context)
    assert result is not None
    assert "error" in result["compiler"]


# ---------------------------------------------------------------------------
# _run_yara_analysis
# ---------------------------------------------------------------------------

def test_run_yara_analysis_no_analyzer_returns_none():
    stage = make_stage()
    result = stage._run_yara_analysis(make_context())
    assert result is None


class FakeYaraAnalyzer:
    def __init__(self, **kwargs):
        pass

    def scan(self, custom_rules=None) -> list:
        return [{"rule": "test_rule"}]


def test_run_yara_analysis_with_registered_analyzer():
    registry = AnalyzerRegistry()
    registry.register(
        name="yara_analyzer",
        analyzer_class=FakeYaraAnalyzer,
        category="detection",
        file_formats={"ANY"},
        required=False,
    )
    stage = make_stage(registry=registry, options={"custom_yara": "/rules"})
    context = make_context()
    result = stage._run_yara_analysis(context)
    assert result == {"yara_matches": [{"rule": "test_rule"}]}
    assert context["results"]["yara_matches"] == [{"rule": "test_rule"}]


def test_run_yara_analysis_without_custom_rules():
    registry = AnalyzerRegistry()
    registry.register(
        name="yara_analyzer",
        analyzer_class=FakeYaraAnalyzer,
        category="detection",
        file_formats={"ANY"},
        required=False,
    )
    stage = make_stage(registry=registry, options={})
    context = make_context()
    result = stage._run_yara_analysis(context)
    assert result is not None
    assert "yara_matches" in result


class BrokenYaraAnalyzer:
    def __init__(self, **kwargs):
        pass

    def scan(self, custom_rules=None):
        raise RuntimeError("yara scan failed")


def test_run_yara_analysis_handles_exception():
    registry = AnalyzerRegistry()
    registry.register(
        name="yara_analyzer",
        analyzer_class=BrokenYaraAnalyzer,
        category="detection",
        file_formats={"ANY"},
        required=False,
    )
    stage = make_stage(registry=registry)
    context = make_context()
    result = stage._run_yara_analysis(context)
    assert result == {"yara_matches": []}
    assert context["results"]["yara_matches"] == []


# ---------------------------------------------------------------------------
# _execute options gate: detect_packer=False, detect_crypto=False
# ---------------------------------------------------------------------------

def test_execute_skips_packer_when_option_false():
    registry = AnalyzerRegistry()
    registry.register(
        name="packer_detector",
        analyzer_class=FakePackerDetector,
        category="detection",
        file_formats={"ANY"},
        required=False,
    )
    stage = make_stage(registry=registry, options={"detect_packer": False})
    context = make_context()
    result = stage._execute(context)
    assert "packer" not in result


def test_execute_skips_crypto_when_option_false():
    registry = AnalyzerRegistry()
    registry.register(
        name="crypto_analyzer",
        analyzer_class=FakeCryptoAnalyzer,
        category="detection",
        file_formats={"ANY"},
        required=False,
    )
    stage = make_stage(registry=registry, options={"detect_crypto": False})
    context = make_context()
    result = stage._execute(context)
    assert "crypto" not in result


def test_execute_includes_all_detections_when_enabled():
    registry = AnalyzerRegistry()
    registry.register(
        name="packer_detector",
        analyzer_class=FakePackerDetector,
        category="detection",
        file_formats={"ANY"},
        required=False,
    )
    registry.register(
        name="crypto_analyzer",
        analyzer_class=FakeCryptoAnalyzer,
        category="detection",
        file_formats={"ANY"},
        required=False,
    )
    registry.register(
        name="anti_analysis",
        analyzer_class=FakeAntiAnalysis,
        category="detection",
        file_formats={"ANY"},
        required=False,
    )
    registry.register(
        name="compiler_detector",
        analyzer_class=FakeCompilerDetector,
        category="detection",
        file_formats={"ANY"},
        required=False,
    )
    registry.register(
        name="yara_analyzer",
        analyzer_class=FakeYaraAnalyzer,
        category="detection",
        file_formats={"ANY"},
        required=False,
    )
    stage = make_stage(
        registry=registry,
        options={"detect_packer": True, "detect_crypto": True},
    )
    context = make_context()
    result = stage._execute(context)
    assert "packer" in result
    assert "crypto" in result
    assert "anti_analysis" in result
    assert "compiler" in result
    assert "yara_matches" in result
