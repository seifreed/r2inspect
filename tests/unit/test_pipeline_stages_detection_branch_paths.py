#!/usr/bin/env python3
"""Branch-path tests for r2inspect/pipeline/stages_detection.py - real objects only."""

from __future__ import annotations

from typing import Any

import pytest

from r2inspect.pipeline.stages_detection import DetectionStage
from r2inspect.registry.analyzer_registry import AnalyzerRegistry


# ---------------------------------------------------------------------------
# Minimal supporting classes - no mocks
# ---------------------------------------------------------------------------


class FakeAdapter:
    """Minimal adapter satisfying the interface without r2."""
    pass


class FakeConfig:
    pass


def _make_stage(
    options: dict | None = None,
    registry: AnalyzerRegistry | None = None,
) -> DetectionStage:
    if registry is None:
        registry = AnalyzerRegistry()
    return DetectionStage(
        registry=registry,
        adapter=FakeAdapter(),
        config=FakeConfig(),
        filename="sample.bin",
        options=options or {},
    )


def _make_context() -> dict[str, Any]:
    return {"options": {}, "results": {}, "metadata": {}}


# ---------------------------------------------------------------------------
# Instantiation - covers __init__ body (lines 28, 34-38)
# ---------------------------------------------------------------------------


def test_stage_initializes_with_name_detection():
    stage = _make_stage()
    assert stage.name == "detection"


def test_stage_initializes_with_correct_description():
    stage = _make_stage()
    description = stage.description.lower()
    assert "detection" in description or "pattern" in description or "signature" in description


def test_stage_is_optional():
    stage = _make_stage()
    assert stage.optional is True


def test_stage_has_format_detection_dependency():
    stage = _make_stage()
    assert "format_detection" in stage.dependencies


def test_stage_stores_registry():
    registry = AnalyzerRegistry()
    stage = _make_stage(registry=registry)
    assert stage.registry is registry


def test_stage_stores_adapter():
    adapter = FakeAdapter()
    registry = AnalyzerRegistry()
    stage = DetectionStage(
        registry=registry,
        adapter=adapter,
        config=FakeConfig(),
        filename="x.bin",
        options={},
    )
    assert stage.adapter is adapter


def test_stage_stores_filename():
    stage = DetectionStage(
        registry=AnalyzerRegistry(),
        adapter=FakeAdapter(),
        config=FakeConfig(),
        filename="malware.exe",
        options={},
    )
    assert stage.filename == "malware.exe"


def test_stage_stores_options():
    opts = {"detect_packer": False, "detect_crypto": True}
    stage = _make_stage(options=opts)
    assert stage.options is opts


# ---------------------------------------------------------------------------
# _execute - empty registry (lines 41-64)
# ---------------------------------------------------------------------------


def test_execute_returns_empty_dict_with_no_analyzers():
    stage = _make_stage(options={"detect_packer": True, "detect_crypto": True})
    context = _make_context()
    result = stage._execute(context)
    assert isinstance(result, dict)
    assert result == {}


def test_execute_skips_packer_when_option_is_false():
    class FakePacker:
        def __init__(self, **kwargs):
            pass

        def detect(self):
            return {"packed": True}

    registry = AnalyzerRegistry()
    registry.register("packer_detector", FakePacker, category="detection", file_formats={"ANY"})
    stage = _make_stage(registry=registry, options={"detect_packer": False})
    context = _make_context()
    result = stage._execute(context)
    assert "packer" not in result


def test_execute_skips_crypto_when_option_is_false():
    class FakeCrypto:
        def __init__(self, **kwargs):
            pass

        def detect(self):
            return {"algorithms": ["AES"]}

    registry = AnalyzerRegistry()
    registry.register("crypto_analyzer", FakeCrypto, category="detection", file_formats={"ANY"})
    stage = _make_stage(registry=registry, options={"detect_crypto": False})
    context = _make_context()
    result = stage._execute(context)
    assert "crypto" not in result


def test_execute_includes_packer_when_option_defaults_to_true():
    class FakePacker:
        def __init__(self, **kwargs):
            pass

        def detect(self):
            return {"packed": False}

    registry = AnalyzerRegistry()
    registry.register("packer_detector", FakePacker, category="detection", file_formats={"ANY"})
    stage = _make_stage(registry=registry, options={})
    context = _make_context()
    result = stage._execute(context)
    assert "packer" in result


def test_execute_all_analyzers_registered_all_keys_present():
    class FakePacker:
        def __init__(self, **kwargs):
            pass

        def detect(self):
            return {"packed": False}

    class FakeCrypto:
        def __init__(self, **kwargs):
            pass

        def detect(self):
            return {"algorithms": []}

    class FakeAntiAnalysis:
        def __init__(self, **kwargs):
            pass

        def detect(self):
            return {"techniques": []}

    class FakeCompilerDetector:
        def __init__(self, **kwargs):
            pass

        def detect_compiler(self):
            return {"compiler": "gcc"}

    class FakeYara:
        def __init__(self, **kwargs):
            pass

        def scan(self, custom_rules=None):
            return []

    registry = AnalyzerRegistry()
    registry.register("packer_detector", FakePacker, category="detection", file_formats={"ANY"})
    registry.register("crypto_analyzer", FakeCrypto, category="detection", file_formats={"ANY"})
    registry.register("anti_analysis", FakeAntiAnalysis, category="detection", file_formats={"ANY"})
    registry.register("compiler_detector", FakeCompilerDetector, category="detection", file_formats={"ANY"})
    registry.register("yara_analyzer", FakeYara, category="detection", file_formats={"ANY"})

    stage = _make_stage(registry=registry, options={"detect_packer": True, "detect_crypto": True})
    context = _make_context()
    result = stage._execute(context)

    assert "packer" in result
    assert "crypto" in result
    assert "anti_analysis" in result
    assert "compiler" in result
    assert "yara_matches" in result


# ---------------------------------------------------------------------------
# _run_analyzer - lines 64-85
# ---------------------------------------------------------------------------


def test_run_analyzer_not_registered_returns_none():
    stage = _make_stage()
    context = _make_context()
    result = stage._run_analyzer(context, "does_not_exist", "key")
    assert result is None


def test_run_analyzer_registered_returns_result():
    class FakeDetector:
        def __init__(self, **kwargs):
            pass

        def detect(self):
            return {"flag": True}

    registry = AnalyzerRegistry()
    registry.register("my_detector", FakeDetector, category="detection", file_formats={"ANY"})
    stage = _make_stage(registry=registry)
    context = _make_context()
    result = stage._run_analyzer(context, "my_detector", "my_key")
    assert result == {"my_key": {"flag": True}}
    assert context["results"]["my_key"] == {"flag": True}


def test_run_analyzer_exception_returns_error_dict():
    class BrokenDetector:
        def __init__(self, **kwargs):
            pass

        def detect(self):
            raise RuntimeError("broken")

    registry = AnalyzerRegistry()
    registry.register("broken", BrokenDetector, category="detection", file_formats={"ANY"})
    stage = _make_stage(registry=registry)
    context = _make_context()
    result = stage._run_analyzer(context, "broken", "broken_key")
    assert result is not None
    assert "error" in result["broken_key"]
    assert context["results"]["broken_key"]["error"] != ""


def test_run_analyzer_exception_error_contains_message():
    class BrokenDetector:
        def __init__(self, **kwargs):
            pass

        def detect(self):
            raise ValueError("specific error message")

    registry = AnalyzerRegistry()
    registry.register("broken", BrokenDetector, category="detection", file_formats={"ANY"})
    stage = _make_stage(registry=registry)
    context = _make_context()
    result = stage._run_analyzer(context, "broken", "k")
    assert "specific error message" in result["k"]["error"]


# ---------------------------------------------------------------------------
# Delegation methods - lines 88, 91, 94
# ---------------------------------------------------------------------------


def test_run_packer_detection_no_analyzer_returns_none():
    stage = _make_stage()
    assert stage._run_packer_detection(_make_context()) is None


def test_run_crypto_detection_no_analyzer_returns_none():
    stage = _make_stage()
    assert stage._run_crypto_detection(_make_context()) is None


def test_run_anti_analysis_detection_no_analyzer_returns_none():
    stage = _make_stage()
    assert stage._run_anti_analysis_detection(_make_context()) is None


def test_run_packer_detection_uses_packer_key():
    class FakePacker:
        def __init__(self, **kwargs):
            pass

        def detect(self):
            return {"packed": True}

    registry = AnalyzerRegistry()
    registry.register("packer_detector", FakePacker, category="detection", file_formats={"ANY"})
    stage = _make_stage(registry=registry)
    result = stage._run_packer_detection(_make_context())
    assert result == {"packer": {"packed": True}}


def test_run_crypto_detection_uses_crypto_key():
    class FakeCrypto:
        def __init__(self, **kwargs):
            pass

        def detect(self):
            return {"algorithms": ["RC4"]}

    registry = AnalyzerRegistry()
    registry.register("crypto_analyzer", FakeCrypto, category="detection", file_formats={"ANY"})
    stage = _make_stage(registry=registry)
    result = stage._run_crypto_detection(_make_context())
    assert result == {"crypto": {"algorithms": ["RC4"]}}


def test_run_anti_analysis_detection_uses_anti_analysis_key():
    class FakeAnti:
        def __init__(self, **kwargs):
            pass

        def detect(self):
            return {"techniques": ["anti_debug"]}

    registry = AnalyzerRegistry()
    registry.register("anti_analysis", FakeAnti, category="detection", file_formats={"ANY"})
    stage = _make_stage(registry=registry)
    result = stage._run_anti_analysis_detection(_make_context())
    assert result == {"anti_analysis": {"techniques": ["anti_debug"]}}


# ---------------------------------------------------------------------------
# _run_compiler_detection - lines 97-119
# ---------------------------------------------------------------------------


def test_run_compiler_detection_no_analyzer_returns_none():
    stage = _make_stage()
    assert stage._run_compiler_detection(_make_context()) is None


def test_run_compiler_detection_with_registered_analyzer():
    class FakeCompiler:
        def __init__(self, **kwargs):
            pass

        def detect_compiler(self):
            return {"compiler": "clang", "version": "14.0"}

    registry = AnalyzerRegistry()
    registry.register("compiler_detector", FakeCompiler, category="detection", file_formats={"ANY"})
    stage = _make_stage(registry=registry)
    context = _make_context()
    result = stage._run_compiler_detection(context)
    assert result == {"compiler": {"compiler": "clang", "version": "14.0"}}
    assert context["results"]["compiler"] == {"compiler": "clang", "version": "14.0"}


def test_run_compiler_detection_exception_returns_error():
    class BrokenCompiler:
        def __init__(self, **kwargs):
            pass

        def detect_compiler(self):
            raise RuntimeError("compiler detection failed")

    registry = AnalyzerRegistry()
    registry.register("compiler_detector", BrokenCompiler, category="detection", file_formats={"ANY"})
    stage = _make_stage(registry=registry)
    context = _make_context()
    result = stage._run_compiler_detection(context)
    assert result is not None
    assert "error" in result["compiler"]
    assert "compiler detection failed" in result["compiler"]["error"]
    assert context["results"]["compiler"]["error"] != ""


# ---------------------------------------------------------------------------
# _run_yara_analysis - lines 125-133
# ---------------------------------------------------------------------------


def test_run_yara_analysis_no_analyzer_returns_none():
    stage = _make_stage()
    assert stage._run_yara_analysis(_make_context()) is None


def test_run_yara_analysis_with_registered_analyzer_no_custom_rules():
    class FakeYara:
        def __init__(self, **kwargs):
            pass

        def scan(self, custom_rules=None):
            return [{"rule": "test"}]

    registry = AnalyzerRegistry()
    registry.register("yara_analyzer", FakeYara, category="detection", file_formats={"ANY"})
    stage = _make_stage(registry=registry, options={})
    context = _make_context()
    result = stage._run_yara_analysis(context)
    assert result == {"yara_matches": [{"rule": "test"}]}
    assert context["results"]["yara_matches"] == [{"rule": "test"}]


def test_run_yara_analysis_passes_custom_rules():
    received_rules = [None]

    class FakeYara:
        def __init__(self, **kwargs):
            pass

        def scan(self, custom_rules=None):
            received_rules[0] = custom_rules
            return []

    registry = AnalyzerRegistry()
    registry.register("yara_analyzer", FakeYara, category="detection", file_formats={"ANY"})
    stage = _make_stage(registry=registry, options={"custom_yara": "/path/to/rules"})
    stage._run_yara_analysis(_make_context())
    assert received_rules[0] == "/path/to/rules"


def test_run_yara_analysis_exception_returns_empty_list():
    class BrokenYara:
        def __init__(self, **kwargs):
            pass

        def scan(self, custom_rules=None):
            raise RuntimeError("yara failed")

    registry = AnalyzerRegistry()
    registry.register("yara_analyzer", BrokenYara, category="detection", file_formats={"ANY"})
    stage = _make_stage(registry=registry)
    context = _make_context()
    result = stage._run_yara_analysis(context)
    assert result == {"yara_matches": []}
    assert context["results"]["yara_matches"] == []
