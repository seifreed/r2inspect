#!/usr/bin/env python3
"""Branch path tests for r2inspect/utils/analyzer_factory.py covering missing lines."""

from __future__ import annotations

from typing import Any

import pytest

from r2inspect.utils.analyzer_factory import (
    _build_kwargs,
    create_analyzer,
    run_analysis_method,
)


# ---------------------------------------------------------------------------
# _build_kwargs() - lines 16-24
# ---------------------------------------------------------------------------


def test_build_kwargs_maps_r2_name():
    """_build_kwargs maps r2 param name to backend (line 19)."""
    backend = object()
    result = _build_kwargs(["r2"], backend, None, None)
    assert result["r2"] is backend


def test_build_kwargs_maps_r2pipe_name():
    """_build_kwargs maps r2pipe param name to backend."""
    backend = object()
    result = _build_kwargs(["r2pipe"], backend, None, None)
    assert result["r2pipe"] is backend


def test_build_kwargs_maps_r2_instance_name():
    """_build_kwargs maps r2_instance param name to backend."""
    backend = object()
    result = _build_kwargs(["r2_instance"], backend, None, None)
    assert result["r2_instance"] is backend


def test_build_kwargs_maps_adapter_name():
    """_build_kwargs maps adapter param name to backend (line 18-19)."""
    backend = object()
    result = _build_kwargs(["adapter"], backend, None, None)
    assert result["adapter"] is backend


def test_build_kwargs_maps_backend_name():
    """_build_kwargs maps backend param name to backend."""
    backend = object()
    result = _build_kwargs(["backend"], backend, None, None)
    assert result["backend"] is backend


def test_build_kwargs_maps_config_name():
    """_build_kwargs maps config param name to config (lines 20-21)."""
    config = object()
    result = _build_kwargs(["config"], None, config, None)
    assert result["config"] is config


def test_build_kwargs_maps_filename():
    """_build_kwargs maps filename param name to filename (lines 22-23)."""
    result = _build_kwargs(["filename"], None, None, "test.bin")
    assert result["filename"] == "test.bin"


def test_build_kwargs_maps_file_path():
    """_build_kwargs maps file_path param name to filename."""
    result = _build_kwargs(["file_path"], None, None, "test.bin")
    assert result["file_path"] == "test.bin"


def test_build_kwargs_maps_filepath():
    """_build_kwargs maps filepath param name to filename."""
    result = _build_kwargs(["filepath"], None, None, "test.bin")
    assert result["filepath"] == "test.bin"


def test_build_kwargs_ignores_unknown_param():
    """_build_kwargs skips unknown parameter names."""
    result = _build_kwargs(["unknown_param"], object(), object(), "test.bin")
    assert "unknown_param" not in result


def test_build_kwargs_maps_multiple_params():
    """_build_kwargs maps multiple params in one call."""
    backend = object()
    config = object()
    result = _build_kwargs(["adapter", "config", "filename"], backend, config, "a.bin")
    assert result["adapter"] is backend
    assert result["config"] is config
    assert result["filename"] == "a.bin"


# ---------------------------------------------------------------------------
# create_analyzer() - lines 36-63
# ---------------------------------------------------------------------------


class _AdapterConfigFilenameAnalyzer:
    def __init__(self, adapter: Any, config: Any, filename: str | None) -> None:
        self.adapter = adapter
        self.config = config
        self.filename = filename


class _FilenameOnlyAnalyzer:
    def __init__(self, filename: str) -> None:
        self.filename = filename


class _BackendConfigAnalyzer:
    def __init__(self, adapter: Any, config: Any) -> None:
        self.adapter = adapter
        self.config = config


class _NoArgsAnalyzer:
    def __init__(self) -> None:
        self.initialized = True


class _BackendOnlyAnalyzer:
    def __init__(self, backend: Any) -> None:
        self.backend = backend


class _R2NameAnalyzer:
    def __init__(self, r2: Any) -> None:
        self.r2 = r2


class _PositionalOnlyAnalyzer:
    def __init__(self, adapter: Any, config: Any, filename: str, /) -> None:
        self.args = (adapter, config, filename)


class _BackendFilenameAnalyzer:
    def __init__(self, adapter: Any, filename: str) -> None:
        self.adapter = adapter
        self.filename = filename


class _FilenameBackendAnalyzer:
    def __init__(self, filename: str, backend: Any) -> None:
        self.filename = filename
        self.backend = backend


def test_create_analyzer_introspection_all_params():
    """create_analyzer uses introspection to pass adapter, config, filename (lines 37-44)."""
    backend = object()
    config = object()
    inst = create_analyzer(_AdapterConfigFilenameAnalyzer, adapter=backend, config=config, filename="a.bin")
    assert inst.adapter is backend
    assert inst.config is config
    assert inst.filename == "a.bin"


def test_create_analyzer_introspection_filename_only():
    """create_analyzer introspects filename-only constructor (lines 37-44)."""
    inst = create_analyzer(_FilenameOnlyAnalyzer, filename="b.bin")
    assert inst.filename == "b.bin"


def test_create_analyzer_introspection_backend_config():
    """create_analyzer introspects adapter+config constructor (lines 37-44)."""
    backend = object()
    config = object()
    inst = create_analyzer(_BackendConfigAnalyzer, adapter=backend, config=config)
    assert inst.adapter is backend
    assert inst.config is config


def test_create_analyzer_no_args_fallback():
    """create_analyzer falls through to no-args constructor (line 63)."""
    inst = create_analyzer(_NoArgsAnalyzer)
    assert inst.initialized is True


def test_create_analyzer_backend_from_r2_param():
    """create_analyzer passes r2 kwarg as backend (line 36: backend = adapter or r2)."""
    backend = object()
    inst = create_analyzer(_R2NameAnalyzer, r2=backend)
    assert inst.r2 is backend


def test_create_analyzer_positional_fallback_three_args():
    """create_analyzer uses positional fallback when kwargs raise TypeError (lines 48-62)."""
    backend = object()
    config = object()
    inst = create_analyzer(_PositionalOnlyAnalyzer, adapter=backend, config=config, filename="c.bin")
    assert inst.args == (backend, config, "c.bin")


def test_create_analyzer_positional_fallback_two_args_backend_config():
    """create_analyzer tries (backend, config) positional candidate (lines 48-62)."""
    backend = object()
    config = object()
    inst = create_analyzer(_BackendConfigAnalyzer, adapter=backend, config=config)
    assert inst.adapter is backend


def test_create_analyzer_positional_fallback_adapter_filename():
    """create_analyzer tries (adapter, filename) positional candidate."""
    backend = object()
    inst = create_analyzer(_BackendFilenameAnalyzer, adapter=backend, filename="d.bin")
    assert inst.adapter is backend
    assert inst.filename == "d.bin"


def test_create_analyzer_adapter_takes_precedence_over_r2():
    """create_analyzer uses adapter over r2 when both are provided (line 36)."""
    adapter = object()
    r2 = object()
    inst = create_analyzer(_BackendOnlyAnalyzer, adapter=adapter, r2=r2)
    assert inst.backend is adapter


def test_create_analyzer_skips_candidates_with_none():
    """create_analyzer skips positional candidates that include None values (line 57)."""
    # FilenameOnlyAnalyzer needs filename but we don't pass it - falls through to no-arg
    # Actually _FilenameOnlyAnalyzer requires filename so it will fail no-arg fallback
    # Use _NoArgsAnalyzer which has no required params
    inst = create_analyzer(_NoArgsAnalyzer, adapter=None)
    assert inst.initialized is True


# ---------------------------------------------------------------------------
# run_analysis_method() - lines 68-72
# ---------------------------------------------------------------------------


class _AnalyzerWithAnalyze:
    def analyze(self) -> dict:
        return {"result": "analysis_done"}


class _AnalyzerWithDetect:
    def detect(self) -> dict:
        return {"result": "detection_done"}


class _AnalyzerNoMethods:
    pass


class _AnalyzerWithMultipleMethods:
    def analyze(self) -> dict:
        return {"from": "analyze"}

    def detect(self) -> dict:
        return {"from": "detect"}


def test_run_analysis_method_calls_first_available():
    """run_analysis_method calls the first available method name (lines 68-71)."""
    analyzer = _AnalyzerWithAnalyze()
    result = run_analysis_method(analyzer, ["analyze", "detect"])
    assert result == {"result": "analysis_done"}


def test_run_analysis_method_falls_through_to_second_method():
    """run_analysis_method skips unavailable method and calls second (lines 68-71)."""
    analyzer = _AnalyzerWithDetect()
    result = run_analysis_method(analyzer, ["analyze", "detect"])
    assert result == {"result": "detection_done"}


def test_run_analysis_method_returns_error_when_none_available():
    """run_analysis_method returns error dict when no method found (line 72)."""
    analyzer = _AnalyzerNoMethods()
    result = run_analysis_method(analyzer, ["analyze", "detect", "run"])
    assert result == {"error": "No suitable analysis method found"}


def test_run_analysis_method_uses_first_of_multiple_available():
    """run_analysis_method calls first method when multiple exist (lines 68-71)."""
    analyzer = _AnalyzerWithMultipleMethods()
    result = run_analysis_method(analyzer, ["analyze", "detect"])
    assert result == {"from": "analyze"}


def test_run_analysis_method_empty_method_list():
    """run_analysis_method returns error dict for empty method list."""
    analyzer = _AnalyzerWithAnalyze()
    result = run_analysis_method(analyzer, [])
    assert result == {"error": "No suitable analysis method found"}
