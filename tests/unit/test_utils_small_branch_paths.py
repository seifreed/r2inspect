#!/usr/bin/env python3
"""Branch path tests for utility modules."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from r2inspect.cli.output_json import JsonOutputFormatter


# ---------------------------------------------------------------------------
# output_json.py
# ---------------------------------------------------------------------------


def test_json_formatter_serializes_normal_results() -> None:
    """JsonOutputFormatter.to_json returns valid JSON for normal results."""
    import json

    formatter = JsonOutputFormatter({"key": "value", "count": 42})
    output = formatter.to_json()
    parsed = json.loads(output)
    assert parsed["key"] == "value"


def test_json_formatter_handles_serialization_failure() -> None:
    """JsonOutputFormatter.to_json returns error JSON when circular reference detected."""
    import json

    circular: dict = {}
    circular["self"] = circular
    formatter = JsonOutputFormatter(circular)
    output = formatter.to_json()
    parsed = json.loads(output)
    assert "error" in parsed


# ---------------------------------------------------------------------------
# ssdeep_loader.py
# ---------------------------------------------------------------------------


def test_get_ssdeep_returns_module_on_second_call() -> None:
    """get_ssdeep returns cached module on second call without re-importing."""
    import r2inspect.infrastructure.ssdeep_loader as sl

    first = sl.get_ssdeep()
    second = sl.get_ssdeep()
    assert first is second


def test_get_ssdeep_double_check_inside_lock() -> None:
    """get_ssdeep returns cached value when module is set while thread waits for lock."""
    import r2inspect.infrastructure.ssdeep_loader as sl

    original_module = sl._ssdeep_module

    sl._ssdeep_module = None
    results: list = []

    with sl._import_lock:
        t = threading.Thread(target=lambda: results.append(sl.get_ssdeep()))
        t.start()
        sl._ssdeep_module = original_module

    t.join(timeout=5)
    assert len(results) == 1
    assert results[0] is original_module


def _raise_ssdeep_import_error() -> object:
    raise ImportError("Blocked for test")


def test_get_ssdeep_returns_none_when_import_blocked() -> None:
    """get_ssdeep returns None and caches None when ssdeep import is blocked."""
    import r2inspect.infrastructure.ssdeep_loader as sl

    original_module = sl._ssdeep_module
    sl._ssdeep_module = None

    try:
        result = sl.get_ssdeep(importer=_raise_ssdeep_import_error)
        assert result is None
        assert sl._ssdeep_module is None
    finally:
        sl._ssdeep_module = original_module


# ---------------------------------------------------------------------------
# analyzer_runner.py
# ---------------------------------------------------------------------------


def test_run_analyzer_on_file_executes_analyze_with_real_file() -> None:
    """run_analyzer_on_file opens adapter and invokes analyze(); lines 27-30 execute."""
    from r2inspect.adapters.analyzer_runner import run_analyzer_on_file

    class SimpleAnalyzer:
        def __init__(self, adapter, filepath):
            self.adapter = adapter
            self.filepath = filepath

        def analyze(self):
            return {"completed": True}

    pe_path = Path("samples/fixtures/hello_pe.exe")
    if not pe_path.exists():
        pytest.skip("hello_pe.exe fixture not found")

    result = run_analyzer_on_file(SimpleAnalyzer, str(pe_path))
    assert result == {"completed": True}


def test_run_analyzer_on_file_returns_none_when_analyze_missing() -> None:
    """run_analyzer_on_file returns None when the analyzer has no analyze method."""
    from r2inspect.adapters.analyzer_runner import run_analyzer_on_file

    class NoAnalyzeMethod:
        def __init__(self, adapter, filepath):
            pass

    pe_path = Path("samples/fixtures/hello_pe.exe")
    if not pe_path.exists():
        pytest.skip("hello_pe.exe fixture not found")

    result = run_analyzer_on_file(NoAnalyzeMethod, str(pe_path))
    assert result is None


def test_run_analyzer_on_file_returns_none_on_bad_path() -> None:
    """run_analyzer_on_file returns None when the file path does not exist."""
    from r2inspect.adapters.analyzer_runner import run_analyzer_on_file

    class SimpleAnalyzer:
        def __init__(self, adapter, filepath):
            pass

        def analyze(self):
            return {}

    result = run_analyzer_on_file(SimpleAnalyzer, "/nonexistent/path/to/file.exe")
    assert result is None
