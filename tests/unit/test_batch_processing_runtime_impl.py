"""Unit tests for the batch_processing_runtime orchestration impl.

The impl now takes a ``BatchRunRequest`` and ``BatchRunCollaborators``
parameter object pair, which makes it directly testable with hand-rolled
doubles (no mocks / monkeypatch) for each branch.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import dataclasses

from r2inspect.cli.batch_processing_runtime import (
    BatchRunCollaborators,
    BatchRunRequest,
    _warn_missing_output_format,
    run_batch_analysis,
)


class _FakeConsole:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def print(self, message: str) -> None:
        self.lines.append(message)


class _FakeBatchResult:
    def __init__(self) -> None:
        self.files_to_process = [Path("a.bin")]
        self.all_results: dict[str, dict[str, Any]] = {"a.bin": {}}
        self.failed_files: list[tuple[str, str]] = []
        self.output_path = Path("out")
        self.elapsed_time = 1.0


class _FakeBatchService:
    def __init__(self, result: Any) -> None:
        self._result = result

    def run_batch_analysis(self, **_kwargs: Any) -> Any:
        return self._result


def _request() -> BatchRunRequest:
    return BatchRunRequest(
        batch_dir="dir",
        options={},
        output_json=False,
        output_csv=False,
        output_dir=None,
        recursive=False,
        extensions="exe",
        verbose=False,
        config_obj=None,
        auto_detect=False,
        threads=2,
        quiet=False,
    )


def test_warn_missing_output_format_warns_for_output_without_format() -> None:
    console = _FakeConsole()
    request = dataclasses.replace(_request(), output_dir="out", output_json=False, output_csv=False)
    _warn_missing_output_format(console, request)
    assert any("no result files will be written" in line for line in console.lines)


def test_warn_missing_output_format_silent_with_json() -> None:
    console = _FakeConsole()
    request = dataclasses.replace(_request(), output_dir="out", output_json=True)
    _warn_missing_output_format(console, request)
    assert console.lines == []


def test_warn_missing_output_format_silent_without_output_dir() -> None:
    console = _FakeConsole()
    request = dataclasses.replace(_request(), output_dir=None)
    _warn_missing_output_format(console, request)
    assert console.lines == []


def test_warn_missing_output_format_silent_when_quiet() -> None:
    console = _FakeConsole()
    request = dataclasses.replace(_request(), output_dir="out", quiet=True)
    _warn_missing_output_format(console, request)
    assert console.lines == []


def _collaborators(
    batch_service: Any, *, looks_like: bool, sink: dict[str, Any]
) -> BatchRunCollaborators:
    def _record(key: str) -> Any:
        def _fn(*args: Any, **kwargs: Any) -> Any:
            sink[key] = (args, kwargs)
            return None

        return _fn

    return BatchRunCollaborators(
        console=sink["console"],
        configure_batch_logging=lambda: sink.__setitem__("configured", True),
        setup_batch_output_directory=lambda *a: Path("out"),
        find_files_to_process=lambda *a, **k: [],
        setup_rate_limiter=lambda *a: "rate-limiter",
        batch_service=batch_service,
        create_batch_summary=lambda *a: "summary.json",
        display_no_files_message=_record("no_files"),
        display_batch_results=_record("results"),
        looks_like_batch_result=lambda _result: looks_like,
    )


def test_run_batch_analysis_no_files_displays_message() -> None:
    """A None service result triggers the no-files message and returns early."""
    sink: dict[str, Any] = {"console": _FakeConsole()}
    collaborators = _collaborators(_FakeBatchService(None), looks_like=True, sink=sink)

    run_batch_analysis(_request(), collaborators)

    assert "no_files" in sink
    assert "results" not in sink


def test_run_batch_analysis_invalid_result_warns_and_returns() -> None:
    """A non-batch-result object is rejected by the looks_like guard."""
    sink: dict[str, Any] = {"console": _FakeConsole()}
    collaborators = _collaborators(_FakeBatchService(object()), looks_like=False, sink=sink)

    run_batch_analysis(_request(), collaborators)

    assert "no_files" not in sink
    assert "results" not in sink


def test_run_batch_analysis_happy_path_renders_summary() -> None:
    """A valid result drives the summary and results rendering collaborators."""
    sink: dict[str, Any] = {"console": _FakeConsole()}
    collaborators = _collaborators(
        _FakeBatchService(_FakeBatchResult()), looks_like=True, sink=sink
    )

    run_batch_analysis(_request(), collaborators)

    assert "results" in sink
    console = sink["console"]
    assert any("Found 1 files" in line for line in console.lines)
