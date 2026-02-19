#!/usr/bin/env python3
"""Branch path tests for application layer modules."""

from __future__ import annotations

import os

from r2inspect.application.analysis_service import AnalysisService
from r2inspect.application.batch_discovery import is_pe_executable
from r2inspect.core.result_aggregator import ResultAggregator


# ---------------------------------------------------------------------------
# analysis_service.py
# ---------------------------------------------------------------------------

def test_add_statistics_adds_error_stats_when_errors_present() -> None:
    """add_statistics inserts error_statistics when total_errors > 0."""
    from r2inspect.utils.error_handler import (
        get_error_stats,
        global_error_manager,
        reset_error_stats,
    )
    from r2inspect.error_handling.classifier import ErrorCategory, ErrorInfo, ErrorSeverity

    reset_error_stats()

    # Inject a synthetic error directly into the global error manager
    error_info = ErrorInfo(
        exception=RuntimeError("synthetic"),
        category=ErrorCategory.UNKNOWN,
        severity=ErrorSeverity.LOW,
        recoverable=True,
        suggested_action="none",
    )
    global_error_manager.handle_error(error_info)

    service = AnalysisService()
    results: dict = {}
    service.add_statistics(results)

    reset_error_stats()

    assert "error_statistics" in results
    assert results["error_statistics"]["total_errors"] > 0


def test_add_statistics_does_not_add_error_stats_when_no_errors() -> None:
    """add_statistics does not add error_statistics when there are no errors."""
    from r2inspect.utils.error_handler import reset_error_stats

    reset_error_stats()
    service = AnalysisService()
    results: dict = {}
    service.add_statistics(results)
    assert "error_statistics" not in results


def test_validate_results_with_schema_validation_enabled() -> None:
    """validate_results executes validation logic when R2INSPECT_VALIDATE_SCHEMAS=1."""
    service = AnalysisService()
    old_val = os.environ.get("R2INSPECT_VALIDATE_SCHEMAS")
    os.environ["R2INSPECT_VALIDATE_SCHEMAS"] = "1"
    try:
        service.validate_results({"pe": {"available": True, "error": None}})
    finally:
        if old_val is None:
            os.environ.pop("R2INSPECT_VALIDATE_SCHEMAS", None)
        else:
            os.environ["R2INSPECT_VALIDATE_SCHEMAS"] = old_val


def test_has_circuit_breaker_data_returns_true_for_open_state() -> None:
    """has_circuit_breaker_data returns True when a circuit state is not 'closed'."""
    stats = {"circuit_a": {"state": "open", "failures": 3}}
    assert AnalysisService.has_circuit_breaker_data(stats) is True


def test_has_circuit_breaker_data_returns_false_for_empty() -> None:
    """has_circuit_breaker_data returns False for an empty dict."""
    assert AnalysisService.has_circuit_breaker_data({}) is False


# ---------------------------------------------------------------------------
# batch_discovery.py
# ---------------------------------------------------------------------------

def test_is_pe_executable_returns_true_for_mz_header_with_seek_error() -> None:
    """is_pe_executable returns True for MZ header even when PE offset seek raises."""
    header = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"  # pe_offset = 0x40 = 64

    class _RaisingHandle:
        def seek(self, pos):
            raise OSError("seek error")

        def read(self, size):
            return b""

    result = is_pe_executable(header, _RaisingHandle())
    assert result is True


def test_is_pe_executable_returns_false_for_non_mz() -> None:
    """is_pe_executable returns False when header does not start with MZ."""
    header = b"\x7fELF" + b"\x00" * 60

    class _DummyHandle:
        def seek(self, pos):
            pass

        def read(self, size):
            return b""

    result = is_pe_executable(header, _DummyHandle())
    assert result is False


# ---------------------------------------------------------------------------
# result_aggregator.py
# ---------------------------------------------------------------------------

def test_generate_executive_summary_returns_summary_for_empty_results() -> None:
    """generate_executive_summary returns a dict for empty analysis results."""
    aggregator = ResultAggregator()
    summary = aggregator.generate_executive_summary({})
    assert isinstance(summary, dict)


def test_generate_executive_summary_exception_path_returns_error_dict() -> None:
    """generate_executive_summary catches exceptions and returns error dict."""
    aggregator = ResultAggregator()

    class ExplodingResults:
        def get(self, key, default=None):
            raise RuntimeError("Simulated failure")

    summary = aggregator.generate_executive_summary(ExplodingResults())
    assert "error" in summary
