#!/usr/bin/env python3
"""Branch path tests for application layer modules."""

from __future__ import annotations

import os

from r2inspect.application.analysis_service import AnalysisService
from r2inspect.application.batch_discovery import is_pe_executable
from r2inspect.domain.analysis_runtime import AnalysisRuntimeStats
from r2inspect.core.result_aggregator import ResultAggregator
from r2inspect.interfaces.runtime import AnalysisRuntimePort, ResultValidationPort


# ---------------------------------------------------------------------------
# Concrete fakes replacing unittest.mock
# ---------------------------------------------------------------------------


class FakeRuntime:
    """In-memory implementation of AnalysisRuntimePort."""

    def __init__(self, stats: AnalysisRuntimeStats | None = None) -> None:
        self._stats = stats or AnalysisRuntimeStats({}, {}, {})
        self.reset_called = False

    def reset(self) -> None:
        self.reset_called = True

    def collect(self) -> AnalysisRuntimeStats:
        return self._stats


class FakeValidator:
    """In-memory implementation of ResultValidationPort."""

    def __init__(self) -> None:
        self.validate_calls: list[tuple[dict, bool]] = []

    def validate(self, results: dict, *, enabled: bool) -> None:
        self.validate_calls.append((results, enabled))


class FakeInspector:
    """Minimal inspector stand-in that returns a canned result."""

    def __init__(self, result: dict | None = None) -> None:
        self._result = result or {}
        self.analyze_calls: list[dict] = []

    def analyze(self, **kwargs) -> dict:
        self.analyze_calls.append(kwargs)
        return self._result


# ---------------------------------------------------------------------------
# analysis_service.py
# ---------------------------------------------------------------------------


def test_add_statistics_adds_error_stats_when_errors_present() -> None:
    """add_statistics inserts error_statistics when total_errors > 0."""
    from r2inspect.error_handling.classifier import (
        global_error_manager,
        reset_error_stats,
    )
    from r2inspect.error_handling.classifier import ErrorCategory, ErrorInfo, ErrorSeverity

    reset_error_stats()

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
    from r2inspect.error_handling.classifier import reset_error_stats

    reset_error_stats()
    service = AnalysisService()
    results: dict = {}
    service.add_statistics(results)
    assert "error_statistics" not in results


def test_reset_stats_forwards_to_error_manager() -> None:
    """reset_stats delegates to the configured runtime port."""
    runtime = FakeRuntime()
    service = AnalysisService(runtime=runtime)

    service.reset_stats()

    assert runtime.reset_called is True


def test_execute_calls_inspector_analyze_with_kwargs() -> None:
    """execute calls analyze on the inspector with expanded keyword arguments."""
    service = AnalysisService()
    inspector = FakeInspector(result={"ok": True})

    result = service.execute(inspector, {"depth": 3})

    assert inspector.analyze_calls == [{"depth": 3}]
    assert result["ok"] is True


def test_add_statistics_adds_retry_and_circuit_stats() -> None:
    """add_statistics adds optional blocks only when stats show activity."""
    runtime = FakeRuntime(
        AnalysisRuntimeStats(
            {"total_errors": 0},
            {"total_retries": 4},
            {"opened": 1, "closed": 0, "state": "closed"},
        )
    )
    service = AnalysisService(runtime=runtime)
    results: dict[str, object] = {}

    service.add_statistics(results)

    assert results["retry_statistics"] == {"total_retries": 4}
    assert results["circuit_breaker_statistics"] == {
        "opened": 1,
        "closed": 0,
        "state": "closed",
    }


def test_validate_results_skips_when_flag_disabled() -> None:
    """validate_results returns early when schema validation flag is falsy."""
    validator = FakeValidator()
    service = AnalysisService(
        result_validator=validator,
        validation_enabled=lambda: False,
    )
    service.validate_results({"pe": {"available": True, "error": None}})

    assert len(validator.validate_calls) == 1
    assert validator.validate_calls[0] == (
        {"pe": {"available": True, "error": None}},
        False,
    )


def test_validate_results_calls_converter_for_registered_payloads() -> None:
    """validate_results delegates to the configured validator when enabled."""
    validator = FakeValidator()
    service = AnalysisService(
        result_validator=validator,
        validation_enabled=lambda: True,
    )
    payload = {"pe": {"value": 1}, "other": "ignore"}
    service.validate_results(payload)

    assert len(validator.validate_calls) == 1
    assert validator.validate_calls[0] == (payload, True)


def test_has_circuit_breaker_data_with_nested_dict_values() -> None:
    """Nested int values in circuit map trigger a positive path."""
    assert AnalysisService.has_circuit_breaker_data({"cb": {"failures": 3}}) is True


def test_has_circuit_breaker_data_false_on_zero_and_closed() -> None:
    """Nested structures with zero or closed states return False."""
    assert (
        AnalysisService.has_circuit_breaker_data(
            {"cb": {"failures": 0}, "cb2": {"state": "closed"}, "cb3": 0.0}
        )
        is False
    )


def test_validate_results_with_schema_validation_enabled() -> None:
    """validate_results executes validation logic when enabled=True."""
    validator = FakeValidator()
    service = AnalysisService(
        result_validator=validator,
        validation_enabled=lambda: True,
    )
    service.validate_results({"pe": {"available": True, "error": None}})

    assert len(validator.validate_calls) == 1
    assert validator.validate_calls[0][1] is True


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
    header = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"

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
