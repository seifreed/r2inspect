from __future__ import annotations

import sys
from io import StringIO
from pathlib import Path

from rich.console import Console

from r2inspect.cli import analysis_runner as ar
from r2inspect.cli import display as display_module
from r2inspect.cli import display_base
from r2inspect.error_handling.policies import ErrorHandlingStrategy, ErrorPolicy
from r2inspect.error_handling.unified_handler import (
    get_circuit_breaker_stats,
    handle_errors,
    reset_circuit_breakers,
)
from r2inspect.utils.error_handler import (
    ErrorCategory,
    ErrorInfo,
    ErrorSeverity,
    global_error_manager,
    reset_error_stats,
)
from r2inspect.utils.retry_manager import (
    RetryableError,
    RetryConfig,
    RetryStrategy,
    reset_retry_stats,
    retry_on_failure,
)


def _seed_error_stats() -> None:
    info = ErrorInfo(
        exception=ValueError("boom"),
        severity=ErrorSeverity.MEDIUM,
        category=ErrorCategory.INPUT_VALIDATION,
        recoverable=False,
        context={},
        suggested_action="fix",
    )
    global_error_manager.handle_error(info)


def _seed_retry_stats() -> None:
    reset_retry_stats()
    attempts = {"count": 0}

    @retry_on_failure(
        config=RetryConfig(
            max_attempts=2, base_delay=0.0, jitter=False, strategy=RetryStrategy.FIXED_DELAY
        )
    )
    def flaky(**_kwargs: object) -> str:
        if attempts["count"] == 0:
            attempts["count"] += 1
            raise RetryableError("try again")
        return "ok"

    assert flaky() == "ok"


def _seed_circuit_stats() -> None:
    reset_circuit_breakers()

    policy = ErrorPolicy(
        ErrorHandlingStrategy.CIRCUIT_BREAK,
        max_retries=1,
        retry_delay=0.01,
        retry_backoff=1.0,
        retry_jitter=False,
        circuit_threshold=1,
        circuit_timeout=1,
        fallback_value={},
    )

    @handle_errors(policy)
    def boom() -> dict:
        raise RuntimeError("fail")

    try:
        boom()
    except Exception:
        pass


def test_print_status_if_appropriate() -> None:
    original_file = ar.console.file
    try:
        buffer = StringIO()
        ar.console.file = buffer
        ar.print_status_if_appropriate(output_json=False, output_csv=False, output_file=None)
        out = buffer.getvalue()
        assert "Starting analysis" in out

        buffer = StringIO()
        ar.console.file = buffer
        ar.print_status_if_appropriate(output_json=True, output_csv=False, output_file=None)
        assert buffer.getvalue() == ""
    finally:
        ar.console.file = original_file


def test_add_statistics_to_results() -> None:
    reset_error_stats()
    reset_retry_stats()
    reset_circuit_breakers()
    results: dict[str, object] = {}
    ar.add_statistics_to_results(results)
    assert "error_statistics" not in results
    assert "retry_statistics" not in results
    expected_circuit = ar.has_circuit_breaker_data(get_circuit_breaker_stats())
    if expected_circuit:
        assert "circuit_breaker_statistics" in results
    else:
        assert "circuit_breaker_statistics" not in results

    _seed_error_stats()
    _seed_retry_stats()
    _seed_circuit_stats()

    results = {}
    ar.add_statistics_to_results(results)
    assert "error_statistics" in results
    assert "retry_statistics" in results
    assert "circuit_breaker_statistics" in results


def test_output_results_json_stdout() -> None:
    results = {"ok": True}
    original_stdout = sys.stdout
    try:
        buffer = StringIO()
        sys.stdout = buffer
        ar.output_results(
            results, output_json=True, output_csv=False, output_file=None, verbose=False
        )
        assert '"ok"' in buffer.getvalue()
    finally:
        sys.stdout = original_stdout


def test_output_console_results_verbose_stats() -> None:
    _seed_error_stats()
    _seed_retry_stats()
    _seed_circuit_stats()
    results = {"file_info": {"name": "x"}}
    original_console = display_base.console
    original_display_console = display_module.console
    try:
        buffer = StringIO()
        console = Console(file=buffer, force_terminal=False, color_system=None)
        display_base.console = console
        display_module.console = console
        ar.output_console_results(results, verbose=True)
        out = buffer.getvalue()
        assert "file" in out.lower()
    finally:
        display_base.console = original_console
        display_module.console = original_display_console
