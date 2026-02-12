#!/usr/bin/env python3
"""Helpers for formatting and emitting analyze command output."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ...application.analysis_service import default_analysis_service
from ...error_handling.stats import get_circuit_breaker_stats, get_error_stats, get_retry_stats
from ...utils.output import OutputFormatter


def print_status_if_needed(
    console: Any,
    output_json: bool,
    output_csv: bool,
    output_file: str | Path | None,
) -> None:
    """Print status message if appropriate based on output options."""
    writing_to_file = bool(output_file)
    writing_to_console = not output_json and not output_csv
    emitting_with_output_file = (output_json or output_csv) and writing_to_file

    if writing_to_console or emitting_with_output_file:
        console.print("[bold green]Starting analysis...[/bold green]")


def add_statistics_to_results(results: dict[str, Any]) -> None:
    """Add error, retry, and circuit breaker statistics to results."""
    default_analysis_service.add_statistics(results)


def output_results(
    results: dict[str, Any],
    output_json: bool,
    output_csv: bool,
    output_file: str | Path | None,
    verbose: bool,
    console: Any,
) -> None:
    """Output results in the appropriate format."""
    formatter = OutputFormatter(results)

    if output_json:
        _output_json_results(formatter, output_file, console)
    elif output_csv:
        _output_csv_results(formatter, output_file, console)
    else:
        _output_console_results(results, verbose)


def _output_json_results(
    formatter: OutputFormatter,
    output_file: str | Path | None,
    console: Any,
) -> None:
    """Output results in JSON format."""
    json_output = formatter.to_json()
    _write_output(json_output, output_file, console, "JSON")


def _output_csv_results(
    formatter: OutputFormatter,
    output_file: str | Path | None,
    console: Any,
) -> None:
    """Output results in CSV format."""
    csv_output = formatter.to_csv()
    _write_output(csv_output, output_file, console, "CSV")


def _output_console_results(
    results: dict[str, Any],
    verbose: bool,
) -> None:
    """Output results to console with optional verbose statistics."""
    from ..display import display_results

    display_results(results)

    if verbose:
        _display_verbose_statistics()


def _display_verbose_statistics() -> None:
    """Display verbose error and performance statistics."""
    from ..display import display_error_statistics, display_performance_statistics

    error_stats, retry_stats, circuit_stats = _collect_statistics()

    if error_stats["total_errors"] > 0:
        display_error_statistics(error_stats)

    if retry_stats.get("total_retries", 0) > 0 or default_analysis_service.has_circuit_breaker_data(
        circuit_stats
    ):
        display_performance_statistics(retry_stats, circuit_stats)


def _collect_statistics() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Gather error, retry, and circuit breaker statistics once."""
    error_stats = get_error_stats()
    retry_stats = get_retry_stats()
    circuit_stats = get_circuit_breaker_stats()
    return error_stats, retry_stats, circuit_stats


def _write_output(
    content: str,
    output_file: str | Path | None,
    console: Any,
    label: str,
) -> None:
    if output_file:
        with open(output_file, "w") as f:
            f.write(content)
        console.print(f"[green]{label} results saved to: {output_file}[/green]")
    else:
        print(content)
