#!/usr/bin/env python3
"""Helpers for formatting and emitting analyze command output."""

from __future__ import annotations

from pathlib import Path
from typing import Any

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
    error_stats, retry_stats, circuit_stats = _collect_statistics()

    if error_stats.get("total_errors", 0) > 0:
        results["error_statistics"] = error_stats

    if retry_stats.get("total_retries", 0) > 0:
        results["retry_statistics"] = retry_stats

    if _has_circuit_breaker_data(circuit_stats):
        results["circuit_breaker_statistics"] = circuit_stats


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

    if output_file:
        with open(output_file, "w") as f:
            f.write(json_output)
        console.print(f"[green]JSON results saved to: {output_file}[/green]")
    else:
        print(json_output)


def _output_csv_results(
    formatter: OutputFormatter,
    output_file: str | Path | None,
    console: Any,
) -> None:
    """Output results in CSV format."""
    csv_output = formatter.to_csv()

    if output_file:
        with open(output_file, "w") as f:
            f.write(csv_output)
        console.print(f"[green]CSV results saved to: {output_file}[/green]")
    else:
        print(csv_output)


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
    from ..analysis_runner import has_circuit_breaker_data
    from ..display import display_error_statistics, display_performance_statistics

    error_stats, retry_stats, circuit_stats = _collect_statistics()

    if error_stats["total_errors"] > 0:
        display_error_statistics(error_stats)

    if retry_stats.get("total_retries", 0) > 0 or has_circuit_breaker_data(circuit_stats):
        display_performance_statistics(retry_stats, circuit_stats)


def _collect_statistics() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Gather error, retry, and circuit breaker statistics once."""
    error_stats = get_error_stats()
    retry_stats = get_retry_stats()
    circuit_stats = get_circuit_breaker_stats()
    return error_stats, retry_stats, circuit_stats


def _has_circuit_breaker_data(circuit_stats: dict[str, Any]) -> bool:
    """Check if circuit breaker statistics contain meaningful data."""
    if not circuit_stats:
        return False

    for _, value in circuit_stats.items():
        if isinstance(value, int | float) and value > 0:
            return True

    return False
