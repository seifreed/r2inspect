#!/usr/bin/env python3
"""Public facade for single-file CLI analysis execution and output."""

from pathlib import Path
from typing import Any

from rich.console import Console

from ..application.options import build_analysis_options
from ..application.analysis_service import default_analysis_service
from ..application.use_cases import AnalyzeBinaryUseCase
from ..cli.output_formatters import OutputFormatter
from . import analysis_runner_support as _runner_support
from .commands import analysis_output

console = Console()


def run_analysis(
    inspector: Any,
    options: dict[str, Any],
    output_json: bool,
    output_csv: bool,
    output_file: str | Path | None,
    verbose: bool = False,
) -> dict[str, Any]:
    print_status_if_appropriate(output_json, output_csv, output_file)
    result = AnalyzeBinaryUseCase().run(inspector, options)
    results = result.to_dict()
    output_results(results, output_json, output_csv, output_file, verbose)
    return results


def print_status_if_appropriate(
    output_json: bool, output_csv: bool, output_file: str | Path | None
) -> None:
    """Print status message if appropriate based on output options."""
    analysis_output.print_status_if_needed(console, output_json, output_csv, output_file)


def add_statistics_to_results(results: dict[str, Any]) -> None:
    """Augment results with service-level retry and circuit-breaker stats."""
    default_analysis_service.add_statistics(results)


def has_circuit_breaker_data(circuit_stats: dict[str, Any]) -> bool:
    """Return whether the circuit-breaker payload contains real signal."""
    return default_analysis_service.has_circuit_breaker_data(circuit_stats)


def output_results(
    results: dict[str, Any],
    output_json: bool,
    output_csv: bool,
    output_file: str | Path | None,
    verbose: bool,
) -> None:
    """Output results in the appropriate format."""
    analysis_output.output_results(results, output_json, output_csv, output_file, verbose, console)


def output_json_results(formatter: OutputFormatter, output_file: str | Path | None) -> None:
    """Output results in JSON format."""
    analysis_output._output_json_results(formatter, output_file, console)


def output_csv_results(formatter: OutputFormatter, output_file: str | Path | None) -> None:
    """Output results in CSV format."""
    analysis_output._output_csv_results(formatter, output_file, console)


def output_console_results(results: dict[str, Any], verbose: bool) -> None:
    """Output results to console with optional verbose statistics."""
    analysis_output._output_console_results(results, verbose)


def setup_single_file_output(
    output_json: bool,
    output_csv: bool,
    output: str | Path | None,
    filename: str,
) -> str | Path | None:
    """Return the derived output path for single-file CLI execution."""
    return _runner_support.setup_single_file_output(output_json, output_csv, output, filename)


def setup_analysis_options(yara: str | None, sanitized_xor: str | None) -> dict[str, Any]:
    """Build the default analysis option set for CLI execution."""
    return build_analysis_options(yara, sanitized_xor)


def handle_main_error(e: Exception, verbose: bool) -> None:
    """Report a top-level CLI error and terminate with exit code 1."""
    _runner_support.handle_main_error(console, e, verbose)


__all__ = [
    "OutputFormatter",
    "add_statistics_to_results",
    "console",
    "handle_main_error",
    "has_circuit_breaker_data",
    "output_console_results",
    "output_csv_results",
    "output_json_results",
    "output_results",
    "print_status_if_appropriate",
    "run_analysis",
    "setup_analysis_options",
    "setup_single_file_output",
]
