#!/usr/bin/env python3
"""
r2inspect CLI Analysis Runner Module

Provides analysis orchestration and result output functions.
Extracted from cli_utils.py for better modularity.

Copyright (C) 2025 Marc Rivero López

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

import sys
from pathlib import Path
from typing import Any

from rich.console import Console

from ..application.analysis_service import default_analysis_service
from ..application.use_cases import AnalyzeBinaryUseCase
from ..utils.output import OutputFormatter

console = Console()


def run_analysis(
    inspector: Any,
    options: dict[str, Any],
    output_json: bool,
    output_csv: bool,
    output_file: str | Path | None,
    verbose: bool = False,
) -> dict[str, Any]:
    """
    Run complete analysis and display results.

    Args:
        inspector: Inspector instance
        options: Analysis options dictionary
        output_json: Whether to output JSON
        output_csv: Whether to output CSV
        output_file: Output file path
        verbose: Enable verbose output

    Returns:
        Analysis results dictionary
    """
    # Import here to avoid circular dependency
    from .display import display_error_statistics, display_performance_statistics, display_results

    print_status_if_appropriate(output_json, output_csv, output_file)

    # Perform analysis
    results = AnalyzeBinaryUseCase().run(inspector, options)

    # Output results in appropriate format
    output_results(results, output_json, output_csv, output_file, verbose)

    return results


def print_status_if_appropriate(
    output_json: bool, output_csv: bool, output_file: str | Path | None
) -> None:
    """
    Print status message if appropriate based on output options.

    Args:
        output_json: Whether JSON output is enabled
        output_csv: Whether CSV output is enabled
        output_file: Output file path
    """
    if not output_json and not output_csv or (output_json or output_csv) and output_file:
        console.print("[bold green]Starting analysis...[/bold green]")


def add_statistics_to_results(results: dict[str, Any]) -> None:
    """
    Add error, retry, and circuit breaker statistics to results.

    Args:
        results: Results dictionary to augment
    """
    default_analysis_service.add_statistics(results)


def has_circuit_breaker_data(circuit_stats: dict[str, Any]) -> bool:
    """
    Check if circuit breaker statistics contain any meaningful data.

    Args:
        circuit_stats: Circuit breaker statistics dictionary

    Returns:
        True if there is meaningful data, False otherwise
    """
    return default_analysis_service.has_circuit_breaker_data(circuit_stats)


def output_results(
    results: dict[str, Any],
    output_json: bool,
    output_csv: bool,
    output_file: str | Path | None,
    verbose: bool,
) -> None:
    """
    Output results in the appropriate format.

    Args:
        results: Analysis results dictionary
        output_json: Whether to output JSON
        output_csv: Whether to output CSV
        output_file: Output file path
        verbose: Enable verbose output
    """
    # Import here to avoid circular dependency
    from .display import display_error_statistics, display_performance_statistics, display_results

    formatter = OutputFormatter(results)

    if output_json:
        output_json_results(formatter, output_file)
    elif output_csv:
        output_csv_results(formatter, output_file)
    else:
        output_console_results(results, verbose)


def output_json_results(formatter: OutputFormatter, output_file: str | Path | None) -> None:
    """
    Output results in JSON format.

    Args:
        formatter: OutputFormatter instance
        output_file: Output file path (or None for stdout)
    """
    json_output = formatter.to_json()
    if output_file:
        with open(output_file, "w") as f:
            f.write(json_output)
        console.print(f"[green]JSON results saved to: {output_file}[/green]")
    else:
        print(json_output)


def output_csv_results(formatter: OutputFormatter, output_file: str | Path | None) -> None:
    """
    Output results in CSV format.

    Args:
        formatter: OutputFormatter instance
        output_file: Output file path (or None for stdout)
    """
    csv_output = formatter.to_csv()
    if output_file:
        with open(output_file, "w") as f:
            f.write(csv_output)
        console.print(f"[green]CSV results saved to: {output_file}[/green]")
    else:
        print(csv_output)


def output_console_results(results: dict[str, Any], verbose: bool) -> None:
    """
    Output results to console with optional verbose statistics.

    Args:
        results: Analysis results dictionary
        verbose: Enable verbose output with statistics
    """
    # Import here to avoid circular dependency
    from .display import display_error_statistics, display_performance_statistics, display_results

    display_results(results)

    if verbose:
        error_stats = results.get("error_statistics", {})
        if error_stats.get("total_errors", 0) > 0:
            display_error_statistics(error_stats)

        retry_stats = results.get("retry_statistics", {})
        circuit_stats = results.get("circuit_breaker_statistics", {})

        if retry_stats.get("total_retries", 0) > 0 or has_circuit_breaker_data(circuit_stats):
            display_performance_statistics(retry_stats, circuit_stats)


def setup_single_file_output(
    output_json: bool,
    output_csv: bool,
    output: str | Path | None,
    filename: str,
) -> str | Path | None:
    """
    Setup output file for single file mode.

    Args:
        output_json: Whether JSON output is enabled
        output_csv: Whether CSV output is enabled
        output: User-provided output path
        filename: Input filename

    Returns:
        Output file path or None
    """
    if (output_json or output_csv) and not output:
        # Create output directory if it doesn't exist
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)

        # Generate filename based on input file
        input_path = Path(filename)
        base_name = input_path.stem

        if output_json:
            output = output_dir / f"{base_name}_analysis.json"
        elif output_csv:
            output = output_dir / f"{base_name}_analysis.csv"

    return output


def setup_analysis_options(yara: str | None, sanitized_xor: str | None) -> dict[str, Any]:
    """
    Setup analysis options with all modules enabled by default.

    Args:
        yara: YARA rules directory path
        sanitized_xor: Sanitized XOR search string

    Returns:
        Analysis options dictionary
    """
    return {
        "detect_packer": True,
        "detect_crypto": True,
        "detect_av": True,
        "full_analysis": True,
        "custom_yara": yara,
        "xor_search": sanitized_xor,
    }


def handle_main_error(e: Exception, verbose: bool) -> None:
    """
    Handle errors in main function.

    Args:
        e: Exception that occurred
        verbose: Enable verbose error output
    """
    console.print(f"[red]Error: {str(e)}[/red]")
    if verbose:
        import traceback

        traceback.print_exc()
    sys.exit(1)
