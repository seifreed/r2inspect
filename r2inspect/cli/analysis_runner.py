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

from rich.console import Console

from ..utils.error_handler import get_error_stats, reset_error_stats
from ..utils.output import OutputFormatter
from ..utils.r2_helpers import get_circuit_breaker_stats, get_retry_stats

console = Console()


def run_analysis(inspector, options, output_json, output_csv, output_file, verbose=False):
    """
    Run complete analysis and display results.

    Args:
        inspector: R2Inspector instance
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

    reset_error_stats()

    print_status_if_appropriate(output_json, output_csv, output_file)

    # Perform analysis
    results = inspector.analyze(**options)

    # Add statistics to results
    add_statistics_to_results(results)

    # Output results in appropriate format
    output_results(results, output_json, output_csv, output_file, verbose)

    return results


def print_status_if_appropriate(output_json, output_csv, output_file):
    """
    Print status message if appropriate based on output options.

    Args:
        output_json: Whether JSON output is enabled
        output_csv: Whether CSV output is enabled
        output_file: Output file path
    """
    if not output_json and not output_csv or (output_json or output_csv) and output_file:
        console.print("[bold green]Starting analysis...[/bold green]")


def add_statistics_to_results(results):
    """
    Add error, retry, and circuit breaker statistics to results.

    Args:
        results: Results dictionary to augment
    """
    error_stats = get_error_stats()
    retry_stats = get_retry_stats()
    circuit_stats = get_circuit_breaker_stats()

    if error_stats["total_errors"] > 0:
        results["error_statistics"] = error_stats

    if retry_stats.get("total_retries", 0) > 0:
        results["retry_statistics"] = retry_stats

    if has_circuit_breaker_data(circuit_stats):
        results["circuit_breaker_statistics"] = circuit_stats


def has_circuit_breaker_data(circuit_stats):
    """
    Check if circuit breaker statistics contain any meaningful data.

    Args:
        circuit_stats: Circuit breaker statistics dictionary

    Returns:
        True if there is meaningful data, False otherwise
    """
    if not circuit_stats:
        return False

    for k, v in circuit_stats.items():
        if isinstance(v, int | float) and v > 0:
            return True
    return False


def output_results(results, output_json, output_csv, output_file, verbose):
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


def output_json_results(formatter, output_file):
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


def output_csv_results(formatter, output_file):
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


def output_console_results(results, verbose):
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
        error_stats = get_error_stats()
        if error_stats["total_errors"] > 0:
            display_error_statistics(error_stats)

        retry_stats = get_retry_stats()
        circuit_stats = get_circuit_breaker_stats()

        if retry_stats["total_retries"] > 0 or has_circuit_breaker_data(circuit_stats):
            display_performance_statistics(retry_stats, circuit_stats)


def setup_single_file_output(output_json, output_csv, output, filename):
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


def setup_analysis_options(yara, sanitized_xor):
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


def handle_main_error(e, verbose):
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
