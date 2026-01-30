#!/usr/bin/env python3
"""
r2inspect CLI Commands - Analyze Command

Single file analysis command implementation.

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

from pathlib import Path
from typing import Any

from ...core import R2Inspector
from ...utils.error_handler import get_error_stats, reset_error_stats
from ...utils.output import OutputFormatter
from ...utils.r2_helpers import get_circuit_breaker_stats, get_retry_stats
from .base import Command, apply_thread_settings


class AnalyzeCommand(Command):
    """
    Command for analyzing a single binary file.

    Encapsulates the complete workflow for single file analysis:
    - Configuration loading
    - R2Inspector initialization
    - Analysis execution
    - Result formatting and output
    - Statistics collection and display

    Responsibilities:
    - Validate file input
    - Execute malware analysis via R2Inspector
    - Handle output formatting (JSON, CSV, console)
    - Display error and performance statistics
    """

    def execute(self, args: dict[str, Any]) -> int:
        """
        Execute single file analysis.

        Args:
            args: Dictionary containing:
                - filename: Path to file to analyze
                - config: Optional config file path
                - yara: Optional YARA rules directory
                - xor: Optional XOR search string
                - output_json: JSON output flag
                - output_csv: CSV output flag
                - output: Output file path
                - verbose: Verbose output flag

        Returns:
            0 on success, 1 on failure
        """
        filename = args["filename"]
        config = self._get_config(args.get("config"))
        verbose = args.get("verbose", False)
        threads = args.get("threads")

        apply_thread_settings(config, threads)

        try:
            self.context.console.print(f"[blue]Initializing analysis for: {filename}[/blue]")

            # Configure analysis options
            analysis_options = self._setup_analysis_options(
                yara=args.get("yara"),
                xor=args.get("xor"),
            )

            # Initialize R2Inspector with context manager for proper cleanup
            with R2Inspector(
                filename=filename,
                config=config,
                verbose=verbose,
            ) as inspector:
                # Execute analysis and handle results
                self._run_analysis(
                    inspector=inspector,
                    options=analysis_options,
                    output_json=args.get("output_json", False),
                    output_csv=args.get("output_csv", False),
                    output_file=args.get("output"),
                    verbose=verbose,
                )

            return 0

        except KeyboardInterrupt:
            self.context.console.print("\n[yellow]Analysis interrupted by user[/yellow]")
            return 1

        except Exception as e:
            self._handle_error(e, verbose)
            return 1

    def _run_analysis(
        self,
        inspector: R2Inspector,
        options: dict[str, Any],
        output_json: bool,
        output_csv: bool,
        output_file: str | None,
        verbose: bool = False,
    ) -> None:
        """
        Execute analysis and output results.

        Args:
            inspector: Initialized R2Inspector instance
            options: Analysis options dictionary
            output_json: Flag for JSON output
            output_csv: Flag for CSV output
            output_file: Output file path
            verbose: Verbose output flag
        """
        # Reset error statistics for clean analysis
        reset_error_stats()

        # Print status if appropriate
        self._print_status_if_needed(output_json, output_csv, output_file)

        # Perform analysis
        results = inspector.analyze(**options)

        # Add statistics to results
        self._add_statistics_to_results(results)

        # Output results in appropriate format
        self._output_results(results, output_json, output_csv, output_file, verbose)

    def _print_status_if_needed(
        self,
        output_json: bool,
        output_csv: bool,
        output_file: str | None,
    ) -> None:
        """
        Print status message if appropriate based on output options.

        Status is printed when:
        - Not using JSON/CSV output
        - Using JSON/CSV but also writing to console (no output file)

        Args:
            output_json: JSON output flag
            output_csv: CSV output flag
            output_file: Output file path
        """
        writing_to_file = bool(output_file)
        writing_to_console = not output_json and not output_csv
        emitting_with_output_file = (output_json or output_csv) and writing_to_file

        if writing_to_console or emitting_with_output_file:
            self.context.console.print("[bold green]Starting analysis...[/bold green]")

    def _add_statistics_to_results(self, results: dict[str, Any]) -> None:
        """
        Add error, retry, and circuit breaker statistics to results.

        Statistics are only added if they contain meaningful data to avoid
        cluttering output with zero values.

        Args:
            results: Analysis results dictionary (modified in place)
        """
        error_stats, retry_stats, circuit_stats = self._collect_statistics()

        if error_stats.get("total_errors", 0) > 0:
            results["error_statistics"] = error_stats

        if retry_stats.get("total_retries", 0) > 0:
            results["retry_statistics"] = retry_stats

        if self._has_circuit_breaker_data(circuit_stats):
            results["circuit_breaker_statistics"] = circuit_stats

    def _has_circuit_breaker_data(self, circuit_stats: dict[str, Any]) -> bool:
        """
        Check if circuit breaker statistics contain meaningful data.

        Args:
            circuit_stats: Circuit breaker statistics dictionary

        Returns:
            True if contains non-zero values, False otherwise
        """
        if not circuit_stats:
            return False

        for k, v in circuit_stats.items():
            if isinstance(v, int | float) and v > 0:
                return True

        return False

    def _output_results(
        self,
        results: dict[str, Any],
        output_json: bool,
        output_csv: bool,
        output_file: str | None,
        verbose: bool,
    ) -> None:
        """
        Output results in the appropriate format.

        Delegates to specific output methods based on format flags.

        Args:
            results: Analysis results dictionary
            output_json: JSON output flag
            output_csv: CSV output flag
            output_file: Output file path
            verbose: Verbose output flag
        """
        formatter = OutputFormatter(results)

        if output_json:
            self._output_json_results(formatter, output_file)
        elif output_csv:
            self._output_csv_results(formatter, output_file)
        else:
            self._output_console_results(results, verbose)

    def _output_json_results(
        self,
        formatter: OutputFormatter,
        output_file: str | None,
    ) -> None:
        """
        Output results in JSON format.

        Args:
            formatter: OutputFormatter instance with results
            output_file: Output file path (None for stdout)
        """
        json_output = formatter.to_json()

        if output_file:
            with open(output_file, "w") as f:
                f.write(json_output)
            self.context.console.print(f"[green]JSON results saved to: {output_file}[/green]")
        else:
            print(json_output)

    def _output_csv_results(
        self,
        formatter: OutputFormatter,
        output_file: str | None,
    ) -> None:
        """
        Output results in CSV format.

        Args:
            formatter: OutputFormatter instance with results
            output_file: Output file path (None for stdout)
        """
        csv_output = formatter.to_csv()

        if output_file:
            with open(output_file, "w") as f:
                f.write(csv_output)
            self.context.console.print(f"[green]CSV results saved to: {output_file}[/green]")
        else:
            print(csv_output)

    def _output_console_results(
        self,
        results: dict[str, Any],
        verbose: bool,
    ) -> None:
        """
        Output results to console with optional verbose statistics.

        Imports display functions from cli module to maintain identical
        output formatting and avoid code duplication.

        Args:
            results: Analysis results dictionary
            verbose: Verbose output flag for statistics display
        """
        # Import display functions from cli.display to avoid package export issues
        from ..display import display_results

        display_results(results)

        if verbose:
            self._display_verbose_statistics()

    def _display_verbose_statistics(self) -> None:
        """
        Display verbose error and performance statistics.

        Only displays statistics that have meaningful data to avoid
        cluttering output with empty tables.
        """
        # Import display functions from cli
        from .. import (
            display_error_statistics,
            display_performance_statistics,
            has_circuit_breaker_data,
        )

        error_stats, retry_stats, circuit_stats = self._collect_statistics()

        if error_stats["total_errors"] > 0:
            display_error_statistics(error_stats)

        if retry_stats.get("total_retries", 0) > 0 or has_circuit_breaker_data(circuit_stats):
            display_performance_statistics(retry_stats, circuit_stats)

    def _collect_statistics(self):
        """Gather error, retry, and circuit breaker statistics once."""
        error_stats = get_error_stats()
        retry_stats = get_retry_stats()
        circuit_stats = get_circuit_breaker_stats()
        return error_stats, retry_stats, circuit_stats

    def _handle_error(self, error: Exception, verbose: bool) -> None:
        """
        Handle analysis errors with appropriate logging and output.

        Args:
            error: Exception that occurred
            verbose: Verbose output flag for detailed error info
        """
        self.context.logger.error(f"Error during analysis: {error}")

        if verbose:
            self.context.console.print(f"[red]Error: {error}[/red]")
            import traceback

            self.context.console.print(f"[dim]{traceback.format_exc()}[/dim]")
        else:
            self.context.console.print(f"[red]Analysis failed: {error}[/red]")
            self.context.console.print("[dim]Use --verbose for detailed error information[/dim]")
