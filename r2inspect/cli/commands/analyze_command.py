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

from ...application.use_cases import AnalyzeBinaryUseCase
from ...factory import create_inspector
from . import analysis_output
from .base import Command, apply_thread_settings


class AnalyzeCommand(Command):
    """
    Command for analyzing a single binary file.

    Encapsulates the complete workflow for single file analysis:
    - Configuration loading
    - Inspector initialization
    - Analysis execution
    - Result formatting and output
    - Statistics collection and display

    Responsibilities:
    - Validate file input
    - Execute malware analysis via inspector
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

            # Initialize inspector with context manager for proper cleanup
            with create_inspector(
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
        inspector: Any,
        options: dict[str, Any],
        output_json: bool,
        output_csv: bool,
        output_file: str | Path | None,
        verbose: bool = False,
    ) -> None:
        """
        Execute analysis and output results.

        Args:
            inspector: Initialized inspector instance
            options: Analysis options dictionary
            output_json: Flag for JSON output
            output_csv: Flag for CSV output
            output_file: Output file path
            verbose: Verbose output flag
        """
        # Print status if appropriate
        self._print_status_if_needed(output_json, output_csv, output_file)

        # Perform analysis
        results = AnalyzeBinaryUseCase().run(inspector, options)

        # Output results in appropriate format
        self._output_results(
            results,
            output_json,
            output_csv,
            output_file,
            verbose,
        )

    def _print_status_if_needed(
        self,
        output_json: bool,
        output_csv: bool,
        output_file: str | Path | None,
    ) -> None:
        """Print status message if appropriate based on output options."""
        analysis_output.print_status_if_needed(
            self.context.console,
            output_json,
            output_csv,
            output_file,
        )

    def _output_results(
        self,
        results: dict[str, Any],
        output_json: bool,
        output_csv: bool,
        output_file: str | Path | None,
        verbose: bool,
    ) -> None:
        """Output results in the appropriate format."""
        analysis_output.output_results(
            results,
            output_json,
            output_csv,
            output_file,
            verbose,
            self.context.console,
        )

    def _output_json_results(
        self,
        formatter: Any,
        output_file: str | Path | None,
    ) -> None:
        """Output results in JSON format."""
        analysis_output._output_json_results(formatter, output_file, self.context.console)

    def _output_csv_results(
        self,
        formatter: Any,
        output_file: str | Path | None,
    ) -> None:
        """Output results in CSV format."""
        analysis_output._output_csv_results(formatter, output_file, self.context.console)

    def _output_console_results(
        self,
        results: dict[str, Any],
        verbose: bool,
    ) -> None:
        """Output results to console with optional verbose statistics."""
        analysis_output._output_console_results(results, verbose)

    def _display_verbose_statistics(self) -> None:
        """Display verbose error and performance statistics."""
        analysis_output._display_verbose_statistics()

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
