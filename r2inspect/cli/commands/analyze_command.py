#!/usr/bin/env python3
"""Single-file analysis command."""

from pathlib import Path
from typing import Any

from ...application.analysis_service import default_analysis_service
from ...application.use_cases import AnalyzeBinaryUseCase
from ...factory import create_inspector
from . import analysis_output
from .base import Command, apply_thread_settings


class AnalyzeCommand(Command):
    """Single-file analysis command."""

    def execute(self, args: dict[str, Any]) -> int:
        """Execute single-file analysis."""
        filename = args["filename"]
        config = self._get_config(args.get("config"))
        verbose = args.get("verbose", False)
        threads = args.get("threads")

        apply_thread_settings(config, threads)

        try:
            self._show_analysis_start(filename)
            analysis_options = self._setup_analysis_options(
                yara=args.get("yara"),
                xor=args.get("xor"),
            )
            with create_inspector(
                filename=filename,
                config=config,
                verbose=verbose,
            ) as inspector:
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
            self._handle_error(e, verbose, "Analysis")
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
        """Execute analysis and render results."""
        self._print_status_if_needed(output_json, output_csv, output_file)
        result = AnalyzeBinaryUseCase().run(inspector, options)
        results = result.to_dict()
        self._output_results(results, output_json, output_csv, output_file, verbose)

    def _show_analysis_start(self, filename: str) -> None:
        """Render the start banner for a single-file analysis run."""
        self.context.console.print(f"[blue]Initializing analysis for: {filename}[/blue]")

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

    def _add_statistics_to_results(self, results: dict[str, Any]) -> None:
        """Compatibility helper kept for older tests and callers."""
        analysis_output.add_statistics_to_results(results)

    def _display_verbose_statistics(self) -> None:
        """Display verbose error and performance statistics."""
        analysis_output._display_verbose_statistics()

    def _has_circuit_breaker_data(self, stats: dict[str, Any]) -> bool:
        """Compatibility helper kept for tests and legacy callers."""
        return default_analysis_service.has_circuit_breaker_data(stats)
