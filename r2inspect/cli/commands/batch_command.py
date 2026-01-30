#!/usr/bin/env python3
"""
r2inspect CLI Commands - Batch Command

Batch directory analysis command implementation.

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

import time
from pathlib import Path
from typing import Any

from .base import Command, apply_thread_settings


class BatchCommand(Command):
    """
    Command for batch analysis of multiple binary files in a directory.

    Encapsulates the complete workflow for batch directory analysis:
    - File discovery (recursive, with extension filtering or auto-detection)
    - Parallel processing with configurable thread pool
    - Progress tracking with real-time updates
    - Rate limiting and memory management
    - Batch summary generation (JSON/CSV)
    - Statistics collection and reporting

    Responsibilities:
    - Discover files to process based on criteria
    - Coordinate parallel file analysis
    - Aggregate results and generate summaries
    - Display batch statistics and failed files
    """

    def execute(self, args: dict[str, Any]) -> int:
        """
        Execute batch directory analysis.

        Args:
            args: Dictionary containing:
                - batch: Path to directory to analyze
                - config: Optional config file path
                - yara: Optional YARA rules directory
                - xor: Optional XOR search string
                - output_json: JSON output flag
                - output_csv: CSV output flag
                - output: Output directory path
                - extensions: File extensions to process
                - threads: Number of parallel threads
                - verbose: Verbose output flag
                - quiet: Suppress non-critical output

        Returns:
            0 on success, 1 on failure
        """
        batch_dir = args["batch"]
        config = self._get_config(args.get("config"))
        verbose = args.get("verbose", False)
        quiet = args.get("quiet", False)
        threads = args.get("threads", 10)
        extensions: str | None = args.get("extensions")
        output: str | None = args.get("output")

        try:
            apply_thread_settings(config, threads)
            # Setup batch parameters
            recursive, auto_detect, output_dir = self._setup_batch_mode(
                batch_dir,
                extensions,
                args.get("output_json", False),
                args.get("output_csv", False),
                output,
            )

            # Configure analysis options
            analysis_options = self._setup_analysis_options(
                yara=args.get("yara"),
                xor=args.get("xor"),
            )

            # Execute batch analysis
            self._run_batch_analysis(
                batch_dir=batch_dir,
                options=analysis_options,
                output_json=args.get("output_json", False),
                output_csv=args.get("output_csv", False),
                output_dir=output_dir,
                recursive=recursive,
                extensions=extensions,
                verbose=verbose,
                config_obj=config,
                auto_detect=auto_detect,
                threads=threads,
                quiet=quiet,
            )

            return 0

        except KeyboardInterrupt:
            self.context.console.print("\n[yellow]Batch analysis interrupted by user[/yellow]")
            return 1

        except Exception as e:
            self._handle_error(e, verbose)
            return 1

    def _setup_batch_mode(
        self,
        _batch: str,
        extensions: str | None,
        output_json: bool,
        output_csv: bool,
        output: str | None,
    ) -> tuple[bool, bool, str | None]:
        """
        Setup batch mode parameters.

        Args:
            batch: Batch directory path
            extensions: File extensions filter
            output_json: JSON output flag
            output_csv: CSV output flag
            output: Output directory path

        Returns:
            Tuple of (recursive, auto_detect, output_path)
        """
        recursive = True  # Always recursive for batch mode
        auto_detect = not extensions  # Auto-detect if no extensions specified

        # Set default output directory if not specified but JSON/CSV requested
        if (output_json or output_csv) and not output:
            output = "output"

        return recursive, auto_detect, output

    def _run_batch_analysis(
        self,
        batch_dir: str,
        options: dict[str, Any],
        output_json: bool,
        output_csv: bool,
        output_dir: str | None,
        recursive: bool,
        extensions: str | None,
        verbose: bool,
        config_obj: Any,
        auto_detect: bool,
        threads: int = 10,
        quiet: bool = False,
    ) -> None:
        """
        Run batch analysis on multiple files in a directory.

        Coordinates the complete batch analysis workflow including:
        - File discovery and filtering
        - Parallel processing setup
        - Progress tracking
        - Results aggregation
        - Summary generation

        Args:
            batch_dir: Directory to analyze
            options: Analysis options dictionary
            output_json: JSON output flag
            output_csv: CSV output flag
            output_dir: Output directory path
            recursive: Recursive directory traversal flag
            extensions: File extensions to filter
            verbose: Verbose output flag
            config_obj: Configuration object
            auto_detect: Auto-detect file types flag
            threads: Number of parallel threads
            quiet: Suppress non-critical output
        """
        # Import batch processing utilities from cli module
        from .. import (
            create_batch_summary,
            display_batch_results,
            display_no_files_message,
            find_files_to_process,
            process_files_parallel,
            setup_batch_output_directory,
            setup_rate_limiter,
        )

        batch_path = Path(batch_dir)

        # Find files to process
        files_to_process = find_files_to_process(
            batch_path, auto_detect, extensions, recursive, verbose, quiet
        )

        if not files_to_process:
            display_no_files_message(auto_detect, extensions)
            return

        if not quiet:
            self.context.console.print(
                f"[bold green]Found {len(files_to_process)} files to process[/bold green]"
            )
            self.context.console.print(f"[blue]Using {threads} parallel threads[/blue]")

        # Configure logging for batch processing
        self._configure_batch_logging(verbose, quiet)

        # Setup output directory
        output_path = setup_batch_output_directory(output_dir, output_json, output_csv)

        # Results storage
        all_results: dict[str, dict[str, Any]] = {}
        failed_files: list[str] = []

        # Start timing
        start_time = time.time()

        # Process files in parallel
        rate_limiter = setup_rate_limiter(threads, verbose)
        process_files_parallel(
            files_to_process,
            all_results,
            failed_files,
            output_path,
            batch_path,
            config_obj,
            options,
            output_json,
            threads,
            rate_limiter,
        )

        # Calculate elapsed time
        elapsed_time = time.time() - start_time

        # Create summary report and get output filename
        output_filename = create_batch_summary(
            all_results, failed_files, output_path, output_json, output_csv
        )

        # Display final results
        display_batch_results(
            all_results,
            failed_files,
            elapsed_time,
            files_to_process,
            rate_limiter,
            verbose,
            output_filename,
        )

    def _configure_batch_logging(self, verbose: bool, quiet: bool) -> None:
        """
        Configure logging levels for batch processing.

        Adjusts logging verbosity to reduce noise during batch operations
        while still capturing critical errors.

        Args:
            verbose: Verbose output flag
            quiet: Suppress non-critical output flag
        """
        if not verbose:
            from ...utils.logger import configure_batch_logging

            configure_batch_logging()

        # If quiet mode, suppress even more logging
        if quiet:
            import logging

            logging.getLogger("r2inspect").setLevel(logging.CRITICAL)
            logging.getLogger("r2inspect.modules").setLevel(logging.CRITICAL)

    def _setup_analysis_options(
        self,
        yara: str | None = None,
        xor: str | None = None,
    ) -> dict[str, Any]:
        """
        Setup analysis options with all modules enabled by default.

        Overrides base implementation to enable all analysis modules
        for comprehensive batch scanning.

        Args:
            yara: Path to custom YARA rules directory
            xor: XOR key for string search

        Returns:
            Dictionary of analysis options with all modules enabled
        """
        options: dict[str, Any] = {
            "detect_packer": True,
            "detect_crypto": True,
            "detect_av": True,
            "full_analysis": True,
        }

        if yara:
            options["custom_yara"] = yara

        if xor:
            options["xor_search"] = xor

        return options

    def _handle_error(self, error: Exception, verbose: bool) -> None:
        """
        Handle batch analysis errors with appropriate logging and output.

        Args:
            error: Exception that occurred
            verbose: Verbose output flag for detailed error info
        """
        self.context.logger.error(f"Error during batch analysis: {error}")

        if verbose:
            self.context.console.print(f"[red]Error: {error}[/red]")
            import traceback

            self.context.console.print(f"[dim]{traceback.format_exc()}[/dim]")
        else:
            self.context.console.print(f"[red]Batch analysis failed: {error}[/red]")
            self.context.console.print("[dim]Use --verbose for detailed error information[/dim]")
