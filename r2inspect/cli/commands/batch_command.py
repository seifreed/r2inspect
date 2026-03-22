#!/usr/bin/env python3
"""Batch directory analysis command."""

import logging
from typing import Any

from ...application.options import build_analysis_options
from ...infrastructure.logging import configure_batch_logging
from .base import Command, apply_thread_settings


class BatchCommand(Command):
    """Batch analysis command."""

    def execute(self, args: dict[str, Any]) -> int:
        """Execute batch directory analysis."""
        batch_dir = args["batch"]
        config = self._get_config(args.get("config"))
        verbose = args.get("verbose", False)
        quiet = args.get("quiet", False)
        threads = args.get("threads", 10)
        extensions: str | None = args.get("extensions")
        output: str | None = args.get("output")

        try:
            apply_thread_settings(config, threads)
            recursive, auto_detect, output_dir = self._setup_batch_mode(
                batch_dir,
                extensions,
                args.get("output_json", False),
                args.get("output_csv", False),
                output,
            )

            analysis_options = self._setup_analysis_options(
                yara=args.get("yara"),
                xor=args.get("xor"),
            )
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
            self._handle_error(e, verbose, "Batch analysis")
            return 1

    def _setup_batch_mode(
        self,
        _batch: str,
        extensions: str | None,
        output_json: bool,
        output_csv: bool,
        output: str | None,
    ) -> tuple[bool, bool, str | None]:
        recursive = True
        auto_detect = not extensions
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
        """Run batch analysis on multiple files in a directory."""
        from ..batch_processing import (
            ensure_batch_shutdown,
            run_batch_analysis,
            schedule_forced_exit,
        )

        self._configure_batch_logging(verbose, quiet)

        run_batch_analysis(
            batch_dir=batch_dir,
            options=options,
            output_json=output_json,
            output_csv=output_csv,
            output_dir=output_dir,
            recursive=recursive,
            extensions=extensions,
            verbose=verbose,
            config_obj=config_obj,
            auto_detect=auto_detect,
            threads=threads,
            quiet=quiet,
        )
        ensure_batch_shutdown()
        schedule_forced_exit()

    def _configure_batch_logging(self, verbose: bool, quiet: bool) -> None:
        if not verbose:
            configure_batch_logging()
        if quiet:
            from ..command_runtime import configure_logging_levels

            configure_logging_levels(verbose=False, quiet=True)

    def _setup_analysis_options(
        self,
        yara: str | None = None,
        xor: str | None = None,
    ) -> dict[str, Any]:
        return build_analysis_options(yara, xor)
