#!/usr/bin/env python3
"""Batch directory analysis command."""

import logging
from typing import Any

from ...application.options import build_analysis_options
from ...infrastructure.logging import configure_batch_logging
from ..batch_processing_runtime import BatchRunRequest
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
                extensions,
                args.get("output_json", False),
                args.get("output_csv", False),
                output,
            )

            analysis_options = self._setup_analysis_options(
                yara=args.get("yara"),
                xor=args.get("xor"),
            )
            request = BatchRunRequest(
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
            self._run_batch_analysis(request)

            return 0

        except KeyboardInterrupt:
            self.context.console.print("\n[yellow]Batch analysis interrupted by user[/yellow]")
            return 1

        except Exception as e:
            self._handle_error(e, verbose, "Batch analysis")
            return 1

    def _setup_batch_mode(
        self,
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

    def _run_batch_analysis(self, request: BatchRunRequest) -> None:
        """Run batch analysis on multiple files in a directory."""
        from ..batch_processing import (
            ensure_batch_shutdown,
            run_batch_analysis,
            schedule_forced_exit,
        )

        self._configure_batch_logging(request.verbose, request.quiet)
        run_batch_analysis(request)
        ensure_batch_shutdown()
        schedule_forced_exit()

    def _configure_batch_logging(self, verbose: bool, quiet: bool) -> None:
        if not verbose:
            configure_batch_logging()
        if quiet:
            # Batch quiet mode is stricter than the shared quiet config:
            # a batch run processes many files, so r2inspect's own loggers
            # are raised to CRITICAL (not WARNING). 8f3da63 lost this by
            # delegating to the shared WARNING-level helper.
            logging.getLogger("r2pipe").setLevel(logging.CRITICAL)
            for name in ("r2inspect", "r2inspect.modules", "r2inspect.pipeline"):
                logging.getLogger(name).setLevel(logging.CRITICAL)

    def _setup_analysis_options(
        self,
        yara: str | None = None,
        xor: str | None = None,
    ) -> dict[str, Any]:
        return build_analysis_options(yara, xor)


__all__ = [
    "logging",
]
