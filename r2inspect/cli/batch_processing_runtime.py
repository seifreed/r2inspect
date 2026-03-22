"""Operational runtime helpers for CLI batch processing."""

from __future__ import annotations

import time
from typing import Any

from ..application.batch_models import BatchDependencies
from ..infrastructure.logging import get_logger

logger = get_logger(__name__)


def _configure_logging(verbose: bool, quiet: bool, configure_batch_logging: Any) -> None:
    """Set log levels for the batch run based on verbosity flags."""
    from .command_runtime import configure_logging_levels

    if not verbose:
        configure_batch_logging()
    if quiet:
        configure_logging_levels(verbose=False, quiet=True)


def _build_deps(
    find_files_to_process: Any,
    setup_rate_limiter: Any,
) -> BatchDependencies:
    """Assemble the dependency bundle for batch execution."""
    return BatchDependencies(
        find_files_to_process=find_files_to_process,
        setup_rate_limiter=setup_rate_limiter,
        process_files_parallel=lambda *_args, **_kwargs: None,
        now=time.time,
    )


def _display_run_header(console: Any, files_count: int, threads: int, quiet: bool) -> None:
    """Print the initial progress banner if not in quiet mode."""
    if not quiet:
        console.print(f"[bold green]Found {files_count} files to process[/bold green]")
        console.print(f"[blue]Using {threads} parallel threads[/blue]")


def run_batch_analysis(
    *,
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
    threads: int,
    quiet: bool,
    console: Any,
    configure_batch_logging: Any,
    setup_batch_output_directory: Any,
    find_files_to_process: Any,
    setup_rate_limiter: Any,
    batch_service: Any,
    create_batch_summary: Any,
    display_no_files_message: Any,
    display_batch_results: Any,
    looks_like_batch_result: Any,
) -> None:
    """Orchestrate a single batch analysis run.

    Configures logging, invokes the batch service, and renders
    the summary output to the console.
    """
    _configure_logging(verbose, quiet, configure_batch_logging)

    output_path = setup_batch_output_directory(output_dir, output_json, output_csv)
    deps = _build_deps(find_files_to_process, setup_rate_limiter)

    batch_result = batch_service.run_batch_analysis(
        batch_dir=batch_dir,
        options=options,
        recursive=recursive,
        extensions=extensions,
        verbose=verbose,
        config_obj=config_obj,
        auto_detect=auto_detect,
        threads=threads,
        output_path=output_path,
        deps=deps,
    )

    if batch_result is None:
        display_no_files_message(auto_detect, extensions)
        return
    if not looks_like_batch_result(batch_result):
        logger.warning("Batch analysis returned invalid result object")
        return

    _display_run_header(console, len(batch_result.files_to_process), threads, quiet)

    rate_limiter = setup_rate_limiter(threads, verbose)

    output_filename = create_batch_summary(
        batch_result.all_results,
        batch_result.failed_files,
        batch_result.output_path,
        output_json,
        output_csv,
    )
    display_batch_results(
        batch_result.all_results,
        batch_result.failed_files,
        batch_result.elapsed_time,
        batch_result.files_to_process,
        rate_limiter,
        verbose,
        output_filename,
    )
