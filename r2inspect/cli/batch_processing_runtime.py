"""Operational runtime helpers for CLI batch processing."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from ..application.batch_models import BatchDependencies


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
    default_batch_service: Any,
    create_batch_summary: Any,
    display_no_files_message: Any,
    display_batch_results: Any,
    looks_like_batch_result: Any,
) -> None:
    if not verbose:
        configure_batch_logging()
    if quiet:
        logging.getLogger("r2inspect").setLevel(logging.CRITICAL)
        logging.getLogger("r2inspect.modules").setLevel(logging.CRITICAL)

    output_path = setup_batch_output_directory(output_dir, output_json, output_csv)
    deps = BatchDependencies(
        find_files_to_process=find_files_to_process,
        setup_rate_limiter=setup_rate_limiter,
        process_files_parallel=lambda *_args, **_kwargs: None,
        now=time.time,
    )
    batch_result = default_batch_service.run_batch_analysis(
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
        return

    if not quiet:
        console.print(
            f"[bold green]Found {len(batch_result.files_to_process)} files to process[/bold green]"
        )
        console.print(f"[blue]Using {threads} parallel threads[/blue]")

    # Obtain rate_limiter from the injected factory rather than from the
    # domain result object (it is an infrastructure concern).
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
