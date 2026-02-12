#!/usr/bin/env python3
"""Application service for batch analysis orchestration."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class BatchDependencies:
    find_files_to_process: Callable[..., list[Path]]
    display_no_files_message: Callable[[bool, str | None], None]
    setup_output_directory: Callable[[str | None, bool, bool], Path]
    setup_rate_limiter: Callable[[int, bool], Any]
    process_files_parallel: Callable[..., None]
    create_batch_summary: Callable[..., str | None]
    display_batch_results: Callable[..., None]
    display_found_files: Callable[[int, int], None] | None = None
    configure_batch_logging: Callable[[], None] | None = None
    configure_quiet_logging: Callable[[], None] | None = None
    now: Callable[[], float] | None = None


class BatchAnalysisService:
    """Coordinate batch analysis using injected CLI dependencies."""

    def run_batch_analysis(
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
        threads: int,
        quiet: bool,
        deps: BatchDependencies,
    ) -> None:
        now = deps.now or __import__("time").time
        batch_path = Path(batch_dir)

        files_to_process = deps.find_files_to_process(
            batch_path, auto_detect, extensions, recursive, verbose, quiet
        )
        if not files_to_process:
            deps.display_no_files_message(auto_detect, extensions)
            return
        if deps.display_found_files:
            deps.display_found_files(len(files_to_process), threads)

        if deps.configure_batch_logging and not verbose:
            deps.configure_batch_logging()

        if quiet and deps.configure_quiet_logging:
            deps.configure_quiet_logging()

        output_path = deps.setup_output_directory(output_dir, output_json, output_csv)

        all_results: dict[str, dict[str, Any]] = {}
        failed_files: list[tuple[str, str]] = []

        start_time = now()
        rate_limiter = deps.setup_rate_limiter(threads, verbose)
        deps.process_files_parallel(
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
        elapsed_time = now() - start_time

        output_filename = deps.create_batch_summary(
            all_results, failed_files, output_path, output_json, output_csv
        )

        deps.display_batch_results(
            all_results,
            failed_files,
            elapsed_time,
            files_to_process,
            rate_limiter,
            verbose,
            output_filename,
        )


default_batch_service = BatchAnalysisService()
