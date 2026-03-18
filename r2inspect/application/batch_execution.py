#!/usr/bin/env python3
"""Pure application helpers for batch execution orchestration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..domain.analysis_runtime import BatchRunResult
from .batch_models import BatchDependencies, BatchExecutionPlan


def resolve_output_path(
    deps: BatchDependencies,
    output_dir: str | None,
    output_json: bool,
    output_csv: bool,
    output_path: Path | None,
) -> Path:
    if output_path is not None:
        return output_path
    if deps.setup_output_directory is not None:
        return deps.setup_output_directory(output_dir, output_json, output_csv)
    return Path(
        output_dir or ("output" if output_json or output_csv else "r2inspect_batch_results")
    )


def build_execution_plan(
    *,
    batch_dir: str,
    deps: BatchDependencies,
    output_dir: str | None,
    output_json: bool,
    output_csv: bool,
    output_path: Path | None,
    auto_detect: bool,
    extensions: str | None,
    recursive: bool,
    verbose: bool,
    quiet: bool,
) -> BatchExecutionPlan:
    batch_path = Path(batch_dir)
    files_to_process = deps.find_files_to_process(
        batch_path, auto_detect, extensions, recursive, verbose, quiet
    )
    return BatchExecutionPlan(
        batch_path=batch_path,
        output_path=resolve_output_path(deps, output_dir, output_json, output_csv, output_path),
        files_to_process=files_to_process,
    )


def configure_batch_runtime(
    deps: BatchDependencies,
    *,
    files_to_process: list[Path],
    threads: int,
    verbose: bool,
    quiet: bool,
) -> None:
    if deps.display_found_files is not None:
        deps.display_found_files(len(files_to_process), threads)
    if deps.configure_batch_logging is not None and not verbose:
        deps.configure_batch_logging()
    if quiet and deps.configure_quiet_logging is not None:
        deps.configure_quiet_logging()


def execute_batch_plan(
    *,
    plan: BatchExecutionPlan,
    deps: BatchDependencies,
    options: dict[str, Any],
    output_json: bool,
    config_obj: Any,
    threads: int,
    verbose: bool,
) -> tuple[BatchRunResult, Any]:
    """Execute the batch plan and return (result, rate_limiter) separately.

    The rate_limiter is an infrastructure concern and does not belong in the
    domain result object.
    """
    now = deps.now or __import__("time").time
    all_results: dict[str, dict[str, Any]] = {}
    failed_files: list[tuple[str, str]] = []
    start_time = now()
    rate_limiter = deps.setup_rate_limiter(threads, verbose)
    deps.process_files_parallel(
        plan.files_to_process,
        all_results,
        failed_files,
        plan.output_path,
        plan.batch_path,
        config_obj,
        options,
        output_json,
        threads,
        rate_limiter,
    )
    result = BatchRunResult(
        files_to_process=plan.files_to_process,
        all_results=all_results,
        failed_files=failed_files,
        elapsed_time=now() - start_time,
        output_path=plan.output_path,
    )
    return result, rate_limiter


def finalize_batch_result(
    deps: BatchDependencies,
    *,
    batch_result: BatchRunResult,
    rate_limiter: Any,
    output_json: bool,
    output_csv: bool,
    verbose: bool,
) -> None:
    if deps.create_batch_summary is None or deps.display_batch_results is None:
        return
    output_filename = deps.create_batch_summary(
        batch_result.all_results,
        batch_result.failed_files,
        batch_result.output_path,
        output_json,
        output_csv,
    )
    deps.display_batch_results(
        batch_result.all_results,
        batch_result.failed_files,
        batch_result.elapsed_time,
        batch_result.files_to_process,
        rate_limiter,
        verbose,
        output_filename,
    )
