#!/usr/bin/env python3
"""Support helpers for the CLI batch output facade.

This module owns the small leaf operations used by ``batch_output`` so the
facade can preserve its historical API without carrying all implementation
details directly.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..application.batch_stats import collect_batch_statistics
from . import batch_output_runtime as _runtime
from . import batch_output_summary as _summary
from . import batch_summary_views as _views
from .batch_output_csv import (
    FIELDNAMES as _BATCH_CSV_FIELDNAMES,
    write_csv_results as _write_csv_results_logic,
)
from .batch_output_json import (
    build_batch_summary_payload as _build_batch_summary_payload_impl,
    create_json_batch_summary as _create_json_batch_summary_impl,
    determine_csv_file_path as _determine_csv_file_path_impl,
    write_individual_json_results as _write_individual_json_results_impl,
)
from .output_formatters import OutputFormatter


def write_individual_json_results(
    all_results: dict[str, dict[str, Any]], output_path: Path
) -> None:
    """Write one JSON file per analyzed input."""
    _write_individual_json_results_impl(all_results, output_path)


def build_batch_summary_payload(
    all_results: dict[str, dict[str, Any]],
    failed_files: list[tuple[str, str]],
) -> dict[str, Any]:
    """Build the JSON summary payload shared by CLI batch outputs."""
    return _build_batch_summary_payload_impl(
        all_results,
        failed_files,
        collect_batch_statistics=collect_batch_statistics,
    )


def get_csv_fieldnames() -> list[str]:
    """Return a copy of the CSV fieldnames used by batch exports."""
    return list(_BATCH_CSV_FIELDNAMES)


def write_csv_results(csv_file: Path, all_results: dict[str, dict[str, Any]]) -> None:
    """Write batch results to CSV using the canonical formatter."""
    _write_csv_results_logic(
        csv_file,
        all_results,
        output_formatter_cls=OutputFormatter,
        fieldnames=get_csv_fieldnames(),
    )


def determine_csv_file_path(output_path: Path, timestamp: str) -> tuple[Path, str]:
    """Resolve the final CSV file path and output name."""
    return _determine_csv_file_path_impl(output_path, timestamp)


def create_json_batch_summary(
    all_results: dict[str, dict[str, Any]],
    failed_files: list[tuple[str, str]],
    output_path: Path,
    timestamp: str,
) -> str:
    """Create the JSON summary artifact and return its filename."""
    return _create_json_batch_summary_impl(
        all_results,
        failed_files,
        output_path,
        timestamp,
        collect_batch_statistics=collect_batch_statistics,
    )


def default_output_path(output_json: bool, output_csv: bool) -> Path:
    """Return the default output directory for batch artifacts."""
    return _runtime.default_output_path(output_json, output_csv)


def render_summary_row(
    file_key: str, result: dict[str, Any], *, include_md5: bool
) -> tuple[str, ...]:
    """Render a single summary row for the batch summary table."""
    return _summary.render_summary_row(file_key, result, include_md5=include_md5)


def display_no_files_message(console: Any, auto_detect: bool, extensions: str | None) -> None:
    """Display the standard 'no files found' message."""
    _runtime.display_no_files_message(console, auto_detect, extensions)


def setup_batch_output_directory(
    output_dir: str | None,
    output_json: bool,
    output_csv: bool,
    *,
    default_output_path_fn: Any,
) -> Path:
    """Prepare the output directory or file path for batch output."""
    return _runtime.setup_batch_output_directory(
        output_dir,
        output_json,
        output_csv,
        default_output_path_fn=default_output_path_fn,
    )


def configure_batch_logging(verbose: bool, quiet: bool, *, configure_batch_logging_fn: Any) -> None:
    """Apply batch logging configuration through the injected runtime hook."""
    _runtime.configure_batch_logging(
        verbose,
        quiet,
        configure_batch_logging_fn=configure_batch_logging_fn,
    )


def prepare_batch_run(**kwargs: Any) -> tuple[list[Path], Path] | None:
    """Resolve files, logging and output path before running batch mode."""
    return _runtime.prepare_batch_run(**kwargs)


def init_batch_results() -> tuple[dict[str, dict[str, Any]], list[tuple[str, str]]]:
    """Create empty batch result containers."""
    return _runtime.init_batch_results()


def show_summary_table(all_results: dict[str, dict[str, Any]], *, console: Any) -> None:
    """Render the summary table for batch results."""
    _views.show_summary_table(all_results, console=console)


simplify_file_type = _views.simplify_file_type
extract_compile_time = _views.extract_compile_time
compiler_name = _views.compiler_name
collect_yara_matches = _views.collect_yara_matches
build_small_row = _views.build_small_row
build_large_row = _views.build_large_row
build_summary_table_small = _views.build_summary_table_small
build_summary_table_large = _views.build_summary_table_large

__all__ = [
    "build_batch_summary_payload",
    "build_large_row",
    "build_small_row",
    "build_summary_table_large",
    "build_summary_table_small",
    "collect_yara_matches",
    "compiler_name",
    "configure_batch_logging",
    "create_json_batch_summary",
    "default_output_path",
    "determine_csv_file_path",
    "display_no_files_message",
    "extract_compile_time",
    "get_csv_fieldnames",
    "init_batch_results",
    "prepare_batch_run",
    "render_summary_row",
    "setup_batch_output_directory",
    "show_summary_table",
    "simplify_file_type",
    "write_csv_results",
    "write_individual_json_results",
]
