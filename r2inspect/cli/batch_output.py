#!/usr/bin/env python3
"""CLI batch output facade.

Leaf output behavior lives in support/runtime modules; this facade keeps the
patchable API that the CLI entry points and tests consume.
"""

from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from ..application.batch_stats import (
    collect_batch_statistics,
    update_compiler_stats,
    update_crypto_stats,
    update_file_type_stats,
    update_indicator_stats,
    update_packer_stats,
)
from ..cli import batch_output_support as _support
from ..cli import batch_output_summary as _summary
from ..cli import batch_output_runtime as _runtime
from ..cli import batch_processing_support as _processing_support

console = Console()

# Patchable facade exports used directly by tests.
_write_individual_json_results = _support.write_individual_json_results
_build_batch_summary_payload = _support.build_batch_summary_payload
_default_output_path = _support.default_output_path
_render_summary_row = _support.render_summary_row
get_csv_fieldnames = _support.get_csv_fieldnames
write_csv_results = _support.write_csv_results
determine_csv_file_path = _support.determine_csv_file_path
create_json_batch_summary = _support.create_json_batch_summary


def find_files_to_process(
    batch_path: Path,
    auto_detect: bool,
    extensions: str | None,
    recursive: bool,
    verbose: bool,
    quiet: bool = False,
) -> list[Path]:
    """Resolve batch input files using auto-detection or explicit extensions."""
    from .batch_processing import find_executable_files_by_magic

    return _processing_support.find_files_to_process(
        batch_path=batch_path,
        auto_detect=auto_detect,
        extensions=extensions,
        recursive=recursive,
        verbose=verbose,
        quiet=quiet,
        console=console,
        find_executable_files_by_magic_fn=find_executable_files_by_magic,
    )


def find_files_by_extensions(batch_path: Path, extensions: str, recursive: bool) -> list[Path]:
    """Keep extension-based discovery patchable from this facade."""
    return _processing_support.find_files_by_extensions(batch_path, extensions, recursive)


def display_no_files_message(auto_detect: bool, extensions: str | None) -> None:
    _support.display_no_files_message(console, auto_detect, extensions)


def setup_batch_output_directory(
    output_dir: str | None, output_json: bool, output_csv: bool
) -> Path:
    return _support.setup_batch_output_directory(
        output_dir,
        output_json,
        output_csv,
        default_output_path_fn=_default_output_path,
    )


def _configure_batch_logging(verbose: bool, quiet: bool) -> None:
    from ..infrastructure.logging import configure_batch_logging

    _support.configure_batch_logging(
        verbose,
        quiet,
        configure_batch_logging_fn=configure_batch_logging,
    )


def _prepare_batch_run(
    batch_path: Path,
    auto_detect: bool,
    extensions: str | None,
    recursive: bool,
    verbose: bool,
    quiet: bool,
    output_dir: str | None,
    output_json: bool,
    output_csv: bool,
    threads: int,
) -> tuple[list[Path], Path] | None:
    return _support.prepare_batch_run(
        batch_path=batch_path,
        auto_detect=auto_detect,
        extensions=extensions,
        recursive=recursive,
        verbose=verbose,
        quiet=quiet,
        output_dir=output_dir,
        output_json=output_json,
        output_csv=output_csv,
        threads=threads,
        console=console,
        find_files_to_process=find_files_to_process,
        display_no_files_message_fn=display_no_files_message,
        configure_batch_logging_fn=_configure_batch_logging,
        setup_batch_output_directory_fn=setup_batch_output_directory,
    )


def _init_batch_results() -> tuple[dict[str, dict[str, Any]], list[tuple[str, str]]]:
    return _support.init_batch_results()


def run_batch_analysis(
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
    from .batch_processing import run_batch_analysis as _run_batch_analysis

    _runtime.run_batch_analysis(
        delegate=_run_batch_analysis,
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


def create_batch_summary(
    all_results: dict[str, dict[str, Any]],
    failed_files: list[tuple[str, str]],
    output_path: Path,
    output_json: bool,
    output_csv: bool,
) -> str | None:
    """Create the final batch summary artifact."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return _summary.create_batch_summary(
        all_results=all_results,
        failed_files=failed_files,
        output_path=output_path,
        output_json=output_json,
        output_csv=output_csv,
        determine_csv_file_path=determine_csv_file_path,
        write_csv_results=write_csv_results,
        create_json_batch_summary=create_json_batch_summary,
        show_summary_table=_show_summary_table,
        timestamp=timestamp,
    )


def _show_summary_table(all_results: dict[str, dict[str, Any]]) -> None:
    _support.show_summary_table(all_results, console=console)


# Patchable facade exports still used by direct module tests.
_simplify_file_type = _support.simplify_file_type
_extract_compile_time = _support.extract_compile_time
_compiler_name = _support.compiler_name
_collect_yara_matches = _support.collect_yara_matches
_build_small_row = _support.build_small_row
_build_large_row = _support.build_large_row
_build_summary_table_small = _support.build_summary_table_small
_build_summary_table_large = _support.build_summary_table_large

__all__ = [
    "_build_batch_summary_payload",
    "_build_large_row",
    "_build_small_row",
    "_build_summary_table_large",
    "_build_summary_table_small",
    "_collect_yara_matches",
    "_compiler_name",
    "_default_output_path",
    "_extract_compile_time",
    "_render_summary_row",
    "_show_summary_table",
    "_simplify_file_type",
    "_write_individual_json_results",
    "collect_batch_statistics",
    "console",
    "create_batch_summary",
    "create_json_batch_summary",
    "determine_csv_file_path",
    "display_no_files_message",
    "find_files_by_extensions",
    "find_files_to_process",
    "get_csv_fieldnames",
    "run_batch_analysis",
    "setup_batch_output_directory",
    "update_compiler_stats",
    "update_crypto_stats",
    "update_file_type_stats",
    "update_indicator_stats",
    "update_packer_stats",
    "write_csv_results",
]
