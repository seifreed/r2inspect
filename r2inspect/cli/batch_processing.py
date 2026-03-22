#!/usr/bin/env python3
"""CLI batch processing facade.

This module keeps a patchable batch-processing facade while delegating leaf
operations to support and runtime modules with narrower responsibilities.
"""

import sys
from pathlib import Path
from typing import Any

from rich.console import Console

from ..application.batch_discovery import _is_executable_signature
from ..application.batch_discovery import check_executable_signature
from ..application.batch_discovery import discover_executables_by_magic
from ..application.batch_discovery import is_elf_executable
from ..application.batch_discovery import is_macho_executable
from ..application.batch_discovery import is_pe_executable
from ..application.batch_discovery import is_script_executable
from ..application.batch_service import default_batch_service
from ..application.batch_stats import (
    collect_batch_statistics,
    update_compiler_stats,
    update_crypto_stats,
    update_file_type_stats,
    update_indicator_stats,
    update_packer_stats,
)
from ..infrastructure.logging import get_logger
from ..infrastructure.logging import configure_batch_logging
from .batch_paths import (
    setup_analysis_options,
    setup_batch_mode,
    setup_batch_output_directory,
    setup_single_file_output,
)
from .batch_lifecycle import (
    ensure_shutdown as ensure_batch_shutdown,
    flush_coverage_data as _flush_coverage_data,
    pytest_running as _pytest_running,
    safe_exit as _safe_exit,
    schedule_exit as schedule_forced_exit,
)
from .batch_output import (
    create_json_batch_summary,
    determine_csv_file_path,
    get_csv_fieldnames,
    write_csv_results,
)
from . import batch_discovery_runtime as _batch_discovery_runtime
from . import batch_processing_support as _support
from .batch_processing_runtime import run_batch_analysis as _run_batch_analysis_impl
from .batch_service_runtime import (
    build_batch_dependencies as _build_batch_dependencies,
    build_batch_service_facade as _build_batch_service_facade,
)
from .batch_workers import _cap_threads_for_execution, process_files_parallel, process_single_file

console = Console()
logger = get_logger(__name__)
_MAGIC_UNINITIALIZED = _batch_discovery_runtime._MAGIC_UNINITIALIZED
magic = _batch_discovery_runtime.magic

# Patchable facade export used by tests and runtime glue.
_looks_like_batch_result = _support.looks_like_batch_result
_resolve_magic_module = _batch_discovery_runtime.resolve_magic_module


def _init_magic() -> Any | None:
    """Initialize python-magic through the shared discovery runtime."""
    global magic
    _batch_discovery_runtime.magic = magic
    magic = _batch_discovery_runtime.resolve_magic_module()
    return magic


def setup_rate_limiter(threads: int, verbose: bool) -> Any:
    return _support.setup_rate_limiter(
        console,
        threads,
        verbose,
        cap_threads_fn=_cap_threads_for_execution,
    )


def display_batch_results(
    all_results: dict[str, dict[str, Any]],
    failed_files: list[tuple[str, str]],
    elapsed_time: float,
    files_to_process: list[Path],
    rate_limiter: Any,
    verbose: bool,
    output_filename: str | None,
) -> None:
    _support.display_batch_results(
        console,
        all_results=all_results,
        failed_files=failed_files,
        elapsed_time=elapsed_time,
        files_to_process=files_to_process,
        rate_limiter=rate_limiter,
        verbose=verbose,
        output_filename=output_filename,
    )


def display_rate_limiter_stats(rate_stats: dict[str, Any]) -> None:
    _support.display_rate_limiter_stats(console, rate_stats)


def display_memory_stats() -> None:
    _support.display_memory_stats(console)


def display_failed_files(failed_files: list[tuple[str, str]], verbose: bool) -> None:
    _support.display_failed_files(console, failed_files, verbose)


def handle_main_error(error: Exception, verbose: bool) -> None:
    _support.handle_main_error(console, error, verbose)


def display_no_files_message(auto_detect: bool, extensions: str | None) -> None:
    _support.display_no_files_message(console, auto_detect, extensions)


def find_executable_files_by_magic(
    directory: str | Path, recursive: bool = False, verbose: bool = False
) -> list[Path]:
    global magic
    if magic is _MAGIC_UNINITIALIZED:
        _batch_discovery_runtime.magic = magic
        magic_module = _batch_discovery_runtime.resolve_magic_module()
        magic = _batch_discovery_runtime.magic
    else:
        magic_module = magic

    files, init_errors, file_errors, scanned = discover_executables_by_magic(
        directory,
        recursive=recursive,
        magic_module=magic_module,
    )

    for message in init_errors:
        if message == "python-magic not available; skipping magic-based detection":
            return []
        if message.startswith("Error initializing magic:"):
            console.print(f"[red]{message}[/red]")
            console.print("[yellow]Falling back to file extension detection[/yellow]")
            return []
        console.print(f"[yellow]{message}[/yellow]")
        return []

    if verbose:
        console.print(f"[blue]Scanning {scanned} files for executable signatures...[/blue]")
        for file_path, error in file_errors:
            console.print(f"[yellow]Error checking {file_path}: {error}[/yellow]")
        for file_path in files:
            console.print(f"[green]Found executable: {file_path}[/green]")

    return files


def find_files_to_process(
    batch_path: Path,
    auto_detect: bool,
    extensions: str | None,
    recursive: bool,
    verbose: bool,
    quiet: bool = False,
) -> list[Path]:
    return _support.find_files_to_process(
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
    return _support.find_files_by_extensions(batch_path, extensions, recursive)


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
    from .batch_output import create_batch_summary

    find_files_wrapper = _support.build_find_files_wrapper(find_files_to_process)

    deps = _build_batch_dependencies(
        find_files_to_process=find_files_wrapper,
        setup_rate_limiter=setup_rate_limiter,
        process_files_parallel=process_files_parallel,
    )
    _run_batch_analysis_impl(
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
        console=console,
        configure_batch_logging=configure_batch_logging,
        setup_batch_output_directory=setup_batch_output_directory,
        find_files_to_process=find_files_wrapper,
        setup_rate_limiter=setup_rate_limiter,
        batch_service=_build_batch_service_facade(default_batch_service, deps),
        create_batch_summary=create_batch_summary,
        display_no_files_message=display_no_files_message,
        display_batch_results=display_batch_results,
        looks_like_batch_result=_looks_like_batch_result,
    )
