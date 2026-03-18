#!/usr/bin/env python3
"""Support helpers for the CLI batch processing facade.

The public ``batch_processing`` module intentionally keeps a stable historical
surface for tests and callers. This module keeps the leaf operations cohesive so
the facade only coordinates console-bound behavior.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from . import batch_discovery_runtime as _batch_discovery_runtime
from .batch_lifecycle import setup_rate_limiter as _setup_rate_limiter
from .batch_reporting import (
    display_batch_results as _display_batch_results,
    display_failed_files as _display_failed_files,
    display_memory_stats as _display_memory_stats,
    display_no_files_message as _display_no_files_message,
    display_rate_limiter_stats as _display_rate_limiter_stats,
    handle_main_error as _handle_main_error,
)


def looks_like_batch_result(value: Any) -> bool:
    """Check whether an object behaves like the batch result contract."""
    return (
        isinstance(getattr(value, "all_results", None), dict)
        and isinstance(getattr(value, "failed_files", None), list)
        and isinstance(getattr(value, "files_to_process", None), list)
        and isinstance(getattr(value, "elapsed_time", None), int | float)
        and hasattr(value, "output_path")
    )


def setup_rate_limiter(
    console: Any,
    threads: int,
    verbose: bool,
    *,
    cap_threads_fn: Any | None = None,
) -> Any:
    """Create the CLI batch rate limiter."""
    kwargs = {}
    if cap_threads_fn is not None:
        kwargs["cap_threads_fn"] = cap_threads_fn
    return _setup_rate_limiter(threads, verbose, console, **kwargs)


def display_batch_results(
    console: Any,
    *,
    all_results: dict[str, dict[str, Any]],
    failed_files: list[tuple[str, str]],
    elapsed_time: float,
    files_to_process: list[Path],
    rate_limiter: Any,
    verbose: bool,
    output_filename: str | None,
) -> None:
    """Render the final batch result summary to the console."""
    _display_batch_results(
        console,
        all_results=all_results,
        failed_files=failed_files,
        elapsed_time=elapsed_time,
        files_to_process=files_to_process,
        rate_limiter=rate_limiter,
        verbose=verbose,
        output_filename=output_filename,
    )


def display_rate_limiter_stats(console: Any, rate_stats: dict[str, Any]) -> None:
    """Display batch rate-limiter statistics."""
    _display_rate_limiter_stats(console, rate_stats)


def display_memory_stats(console: Any) -> None:
    """Display memory statistics for the current batch run."""
    _display_memory_stats(console)


def display_failed_files(console: Any, failed_files: list[tuple[str, str]], verbose: bool) -> None:
    """Display failed batch items with optional verbose detail."""
    _display_failed_files(console, failed_files, verbose)


def handle_main_error(console: Any, error: Exception, verbose: bool) -> None:
    """Render the top-level batch error to the console."""
    _handle_main_error(console, error, verbose)


def display_no_files_message(console: Any, auto_detect: bool, extensions: str | None) -> None:
    """Display the standard message used when discovery finds no files."""
    _display_no_files_message(console, auto_detect, extensions)


def find_files_to_process(
    *,
    batch_path: Path,
    auto_detect: bool,
    extensions: str | None,
    recursive: bool,
    verbose: bool,
    quiet: bool,
    console: Any,
    find_executable_files_by_magic_fn: Any,
) -> list[Path]:
    """Resolve batch input files using the configured discovery strategy."""
    return _batch_discovery_runtime.find_files_to_process(
        batch_path,
        auto_detect,
        extensions,
        recursive,
        verbose,
        quiet=quiet,
        console=console,
        find_executable_files_by_magic_fn=find_executable_files_by_magic_fn,
    )


def find_files_by_extensions(batch_path: Path, extensions: str, recursive: bool) -> list[Path]:
    """Resolve batch input files from explicit extension filters."""
    return _batch_discovery_runtime.find_files_by_extensions(batch_path, extensions, recursive)


def build_find_files_wrapper(find_files_to_process_fn: Any) -> Any:
    """Build the adapter expected by ``BatchDependencies`` and batch runtime."""

    def _find_files_wrapper(
        batch_path: Path,
        use_auto_detect: bool,
        extension_filter: str | None,
        use_recursive: bool,
        verbose_output: bool,
        quiet_output: bool = False,
    ) -> list[Path]:
        return cast(
            list[Path],
            find_files_to_process_fn(
                batch_path,
                use_auto_detect,
                extension_filter,
                use_recursive,
                verbose_output,
                quiet_output,
            ),
        )

    return _find_files_wrapper


__all__ = [
    "build_find_files_wrapper",
    "display_batch_results",
    "display_failed_files",
    "display_memory_stats",
    "display_no_files_message",
    "display_rate_limiter_stats",
    "find_files_by_extensions",
    "find_files_to_process",
    "handle_main_error",
    "looks_like_batch_result",
    "setup_rate_limiter",
]
