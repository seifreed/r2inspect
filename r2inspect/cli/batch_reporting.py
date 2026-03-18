#!/usr/bin/env python3
"""Batch presentation helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.console import Console

from . import batch_presentation as _batch_presentation


def display_rate_limiter_stats(console: Console, rate_stats: dict[str, Any]) -> None:
    """Display rate limiter statistics."""
    _batch_presentation.display_rate_limiter_stats(console, rate_stats)


def display_memory_stats(console: Console) -> None:
    """Display memory statistics if available."""
    _batch_presentation.display_memory_stats(console)


def display_failed_files(
    console: Console,
    failed_files: list[tuple[str, str]],
    verbose: bool,
) -> None:
    """Display failed files information."""
    _batch_presentation.display_failed_files(console, failed_files, verbose)


def display_no_files_message(
    console: Console,
    auto_detect: bool,
    extensions: str | None,
) -> None:
    """Display appropriate message when no files are found."""
    _batch_presentation.display_no_files_message(console, auto_detect, extensions)


def handle_main_error(console: Console, error: Exception, verbose: bool) -> None:
    """Handle errors in main function."""
    _batch_presentation.handle_main_error(console, error, verbose)


def display_batch_results(
    console: Console,
    *,
    all_results: dict[str, dict[str, Any]],
    failed_files: list[tuple[str, str]],
    elapsed_time: float,
    files_to_process: list[Path],
    rate_limiter: Any,
    verbose: bool,
    output_filename: str | None,
) -> None:
    """Display final batch analysis results."""
    rate_stats = rate_limiter.get_stats()
    success_count = len(all_results)
    total_count = len(files_to_process)

    console.print("\n[bold green]Analysis Complete![/bold green]")
    console.print(f"[green]Processed: {success_count}/{total_count} files[/green]")
    console.print(f"[blue]Time: {elapsed_time:.1f}s[/blue]")
    console.print(f"[cyan]Rate: {success_count / elapsed_time:.1f} files/sec[/cyan]")

    if verbose and rate_stats:
        display_rate_limiter_stats(console, rate_stats)
        display_memory_stats(console)

    if output_filename:
        console.print(f"[cyan]Output: {output_filename}[/cyan]")

    if failed_files:
        display_failed_files(console, failed_files, verbose)
