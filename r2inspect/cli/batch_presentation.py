#!/usr/bin/env python3
"""Presentation helpers for batch CLI execution."""

from __future__ import annotations

import sys
from typing import Any

from ..abstractions.coercion_support import coerce_number


def display_rate_limiter_stats(console: Any, rate_stats: dict[str, Any]) -> None:
    """Display rate limiter statistics."""
    console.print("[dim]Rate limiter stats:[/dim]")
    console.print(f"[dim]  Success rate: {coerce_number(rate_stats.get('success_rate')):.1%}[/dim]")
    console.print(
        f"[dim]  Avg wait time: {coerce_number(rate_stats.get('avg_wait_time')):.2f}s[/dim]"
    )
    console.print(
        f"[dim]  Final rate: {coerce_number(rate_stats.get('current_rate')):.1f} files/sec[/dim]"
    )


def display_memory_stats(console: Any) -> None:
    """Display memory statistics if available."""
    from ..infrastructure.memory import get_memory_stats

    memory_stats = get_memory_stats()
    if memory_stats.get("status") != "error":
        console.print("[dim]Memory stats:[/dim]")
        peak_memory_mb = coerce_number(memory_stats.get("peak_memory_mb", 0))
        process_memory_mb = coerce_number(memory_stats.get("process_memory_mb", 0))
        console.print(f"[dim]  Peak usage: {peak_memory_mb:.1f}MB[/dim]")
        console.print(f"[dim]  Current usage: {process_memory_mb:.1f}MB[/dim]")
        console.print(f"[dim]  GC cycles: {memory_stats.get('gc_count', 0)}[/dim]")


def display_failed_files(console: Any, failed_files: list[tuple[str, str]], verbose: bool) -> None:
    """Display failed files information."""
    console.print(f"[red]Failed: {len(failed_files)} files[/red]")
    if verbose:
        console.print("\n[red]Failed files details:[/red]")
        for item in failed_files[:10]:
            if not isinstance(item, tuple) or len(item) < 2:
                continue
            failed_file, error = item[0], item[1]
            error_text = str(error)
            console.print(
                f"[dim]{failed_file}: {error_text[:100]}{'...' if len(error_text) > 100 else ''}[/dim]"
            )
        if len(failed_files) > 10:
            console.print(f"[dim]... and {len(failed_files) - 10} more[/dim]")
    else:
        console.print("[dim]Use --verbose to see error details[/dim]")


def _no_files_message(auto_detect: bool, extensions: str | None) -> list[str]:
    if auto_detect:
        return [
            "[yellow]No executable files detected in the directory[/yellow]",
            "[dim]Tip: Files might not be executable format or may be corrupted[/dim]",
        ]
    return [
        f"[yellow]No files found with extensions: {extensions}[/yellow]",
        "[dim]Tip: Use without --extensions for auto-detection[/dim]",
    ]


def display_batch_results(
    console: Any,
    all_results: dict[str, dict[str, Any]],
    failed_files: list[tuple[str, str]],
    elapsed_time: float,
    files_to_process: list[Any],
    rate_limiter: Any,
    verbose: bool,
    output_filename: str | None,
) -> None:
    """Display final batch analysis results."""
    rate_stats = rate_limiter.get_stats()
    success_count = len(all_results)
    total_count = len(files_to_process)
    elapsed_time = coerce_number(elapsed_time)

    console.print("\n[bold green]Analysis Complete![/bold green]")
    console.print(f"[green]Processed: {success_count}/{total_count} files[/green]")
    console.print(f"[blue]Time: {elapsed_time:.1f}s[/blue]")
    rate = success_count / elapsed_time if elapsed_time > 0 else 0.0
    console.print(f"[cyan]Rate: {rate:.1f} files/sec[/cyan]")

    if verbose and rate_stats:
        display_rate_limiter_stats(console, rate_stats)
        display_memory_stats(console)

    if output_filename:
        console.print(f"[cyan]Output: {output_filename}[/cyan]")

    if failed_files:
        display_failed_files(console, failed_files, verbose)


def display_no_files_message(console: Any, auto_detect: bool, extensions: str | None) -> None:
    """Display appropriate message when no files are found."""
    for line in _no_files_message(auto_detect, extensions):
        console.print(line)


def handle_main_error(console: Any, error: Exception, verbose: bool) -> None:
    """Handle errors in main function."""
    console.print(f"[red]Error: {str(error)}[/red]")
    if verbose:
        import traceback

        traceback.print_exc()
    sys.exit(1)
