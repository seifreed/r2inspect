"""Operational runtime helpers for CLI batch output."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, cast


def default_output_path(output_json: bool, output_csv: bool) -> Path:
    output_path = Path("output" if output_json or output_csv else "r2inspect_batch_results")
    output_path.mkdir(exist_ok=True)
    return output_path


def display_no_files_message(console: Any, auto_detect: bool, extensions: str | None) -> None:
    if auto_detect:
        console.print("[yellow]No executable files detected in the directory[/yellow]")
        console.print("[dim]Tip: Files might not be executable format or may be corrupted[/dim]")
        return
    console.print(f"[yellow]No files found with extensions: {extensions}[/yellow]")
    console.print("[dim]Tip: Use without --extensions for auto-detection[/dim]")


def setup_batch_output_directory(
    output_dir: str | None,
    output_json: bool,
    output_csv: bool,
    *,
    default_output_path_fn: Any,
) -> Path:
    if output_dir:
        output_path = Path(output_dir)
        if output_path.suffix in [".csv", ".json"]:
            output_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            output_path.mkdir(parents=True, exist_ok=True)
        return output_path
    return cast(Path, default_output_path_fn(output_json, output_csv))


def configure_batch_logging(verbose: bool, quiet: bool, *, configure_batch_logging_fn: Any) -> None:
    if not verbose:
        configure_batch_logging_fn()

    if quiet:
        logging.getLogger("r2inspect").setLevel(logging.CRITICAL)
        logging.getLogger("r2inspect.modules").setLevel(logging.CRITICAL)


def prepare_batch_run(
    *,
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
    console: Any,
    find_files_to_process: Any,
    display_no_files_message_fn: Any,
    configure_batch_logging_fn: Any,
    setup_batch_output_directory_fn: Any,
) -> tuple[list[Path], Path] | None:
    files_to_process = find_files_to_process(
        batch_path, auto_detect, extensions, recursive, verbose, quiet
    )
    if not files_to_process:
        display_no_files_message_fn(auto_detect, extensions)
        return None
    if not quiet:
        console.print(f"[bold green]Found {len(files_to_process)} files to process[/bold green]")
        console.print(f"[blue]Using {threads} parallel threads[/blue]")
    configure_batch_logging_fn(verbose, quiet)
    output_path = setup_batch_output_directory_fn(output_dir, output_json, output_csv)
    return files_to_process, output_path


def init_batch_results() -> tuple[dict[str, dict[str, Any]], list[tuple[str, str]]]:
    return {}, []


def run_batch_analysis(*, delegate: Any, **kwargs: Any) -> None:
    delegate(**kwargs)
