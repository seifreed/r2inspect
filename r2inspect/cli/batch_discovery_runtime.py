#!/usr/bin/env python3
"""Discovery helpers for CLI batch facades."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, cast

from ..application.batch_discovery import check_executable_signature
from ..application.batch_discovery import discover_executables_by_magic
from ..application.batch_discovery import find_files_by_extensions as core_find_files_by_extensions

_MAGIC_UNINITIALIZED = object()
magic: Any = _MAGIC_UNINITIALIZED


def resolve_magic_module() -> Any | None:
    """Resolve python-magic lazily to avoid import-time native crashes on Windows."""
    global magic
    if magic is not _MAGIC_UNINITIALIZED:
        return magic
    if sys.platform == "win32":
        magic = None
        return magic
    try:
        import magic as magic_module

        magic = magic_module
    except Exception:
        magic = None
    return magic


def find_executable_files_by_magic(
    directory: str | Path,
    *,
    recursive: bool,
    verbose: bool,
    console: Any,
) -> list[Path]:
    """Find executable files using magic bytes detection."""
    magic_module = resolve_magic_module()
    if magic_module is None:
        console.print("[yellow]python-magic not available; skipping magic-based detection[/yellow]")
        return []

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

    if init_errors:
        return []

    if verbose:
        console.print(f"[blue]Scanning {scanned} files for executable signatures...[/blue]")
        for file_path, error in file_errors:
            console.print(f"[yellow]Error checking {file_path}: {error}[/yellow]")
        for file_path in files:
            console.print(f"[green]Found executable: {file_path}[/green]")

    return files


def find_files_by_extensions(batch_path: Path, extensions: str, recursive: bool) -> list[Path]:
    return core_find_files_by_extensions(batch_path, extensions, recursive)


def find_files_to_process(
    batch_path: Path,
    auto_detect: bool,
    extensions: str | None,
    recursive: bool,
    verbose: bool,
    *,
    quiet: bool,
    console: Any,
    find_executable_files_by_magic_fn: Any,
) -> list[Path]:
    if auto_detect:
        if not quiet:
            console.print("[blue]Auto-detecting executable files (default behavior)...[/blue]")
        return cast(
            list[Path],
            find_executable_files_by_magic_fn(batch_path, recursive=recursive, verbose=verbose),
        )
    if not quiet:
        console.print(f"[blue]Searching for files with extensions: {extensions}[/blue]")
    if not extensions:
        return []
    return find_files_by_extensions(batch_path, extensions, recursive)
