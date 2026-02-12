#!/usr/bin/env python3
"""
r2inspect CLI Batch Discovery Module

Provides executable discovery helpers for CLI batch processing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.console import Console

from ..application.batch_discovery import _is_executable_signature as core_is_executable_signature
from ..application.batch_discovery import discover_executables_by_magic, init_magic_detectors
from ..application.batch_discovery import is_elf_executable as core_is_elf_executable
from ..application.batch_discovery import is_macho_executable as core_is_macho_executable
from ..application.batch_discovery import is_pe_executable as core_is_pe_executable
from ..application.batch_discovery import is_script_executable as core_is_script_executable

console = Console()
_magic: Any | None
try:
    import magic as _magic
except Exception:
    _magic = None
magic: Any | None = _magic


def _init_magic() -> tuple[Any, Any] | None:
    if magic is None:
        console.print("[yellow]python-magic not available; skipping magic-based detection[/yellow]")
        return None
    try:
        return init_magic_detectors(magic)
    except Exception as e:
        console.print(f"[red]Error initializing magic: {e}[/red]")
        console.print("[yellow]Falling back to file extension detection[/yellow]")
        return None


def _is_executable_signature(mime_type: str, description: str) -> bool:
    return core_is_executable_signature(mime_type, description)


def find_executable_files_by_magic(
    directory: str | Path, recursive: bool = False, verbose: bool = False
) -> list[Path]:
    """Find executable files using magic bytes detection (PE, ELF, Mach-O, etc.)"""
    files, init_errors, file_errors, scanned = discover_executables_by_magic(
        directory,
        recursive=recursive,
        magic_module=magic,
    )

    for message in init_errors:
        if message.startswith("Error initializing magic:"):
            console.print(f"[red]{message}[/red]")
            console.print("[yellow]Falling back to file extension detection[/yellow]")
        else:
            console.print(f"[yellow]{message}[/yellow]")
        return []

    if verbose:
        console.print(f"[blue]Scanning {scanned} files for executable signatures...[/blue]")

    for file_path, error in file_errors:
        if verbose:
            console.print(f"[yellow]Error checking {file_path}: {error}[/yellow]")

    if verbose:
        for file_path in files:
            console.print(f"[green]Found executable: {file_path}[/green]")

    return files


def is_pe_executable(header: bytes, file_handle: Any) -> bool:
    return core_is_pe_executable(header, file_handle)


def is_elf_executable(header: bytes) -> bool:
    return core_is_elf_executable(header)


def is_macho_executable(header: bytes) -> bool:
    return core_is_macho_executable(header)


def is_script_executable(header: bytes) -> bool:
    return core_is_script_executable(header)


__all__ = [
    "find_executable_files_by_magic",
    "is_pe_executable",
    "is_elf_executable",
    "is_macho_executable",
    "is_script_executable",
]
