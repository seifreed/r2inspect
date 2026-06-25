#!/usr/bin/env python3
"""Discovery helpers for CLI batch facades."""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from ..application.batch_discovery import check_executable_signature
from ..application.batch_discovery import find_files_by_extensions as core_find_files_by_extensions
from ..infrastructure.logging import get_logger

logger = get_logger(__name__)

_MAGIC_UNINITIALIZED = object()
magic: Any = _MAGIC_UNINITIALIZED


def _import_magic() -> Any:
    import magic as magic_module

    return magic_module


def resolve_magic_module(
    *,
    platform: str | None = None,
    importer: Callable[[], Any] | None = None,
) -> Any | None:
    """Resolve python-magic lazily to avoid import-time native crashes on Windows.

    ``platform`` and ``importer`` default to the live ``sys.platform`` and a
    real ``import magic``; tests inject deterministic values instead of
    patching ``sys`` or ``builtins.__import__``.
    """
    global magic
    if magic is not _MAGIC_UNINITIALIZED:
        return magic
    current_platform = platform if platform is not None else sys.platform
    if current_platform == "win32":
        magic = None
        return magic
    try:
        magic = (importer if importer is not None else _import_magic)()
    except Exception as exc:
        logger.error("Error importing python-magic: %s", exc)
        magic = None
    return magic


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


def validate_magic_module(candidate: Any) -> Any | None:
    """Return the module only if its ``Magic`` constructor actually works."""
    if candidate is None:
        return None
    try:
        candidate.Magic(mime=True)
        candidate.Magic()
    except Exception as exc:
        logger.error("Error validating python-magic module: %s", exc)
        return None
    return candidate


__all__ = [
    "check_executable_signature",
    "validate_magic_module",
]
