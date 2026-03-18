#!/usr/bin/env python3
"""Runtime helpers for CLI validation flow."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, cast


def validate_input_mode(
    console: Any,
    filename: str | None,
    batch: str | None,
    *,
    validate_single_file_fn: Any,
) -> None:
    if not filename and not batch:
        console.print("[red]Error: Must provide either a filename or --batch directory[/red]")
        sys.exit(1)

    if filename and batch:
        console.print("[red]Error: Cannot use both filename and --batch mode simultaneously[/red]")
        sys.exit(1)

    if filename:
        validate_single_file_fn(filename)


def validate_single_file(console: Any, filename: str) -> None:
    file_path = Path(filename)
    if not file_path.exists():
        console.print(f"[red]Error: File does not exist: {filename}[/red]")
        console.print(
            "[yellow]Please provide the full path to the file you want to analyze[/yellow]"
        )
        sys.exit(1)
    if not file_path.is_file():
        console.print(f"[red]Error: Path is not a file: {filename}[/red]")
        sys.exit(1)


def sanitize_xor_string(xor_input: str | None) -> str | None:
    if not xor_input:
        return None

    safe_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-.")
    sanitized = "".join(c for c in xor_input if c in safe_chars)
    if len(sanitized) > 100:
        sanitized = sanitized[:100]
    return sanitized if sanitized else None


def handle_xor_input(console: Any, xor: str | None, *, sanitize_xor_string_fn: Any) -> str | None:
    sanitized_xor = sanitize_xor_string_fn(xor)
    if xor and not sanitized_xor:
        console.print(
            "[yellow]Warning: XOR string contains invalid characters and was filtered[/yellow]"
        )
    return cast(str | None, sanitized_xor)
