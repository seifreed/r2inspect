#!/usr/bin/env python3
"""Support helpers shared by the CLI analysis runner facade."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any


def setup_single_file_output(
    output_json: bool,
    output_csv: bool,
    output: str | Path | None,
    filename: str,
) -> str | Path | None:
    """Derive the default output path for single-file analysis modes."""
    if (output_json or output_csv) and not output:
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)
        base_name = Path(filename).stem

        if output_json:
            return output_dir / f"{base_name}_analysis.json"
        if output_csv:
            return output_dir / f"{base_name}_analysis.csv"

    return output


def handle_main_error(console: Any, error: Exception, verbose: bool) -> None:
    """Render a CLI error, optionally emit a traceback, and exit."""
    console.print(f"[red]Error: {error}[/red]")
    if verbose:
        import traceback

        traceback.print_exc()
    sys.exit(1)
