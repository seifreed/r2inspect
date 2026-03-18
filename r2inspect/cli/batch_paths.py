#!/usr/bin/env python3
"""Path and option helpers for batch CLI execution."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..application.options import build_analysis_options


def setup_batch_mode(
    batch: str,
    extensions: str | None,
    output_json: bool,
    output_csv: bool,
    output: str | None,
) -> tuple[bool, bool, str | None]:
    """Setup batch mode parameters."""
    recursive = True
    use_auto_detect = not extensions

    if (output_json or output_csv) and not output:
        output = "output"

    return recursive, use_auto_detect, output


def setup_single_file_output(
    output_json: bool, output_csv: bool, output: str | None, filename: str
) -> str | Path | None:
    """Setup output file for single file mode."""
    if (output_json or output_csv) and not output:
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)

        input_path = Path(filename)
        base_name = input_path.stem

        if output_json:
            output = str(output_dir / f"{base_name}_analysis.json")
        elif output_csv:
            output = str(output_dir / f"{base_name}_analysis.csv")

    return output


def setup_analysis_options(yara: str | None, sanitized_xor: str | None) -> dict[str, Any]:
    """Setup analysis options with all modules enabled by default."""
    return build_analysis_options(yara, sanitized_xor)


def setup_batch_output_directory(
    output_dir: str | None, output_json: bool, output_csv: bool
) -> Path:
    """Setup the output directory for batch processing."""
    if output_dir:
        output_path = Path(output_dir)
        if output_path.suffix in [".csv", ".json"]:
            parent_dir = output_path.parent
            if not parent_dir.exists():
                parent_dir.mkdir(parents=True, exist_ok=True)
        else:
            if not output_path.exists():
                output_path.mkdir(parents=True, exist_ok=True)
    elif output_json or output_csv:
        output_path = Path("output")
        output_path.mkdir(exist_ok=True)
    else:
        output_path = Path("r2inspect_batch_results")
        output_path.mkdir(exist_ok=True)

    return output_path
