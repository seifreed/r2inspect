#!/usr/bin/env python3
"""Summary and presentation helpers for batch output facades."""

from __future__ import annotations

from typing import Any

from .batch_summary_runtime import create_batch_summary_output
from .batch_summary_tables import (
    build_large_row,
    build_small_row,
    build_summary_table_large,
    build_summary_table_small,
    collect_yara_matches,
    compiler_name,
    extract_compile_time,
    render_summary_row,
    show_summary_table as _show_summary_table_default,
    simplify_file_type,
)


def create_batch_summary(
    *,
    all_results: dict[str, dict[str, Any]],
    failed_files: list[tuple[str, str]],
    output_path: Any,
    output_json: bool,
    output_csv: bool,
    determine_csv_file_path: Any,
    write_csv_results: Any,
    create_json_batch_summary: Any,
    show_summary_table: Any,
    timestamp: str,
) -> str | None:
    output_filename = create_batch_summary_output(
        all_results=all_results,
        failed_files=failed_files,
        output_path=output_path,
        output_json=output_json,
        output_csv=output_csv,
        determine_csv_file_path=determine_csv_file_path,
        write_csv_results=write_csv_results,
        create_json_batch_summary=create_json_batch_summary,
        timestamp=timestamp,
    )
    show_summary_table(all_results)
    return output_filename
