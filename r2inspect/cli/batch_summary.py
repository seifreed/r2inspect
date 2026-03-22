#!/usr/bin/env python3
"""Batch summary output decision helpers and presentation facades.

Combines the former ``batch_summary_runtime`` and ``batch_output_summary``
modules into a single cohesive unit.
"""

from __future__ import annotations

from typing import Any

# --- Formerly batch_summary_runtime.py ---


def create_batch_summary_output(
    *,
    all_results: dict[str, dict[str, Any]],
    failed_files: list[tuple[str, str]],
    output_path: Any,
    output_json: bool,
    output_csv: bool,
    determine_csv_file_path: Any,
    write_csv_results: Any,
    create_json_batch_summary: Any,
    timestamp: str,
) -> str | None:
    output_filename = None

    if output_csv and not output_json:
        csv_file, output_filename = determine_csv_file_path(output_path, timestamp)
        write_csv_results(csv_file, all_results)
    elif output_json and output_csv:
        csv_file, csv_filename = determine_csv_file_path(output_path, timestamp)
        output_filename = (
            f"{output_path.name} + individual JSONs"
            if output_path.suffix == ".csv"
            else f"{csv_filename} + individual JSONs"
        )
        write_csv_results(csv_file, all_results)
    elif output_json and not output_csv:
        output_filename = create_json_batch_summary(
            all_results, failed_files, output_path, timestamp
        )

    return output_filename


# --- Formerly batch_output_summary.py ---


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
