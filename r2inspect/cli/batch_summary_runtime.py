#!/usr/bin/env python3
"""Batch summary output decision helpers."""

from __future__ import annotations

from typing import Any


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
