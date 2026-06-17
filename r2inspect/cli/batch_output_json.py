#!/usr/bin/env python3
"""JSON batch output helpers."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


def per_file_json_name(relative_path: str) -> str:
    """Per-file artifact name derived from the batch-relative path.

    Using the relative path (unique within a batch) instead of just the file
    stem prevents same-stem files in different directories — or same-stem files
    with differing extensions — from silently overwriting each other's report.
    """
    safe = relative_path.replace("\\", "/").strip("/").replace("/", "_")
    return f"{safe}_analysis.json"


def write_individual_json_results(
    all_results: dict[str, dict[str, Any]], output_path: Path
) -> None:
    for file_key, result in all_results.items():
        relative_path = str(result.get("relative_path") or Path(file_key).name)
        per_file_path = output_path / per_file_json_name(relative_path)
        with open(per_file_path, "w", encoding="utf-8") as per_file_handle:
            json.dump(result, per_file_handle, indent=2, default=str)


def build_batch_summary_payload(
    all_results: dict[str, dict[str, Any]],
    failed_files: list[tuple[str, str]],
    *,
    collect_batch_statistics: Any,
) -> dict[str, Any]:
    return {
        "batch_summary": {
            "total_files": len(all_results) + len(failed_files),
            "successful_analyses": len(all_results),
            "failed_analyses": len(failed_files),
            "timestamp": datetime.now().isoformat(),
            "processed_files": list(all_results.keys()),
        },
        "results": all_results,
        "failed_files": [{"file": f[0], "error": f[1]} for f in failed_files],
        "statistics": collect_batch_statistics(all_results),
    }


def determine_csv_file_path(output_path: Path, timestamp: str) -> tuple[Path, str]:
    if output_path.suffix == ".csv":
        return output_path, output_path.name
    if output_path.suffix == ".json":
        # setup_batch_output_directory treats a .json -o target as a file (it
        # mkdir's only the parent), so it is not a directory. Put the CSV
        # companion alongside it (report.json -> report.csv) instead of trying
        # to write under the file, which raises NotADirectoryError.
        csv_file = output_path.with_suffix(".csv")
        return csv_file, csv_file.name
    csv_filename = f"r2inspect_{timestamp}.csv"
    csv_file = output_path / csv_filename
    return csv_file, csv_filename


def create_json_batch_summary(
    all_results: dict[str, dict[str, Any]],
    failed_files: list[tuple[str, str]],
    output_path: Path,
    timestamp: str,
    *,
    collect_batch_statistics: Any,
) -> str:
    write_individual_json_results(all_results, output_path)
    summary_file = output_path / f"r2inspect_batch_{timestamp}.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(
            build_batch_summary_payload(
                all_results,
                failed_files,
                collect_batch_statistics=collect_batch_statistics,
            ),
            f,
            indent=2,
            default=str,
        )
    return f"{summary_file.name} + individual JSONs"
