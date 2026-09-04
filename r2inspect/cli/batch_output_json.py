#!/usr/bin/env python3
"""JSON batch output helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..infrastructure.json_serialization import dump
from ..schemas.batch_v1 import BatchErrorV1, BatchReportReferenceV1, BatchV1
from ..schemas.report_v1 import AnalyzerStatus


def _json_result(result: dict[str, Any]) -> dict[str, Any]:
    """Normalize legacy YARA match objects without stringifying unknown values."""
    matches = result.get("yara_matches")
    if not isinstance(matches, (list, tuple)):
        return result

    normalized: list[Any] = []
    for match in matches:
        if isinstance(match, dict) or match is None or isinstance(match, (str, int, float, bool)):
            normalized.append(match)
        elif hasattr(match, "to_dict") and callable(match.to_dict):
            normalized.append(match.to_dict())
        elif hasattr(match, "rule"):
            normalized.append({"rule": str(match.rule)})
        else:
            normalized.append(match)
    return {**result, "yara_matches": normalized}


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
            dump(_json_result(result), per_file_handle)


def build_batch_summary_payload(
    all_results: dict[str, dict[str, Any]],
    failed_files: list[tuple[str, str]],
    *,
    collect_batch_statistics: Any,
) -> dict[str, Any]:
    del collect_batch_statistics
    references = [_report_reference(file_key, result) for file_key, result in all_results.items()]
    profiles = {
        metadata["profile"]
        for result in all_results.values()
        if isinstance((metadata := result.get("_batch_report")), dict)
        and isinstance(metadata.get("profile"), str)
    }
    return BatchV1(
        analysis_id=str(uuid4()),
        profile=profiles.pop() if len(profiles) == 1 else "standard",
        generated_at=datetime.now(UTC),
        total=len(all_results) + len(failed_files),
        completed=len(all_results),
        failed=len(failed_files),
        reports=references,
        errors=[BatchErrorV1(sample=file, message=error) for file, error in failed_files],
    ).model_dump(mode="json")


def _report_reference(file_key: str, result: dict[str, Any]) -> BatchReportReferenceV1:
    metadata = result.get("_batch_report")
    if not isinstance(metadata, dict):
        metadata = {}
    relative_path = str(result.get("relative_path") or Path(file_key).name)
    return BatchReportReferenceV1(
        sample=relative_path,
        sha256=str(metadata["sha256"]) if metadata.get("sha256") else None,
        status=AnalyzerStatus(str(metadata.get("status", "completed"))),
        report_path=str(metadata.get("report_path") or per_file_json_name(relative_path)),
        analysis_id=str(metadata["analysis_id"]) if metadata.get("analysis_id") else None,
    )


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
    summary_file = output_path / f"r2inspect_batch_{timestamp}.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        dump(
            build_batch_summary_payload(
                all_results,
                failed_files,
                collect_batch_statistics=collect_batch_statistics,
            ),
            f,
        )
    return f"{summary_file.name} + individual JSONs"
