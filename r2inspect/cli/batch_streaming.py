#!/usr/bin/env python3
"""Low-memory (streaming) batch aggregation.

Opt-in via the ``R2INSPECT_BATCH_LOW_MEMORY`` environment variable (matching
the existing ``R2INSPECT_MAX_THREADS`` / ``R2INSPECT_ANALYSIS_DEPTH`` toggles).

The default batch path accumulates every file's full result dict in
``all_results`` for the whole run so it can embed them in the combined JSON
summary — RAM therefore grows with the total size of all analyses. In
streaming mode each result is folded into running statistics, a flat CSV row,
and a compact table projection *as it completes*, then the full dict is
dropped. Memory holds only these lightweight per-file records. The combined
JSON summary references the per-file JSON files (written by the worker when
``-j`` is set) instead of embedding every full result.
"""

from __future__ import annotations

import csv
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..application.batch_stats import (
    update_compiler_stats,
    update_crypto_stats,
    update_file_type_stats,
    update_indicator_stats,
    update_packer_stats,
)
from .output_csv_fields import escape_csv_formula

LOW_MEMORY_ENV = "R2INSPECT_BATCH_LOW_MEMORY"

# Only the keys the summary-table builders read (via render_summary_row).
# Keeping just these instead of the full result is what bounds memory.
_TABLE_FIELDS = ("file_info", "compiler", "yara_matches", "pe_info", "elf_info", "macho_info")


def low_memory_enabled(env: dict[str, str] | None = None) -> bool:
    """Return True when the low-memory batch toggle is set."""
    source = os.environ if env is None else env
    return source.get(LOW_MEMORY_ENV, "").strip().lower() in {"1", "true", "yes"}


def _empty_stats() -> dict[str, Any]:
    return {
        "packers_detected": [],
        "crypto_patterns": [],
        "suspicious_indicators": [],
        "file_types": {},
        "architectures": {},
        "compilers": {},
    }


def _table_projection(result: dict[str, Any]) -> dict[str, Any]:
    return {key: result[key] for key in _TABLE_FIELDS if key in result}


class StreamingBatchAggregator:
    """Fold per-file results into lightweight records, dropping the full dict."""

    def __init__(
        self,
        *,
        output_csv: bool,
        output_formatter_cls: Any,
        fieldnames: list[str],
    ) -> None:
        self._output_csv = output_csv
        self._output_formatter_cls = output_formatter_cls
        self._fieldnames = fieldnames
        self.stats = _empty_stats()
        self.csv_rows: list[dict[str, Any]] = []

    def on_result(self, file_key: str, result: dict[str, Any]) -> dict[str, Any]:
        """Fold one result into the running aggregates; return the compact record."""
        update_packer_stats(self.stats, file_key, result)
        update_crypto_stats(self.stats, file_key, result)
        update_indicator_stats(self.stats, file_key, result)
        update_file_type_stats(self.stats, result)
        update_compiler_stats(self.stats, result)
        if self._output_csv:
            row = self._output_formatter_cls(result)._extract_csv_data(result)
            self.csv_rows.append(
                {field: escape_csv_formula(row.get(field, "")) for field in self._fieldnames}
            )
        return _table_projection(result)


def write_streaming_csv(csv_file: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    """Write the pre-built flat CSV rows collected during streaming."""
    with open(csv_file, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def build_streaming_json_payload(
    aggregator: StreamingBatchAggregator,
    processed_keys: list[str],
    failed_files: list[tuple[str, str]],
) -> dict[str, Any]:
    """Combined summary payload that references per-file JSONs, not embeds them."""
    return {
        "batch_summary": {
            "total_files": len(processed_keys) + len(failed_files),
            "successful_analyses": len(processed_keys),
            "failed_analyses": len(failed_files),
            "timestamp": datetime.now(UTC).isoformat(),
            "processed_files": processed_keys,
            "results_location": "per-file <relative-path>_analysis.json (not embedded in low-memory mode)",
        },
        "failed_files": [{"file": item[0], "error": item[1]} for item in failed_files],
        "statistics": aggregator.stats,
    }


def make_streaming_create_batch_summary(
    aggregator: StreamingBatchAggregator,
    *,
    determine_csv_file_path: Any,
    show_summary_table: Any,
) -> Any:
    """Return a ``create_batch_summary`` collaborator backed by the aggregator.

    Signature matches the default collaborator
    ``(all_results, failed_files, output_path, output_json, output_csv)`` so it
    drops into the existing run flow. ``all_results`` here holds the compact
    table projections (the worker stored the aggregator's return values), so the
    summary table renders correctly while the heavy data was never retained.
    """

    def _create_batch_summary(
        all_results: dict[str, dict[str, Any]],
        failed_files: list[tuple[str, str]],
        output_path: Path,
        output_json: bool,
        output_csv: bool,
    ) -> str | None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_filename: str | None = None
        if output_csv:
            csv_file, csv_name = determine_csv_file_path(output_path, timestamp)
            write_streaming_csv(csv_file, aggregator.csv_rows, aggregator._fieldnames)
            output_filename = csv_name
        if output_json:
            summary_file = output_path / f"r2inspect_batch_{timestamp}.json"
            payload = build_streaming_json_payload(
                aggregator, list(all_results.keys()), failed_files
            )
            with open(summary_file, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, default=str)
            output_filename = (
                f"{output_filename} + {summary_file.name}" if output_csv else summary_file.name
            )
        show_summary_table(all_results)
        return output_filename

    return _create_batch_summary
