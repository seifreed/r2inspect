#!/usr/bin/env python3
"""Canonical output formatting helpers for CLI presentation."""

from __future__ import annotations

import csv
import io
from typing import Any

from rich.console import Console
from rich.table import Table

from . import output_formatter_views as _formatter_views
from .output_csv import CsvOutputFormatter
from .output_json import JsonOutputFormatter


class OutputFormatter:
    """Format analysis results for different output types."""

    def __init__(self, results: dict[str, Any]):
        self.results = results
        self.console = Console()
        self._json_formatter = JsonOutputFormatter(results)
        self._csv_formatter = CsvOutputFormatter(results)

    def to_json(self, indent: int = 2) -> str:
        """Convert results to JSON format."""
        return self._json_formatter.to_json(indent=indent)

    def to_csv(self) -> str:
        """Convert results to CSV format with specific fields."""
        try:
            self._extract_csv_data(self.results)
        except Exception as exc:
            import logging

            logging.getLogger(__name__).error("CSV export failed: %s", exc)
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["Error", "Message"])
            writer.writerow(["CSV Export Failed", str(exc)])
            return output.getvalue()
        return self._csv_formatter.to_csv()

    def _extract_csv_data(self, data: dict[str, Any]) -> dict[str, Any]:
        return self._csv_formatter._extract_csv_data(data)

    def _extract_names_from_list(
        self,
        data: dict[str, Any],
        key: str,
        name_field: str = "name",
        separator: str = ", ",
    ) -> str:
        return self._csv_formatter._extract_names_from_list(data, key, name_field, separator)

    def _extract_imphash(self, data: dict[str, Any]) -> str:
        return self._csv_formatter._extract_imphash(data)

    def _extract_compile_time(self, data: dict[str, Any]) -> str:
        return self._csv_formatter._extract_compile_time(data)

    def _count_duplicate_machoc(self, machoc_hashes: dict[str, Any]) -> int:
        return self._csv_formatter._count_duplicate_machoc(machoc_hashes)

    def _format_file_size(self, size_bytes: Any) -> str:
        return self._csv_formatter._format_file_size(size_bytes)

    def _clean_file_type(self, file_type: Any) -> str:
        return str(self._csv_formatter._clean_file_type(file_type))

    def _flatten_results(self, data: Any, prefix: str = "") -> list[dict[str, str]]:
        return _formatter_views.flatten_results(data, prefix)

    def format_table(self, data: dict[str, Any], title: str = "Analysis Results") -> Table:
        return _formatter_views.format_table(data, title)

    def format_sections(self, sections: list[dict[str, Any]]) -> Table:
        return _formatter_views.format_sections(sections)

    def format_imports(self, imports: list[dict[str, Any]]) -> Table:
        return _formatter_views.format_imports(imports)

    def format_summary(self) -> str:
        summary_lines: list[str] = []
        try:
            summary_lines.append(_formatter_views.SUMMARY_HEADER)
            self._append_file_info_summary(summary_lines)
            self._append_indicators_summary(summary_lines)
            self._append_packer_summary(summary_lines)
            self._append_yara_summary(summary_lines)
        except Exception as exc:
            summary_lines.append(f"Error generating summary: {exc}")
        return "\n".join(summary_lines)

    def _append_file_info_summary(self, summary_lines: list[str]) -> None:
        _formatter_views.append_file_info_summary(summary_lines, self.results)

    def _append_indicators_summary(self, summary_lines: list[str]) -> None:
        _formatter_views.append_indicators_summary(summary_lines, self.results)

    def _append_packer_summary(self, summary_lines: list[str]) -> None:
        _formatter_views.append_packer_summary(summary_lines, self.results)

    def _append_yara_summary(self, summary_lines: list[str]) -> None:
        _formatter_views.append_yara_summary(summary_lines, self.results)


__all__ = ["OutputFormatter"]
