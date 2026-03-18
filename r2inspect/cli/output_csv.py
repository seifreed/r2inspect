#!/usr/bin/env python3
"""CSV formatting helpers for CLI analysis results."""

from __future__ import annotations

import csv
import io
from typing import Any

from . import output_csv_fields as _csv_fields

FIELDNAMES = _csv_fields.FIELDNAMES
FILE_SIZE_UNITS = ("B", "KB", "MB", "GB", "TB")


class CsvOutputFormatter:
    """Serialize one analysis result payload into a single CSV row."""

    def __init__(self, results: dict[str, Any]):
        self.results = results

    def to_csv(self) -> str:
        """Render the current result payload as CSV text."""
        output = io.StringIO()
        try:
            csv_data = self._extract_csv_data(self.results)
            if csv_data:
                dict_writer = csv.DictWriter(output, fieldnames=FIELDNAMES)
                dict_writer.writeheader()
                dict_writer.writerow(csv_data)
            return output.getvalue()
        except Exception as exc:
            self._write_error_csv(output, exc)
            return output.getvalue()
        finally:
            output.close()

    def _extract_names_from_list(
        self, data: dict[str, Any], key: str, name_field: str = "name", separator: str = ", "
    ) -> str:
        items = data.get(key, [])
        if not isinstance(items, list):
            return ""
        names = []
        for item in items:
            if isinstance(item, dict):
                name = item.get(name_field, "")
                if name:
                    names.append(str(name))
            elif item:
                names.append(str(item))
        return separator.join(names)

    def _extract_csv_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Collect the normalized CSV row for an analysis payload."""
        csv_row: dict[str, Any] = {}
        try:
            self._add_file_info(csv_row, data)
            csv_row["compile_time"] = self._extract_compile_time(data)
            csv_row["imphash"] = self._extract_imphash(data)
            self._add_ssdeep(csv_row, data)
            self._add_tlsh(csv_row, data)
            self._add_telfhash(csv_row, data)
            self._add_rich_header(csv_row, data)
            self._add_imports_exports_sections(csv_row, data)
            self._add_anti_analysis(csv_row, data)
            csv_row["yara_matches"] = self._extract_names_from_list(
                data, "yara_matches", name_field="rule"
            )
            self._add_compiler_info(csv_row, data)
            self._add_function_info(csv_row, data)
            self._add_counts(csv_row, data)
        except Exception as exc:
            csv_row["error"] = f"Data extraction failed: {str(exc)}"
        return csv_row

    @staticmethod
    def _write_error_csv(output: io.StringIO, exc: Exception) -> None:
        """Write the fallback error CSV used when serialization fails."""
        row_writer = csv.writer(output)
        row_writer.writerow(["Error", "Message"])
        row_writer.writerow(["CSV Export Failed", str(exc)])

    def _add_file_info(self, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
        _csv_fields.add_file_info(self, csv_row, data)

    def _extract_compile_time(self, data: dict[str, Any]) -> str:
        return _csv_fields.extract_compile_time(data)

    def _extract_imphash(self, data: dict[str, Any]) -> str:
        return _csv_fields.extract_imphash(data)

    def _add_ssdeep(self, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
        _csv_fields.add_ssdeep(csv_row, data)

    def _add_tlsh(self, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
        _csv_fields.add_tlsh(csv_row, data)

    def _add_telfhash(self, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
        _csv_fields.add_telfhash(csv_row, data)

    def _add_rich_header(self, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
        _csv_fields.add_rich_header(self, csv_row, data)

    def _format_rich_header_compilers(self, rich_header_info: dict[str, Any]) -> str:
        return _csv_fields.format_rich_header_compilers(rich_header_info)

    def _add_imports_exports_sections(self, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
        _csv_fields.add_imports_exports_sections(self, csv_row, data)

    def _add_anti_analysis(self, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
        _csv_fields.add_anti_analysis(csv_row, data)

    def _add_compiler_info(self, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
        _csv_fields.add_compiler_info(csv_row, data)

    def _add_function_info(self, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
        _csv_fields.add_function_info(self, csv_row, data)

    def _count_duplicate_machoc(self, machoc_hashes: dict[str, Any]) -> int:
        if not machoc_hashes:
            return 0
        hash_counts: dict[str, int] = {}
        for _, machoc_hash in machoc_hashes.items():
            hash_counts[machoc_hash] = hash_counts.get(machoc_hash, 0) + 1
        return sum(count - 1 for count in hash_counts.values() if count > 1)

    def _add_counts(self, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
        _csv_fields.add_counts(csv_row, data)

    @staticmethod
    def _format_file_size(size: Any) -> str:
        try:
            size_value = float(size)
            if size_value == 0:
                return "0 B"
            index = 0
            while size_value >= 1024 and index < len(FILE_SIZE_UNITS) - 1:
                size_value /= 1024.0
                index += 1
            if index == 0:
                return f"{int(size_value)} {FILE_SIZE_UNITS[index]}"
            return f"{size_value:.1f} {FILE_SIZE_UNITS[index]}"
        except (ValueError, TypeError):
            return str(size)

    @staticmethod
    def _clean_file_type(file_type: Any) -> Any:
        try:
            if not isinstance(file_type, str):
                return file_type
            import re

            cleaned = re.sub(r",\s*\d+\s+sections?", "", str(file_type or ""))
            cleaned = re.sub(r"\d+\s+sections?,?\s*", "", cleaned)
            cleaned = re.sub(r",\s*$", "", cleaned.strip())
            return cleaned
        except Exception:
            return file_type


__all__ = ["CsvOutputFormatter", "FIELDNAMES"]
