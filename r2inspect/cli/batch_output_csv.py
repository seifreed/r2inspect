#!/usr/bin/env python3
"""CSV helpers for batch output facades."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from .output_csv_fields import escape_csv_formula


def write_csv_results(
    csv_file: Path,
    all_results: dict[str, dict[str, Any]],
    *,
    output_formatter_cls: Any,
    fieldnames: list[str],
) -> None:
    with open(csv_file, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for _, result in all_results.items():
            formatter = output_formatter_cls(result)
            csv_data = formatter._extract_csv_data(result)
            writer.writerow(
                {field: escape_csv_formula(csv_data.get(field, "")) for field in fieldnames}
            )
