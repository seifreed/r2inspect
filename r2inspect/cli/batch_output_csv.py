#!/usr/bin/env python3
"""CSV helpers for batch output facades."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

FIELDNAMES = [
    "name",
    "size",
    "compile_time",
    "file_type",
    "md5",
    "sha1",
    "sha256",
    "sha512",
    "imphash",
    "ssdeep_hash",
    "tlsh_binary",
    "tlsh_text_section",
    "tlsh_functions_with_hash",
    "telfhash",
    "telfhash_symbols_used",
    "rich_header_xor_key",
    "rich_header_checksum",
    "richpe_hash",
    "rich_header_compilers",
    "rich_header_entries",
    "compiler",
    "compiler_version",
    "compiler_confidence",
    "imports",
    "exports",
    "sections",
    "anti_debug",
    "anti_vm",
    "anti_sandbox",
    "yara_matches",
    "num_functions",
    "num_unique_machoc",
    "num_duplicate_functions",
    "num_imports",
    "num_exports",
    "num_sections",
]


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
            writer.writerow({field: csv_data.get(field, "") for field in fieldnames})
