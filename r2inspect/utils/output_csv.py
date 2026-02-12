#!/usr/bin/env python3
"""CSV output formatting helpers."""

from __future__ import annotations

import csv
import io
from typing import Any


class CsvOutputFormatter:
    """Format analysis results to CSV."""

    def __init__(self, results: dict[str, Any]):
        self.results = results

    def to_csv(self) -> str:
        """Convert results to CSV format with specific fields."""
        output = io.StringIO()

        try:
            csv_data = self._extract_csv_data(self.results)

            if csv_data:
                fieldnames = [
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
                    "ssdeep_available",
                    "tlsh_binary",
                    "tlsh_text_section",
                    "tlsh_available",
                    "tlsh_functions_with_hash",
                    "telfhash",
                    "telfhash_available",
                    "telfhash_symbols_used",
                    "rich_header_available",
                    "rich_header_xor_key",
                    "rich_header_checksum",
                    "richpe_hash",
                    "rich_header_compilers",
                    "rich_header_entries",
                    "imports",
                    "exports",
                    "sections",
                    "anti_debug",
                    "anti_vm",
                    "anti_sandbox",
                    "yara_matches",
                    "compiler",
                    "compiler_version",
                    "compiler_confidence",
                    "num_functions",
                    "num_unique_machoc",
                    "num_duplicate_functions",
                    "num_imports",
                    "num_exports",
                    "num_sections",
                ]

                dict_writer = csv.DictWriter(output, fieldnames=fieldnames)
                dict_writer.writeheader()
                dict_writer.writerow(csv_data)

            return output.getvalue()

        except Exception as e:
            row_writer = csv.writer(output)
            row_writer.writerow(["Error", "Message"])
            row_writer.writerow(["CSV Export Failed", str(e)])
            return output.getvalue()

        finally:
            output.close()

    def _extract_names_from_list(
        self,
        data: dict[str, Any],
        key: str,
        name_field: str = "name",
        separator: str = ", ",
    ) -> str:
        """Extract names from a list of dicts and join them."""
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
        """Extract specific fields for CSV export."""
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

        except Exception as e:
            csv_row["error"] = f"Data extraction failed: {str(e)}"

        return csv_row

    def _add_file_info(self, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
        file_info = data.get("file_info", {})
        csv_row["name"] = file_info.get("name", "")
        csv_row["size"] = self._format_file_size(file_info.get("size", 0))
        csv_row["file_type"] = self._clean_file_type(file_info.get("file_type", ""))
        csv_row["md5"] = file_info.get("md5", "")
        csv_row["sha1"] = file_info.get("sha1", "")
        csv_row["sha256"] = file_info.get("sha256", "")
        csv_row["sha512"] = file_info.get("sha512", "")

    def _extract_compile_time(self, data: dict[str, Any]) -> str:
        if "pe_info" in data and "compile_time" in data["pe_info"]:
            value = data["pe_info"]["compile_time"]
            return str(value) if value else ""
        if "elf_info" in data and "compile_time" in data["elf_info"]:
            value = data["elf_info"]["compile_time"]
            return str(value) if value else ""
        if "macho_info" in data and "compile_time" in data["macho_info"]:
            value = data["macho_info"]["compile_time"]
            return str(value) if value else ""
        if "file_info" in data and "compile_time" in data["file_info"]:
            value = data["file_info"]["compile_time"]
            return str(value) if value else ""
        return ""

    def _extract_imphash(self, data: dict[str, Any]) -> str:
        if "pe_info" in data and "imphash" in data["pe_info"]:
            value = data["pe_info"]["imphash"]
            return str(value) if value else ""
        return ""

    def _add_ssdeep(self, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
        ssdeep_info = data.get("ssdeep", {})
        csv_row["ssdeep_hash"] = ssdeep_info.get("hash_value", "")

    def _add_tlsh(self, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
        tlsh_info = data.get("tlsh", {})
        csv_row["tlsh_binary"] = tlsh_info.get("binary_tlsh", "")
        csv_row["tlsh_text_section"] = tlsh_info.get("text_section_tlsh", "")
        csv_row["tlsh_functions_with_hash"] = tlsh_info.get("stats", {}).get(
            "functions_with_tlsh", 0
        )

    def _add_telfhash(self, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
        telfhash_info = data.get("telfhash", {})
        csv_row["telfhash"] = telfhash_info.get("telfhash", "")
        csv_row["telfhash_symbols_used"] = telfhash_info.get("filtered_symbols", 0)

    def _add_rich_header(self, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
        rich_header_info = data.get("rich_header", {})
        csv_row["rich_header_xor_key"] = (
            hex(rich_header_info.get("xor_key", 0)) if rich_header_info.get("xor_key") else ""
        )
        csv_row["rich_header_checksum"] = (
            hex(rich_header_info.get("checksum", 0)) if rich_header_info.get("checksum") else ""
        )
        csv_row["richpe_hash"] = rich_header_info.get("richpe_hash", "")
        csv_row["rich_header_compilers"] = self._format_rich_header_compilers(rich_header_info)
        csv_row["rich_header_entries"] = len(rich_header_info.get("compilers", []))

    def _format_rich_header_compilers(self, rich_header_info: dict[str, Any]) -> str:
        compilers_list = []
        if "compilers" in rich_header_info and isinstance(rich_header_info["compilers"], list):
            for compiler in rich_header_info["compilers"]:
                if isinstance(compiler, dict):
                    compiler_name = compiler.get("compiler_name", "")
                    count = compiler.get("count", 0)
                    if compiler_name:
                        compilers_list.append(f"{compiler_name}({count})")
        return ", ".join(compilers_list)

    def _add_imports_exports_sections(self, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
        csv_row["imports"] = self._extract_names_from_list(data, "imports")
        csv_row["exports"] = self._extract_names_from_list(data, "exports")
        csv_row["sections"] = self._extract_names_from_list(data, "sections")

    def _add_anti_analysis(self, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
        anti_analysis = data.get("anti_analysis", {})
        csv_row["anti_debug"] = anti_analysis.get("anti_debug", False)
        csv_row["anti_vm"] = anti_analysis.get("anti_vm", False)
        csv_row["anti_sandbox"] = anti_analysis.get("anti_sandbox", False)

    def _add_compiler_info(self, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
        compiler_info = data.get("compiler", {})
        csv_row["compiler"] = compiler_info.get("compiler", "Unknown")
        csv_row["compiler_version"] = compiler_info.get("version", "Unknown")
        csv_row["compiler_confidence"] = compiler_info.get("confidence", 0.0)

    def _add_function_info(self, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
        functions_info = data.get("functions", {})
        csv_row["num_functions"] = functions_info.get("total_functions", 0)
        machoc_hashes = functions_info.get("machoc_hashes", {})
        csv_row["num_unique_machoc"] = len(set(machoc_hashes.values())) if machoc_hashes else 0
        csv_row["num_duplicate_functions"] = self._count_duplicate_machoc(machoc_hashes)

    def _count_duplicate_machoc(self, machoc_hashes: dict[str, Any]) -> int:
        if not machoc_hashes:
            return 0
        hash_counts: dict[str, int] = {}
        for _, machoc_hash in machoc_hashes.items():
            hash_counts[machoc_hash] = hash_counts.get(machoc_hash, 0) + 1
        return sum(count - 1 for count in hash_counts.values() if count > 1)

    def _add_counts(self, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
        imports = data.get("imports", [])
        exports = data.get("exports", [])
        sections = data.get("sections", [])
        csv_row["num_imports"] = len(imports) if isinstance(imports, list) else 0
        csv_row["num_exports"] = len(exports) if isinstance(exports, list) else 0
        csv_row["num_sections"] = len(sections) if isinstance(sections, list) else 0

    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human-readable units."""
        try:
            size_value = float(size_bytes)
            if size_value == 0:
                return "0 B"

            size_names = ["B", "KB", "MB", "GB", "TB"]
            i = 0

            while size_value >= 1024 and i < len(size_names) - 1:
                size_value /= 1024.0
                i += 1

            if i == 0:
                return f"{int(size_value)} {size_names[i]}"
            return f"{size_value:.1f} {size_names[i]}"

        except (ValueError, TypeError):
            return str(size_bytes)

    def _clean_file_type(self, file_type: str) -> str:
        """Clean file type description to remove extra information like section counts."""
        try:
            import re

            cleaned = re.sub(r",\s*\d+\s+sections?", "", file_type)
            cleaned = re.sub(r"\d+\s+sections?,?\s*", "", cleaned)

            cleaned = re.sub(r",\s*$", "", cleaned.strip())

            return cleaned

        except Exception:
            return file_type
