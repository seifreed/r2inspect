#!/usr/bin/env python3
"""
Output formatting utilities for r2inspect
"""

import csv
import io
import json
from typing import Any

from rich.console import Console
from rich.table import Table


class OutputFormatter:
    """Format analysis results for different output types"""

    def __init__(self, results: dict[str, Any]):
        self.results = results
        self.console = Console()

    def to_json(self, indent: int = 2) -> str:
        """Convert results to JSON format"""
        try:
            return json.dumps(self.results, indent=indent, default=str)
        except Exception as e:
            return json.dumps(
                {
                    "error": f"JSON serialization failed: {str(e)}",
                    "partial_results": {},
                },
                indent=indent,
            )

    def to_csv(self) -> str:
        """Convert results to CSV format with specific fields"""
        output = io.StringIO()

        try:
            # Extract specific fields for CSV
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
            # Fallback simple CSV
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
        """Extract specific fields for CSV export"""
        csv_row = {}

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
            return data["pe_info"]["compile_time"]
        if "elf_info" in data and "compile_time" in data["elf_info"]:
            return data["elf_info"]["compile_time"]
        if "macho_info" in data and "compile_time" in data["macho_info"]:
            return data["macho_info"]["compile_time"]
        if "file_info" in data and "compile_time" in data["file_info"]:
            return data["file_info"]["compile_time"]
        return ""

    def _extract_imphash(self, data: dict[str, Any]) -> str:
        if "pe_info" in data and "imphash" in data["pe_info"]:
            return data["pe_info"]["imphash"]
        return ""

    def _add_ssdeep(self, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
        ssdeep_info = data.get("ssdeep", {})
        csv_row["ssdeep_hash"] = ssdeep_info.get("ssdeep_hash", "")

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
        """Format file size in human-readable units"""
        try:
            size_value = float(size_bytes)
            if size_value == 0:
                return "0 B"

            # Define size units
            size_names = ["B", "KB", "MB", "GB", "TB"]
            i = 0

            # Calculate the appropriate unit
            while size_value >= 1024 and i < len(size_names) - 1:
                size_value /= 1024.0
                i += 1

            # Format with appropriate precision
            if i == 0:  # Bytes
                return f"{int(size_value)} {size_names[i]}"
            else:
                return f"{size_value:.1f} {size_names[i]}"

        except (ValueError, TypeError):
            return str(size_bytes)

    def _clean_file_type(self, file_type: str) -> str:
        """Clean file type description to remove extra information like section counts"""
        try:
            # Remove section count information (e.g., "7 sections")
            import re

            cleaned = re.sub(r",\s*\d+\s+sections?", "", file_type)
            cleaned = re.sub(r"\d+\s+sections?,?\s*", "", cleaned)

            # Remove extra whitespace and trailing commas
            cleaned = re.sub(r",\s*$", "", cleaned.strip())

            return cleaned

        except Exception:
            return file_type

    def _flatten_results(self, data: dict[str, Any], prefix: str = "") -> list[dict[str, Any]]:
        """Flatten nested dictionary for CSV export (legacy method, kept for compatibility)"""
        rows = []

        try:
            for key, value in data.items():
                current_prefix = f"{prefix}.{key}" if prefix else key
                rows.extend(self._flatten_value(value, current_prefix))

        except Exception as e:
            rows.append({"field": "error", "value": f"Flattening failed: {str(e)}"})

        return rows

    def _flatten_value(self, value: Any, prefix: str) -> list[dict[str, Any]]:
        """Flatten a single value based on its type"""
        if isinstance(value, dict):
            return self._flatten_results(value, prefix)
        elif isinstance(value, list):
            return self._flatten_list(value, prefix)
        else:
            return [{"field": prefix, "value": str(value)}]

    def _flatten_list(self, items: list, prefix: str) -> list[dict[str, Any]]:
        """Flatten a list of items"""
        rows = []
        for i, item in enumerate(items):
            item_prefix = f"{prefix}[{i}]"
            rows.extend(self._flatten_value(item, item_prefix))
        return rows

    def format_table(self, data: dict[str, Any], title: str = "Analysis Results") -> Table:
        """Format data as a Rich table"""
        table = Table(title=title, show_header=True)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        for key, value in data.items():
            if isinstance(value, dict | list):
                value_str = json.dumps(value, indent=2, default=str)
            else:
                value_str = str(value)

            table.add_row(key.replace("_", " ").title(), value_str)

        return table

    def format_sections(self, sections: list[dict[str, Any]]) -> Table:
        """Format sections data as a Rich table"""
        table = Table(title="Section Analysis", show_header=True)
        table.add_column("Name", style="cyan")
        table.add_column("Size", style="yellow")
        table.add_column("Flags", style="magenta")
        table.add_column("Entropy", style="green")
        table.add_column("Suspicious", style="red")

        for section in sections:
            suspicious = "Yes" if section.get("suspicious_indicators") else "No"
            table.add_row(
                section.get("name", "Unknown"),
                str(section.get("raw_size", 0)),
                section.get("flags", ""),
                f"{section.get('entropy', 0):.2f}",
                suspicious,
            )

        return table

    def format_imports(self, imports: list[dict[str, Any]]) -> Table:
        """Format imports data with enhanced risk scoring"""
        table = Table(title="Import Analysis", show_header=True)
        table.add_column("Function", style="cyan", width=25)
        table.add_column("Library", style="yellow", width=15)
        table.add_column("Category", style="magenta", width=20)
        table.add_column("Risk Score", style="red", width=10)
        table.add_column("Risk Tags", style="bright_red", width=30)

        # Sort by risk score (highest first)
        sorted_imports = sorted(imports, key=lambda x: x.get("risk_score", 0), reverse=True)

        for imp in sorted_imports:
            risk_score = imp.get("risk_score", 0)
            risk_level = imp.get("risk_level", "Minimal")
            risk_tags = imp.get("risk_tags", [])

            # Color coding based on risk level
            if risk_level == "Critical":
                risk_color = "bright_red"
                score_color = "bright_red"
            elif risk_level == "High":
                risk_color = "red"
                score_color = "red"
            elif risk_level == "Medium":
                risk_color = "yellow"
                score_color = "yellow"
            elif risk_level == "Low":
                risk_color = "green"
                score_color = "green"
            else:  # Minimal
                risk_color = "dim"
                score_color = "dim"

            # Format risk tags
            tags_display = ", ".join(risk_tags[:2])  # Show first 2 tags
            if len(risk_tags) > 2:
                tags_display += f" (+{len(risk_tags) - 2})"

            table.add_row(
                imp.get("name", "Unknown"),
                imp.get("library", "Unknown"),
                imp.get("category", "Unknown"),
                f"[{score_color}]{risk_score}/100[/{score_color}]",
                (
                    f"[{risk_color}]{tags_display}[/{risk_color}]"
                    if tags_display
                    else "[dim]None[/dim]"
                ),
            )

        return table

    def format_summary(self) -> str:
        """Create a summary of the analysis results"""
        summary_lines = []

        try:
            summary_lines.append("=== R2INSPECT ANALYSIS SUMMARY ===\n")

            # File information
            if "file_info" in self.results:
                file_info = self.results["file_info"]
                summary_lines.append(f"File: {file_info.get('name', 'Unknown')}")
                summary_lines.append(f"Size: {file_info.get('size', 0)} bytes")
                summary_lines.append(f"Type: {file_info.get('file_type', 'Unknown')}")
                summary_lines.append(f"MD5: {file_info.get('md5', 'Unknown')}")
                summary_lines.append("")

            # Indicators
            if "indicators" in self.results:
                indicators = self.results["indicators"]
                if indicators:
                    summary_lines.append(f"Suspicious Indicators: {len(indicators)}")
                    for indicator in indicators[:5]:  # Show first 5
                        summary_lines.append(
                            f"  - {indicator.get('type', 'Unknown')}: {indicator.get('description', 'N/A')}"
                        )
                    if len(indicators) > 5:
                        summary_lines.append(f"  ... and {len(indicators) - 5} more")
                    summary_lines.append("")

            # Packer detection
            if "packer" in self.results:
                packer = self.results["packer"]
                if packer.get("is_packed"):
                    summary_lines.append(f"Packer Detected: {packer.get('packer_type', 'Unknown')}")
                    summary_lines.append(f"Confidence: {packer.get('confidence', 0):.2f}")
                    summary_lines.append("")

            # YARA matches
            if "yara_matches" in self.results:
                yara_matches = self.results["yara_matches"]
                if yara_matches:
                    summary_lines.append(f"YARA Matches: {len(yara_matches)}")
                    for match in yara_matches[:3]:  # Show first 3
                        summary_lines.append(f"  - {match.get('rule', 'Unknown')}")
                    summary_lines.append("")

        except Exception as e:
            summary_lines.append(f"Error generating summary: {str(e)}")

        return "\n".join(summary_lines)
