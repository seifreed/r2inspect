#!/usr/bin/env python3
"""
Output formatting utilities for r2inspect
"""

import json
import csv
import io
from typing import Dict, List, Any
from rich.table import Table
from rich.console import Console


class OutputFormatter:
    """Format analysis results for different output types"""

    def __init__(self, results: Dict[str, Any]):
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

                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerow(csv_data)

            return output.getvalue()

        except Exception as e:
            # Fallback simple CSV
            writer = csv.writer(output)
            writer.writerow(["Error", "Message"])
            writer.writerow(["CSV Export Failed", str(e)])
            return output.getvalue()

        finally:
            output.close()

    def _extract_csv_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract specific fields for CSV export"""
        csv_row = {}

        try:
            # File info fields
            file_info = data.get("file_info", {})
            csv_row["name"] = file_info.get("name", "")
            csv_row["size"] = self._format_file_size(file_info.get("size", 0))
            csv_row["file_type"] = self._clean_file_type(file_info.get("file_type", ""))
            csv_row["md5"] = file_info.get("md5", "")
            csv_row["sha1"] = file_info.get("sha1", "")
            csv_row["sha256"] = file_info.get("sha256", "")
            csv_row["sha512"] = file_info.get("sha512", "")

            # Compile time - Extract from different sources based on file type
            compile_time = ""
            # Try PE info first
            if "pe_info" in data and "compile_time" in data["pe_info"]:
                compile_time = data["pe_info"]["compile_time"]
            # Try ELF info
            elif "elf_info" in data and "compile_time" in data["elf_info"]:
                compile_time = data["elf_info"]["compile_time"]
            # Try Mach-O info
            elif "macho_info" in data and "compile_time" in data["macho_info"]:
                compile_time = data["macho_info"]["compile_time"]
            # Fallback to generic file info
            elif "file_info" in data and "compile_time" in data["file_info"]:
                compile_time = data["file_info"]["compile_time"]

            csv_row["compile_time"] = compile_time

            # Import hash (imphash) - Extract from PE info
            imphash = ""
            if "pe_info" in data and "imphash" in data["pe_info"]:
                imphash = data["pe_info"]["imphash"]
            csv_row["imphash"] = imphash

            # SSDeep fuzzy hash
            ssdeep_info = data.get("ssdeep", {})
            csv_row["ssdeep_hash"] = ssdeep_info.get("ssdeep_hash", "")

            # TLSH locality sensitive hash
            tlsh_info = data.get("tlsh", {})
            csv_row["tlsh_binary"] = tlsh_info.get("binary_tlsh", "")
            csv_row["tlsh_text_section"] = tlsh_info.get("text_section_tlsh", "")
            csv_row["tlsh_functions_with_hash"] = tlsh_info.get("stats", {}).get(
                "functions_with_tlsh", 0
            )

            # Telfhash for ELF files
            telfhash_info = data.get("telfhash", {})
            csv_row["telfhash"] = telfhash_info.get("telfhash", "")
            csv_row["telfhash_symbols_used"] = telfhash_info.get("filtered_symbols", 0)

            # Rich Header for PE files
            rich_header_info = data.get("rich_header", {})
            csv_row["rich_header_xor_key"] = (
                hex(rich_header_info.get("xor_key", 0))
                if rich_header_info.get("xor_key")
                else ""
            )
            csv_row["rich_header_checksum"] = (
                hex(rich_header_info.get("checksum", 0))
                if rich_header_info.get("checksum")
                else ""
            )
            csv_row["richpe_hash"] = rich_header_info.get("richpe_hash", "")

            # Rich Header compilers (comma-separated)
            compilers_list = []
            if "compilers" in rich_header_info and isinstance(
                rich_header_info["compilers"], list
            ):
                for compiler in rich_header_info["compilers"]:
                    if isinstance(compiler, dict):
                        compiler_name = compiler.get("compiler_name", "")
                        count = compiler.get("count", 0)
                        if compiler_name:
                            compilers_list.append(f"{compiler_name}({count})")
            csv_row["rich_header_compilers"] = ", ".join(compilers_list)
            csv_row["rich_header_entries"] = len(rich_header_info.get("compilers", []))

            # Imports (comma-separated)
            imports_list = []
            if "imports" in data and isinstance(data["imports"], list):
                for imp in data["imports"]:
                    if isinstance(imp, dict):
                        import_name = imp.get("name", "")
                        if import_name:
                            imports_list.append(import_name)
                    else:
                        imports_list.append(str(imp))
            csv_row["imports"] = ", ".join(imports_list)

            # Exports (comma-separated)
            exports_list = []
            if "exports" in data and isinstance(data["exports"], list):
                for exp in data["exports"]:
                    if isinstance(exp, dict):
                        export_name = exp.get("name", "")
                        if export_name:
                            exports_list.append(export_name)
                    else:
                        exports_list.append(str(exp))
            csv_row["exports"] = ", ".join(exports_list)

            # Sections (comma-separated)
            sections_list = []
            if "sections" in data and isinstance(data["sections"], list):
                for section in data["sections"]:
                    if isinstance(section, dict):
                        section_name = section.get("name", "")
                        if section_name:
                            sections_list.append(section_name)
                    else:
                        sections_list.append(str(section))
            csv_row["sections"] = ", ".join(sections_list)

            # Anti-analysis flags
            anti_analysis = data.get("anti_analysis", {})
            csv_row["anti_debug"] = anti_analysis.get("anti_debug", False)
            csv_row["anti_vm"] = anti_analysis.get("anti_vm", False)
            csv_row["anti_sandbox"] = anti_analysis.get("anti_sandbox", False)

            # YARA matches (comma-separated rule names)
            yara_matches_list = []
            if "yara_matches" in data and isinstance(data["yara_matches"], list):
                for match in data["yara_matches"]:
                    if isinstance(match, dict):
                        rule_name = match.get("rule", "")
                        if rule_name:
                            yara_matches_list.append(rule_name)
                    else:
                        yara_matches_list.append(str(match))
            csv_row["yara_matches"] = ", ".join(yara_matches_list)

            # Compiler information
            compiler_info = data.get("compiler", {})
            csv_row["compiler"] = compiler_info.get("compiler", "Unknown")
            csv_row["compiler_version"] = compiler_info.get("version", "Unknown")
            csv_row["compiler_confidence"] = compiler_info.get("confidence", 0.0)

            # Function analysis information
            functions_info = data.get("functions", {})
            csv_row["num_functions"] = functions_info.get("total_functions", 0)

            # MACHOC hash information
            machoc_hashes = functions_info.get("machoc_hashes", {})
            csv_row["num_unique_machoc"] = (
                len(set(machoc_hashes.values())) if machoc_hashes else 0
            )

            # Calculate duplicate functions (functions with same MACHOC hash)
            num_duplicate_functions = 0
            if machoc_hashes:
                hash_counts = {}
                for func_name, machoc_hash in machoc_hashes.items():
                    hash_counts[machoc_hash] = hash_counts.get(machoc_hash, 0) + 1
                num_duplicate_functions = sum(
                    count - 1 for count in hash_counts.values() if count > 1
                )
            csv_row["num_duplicate_functions"] = num_duplicate_functions

            # Counters
            csv_row["num_imports"] = len(imports_list) if imports_list else 0
            csv_row["num_exports"] = len(exports_list) if exports_list else 0
            csv_row["num_sections"] = len(sections_list) if sections_list else 0

        except Exception as e:
            csv_row["error"] = f"Data extraction failed: {str(e)}"

        return csv_row

    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human-readable units"""
        try:
            size_bytes = int(size_bytes)
            if size_bytes == 0:
                return "0 B"

            # Define size units
            size_names = ["B", "KB", "MB", "GB", "TB"]
            i = 0

            # Calculate the appropriate unit
            while size_bytes >= 1024 and i < len(size_names) - 1:
                size_bytes /= 1024.0
                i += 1

            # Format with appropriate precision
            if i == 0:  # Bytes
                return f"{int(size_bytes)} {size_names[i]}"
            else:
                return f"{size_bytes:.1f} {size_names[i]}"

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

    def _flatten_results(
        self, data: Dict[str, Any], prefix: str = ""
    ) -> List[Dict[str, Any]]:
        """Flatten nested dictionary for CSV export (legacy method, kept for compatibility)"""
        rows = []

        try:
            for key, value in data.items():
                current_prefix = f"{prefix}.{key}" if prefix else key
                rows.extend(self._flatten_value(value, current_prefix))

        except Exception as e:
            rows.append({"field": "error", "value": f"Flattening failed: {str(e)}"})

        return rows

    def _flatten_value(self, value: Any, prefix: str) -> List[Dict[str, Any]]:
        """Flatten a single value based on its type"""
        if isinstance(value, dict):
            return self._flatten_results(value, prefix)
        elif isinstance(value, list):
            return self._flatten_list(value, prefix)
        else:
            return [{"field": prefix, "value": str(value)}]

    def _flatten_list(self, items: list, prefix: str) -> List[Dict[str, Any]]:
        """Flatten a list of items"""
        rows = []
        for i, item in enumerate(items):
            item_prefix = f"{prefix}[{i}]"
            rows.extend(self._flatten_value(item, item_prefix))
        return rows

    def format_table(
        self, data: Dict[str, Any], title: str = "Analysis Results"
    ) -> Table:
        """Format data as a Rich table"""
        table = Table(title=title, show_header=True)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        for key, value in data.items():
            if isinstance(value, (dict, list)):
                value_str = json.dumps(value, indent=2, default=str)
            else:
                value_str = str(value)

            table.add_row(key.replace("_", " ").title(), value_str)

        return table

    def format_sections(self, sections: List[Dict[str, Any]]) -> Table:
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

    def format_imports(self, imports: List[Dict[str, Any]]) -> Table:
        """Format imports data with enhanced risk scoring"""
        table = Table(title="Import Analysis", show_header=True)
        table.add_column("Function", style="cyan", width=25)
        table.add_column("Library", style="yellow", width=15)
        table.add_column("Category", style="magenta", width=20)
        table.add_column("Risk Score", style="red", width=10)
        table.add_column("Risk Tags", style="bright_red", width=30)

        # Sort by risk score (highest first)
        sorted_imports = sorted(
            imports, key=lambda x: x.get("risk_score", 0), reverse=True
        )

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
                f"[{risk_color}]{tags_display}[/{risk_color}]"
                if tags_display
                else "[dim]None[/dim]",
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
                    summary_lines.append(
                        f"Packer Detected: {packer.get('packer_type', 'Unknown')}"
                    )
                    summary_lines.append(
                        f"Confidence: {packer.get('confidence', 0):.2f}"
                    )
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
