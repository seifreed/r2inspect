#!/usr/bin/env python3
"""Output formatting utilities for r2inspect."""

import json
from typing import Any

from rich.console import Console
from rich.table import Table

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
        return self._csv_formatter.to_csv()

    def _extract_csv_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Backward-compatible CSV row extraction for batch output."""
        return self._csv_formatter._extract_csv_data(data)

    def format_table(self, data: dict[str, Any], title: str = "Analysis Results") -> Table:
        """Format data as a Rich table."""
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
        """Format sections data as a Rich table."""
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
                str(section.get("flags", "")),
                f"{section.get('entropy', 0):.2f}",
                suspicious,
            )

        return table

    def format_imports(self, imports: list[dict[str, Any]]) -> Table:
        """Format imports data with enhanced risk scoring."""
        table = Table(title="Import Analysis", show_header=True)
        table.add_column("Function", style="cyan", width=25)
        table.add_column("Library", style="yellow", width=15)
        table.add_column("Category", style="magenta", width=20)
        table.add_column("Risk Score", style="red", width=10)
        table.add_column("Risk Tags", style="bright_red", width=30)

        sorted_imports = sorted(imports, key=lambda x: x.get("risk_score", 0), reverse=True)

        for imp in sorted_imports:
            risk_score = imp.get("risk_score", 0)
            risk_level = imp.get("risk_level", "Minimal")
            risk_tags = imp.get("risk_tags", [])

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
            else:
                risk_color = "dim"
                score_color = "dim"

            tags_display = ", ".join(risk_tags[:2])
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
        """Create a summary of the analysis results."""
        summary_lines: list[str] = []

        try:
            summary_lines.append("=== R2INSPECT ANALYSIS SUMMARY ===\n")
            self._append_file_info_summary(summary_lines)
            self._append_indicators_summary(summary_lines)
            self._append_packer_summary(summary_lines)
            self._append_yara_summary(summary_lines)

        except Exception as e:
            summary_lines.append(f"Error generating summary: {str(e)}")

        return "\n".join(summary_lines)

    def _append_file_info_summary(self, summary_lines: list[str]) -> None:
        file_info = self.results.get("file_info")
        if not file_info:
            return
        summary_lines.append(f"File: {file_info.get('name', 'Unknown')}")
        summary_lines.append(f"Size: {file_info.get('size', 0)} bytes")
        summary_lines.append(f"Type: {file_info.get('file_type', 'Unknown')}")
        summary_lines.append(f"MD5: {file_info.get('md5', 'Unknown')}")
        summary_lines.append("")

    def _append_indicators_summary(self, summary_lines: list[str]) -> None:
        indicators = self.results.get("indicators")
        if not indicators:
            return
        summary_lines.append(f"Suspicious Indicators: {len(indicators)}")
        for indicator in indicators[:5]:
            summary_lines.append(
                f"  - {indicator.get('type', 'Unknown')}: {indicator.get('description', 'N/A')}"
            )
        if len(indicators) > 5:
            summary_lines.append(f"  ... and {len(indicators) - 5} more")
        summary_lines.append("")

    def _append_packer_summary(self, summary_lines: list[str]) -> None:
        packer = self.results.get("packer")
        if not packer or not packer.get("is_packed"):
            return
        summary_lines.append(f"Packer Detected: {packer.get('packer_type', 'Unknown')}")
        summary_lines.append(f"Confidence: {packer.get('confidence', 0):.2f}")
        summary_lines.append("")

    def _append_yara_summary(self, summary_lines: list[str]) -> None:
        yara_matches = self.results.get("yara_matches")
        if not yara_matches:
            return
        summary_lines.append(f"YARA Matches: {len(yara_matches)}")
        for match in yara_matches[:3]:
            summary_lines.append(f"  - {match.get('rule', 'Unknown')}")
        summary_lines.append("")
