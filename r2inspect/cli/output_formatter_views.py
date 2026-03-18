#!/usr/bin/env python3
"""Table and summary helpers for output formatting."""

from __future__ import annotations

import json
from typing import Any

from rich.table import Table

SUMMARY_HEADER = "=== R2INSPECT ANALYSIS SUMMARY ===\n"
MAX_SUMMARY_INDICATORS = 5
MAX_SUMMARY_YARA_MATCHES = 3
IMPORT_RISK_STYLES = {
    "Critical": ("bright_red", "bright_red"),
    "High": ("red", "red"),
    "Medium": ("yellow", "yellow"),
    "Low": ("green", "green"),
    "Minimal": ("dim", "dim"),
}


def flatten_results(data: Any, prefix: str = "") -> list[dict[str, str]]:
    """Flatten nested dictionaries and lists into table-friendly rows."""
    rows: list[dict[str, str]] = []
    if isinstance(data, dict):
        for key, value in data.items():
            next_prefix = f"{prefix}.{key}" if prefix else str(key)
            rows.extend(flatten_results(value, next_prefix))
        return rows
    if isinstance(data, list):
        for idx, value in enumerate(data):
            next_prefix = f"{prefix}[{idx}]"
            rows.extend(flatten_results(value, next_prefix))
        return rows
    rows.append({"field": prefix, "value": str(data)})
    return rows


def format_table(data: dict[str, Any], title: str = "Analysis Results") -> Table:
    """Render a generic key/value table for a result subsection."""
    table = Table(title=title, show_header=True)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")
    for key, value in data.items():
        value_str = _stringify_table_value(value)
        table.add_row(key.replace("_", " ").title(), value_str)
    return table


def format_sections(sections: list[dict[str, Any]]) -> Table:
    """Render the section overview table."""
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


def format_imports(imports: list[dict[str, Any]]) -> Table:
    """Render imports sorted by risk score with compact risk styling."""
    table = Table(title="Import Analysis", show_header=True)
    table.add_column("Function", style="cyan", width=25)
    table.add_column("Library", style="yellow", width=15)
    table.add_column("Category", style="magenta", width=20)
    table.add_column("Risk Score", style="red", width=10)
    table.add_column("Risk Tags", style="bright_red", width=30)
    for imp in sorted(imports, key=lambda item: item.get("risk_score", 0), reverse=True):
        risk_score = imp.get("risk_score", 0)
        risk_level = imp.get("risk_level", "Minimal")
        risk_tags = imp.get("risk_tags", [])
        risk_color, score_color = IMPORT_RISK_STYLES.get(risk_level, ("dim", "dim"))
        tags_display = ", ".join(risk_tags[:2])
        if len(risk_tags) > 2:
            tags_display += f" (+{len(risk_tags) - 2})"
        table.add_row(
            imp.get("name", "Unknown"),
            imp.get("library", "Unknown"),
            imp.get("category", "Unknown"),
            f"[{score_color}]{risk_score}/100[/{score_color}]",
            f"[{risk_color}]{tags_display}[/{risk_color}]" if tags_display else "[dim]None[/dim]",
        )
    return table


def build_summary(results: dict[str, Any]) -> str:
    """Build the plain-text summary used by console and tests."""
    summary_lines: list[str] = []
    try:
        summary_lines.append(SUMMARY_HEADER)
        append_file_info_summary(summary_lines, results)
        append_indicators_summary(summary_lines, results)
        append_packer_summary(summary_lines, results)
        append_yara_summary(summary_lines, results)
    except Exception as exc:
        summary_lines.append(f"Error generating summary: {str(exc)}")
    return "\n".join(summary_lines)


def append_file_info_summary(summary_lines: list[str], results: dict[str, Any]) -> None:
    """Append file identity fields to the text summary."""
    file_info = results.get("file_info")
    if not file_info:
        return
    summary_lines.extend(
        [
            f"File: {file_info.get('name', 'Unknown')}",
            f"Size: {file_info.get('size', 0)} bytes",
            f"Type: {file_info.get('file_type', 'Unknown')}",
            f"MD5: {file_info.get('md5', 'Unknown')}",
            "",
        ]
    )


def append_indicators_summary(summary_lines: list[str], results: dict[str, Any]) -> None:
    """Append suspicious indicator lines to the text summary."""
    indicators = results.get("indicators")
    if not indicators:
        return
    summary_lines.append(f"Suspicious Indicators: {len(indicators)}")
    for indicator in indicators[:MAX_SUMMARY_INDICATORS]:
        summary_lines.append(
            f"  - {indicator.get('type', 'Unknown')}: {indicator.get('description', 'N/A')}"
        )
    if len(indicators) > MAX_SUMMARY_INDICATORS:
        summary_lines.append(f"  ... and {len(indicators) - MAX_SUMMARY_INDICATORS} more")
    summary_lines.append("")


def append_packer_summary(summary_lines: list[str], results: dict[str, Any]) -> None:
    """Append packer detection details to the text summary."""
    packer = results.get("packer")
    if not packer or not packer.get("is_packed"):
        return
    summary_lines.append(f"Packer Detected: {packer.get('packer_type', 'Unknown')}")
    summary_lines.append(f"Confidence: {packer.get('confidence', 0):.2f}")
    summary_lines.append("")


def append_yara_summary(summary_lines: list[str], results: dict[str, Any]) -> None:
    """Append a short YARA summary to the text output."""
    yara_matches = results.get("yara_matches")
    if not yara_matches:
        return
    summary_lines.append(f"YARA Matches: {len(yara_matches)}")
    for match in yara_matches[:MAX_SUMMARY_YARA_MATCHES]:
        summary_lines.append(f"  - {match.get('rule', 'Unknown')}")
    summary_lines.append("")


def _stringify_table_value(value: Any) -> str:
    """Render nested structures as JSON and scalars as plain strings."""
    if isinstance(value, dict | list):
        return json.dumps(value, indent=2, default=str)
    return str(value)
