#!/usr/bin/env python3
"""Batch summary table builders and row formatters."""

from __future__ import annotations

import re
from typing import Any, cast

from rich.table import Table


def render_summary_row(
    file_key: str,
    result: dict[str, Any],
    *,
    include_md5: bool,
) -> tuple[str, ...]:
    file_info = result.get("file_info", {})
    shared = (
        simplify_file_type(file_info.get("file_type", "Unknown")),
        compiler_name(result),
        extract_compile_time(result),
    )
    if include_md5:
        return (file_info.get("md5", "N/A"), *shared, collect_yara_matches(result))
    return (file_info.get("name", file_key), *shared)


def show_summary_table(
    all_results: dict[str, dict[str, Any]],
    *,
    console: Any,
) -> None:
    if len(all_results) > 10:
        table = build_summary_table_small(all_results)
        console.print(table)
        console.print(
            f"[dim]... and {len(all_results) - 10} more files (see CSV output for complete list)[/dim]"
        )
        return

    console.print(build_summary_table_large(all_results))


def simplify_file_type(file_type: str) -> str:
    cleaned = re.sub(r",\s*\d+\s+sections?", "", file_type)
    cleaned = re.sub(r"\d+\s+sections?,?\s*", "", cleaned)
    cleaned = re.sub(r",\s*$", "", cleaned.strip())
    if "PE32+" in cleaned:
        return "PE32+ (x64)"
    if "PE32" in cleaned:
        return "PE32 (x86)"
    if "ELF" in cleaned:
        return "ELF"
    if "Mach-O" in cleaned:
        return "Mach-O"
    return cleaned or "Unknown"


def extract_compile_time(result: dict[str, Any]) -> str:
    for key in ("pe_info", "elf_info", "macho_info"):
        compile_time = result.get(key, {}).get("compile_time")
        if compile_time:
            return str(compile_time)
    return "N/A"


def compiler_name(result: dict[str, Any]) -> str:
    compiler_info = result.get("compiler", {})
    if not compiler_info.get("detected", False):
        return "Unknown"
    compiler = str(compiler_info.get("compiler", "Unknown"))
    version = compiler_info.get("version", "")
    return f"{compiler} {version}" if version and version != "Unknown" else compiler


def collect_yara_matches(result: dict[str, Any]) -> str:
    matches = result.get("yara_matches", [])
    if not isinstance(matches, list):
        return "None"
    names: list[str] = []
    for match in matches:
        if isinstance(match, dict) and "rule" in match:
            names.append(match["rule"])
        elif hasattr(match, "rule"):
            names.append(match.rule)
        else:
            names.append(str(match))
    return ", ".join(names) if names else "None"


def build_small_row(file_key: str, result: dict[str, Any]) -> tuple[str, str, str, str]:
    try:
        return cast(
            tuple[str, str, str, str], render_summary_row(file_key, result, include_md5=False)
        )
    except Exception:
        return file_key, "Error", "Error", "Error"


def build_large_row(file_key: str, result: dict[str, Any]) -> tuple[str, str, str, str, str]:
    try:
        return cast(
            tuple[str, str, str, str, str], render_summary_row(file_key, result, include_md5=True)
        )
    except Exception:
        return file_key, "Error", "Error", "Error", "Error"


def build_summary_table_small(all_results: dict[str, dict[str, Any]]) -> Table:
    table = Table(title="Analysis Summary")
    table.add_column("Filename", style="cyan")
    table.add_column("Type", style="yellow")
    table.add_column("Compiler", style="magenta")
    table.add_column("Compile Time", style="green")
    for files_shown, (file_key, result) in enumerate(all_results.items()):
        if files_shown >= 10:
            break
        table.add_row(*build_small_row(file_key, result))
    return table


def build_summary_table_large(all_results: dict[str, dict[str, Any]]) -> Table:
    table = Table(title="Analysis Summary")
    table.add_column("MD5", style="cyan")
    table.add_column("Type", style="yellow")
    table.add_column("Compiler", style="magenta")
    table.add_column("Compile Time", style="green")
    table.add_column("YARA Matches", style="red")
    for file_key, result in all_results.items():
        table.add_row(*build_large_row(file_key, result))
    return table
