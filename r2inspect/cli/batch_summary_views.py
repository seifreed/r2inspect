#!/usr/bin/env python3
"""Public summary view helpers for batch output."""

from __future__ import annotations

from typing import Any

from rich.table import Table

from . import batch_output_summary as _summary


def show_summary_table(all_results: dict[str, dict[str, Any]], *, console: Any) -> None:
    _summary._show_summary_table_default(all_results, console=console)


def simplify_file_type(file_type: str) -> str:
    return _summary.simplify_file_type(file_type)


def extract_compile_time(result: dict[str, Any]) -> str:
    return _summary.extract_compile_time(result)


def compiler_name(result: dict[str, Any]) -> str:
    return _summary.compiler_name(result)


def collect_yara_matches(result: dict[str, Any]) -> str:
    return _summary.collect_yara_matches(result)


def build_small_row(file_key: str, result: dict[str, Any]) -> tuple[str, str, str, str]:
    return _summary.build_small_row(file_key, result)


def build_large_row(file_key: str, result: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return _summary.build_large_row(file_key, result)


def build_summary_table_small(all_results: dict[str, dict[str, Any]]) -> Table:
    return _summary.build_summary_table_small(all_results)


def build_summary_table_large(all_results: dict[str, dict[str, Any]]) -> Table:
    return _summary.build_summary_table_large(all_results)
