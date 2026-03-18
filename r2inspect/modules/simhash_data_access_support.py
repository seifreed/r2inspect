"""Data access helpers for SimHash analysis."""

from __future__ import annotations

from typing import Any, cast


def get_strings_data(analyzer: Any) -> list[Any]:
    if analyzer.adapter is not None and hasattr(analyzer.adapter, "get_strings"):
        return cast(list[Any], analyzer.adapter.get_strings())
    return cast(list[Any], analyzer._cmd_list("izzj"))


def get_functions(analyzer: Any) -> list[dict[str, Any]]:
    if analyzer.adapter is not None and hasattr(analyzer.adapter, "get_functions"):
        return cast(list[dict[str, Any]], analyzer.adapter.get_functions())
    return cast(list[dict[str, Any]], analyzer._cmd_list("aflj"))


def get_sections(analyzer: Any) -> list[dict[str, Any]]:
    if analyzer.adapter is not None and hasattr(analyzer.adapter, "get_sections"):
        return cast(list[dict[str, Any]], analyzer.adapter.get_sections())
    return cast(list[dict[str, Any]], analyzer._cmd_list("iSj"))


def extract_ops_from_disasm(disasm: Any) -> list[Any]:
    if isinstance(disasm, dict) and isinstance(disasm.get("ops"), list):
        return cast(list[Any], disasm["ops"])
    if isinstance(disasm, list):
        return disasm
    return []
