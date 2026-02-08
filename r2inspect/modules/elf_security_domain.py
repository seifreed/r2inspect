#!/usr/bin/env python3
"""ELF security domain helpers."""

from __future__ import annotations

from typing import Any


def has_nx(ph_info: list[dict[str, Any]] | None) -> bool:
    if not ph_info:
        return False
    for header in ph_info:
        if header.get("type") == "GNU_STACK":
            flags = header.get("flags", "")
            return "x" not in str(flags).lower()
    return False


def has_stack_canary(symbols: list[dict[str, Any]] | None) -> bool:
    for symbol in symbols or []:
        name = symbol.get("name", "")
        if "__stack_chk_fail" in name or "__stack_chk_guard" in name:
            return True
    return False


def has_relro(dynamic_info: str | None) -> bool:
    return bool(dynamic_info and "BIND_NOW" in dynamic_info)


def is_pie(elf_info: dict[str, Any] | None) -> bool:
    if not elf_info or "bin" not in elf_info:
        return False
    elf_type = elf_info["bin"].get("class", "")
    return "DYN" in elf_type.upper()


def path_features(dynamic_info: str | None) -> dict[str, bool]:
    info = dynamic_info or ""
    return {"rpath": "RPATH" in info, "runpath": "RUNPATH" in info}
