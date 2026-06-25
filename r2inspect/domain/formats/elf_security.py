#!/usr/bin/env python3
"""ELF security domain helpers."""

from __future__ import annotations

from typing import Any

from .symbol_features import any_symbol_name


def has_nx(segments: list[dict[str, Any]] | None) -> bool:
    if not segments:
        return False
    for segment in segments:
        # r2's segment list (iSSj) names the stack segment in "name" with the
        # permissions in "perm" (e.g. "-rw-"); older/text shapes used "type"
        # and "flags". NX is on when the GNU_STACK segment is not executable.
        identifier = str(segment.get("name") or segment.get("type") or "").upper()
        if "GNU_STACK" in identifier:
            perms = segment.get("perm") or segment.get("flags") or ""
            if not isinstance(perms, str):
                return False
            return "x" not in perms.lower()
    return False


def has_stack_canary(symbols: list[dict[str, Any]] | None) -> bool:
    return any_symbol_name(
        symbols, lambda name: "__stack_chk_fail" in name or "__stack_chk_guard" in name
    )


def has_relro(relro_value: str | None) -> bool:
    # r2 reports RELRO status in ij.bin/iIj as "partial" or "full" (or "no"/
    # "none"). The previous check scanned the "id" (debug-info) command output
    # for "BIND_NOW", but id is empty for normal binaries, so relro was always
    # False. RELRO is present when the value is partial or full.
    if not isinstance(relro_value, str):
        return False
    return relro_value.strip().lower() in {"partial", "full"}


def is_pie(elf_info: dict[str, Any] | None) -> bool:
    if not elf_info or "bin" not in elf_info:
        return False
    bin_info = elf_info["bin"]
    if not isinstance(bin_info, dict):
        return False
    # r2 exposes position-independence as bin.pic. The ELF object type (DYN vs
    # EXEC) lives in bin.type; bin.class holds the ELF32/ELF64 magic, so the old
    # `"DYN" in class` check was always False and ELF PIE was never detected.
    if bin_info.get("pic"):
        return True
    elf_type = str(bin_info.get("type", ""))
    return "DYN" in elf_type.upper()


def path_features(dynamic_info: str | None) -> dict[str, bool]:
    info = dynamic_info or ""
    return {"rpath": "RPATH" in info, "runpath": "RUNPATH" in info}
