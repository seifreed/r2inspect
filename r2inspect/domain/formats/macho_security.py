#!/usr/bin/env python3
"""Mach-O security domain helpers."""

from __future__ import annotations

from typing import Any


def is_pie(macho_info: dict[str, Any] | None) -> bool:
    if not macho_info or "bin" not in macho_info:
        return False
    file_type = macho_info["bin"].get("filetype", "")
    file_upper = file_type.upper()
    return "DYLIB" in file_upper or "PIE" in file_upper


def has_stack_canary(symbols: list[dict[str, Any]] | None) -> bool:
    for symbol in symbols or []:
        name = symbol.get("name", "")
        if "___stack_chk_fail" in name or "___stack_chk_guard" in name:
            return True
    return False


def has_arc(symbols: list[dict[str, Any]] | None) -> bool:
    for symbol in symbols or []:
        name = symbol.get("name", "")
        if "_objc_" in name and ("retain" in name or "release" in name):
            return True
    return False


def is_encrypted(headers: list[dict[str, Any]] | None) -> bool:
    for header in headers or []:
        if header.get("type") in {"LC_ENCRYPTION_INFO", "LC_ENCRYPTION_INFO_64"}:
            return int(header.get("cryptid", 0)) > 0
    return False


def is_signed(headers: list[dict[str, Any]] | None) -> bool:
    for header in headers or []:
        if header.get("type") == "LC_CODE_SIGNATURE":
            return True
    return False
