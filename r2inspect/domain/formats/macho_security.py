#!/usr/bin/env python3
"""Mach-O security domain helpers."""

from __future__ import annotations

from typing import Any

from .symbol_features import any_symbol_name


def is_pie(macho_info: dict[str, Any] | None) -> bool:
    if not macho_info or "bin" not in macho_info:
        return False
    bin_info = macho_info["bin"]
    if not isinstance(bin_info, dict):
        return False
    # r2 surfaces the MH_PIE header flag as bin.pic; this is the real signal for
    # a position-independent Mach-O executable. filetype does not carry it, so a
    # filetype-only check reported pie=False for every PIE executable.
    if bin_info.get("pic"):
        return True
    file_type = bin_info.get("filetype") or ""
    file_upper = file_type.upper()
    return "DYLIB" in file_upper or "PIE" in file_upper


def has_stack_canary(symbols: list[dict[str, Any]] | None) -> bool:
    # r2 surfaces the canary helpers as ``imp.__stack_chk_fail`` (symbols) and
    # ``__stack_chk_guard`` (imports) -- two leading underscores, sometimes an
    # ``imp.`` prefix. The old ``___stack_chk_*`` (three underscores) literal
    # never matched, so stack_canary was False for every Mach-O.
    return any_symbol_name(
        symbols, lambda name: "_stack_chk_fail" in name or "_stack_chk_guard" in name
    )


def has_arc(symbols: list[dict[str, Any]] | None) -> bool:
    # r2 surfaces the ObjC runtime helpers as ``imp.objc_retain...`` /
    # ``imp.objc_storeStrong`` -- no leading underscore on ``objc`` and often an
    # ``imp.`` prefix. The old ``_objc_`` literal never matched, so arc was
    # False for every ARC binary.
    return any_symbol_name(
        symbols,
        lambda name: "objc_" in name
        and ("retain" in name or "release" in name or "storeStrong" in name),
    )


def is_encrypted(bin_info: dict[str, Any] | None) -> bool:
    # r2 reports Mach-O encryption (LC_ENCRYPTION_INFO with cryptid > 0) as the
    # ij.bin/iIj "crypto" boolean. The previous code scanned ihj, which carries
    # the mach header fields (no load-command "type"), so it was always False.
    return bool(bin_info and bin_info.get("crypto"))


def is_signed(load_commands_text: str | None) -> bool:
    # The code-signature load command is not in ihj (mach header fields); it is
    # listed in the load-command dump (iH) as "LC_CODE_SIGNATURE". The previous
    # code matched header["type"] in the ihj list, which never had it.
    return "LC_CODE_SIGNATURE" in str(load_commands_text or "")
