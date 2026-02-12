#!/usr/bin/env python3
"""Shared helpers for detecting binary file types."""

from __future__ import annotations

from typing import Any

from ..adapters.file_system import default_file_system
from .command_helpers import cmd as cmd_helper
from .command_helpers import cmdj as cmdj_helper
from .logger import get_logger

_logger = get_logger(__name__)


def is_pe_file(
    filepath: Any,
    adapter: Any,
    r2_instance: Any,
    *,
    logger: Any | None = None,
) -> bool:
    """Return True if the file appears to be PE based on magic and r2 info."""
    log = logger or _logger

    try:
        if filepath:
            try:
                magic = default_file_system.read_bytes(filepath, size=2)
                if magic == b"MZ":
                    log.debug("Found MZ header - likely PE file")
                    return True
            except Exception as exc:
                log.debug(f"Could not read file magic bytes: {exc}")

        info_text = ""
        try:
            getter = getattr(adapter, "get_info_text", None)
            if callable(getter):
                info_text = getter() or ""
        except Exception as exc:
            log.debug(f"Error retrieving info text: {exc}")
        if info_text and "pe" in info_text.lower():
            log.debug("PE detected via 'i' command")
            return True

        try:
            info_cmd = cmdj_helper(adapter, r2_instance, "ij", {})
            if info_cmd and "bin" in info_cmd:
                bin_info = info_cmd["bin"]
                if _bin_info_has_pe(bin_info):
                    return True
        except Exception as exc:
            log.debug(f"Error with 'ij' command: {exc}")

    except Exception as exc:
        log.error(f"Error checking if file is PE: {exc}")
    return False


def is_elf_file(
    filepath: Any,
    adapter: Any,
    r2_instance: Any,
    *,
    logger: Any | None = None,
) -> bool:
    """Return True if the file appears to be ELF based on magic and r2 info."""
    log = logger or _logger

    try:
        try:
            info_text = cmd_helper(adapter, r2_instance, "i")
            if "elf" in info_text.lower():
                return True
        except Exception as exc:
            log.debug(f"Error with 'i' command: {exc}")

        try:
            info_cmd = cmdj_helper(adapter, r2_instance, "ij", {})
            if info_cmd and "bin" in info_cmd:
                bin_info = info_cmd["bin"]
                if _bin_info_has_elf(bin_info):
                    return True
        except Exception as exc:
            log.debug(f"Error with 'ij' command: {exc}")

        try:
            if filepath:
                magic = default_file_system.read_bytes(filepath, size=4)
                if magic == b"\x7fELF":
                    return True
        except Exception as exc:
            log.debug(f"Failed to read ELF magic bytes: {exc}")

    except Exception as exc:
        log.error(f"Error checking if file is ELF: {exc}")
    return False


def _bin_info_has_pe(bin_info: dict[str, Any]) -> bool:
    bin_format = str(bin_info.get("format", "")).lower()
    if "pe" in bin_format:
        _logger.debug("PE detected via 'ij' format field")
        return True
    bin_class = str(bin_info.get("class", "")).lower()
    if "pe" in bin_class:
        _logger.debug("PE detected via 'ij' class field")
        return True
    return False


def _bin_info_has_elf(bin_info: dict[str, Any]) -> bool:
    for key in ("format", "type", "class"):
        if "elf" in str(bin_info.get(key, "")).lower():
            return True
    return False
