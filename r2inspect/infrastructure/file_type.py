#!/usr/bin/env python3
"""Shared helpers for detecting binary file types."""

from __future__ import annotations

from typing import Any

from ..adapters.file_system import default_file_system
from .command_helpers import cmd as cmd_helper
from .command_helpers import cmdj as cmdj_helper
from .logging import get_logger

_logger = get_logger(__name__)


def _pe_via_magic(filepath: Any, log: Any) -> bool:
    if not filepath:
        return False
    try:
        if default_file_system.read_bytes(filepath, size=2) == b"MZ":
            log.debug("Found MZ header - likely PE file")
            return True
    except Exception as exc:
        log.debug(f"Could not read file magic bytes: {exc}")
    return False


def _pe_via_info_text(adapter: Any, log: Any) -> bool:
    try:
        getter = getattr(adapter, "get_info_text", None)
        info_text = (getter() or "") if callable(getter) else ""
    except Exception as exc:
        log.debug(f"Error retrieving info text: {exc}")
        return False
    if info_text and "pe" in info_text.lower():
        log.debug("PE detected via 'i' command")
        return True
    return False


def _pe_via_ij(adapter: Any, r2_instance: Any, run_cmdj: Any, log: Any) -> bool:
    try:
        info_cmd = run_cmdj(adapter, r2_instance, "ij", {})
        if info_cmd and "bin" in info_cmd:
            return _bin_info_has_pe(info_cmd["bin"])
    except Exception as exc:
        log.debug(f"Error with 'ij' command: {exc}")
    return False


def is_pe_file(
    filepath: Any,
    adapter: Any,
    r2_instance: Any,
    *,
    logger: Any | None = None,
    cmdj: Any | None = None,
) -> bool:
    """Return True if the file appears to be PE based on magic and r2 info."""
    log = logger or _logger
    run_cmdj = cmdj or cmdj_helper
    try:
        return (
            _pe_via_magic(filepath, log)
            or _pe_via_info_text(adapter, log)
            or _pe_via_ij(adapter, r2_instance, run_cmdj, log)
        )
    except Exception as exc:
        log.error(f"Error checking if file is PE: {exc}")
        return False


def _elf_via_cmd(adapter: Any, r2_instance: Any, run_cmd: Any, log: Any) -> bool:
    try:
        info_text = run_cmd(adapter, r2_instance, "i")
        if "elf" in info_text.lower():
            return True
    except Exception as exc:
        log.debug(f"Error with 'i' command: {exc}")
    return False


def _elf_via_ij(adapter: Any, r2_instance: Any, run_cmdj: Any, log: Any) -> bool:
    try:
        info_cmd = run_cmdj(adapter, r2_instance, "ij", {})
        if info_cmd and "bin" in info_cmd:
            return _bin_info_has_elf(info_cmd["bin"])
    except Exception as exc:
        log.debug(f"Error with 'ij' command: {exc}")
    return False


def _elf_via_magic(filepath: Any, fs: Any, log: Any) -> bool:
    try:
        if filepath and fs.read_bytes(filepath, size=4) == b"\x7fELF":
            return True
    except Exception as exc:
        log.debug(f"Failed to read ELF magic bytes: {exc}")
    return False


def is_elf_file(
    filepath: Any,
    adapter: Any,
    r2_instance: Any,
    *,
    logger: Any | None = None,
    cmd: Any | None = None,
    cmdj: Any | None = None,
    file_system: Any | None = None,
) -> bool:
    """Return True if the file appears to be ELF based on magic and r2 info."""
    log = logger or _logger
    run_cmd = cmd or cmd_helper
    run_cmdj = cmdj or cmdj_helper
    fs = file_system or default_file_system
    try:
        return (
            _elf_via_cmd(adapter, r2_instance, run_cmd, log)
            or _elf_via_ij(adapter, r2_instance, run_cmdj, log)
            or _elf_via_magic(filepath, fs, log)
        )
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
    return any("elf" in str(bin_info.get(key, "")).lower() for key in ("format", "type", "class"))


__all__ = ["is_elf_file", "is_pe_file"]
