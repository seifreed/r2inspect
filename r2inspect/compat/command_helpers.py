#!/usr/bin/env python3
"""Compatibility wrapper for adapter-aware r2 command helpers."""

from __future__ import annotations

from ..adapters.r2_commands import (
    _handle_bytes,
    _handle_disasm,
    _handle_search,
    _handle_simple,
    _parse_address,
    _parse_size,
    cmd,
    cmd_list,
    cmdj,
)

__all__ = [
    "_handle_bytes",
    "_handle_disasm",
    "_handle_search",
    "_handle_simple",
    "_parse_address",
    "_parse_size",
    "cmd",
    "cmd_list",
    "cmdj",
]
