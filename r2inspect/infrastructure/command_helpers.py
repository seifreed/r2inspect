#!/usr/bin/env python3
"""Canonical adapter-aware command helpers.

Thin re-export layer over r2_command_dispatch — keeps import paths stable
for callers while the dispatch implementation can evolve independently.
"""

from __future__ import annotations

from .r2_command_dispatch import (
    _handle_bytes,
    _handle_disasm,
    _handle_search,
    _handle_simple,
    _maybe_use_adapter,
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
    "_maybe_use_adapter",
    "_parse_address",
    "_parse_size",
    "cmd",
    "cmd_list",
    "cmdj",
]
