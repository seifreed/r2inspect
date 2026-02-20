#!/usr/bin/env python3
"""Adapter-level r2 command helpers."""

from __future__ import annotations

from ..infrastructure import r2_helpers as _impl
from ..infrastructure.r2_helpers import *  # noqa: F401,F403

_handle_bytes = _impl._handle_bytes
_handle_disasm = _impl._handle_disasm
_handle_search = _impl._handle_search
_handle_simple = _impl._handle_simple
_parse_address = _impl._parse_address
_parse_size = _impl._parse_size
_SIMPLE_BASE_CALLS = _impl._SIMPLE_BASE_CALLS
cmd = _impl.cmd
cmd_list = _impl.cmd_list
cmdj = _impl.cmdj

for _name in dir(_impl):
    if _name.startswith("_") and not _name.startswith("__"):
        globals().setdefault(_name, getattr(_impl, _name))

__all__ = [name for name in dir(_impl) if not name.startswith("__") and name not in {"_impl"}]
