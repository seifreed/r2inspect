#!/usr/bin/env python3
"""Compatibility shim for r2 command helpers."""

from __future__ import annotations

from ..adapters import r2_commands as _impl
from ..adapters.r2_commands import *  # noqa: F401,F403

_handle_bytes = _impl._handle_bytes
_handle_disasm = _impl._handle_disasm
_handle_search = _impl._handle_search
_handle_simple = _impl._handle_simple
_parse_address = _impl._parse_address
_parse_size = _impl._parse_size
cmd = _impl.cmd
cmd_list = _impl.cmd_list
cmdj = _impl.cmdj
safe_cmd = _impl.safe_cmd
safe_cmd_dict = _impl.safe_cmd_dict
safe_cmdj = _impl.safe_cmdj
safe_cmd_list = _impl.safe_cmd_list

__all__ = getattr(_impl, "__all__", [])
