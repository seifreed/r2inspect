#!/usr/bin/env python3
"""Compatibility shim for r2pipe helpers."""

from __future__ import annotations

from ..adapters import validation as _validation
from ..infrastructure import r2_helpers as _impl
from ..infrastructure.r2_helpers import *  # noqa: F401,F403

_handle_bytes = _impl._handle_bytes
_handle_disasm = _impl._handle_disasm
_handle_search = _impl._handle_search
_handle_simple = _impl._handle_simple
_maybe_use_adapter = _impl._maybe_use_adapter
_parse_address = _impl._parse_address
_parse_size = _impl._parse_size
_parse_section_header = _impl._parse_section_header
_parse_key_value_pair = _impl._parse_key_value_pair
_parse_elf_headers_text = _impl._parse_elf_headers_text
_get_headers_json = _impl._get_headers_json
_select_json_policy = _impl._select_json_policy
_run_cmd_with_timeout = _impl._run_cmd_with_timeout
_validate_dict_data = _validation._validate_dict_data
_validate_list_data = _validation._validate_list_data
_clean_list_items = _validation._clean_list_items
cmd = _impl.cmd
cmd_list = _impl.cmd_list
cmdj = _impl.cmdj

__all__ = [name for name in dir(_impl) if not name.startswith("__") and name not in {"_impl"}]
