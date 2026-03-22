#!/usr/bin/env python3
"""Facade for r2 command execution and header parsing helpers."""

import os
from typing import Any

from ..adapters.validation import (
    validate_r2_data,
)
from ..error_handling.presets import R2_ANALYSIS_POLICY, R2_JSON_DICT_POLICY, R2_JSON_LIST_POLICY
from .r2_command_dispatch import (
    _cmd_fallback,
    _cmdj_fallback,
    _handle_bytes,
    _handle_disasm,
    _handle_search,
    _handle_simple,
    _maybe_use_adapter,
    _parse_address,
    _parse_size,
    _run_cmd_with_timeout,
    _select_json_policy,
    cmd,
    cmd_list,
    cmdj,
    safe_cmd,
    safe_cmd_dict,
    safe_cmd_list,
    safe_cmdj,
    safe_cmdj_any,
)
from .r2_header_parsing import (
    _get_headers_json as _resolve_headers_json,
    _parse_elf_headers_text,
    _parse_key_value_pair,
    _parse_section_header,
    get_elf_headers as _get_elf_headers,
    get_macho_headers as _get_macho_headers,
    get_pe_headers as _get_pe_headers,
    parse_pe_header_text as _parse_pe_header_text,
)


def parse_pe_header_text(r2_instance: Any) -> dict[str, Any] | None:
    return _parse_pe_header_text(r2_instance, safe_cmd)


def get_pe_headers(r2_instance: Any) -> dict[str, Any] | None:
    return _get_pe_headers(r2_instance, safe_cmdj, safe_cmd)


def get_elf_headers(r2_instance: Any) -> list[dict[str, Any]] | None:
    return _get_elf_headers(r2_instance, safe_cmdj, safe_cmd)


def get_macho_headers(r2_instance: Any) -> list[dict[str, Any]] | None:
    return _get_macho_headers(r2_instance, safe_cmdj, safe_cmd)


def _get_headers_json(r2_instance: Any) -> list[dict[str, Any]] | None:
    return _resolve_headers_json(r2_instance, safe_cmdj)
