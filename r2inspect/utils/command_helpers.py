#!/usr/bin/env python3
"""Shared command helpers for adapter-backed r2 access."""

from __future__ import annotations

from typing import Any


def _parse_address(command: str) -> tuple[str, int | None]:
    if "@" not in command:
        return command.strip(), None
    base, address_text = command.split("@", 1)
    base = base.strip()
    address_text = address_text.strip()
    if not address_text:
        return base, None
    try:
        return base, int(address_text, 0)
    except ValueError:
        return base, None


def _parse_size(base: str) -> int | None:
    parts = base.split()
    if len(parts) <= 1:
        return None
    try:
        return int(parts[1], 0)
    except ValueError:
        return None


def _handle_search(adapter: Any, command: str) -> Any | None:
    if command.startswith("/xj ") and hasattr(adapter, "search_hex_json"):
        return adapter.search_hex_json(command[4:].strip())
    if command.startswith("/c ") and hasattr(adapter, "search_text"):
        return adapter.search_text(command[3:].strip())
    if command.startswith("/x ") and hasattr(adapter, "search_hex"):
        return adapter.search_hex(command[3:].strip())
    return None


_SIMPLE_BASE_CALLS: dict[str, str] = {
    "aaa": "analyze_all",
    "i": "get_info_text",
    "id": "get_dynamic_info_text",
    "p=e 100": "get_entropy_pattern",
    "iR~version": "get_pe_version_info_text",
    "iHH": "get_pe_security_text",
    "izz~..": "get_strings_text",
    "izzj": "get_strings",
    "izj": "get_strings_basic",
    "iij": "get_imports",
    "iEj": "get_exports",
    "iSj": "get_sections",
    "isj": "get_symbols",
    "ij": "get_file_info",
    "iej": "get_entry_info",
    "ihj": "get_headers_json",
    "iHj": "get_pe_optional_header",
    "iDj": "get_data_directories",
    "iRj": "get_resources_info",
    "afl": "get_functions",
}


def _handle_simple(adapter: Any, base: str, command: str, address: int | None) -> Any | None:
    if base.startswith("iz~") and hasattr(adapter, "get_strings_filtered"):
        return adapter.get_strings_filtered(command)
    if base == "aflj":
        if address is not None and hasattr(adapter, "get_functions_at"):
            return adapter.get_functions_at(address)
        if hasattr(adapter, "get_functions"):
            return adapter.get_functions()
    if base.startswith("afij") and address is not None and hasattr(adapter, "get_function_info"):
        return adapter.get_function_info(address)
    method_name = _SIMPLE_BASE_CALLS.get(base)
    if method_name and hasattr(adapter, method_name):
        return getattr(adapter, method_name)()
    return None


def _handle_disasm(adapter: Any, base: str, address: int | None) -> Any | None:
    if base.startswith("pdfj") and hasattr(adapter, "get_disasm"):
        return adapter.get_disasm(address=address)
    if base.startswith("pdj") and hasattr(adapter, "get_disasm"):
        return adapter.get_disasm(address=address, size=_parse_size(base))
    if base.startswith("pi") and hasattr(adapter, "get_disasm_text"):
        return adapter.get_disasm_text(address=address, size=_parse_size(base))
    if base.startswith("agj") and hasattr(adapter, "get_cfg"):
        return adapter.get_cfg(address=address)
    return None


def _handle_bytes(adapter: Any, base: str, address: int | None) -> Any | None:
    if address is None:
        return None
    if base.startswith("p8j") and hasattr(adapter, "read_bytes_list"):
        size = _parse_size(base)
        return adapter.read_bytes_list(address, size) if size is not None else None
    if base.startswith("p8") and hasattr(adapter, "read_bytes"):
        size = _parse_size(base)
        if size is None:
            return None
        data = adapter.read_bytes(address, size)
        return data.hex() if data else ""
    if base.startswith("pxj") and hasattr(adapter, "read_bytes_list"):
        size = _parse_size(base)
        return adapter.read_bytes_list(address, size) if size is not None else None
    return None


def _maybe_use_adapter(adapter: Any, command: str) -> Any | None:
    if adapter is None:
        return None
    search_result = _handle_search(adapter, command)
    if search_result is not None:
        return search_result
    base, address = _parse_address(command)
    simple_result = _handle_simple(adapter, base, command, address)
    if simple_result is not None:
        return simple_result
    disasm_result = _handle_disasm(adapter, base, address)
    if disasm_result is not None:
        return disasm_result
    bytes_result = _handle_bytes(adapter, base, address)
    if bytes_result is not None:
        return bytes_result
    return None


def cmd(adapter: Any, _r2: Any, command: str) -> str:
    adapter_result = _maybe_use_adapter(adapter, command)
    return adapter_result if isinstance(adapter_result, str) else ""


def cmdj(adapter: Any, _r2: Any, command: str, default: Any) -> Any:
    adapter_result = _maybe_use_adapter(adapter, command)
    if adapter_result is not None:
        return adapter_result
    return default


def cmd_list(adapter: Any, _r2: Any, command: str) -> list[Any]:
    result = cmdj(adapter, _r2, command, [])
    return result if isinstance(result, list) else []
