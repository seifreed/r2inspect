#!/usr/bin/env python3
"""
R2pipe Helper Functions - Simplified Error Handling

This module provides safe wrappers for r2pipe commands using the unified
error handling system. The new system consolidates retry, circuit breaker,
and fallback logic into a single declarative interface.

Copyright (C) 2025 Marc Rivero Lopez

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Author: Marc Rivero Lopez
"""

import json
import os
import threading
from typing import Any, cast

from ..adapters.validation import validate_r2_data
from ..core.constants import SUBPROCESS_TIMEOUT_SECONDS
from ..error_handling import ErrorHandlingStrategy, ErrorPolicy, handle_errors
from ..error_handling.presets import (
    R2_ANALYSIS_POLICY,
    R2_JSON_DICT_POLICY,
    R2_JSON_LIST_POLICY,
    R2_TEXT_POLICY,
)
from ..interfaces import R2CommandInterface
from ..utils.logger import get_logger

logger = get_logger(__name__)


def safe_cmdj(
    r2_instance: R2CommandInterface, command: str, default: Any | None = None
) -> Any | None:
    """
    Safely execute a radare2 JSON command with unified error handling.

    This function uses the new unified error handling system which consolidates
    retry logic and fallback behavior into a single policy.

    Args:
        r2_instance: The r2pipe instance
        command: The radare2 command to execute
        default: Default value to return on error

    Returns:
        JSON result or default value on error
    """
    # Select policy based on command characteristics
    policy = _select_json_policy(command, default)

    @handle_errors(policy)
    def _execute() -> Any:
        raw = _run_cmd_with_timeout(r2_instance, command, default)
        if not isinstance(raw, str) or not raw.strip():
            return default
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return default

    return _execute()


def safe_cmdj_any(
    r2_instance: R2CommandInterface, command: str, default: Any | None = None
) -> Any | None:
    """
    Safely execute a radare2 JSON command using cmdj when available.

    This prefers cmdj() for native JSON output, falling back to safe_cmdj()
    which parses JSON from cmd() output if cmdj fails.
    """
    if hasattr(r2_instance, "cmdj"):
        try:
            return r2_instance.cmdj(command)
        except Exception:
            pass
    return safe_cmdj(r2_instance, command, default)


def _run_cmd_with_timeout(
    r2_instance: R2CommandInterface, command: str, default: Any | None
) -> Any | None:
    result: dict[str, Any] = {"value": default, "done": False}

    def _run() -> None:
        try:
            result["value"] = r2_instance.cmd(command)
        except Exception:
            result["value"] = default
        finally:
            result["done"] = True

    timeout_seconds: float = float(SUBPROCESS_TIMEOUT_SECONDS)
    env_timeout = os.environ.get("R2INSPECT_CMD_TIMEOUT_SECONDS") if "os" in globals() else None
    if env_timeout:
        try:
            timeout_seconds = float(env_timeout)
        except ValueError:
            timeout_seconds = SUBPROCESS_TIMEOUT_SECONDS

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    thread.join(timeout=timeout_seconds)

    if not result["done"]:
        logger.warning("r2 command timed out: %s", command)
        return default

    return result["value"]


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


def _cmd_fallback(_r2: Any, command: str) -> str:
    if _r2 is None or not hasattr(_r2, "cmd"):
        return ""
    return safe_cmd(_r2, command, "")


def _cmdj_fallback(_r2: Any, command: str, default: Any) -> Any:
    if _r2 is None or not hasattr(_r2, "cmd"):
        return default
    return safe_cmdj_any(_r2, command, default)


def cmd(adapter: Any, _r2: Any, command: str) -> str:
    adapter_result = _maybe_use_adapter(adapter, command)
    if isinstance(adapter_result, str):
        return adapter_result
    return _cmd_fallback(_r2, command)


def cmdj(adapter: Any, _r2: Any, command: str, default: Any) -> Any:
    adapter_result = _maybe_use_adapter(adapter, command)
    if adapter_result is not None:
        return adapter_result
    return _cmdj_fallback(_r2, command, default)


def cmd_list(adapter: Any, _r2: Any, command: str) -> list[Any]:
    result = cmdj(adapter, _r2, command, [])
    return result if isinstance(result, list) else []


def _select_json_policy(command: str, default: Any) -> ErrorPolicy:
    """Select appropriate error policy based on command type"""
    command_lower = command.lower().strip()

    # Analysis commands use circuit breaker with retry
    if command_lower.startswith(("aaa", "aac", "af", "a")):
        return R2_ANALYSIS_POLICY

    # List-returning commands
    if isinstance(default, list):
        return R2_JSON_LIST_POLICY

    # Dict-returning commands (most common)
    return R2_JSON_DICT_POLICY


def safe_cmd_list(r2_instance: R2CommandInterface, command: str) -> list[dict[str, Any]]:
    """
    Safely execute a radare2 JSON command expecting a list result.

    Args:
        r2_instance: The r2pipe instance
        command: The radare2 command to execute

    Returns:
        List result or empty list on error
    """
    result = safe_cmdj(r2_instance, command, [])
    return cast(list[dict[str, Any]], validate_r2_data(result, "list"))


def safe_cmd_dict(r2_instance: R2CommandInterface, command: str) -> dict[str, Any]:
    """
    Safely execute a radare2 JSON command expecting a dict result.

    Args:
        r2_instance: The r2pipe instance
        command: The radare2 command to execute

    Returns:
        Dict result or empty dict on error
    """
    result = safe_cmdj(r2_instance, command, {})
    return cast(dict[str, Any], validate_r2_data(result, "dict"))


def safe_cmd(r2_instance: R2CommandInterface, command: str, default: str = "") -> str:
    """
    Safely execute a radare2 command returning text with unified error handling.

    Args:
        r2_instance: The r2pipe instance
        command: The radare2 command to execute
        default: Default value to return on error

    Returns:
        Command result or default value on error
    """

    @handle_errors(R2_TEXT_POLICY)
    def _execute() -> Any:
        return _run_cmd_with_timeout(r2_instance, command, default)

    return cast(str, _execute())


def parse_pe_header_text(r2_instance: R2CommandInterface) -> dict[str, Any] | None:
    """
    Parse PE header text output from ih command.

    The iHj command doesn't exist in r2, so we parse the text output instead.

    Args:
        r2_instance: The r2pipe instance

    Returns:
        Parsed PE header dict or None on error
    """

    @handle_errors(ErrorPolicy(ErrorHandlingStrategy.FALLBACK, fallback_value=None))
    def _parse() -> dict[str, Any] | None:
        text_output = safe_cmd(r2_instance, "ih")
        if not text_output:
            return None

        result: dict[str, Any] = {
            "nt_headers": {},
            "file_header": {},
            "optional_header": {},
        }
        lines = text_output.split("\n")
        current_section = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            current_section = _parse_section_header(line, current_section)
            if current_section and ":" in line:
                _parse_key_value_pair(line, result, current_section)

        return result

    return cast(dict[str, Any] | None, _parse())


def _parse_section_header(line: str, current_section: str | None) -> str | None:
    """Parse section headers from PE header text"""
    if line == "IMAGE_NT_HEADERS":
        return "nt_headers"
    elif line == "IMAGE_FILE_HEADERS":
        return "file_header"
    elif line == "IMAGE_OPTIONAL_HEADERS":
        return "optional_header"
    return current_section


def _parse_key_value_pair(
    line: str, result: dict[str, dict[str, Any]], current_section: str
) -> None:
    """Parse key-value pairs from PE header text"""
    key, value_raw = line.split(":", 1)
    key = key.strip()
    value_str = value_raw.strip()
    parsed_value: str | int = value_str

    # Try to parse hex values
    if value_str.startswith("0x"):
        try:
            parsed_value = int(value_str, 16)
        except ValueError:
            pass

    result[current_section][key] = parsed_value


def get_pe_headers(r2_instance: Any) -> dict[str, Any] | None:
    """
    Get PE headers information. Parse ihj command output into PE header structure.

    Args:
        r2_instance: The r2pipe instance

    Returns:
        PE headers dict or None on error
    """

    @handle_errors(ErrorPolicy(ErrorHandlingStrategy.FALLBACK, fallback_value=None))
    def _get_headers() -> dict[str, Any] | None:
        # Get headers list from ihj
        headers_list = (
            r2_instance.get_headers_json()
            if hasattr(r2_instance, "get_headers_json")
            else safe_cmdj(r2_instance, "ihj", [])
        )

        if not headers_list or not isinstance(headers_list, list):
            # Fallback to parsing text if JSON fails
            return parse_pe_header_text(r2_instance)

        # Parse the list into PE header structure
        result: dict[str, Any] = {
            "nt_headers": {},
            "file_header": {},
            "optional_header": {},
        }

        # Map field names to header sections
        for item in headers_list:
            if not isinstance(item, dict):
                continue

            name = item.get("name", "")
            value = item.get("value", 0)

            # Map to appropriate section based on field name
            if name in [
                "Signature",
                "Machine",
                "NumberOfSections",
                "TimeDateStamp",
                "PointerToSymbolTable",
                "NumberOfSymbols",
                "SizeOfOptionalHeader",
                "Characteristics",
            ]:
                result["file_header"][name] = value
            elif name in [
                "Magic",
                "MajorLinkerVersion",
                "MinorLinkerVersion",
                "SizeOfCode",
                "SizeOfInitializedData",
                "SizeOfUninitializedData",
                "AddressOfEntryPoint",
                "BaseOfCode",
                "BaseOfData",
                "ImageBase",
                "SectionAlignment",
                "FileAlignment",
                "MajorOperatingSystemVersion",
                "MinorOperatingSystemVersion",
                "MajorImageVersion",
                "MinorImageVersion",
                "MajorSubsystemVersion",
                "MinorSubsystemVersion",
                "Win32VersionValue",
                "SizeOfImage",
                "SizeOfHeaders",
                "CheckSum",
                "Subsystem",
                "DllCharacteristics",
                "SizeOfStackReserve",
                "SizeOfStackCommit",
                "SizeOfHeapReserve",
                "SizeOfHeapCommit",
                "LoaderFlags",
                "NumberOfRvaAndSizes",
            ]:
                result["optional_header"][name] = value
            else:
                # Put in nt_headers by default
                result["nt_headers"][name] = value

        return result

    return cast(dict[str, Any] | None, _get_headers())


def get_elf_headers(r2_instance: Any) -> list[dict[str, Any]] | None:
    """
    Get ELF program headers. Use ihj command which exists in r2.

    Args:
        r2_instance: The r2pipe instance

    Returns:
        List of ELF headers or empty list on error
    """

    @handle_errors(ErrorPolicy(ErrorHandlingStrategy.FALLBACK, fallback_value=[]))
    def _get_headers() -> list[dict[str, Any]]:
        # First try the correct JSON command
        headers = _get_headers_json(r2_instance)
        if headers is not None:
            return headers

        ph_output = (
            r2_instance.get_header_text()
            if hasattr(r2_instance, "get_header_text")
            else safe_cmd(r2_instance, "ih")
        )
        if not ph_output:
            return []

        return _parse_elf_headers_text(ph_output)

    return cast(list[dict[str, Any]] | None, _get_headers())


def _get_headers_json(r2_instance: Any) -> list[dict[str, Any]] | None:
    headers = (
        r2_instance.get_headers_json()
        if hasattr(r2_instance, "get_headers_json")
        else safe_cmdj(r2_instance, "ihj", None)
    )
    if not headers:
        return None
    if isinstance(headers, dict):
        return [headers]
    if isinstance(headers, list):
        return headers
    return None


def _parse_elf_headers_text(ph_output: str) -> list[dict[str, Any]]:
    headers: list[dict[str, Any]] = []
    lines = ph_output.split("\n")
    for line in lines:
        line = line.strip()
        if not line or ":" not in line:
            continue
        parts = line.split(":", 1)
        key = parts[0].strip().lower()
        value = parts[1].strip()
        if key in {"type", "flags", "offset", "vaddr", "paddr", "filesz", "memsz"}:
            headers.append({key: value})
    return headers


def get_macho_headers(r2_instance: Any) -> list[dict[str, Any]] | None:
    """
    Get Mach-O load commands. Use ihj command which exists in r2.

    Args:
        r2_instance: The r2pipe instance

    Returns:
        List of Mach-O load commands or empty list on error
    """

    @handle_errors(ErrorPolicy(ErrorHandlingStrategy.FALLBACK, fallback_value=[]))
    def _get_headers() -> list[dict[str, Any]]:
        # First try the correct JSON command
        headers = (
            r2_instance.get_headers_json()
            if hasattr(r2_instance, "get_headers_json")
            else safe_cmdj(r2_instance, "ihj", None)
        )
        if headers:
            # Convert to list format if needed
            if isinstance(headers, dict):
                return [headers]
            elif isinstance(headers, list):
                return headers

        # Fallback: For Mach-O, try text commands
        headers_output = (
            r2_instance.get_header_text()
            if hasattr(r2_instance, "get_header_text")
            else safe_cmd(r2_instance, "ih")
        )

        if not headers_output:
            return []

        # Parse Mach-O specific header format
        # This would need proper parsing based on actual r2 output for Mach-O files
        return []

    return cast(list[dict[str, Any]] | None, _get_headers())
