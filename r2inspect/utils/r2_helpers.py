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

from typing import Any, cast

from ..error_handling import ErrorHandlingStrategy, ErrorPolicy, handle_errors
from ..error_handling.presets import (
    R2_ANALYSIS_POLICY,
    R2_JSON_DICT_POLICY,
    R2_JSON_LIST_POLICY,
    R2_TEXT_POLICY,
)
from .logger import get_logger

logger = get_logger(__name__)


def validate_r2_data(data: Any, expected_type: str = "dict") -> Any:
    """
    Validate and clean r2 data to prevent type errors

    Args:
        data: The data to validate
        expected_type: 'dict' or 'list'

    Returns:
        Cleaned/validated data or appropriate default
    """
    if expected_type == "dict":
        return _validate_dict_data(data)
    elif expected_type == "list":
        return _validate_list_data(data)
    else:
        return data


def _validate_dict_data(data: Any) -> dict[str, Any]:
    """Validate dictionary data"""
    if isinstance(data, dict):
        return data
    else:
        logger.debug(f"Expected dict but got {type(data)}: {data}")
        return {}


def _validate_list_data(data: Any) -> list[dict[str, Any]]:
    """Validate and clean list data"""
    if isinstance(data, list):
        return _clean_list_items(data)
    else:
        logger.debug(f"Expected list but got {type(data)}: {data}")
        return []


def _clean_list_items(data: list[Any]) -> list[dict[str, Any]]:
    """Clean list items and filter out malformed entries"""
    cleaned = []
    for item in data:
        if isinstance(item, dict):
            _clean_html_entities(item)
            cleaned.append(item)
        else:
            logger.debug(f"Filtering out malformed list item: {type(item)} - {item}")
    return cleaned


def _clean_html_entities(item: dict[str, Any]) -> None:
    """Clean HTML entities from item names"""
    if "name" in item and isinstance(item["name"], str):
        item["name"] = item["name"].replace("&nbsp;", " ").replace("&amp;", "&")


def safe_cmdj(r2_instance: Any, command: str, default: Any | None = None) -> Any | None:
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
        return r2_instance.cmdj(command)

    return _execute()


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


def safe_cmd_list(r2_instance: Any, command: str) -> list[dict[str, Any]]:
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


def safe_cmd_dict(r2_instance: Any, command: str) -> dict[str, Any]:
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


def safe_cmd(r2_instance: Any, command: str, default: str = "") -> str:
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
        return r2_instance.cmd(command)

    return cast(str, _execute())


def parse_pe_header_text(r2_instance: Any) -> dict[str, Any] | None:
    """
    Parse PE header text output from ih command.

    The iHj command doesn't exist in r2, so we parse the text output instead.

    Args:
        r2_instance: The r2pipe instance

    Returns:
        Parsed PE header dict or None on error
    """

    @handle_errors(ErrorPolicy(ErrorHandlingStrategy.FALLBACK, fallback_value=None))
    def _parse():
        text_output = safe_cmd(r2_instance, "ih")
        if not text_output:
            return None

        result = {"nt_headers": {}, "file_header": {}, "optional_header": {}}
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
    def _get_headers():
        # Get headers list from ihj
        headers_list = safe_cmdj(r2_instance, "ihj", [])

        if not headers_list or not isinstance(headers_list, list):
            # Fallback to parsing text if JSON fails
            return parse_pe_header_text(r2_instance)

        # Parse the list into PE header structure
        result = {"nt_headers": {}, "file_header": {}, "optional_header": {}}

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
    def _get_headers():
        # First try the correct JSON command
        headers = _get_headers_json(r2_instance)
        if headers is not None:
            return headers

        ph_output = safe_cmd(r2_instance, "ih")
        if not ph_output:
            return []

        return _parse_elf_headers_text(ph_output)

    return cast(list[dict[str, Any]] | None, _get_headers())


def _get_headers_json(r2_instance: Any) -> list[dict[str, Any]] | None:
    headers = safe_cmdj(r2_instance, "ihj", None)
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
        if len(parts) != 2:
            continue
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
    def _get_headers():
        # First try the correct JSON command
        headers = safe_cmdj(r2_instance, "ihj", None)
        if headers:
            # Convert to list format if needed
            if isinstance(headers, dict):
                return [headers]
            elif isinstance(headers, list):
                return headers

        # Fallback: For Mach-O, try text commands
        headers_output = safe_cmd(r2_instance, "ih")

        if not headers_output:
            return []

        # Parse Mach-O specific header format
        # This would need proper parsing based on actual r2 output for Mach-O files
        return []

    return cast(list[dict[str, Any]] | None, _get_headers())


# Legacy compatibility functions
# These maintain backward compatibility with old circuit breaker/retry system


def get_circuit_breaker_stats() -> dict[str, Any]:
    """Get circuit breaker statistics (compatibility wrapper)"""
    from ..error_handling.unified_handler import get_circuit_breaker_stats

    return get_circuit_breaker_stats()


def reset_circuit_breakers():
    """Reset all circuit breakers (compatibility wrapper)"""
    from ..error_handling.unified_handler import reset_circuit_breakers

    reset_circuit_breakers()
    logger.info("All circuit breakers have been reset")


def get_retry_stats() -> dict[str, Any]:
    """
    Get retry statistics (legacy compatibility)

    Note: The new unified error handling system does not track separate
    retry statistics. This function returns circuit breaker stats instead.
    """
    # Compatibility shim: return circuit breaker stats without emitting warnings
    return get_circuit_breaker_stats()


def reset_retry_stats():
    """
    Reset retry statistics (legacy compatibility)

    Note: The new unified error handling system does not have separate
    retry statistics. This resets circuit breakers instead.
    """
    # Compatibility shim: reset circuit breakers without emitting warnings
    reset_circuit_breakers()
