#!/usr/bin/env python3
"""
R2Pipe Response Validation and Sanitization

This module provides robust validation and sanitization functions for radare2
command outputs. It ensures data integrity, handles edge cases, and provides
type-safe conversions for r2pipe responses.

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)

Key Functions:
    validate_r2_data: Validates and converts r2 responses to expected types
    sanitize_r2_output: Cleans and normalizes r2 text output
    is_valid_r2_response: Checks if a response is valid and usable

Design Principles:
    - Fail-safe defaults: Return empty collections rather than None
    - Type safety: Ensure responses match expected types
    - Data cleaning: Remove common artifacts and malformed entries
    - Logging: Record validation failures for debugging

Usage:
    >>> from r2inspect.adapters.validation import validate_r2_data
    >>>
    >>> # Validate dictionary response
    >>> data = validate_r2_data(response, "dict")
    >>> assert isinstance(data, dict)
    >>>
    >>> # Validate list response
    >>> items = validate_r2_data(response, "list")
    >>> assert isinstance(items, list)
"""

from typing import Any

from ..utils.logger import get_logger

logger = get_logger(__name__)


def validate_r2_data(
    data: Any, expected_type: str = "dict"
) -> dict[str, Any] | list[dict[str, Any]] | Any:
    """
    Validate and clean r2pipe data to ensure type safety.

    This function performs comprehensive validation of radare2 command outputs,
    ensuring they match expected types and filtering out malformed entries.
    It prevents common runtime errors like 'str' object has no attribute 'get'.

    Args:
        data: The data to validate from r2pipe command
        expected_type: Expected type identifier:
            - "dict": Expects dictionary, returns dict or empty dict
            - "list": Expects list, returns list or empty list
            - "str": Expects string, returns string or empty string
            - "bytes": Expects bytes, returns bytes or empty bytes
            - "any": No validation, returns data as-is

    Returns:
        Validated and cleaned data of the expected type, or appropriate
        default value if validation fails

    Example:
        >>> result = validate_r2_data(r2.cmdj("ij"), "dict")
        >>> assert isinstance(result, dict)
        >>>
        >>> sections = validate_r2_data(r2.cmdj("iSj"), "list")
        >>> assert all(isinstance(s, dict) for s in sections)
    """
    if expected_type == "dict":
        return _validate_dict_data(data)
    elif expected_type == "list":
        return _validate_list_data(data)
    elif expected_type == "str":
        return _validate_str_data(data)
    elif expected_type == "bytes":
        return _validate_bytes_data(data)
    elif expected_type == "any":
        return data
    else:
        logger.warning(f"Unknown expected_type '{expected_type}', returning data as-is")
        return data


def _validate_dict_data(data: Any) -> dict[str, Any]:
    """
    Validate dictionary data.

    Ensures the data is a dictionary and performs cleaning operations
    to remove HTML entities and normalize keys.

    Args:
        data: Data to validate

    Returns:
        Dictionary or empty dict if validation fails
    """
    if isinstance(data, dict):
        # Clean HTML entities from string values
        _clean_dict_values(data)
        return data
    else:
        logger.debug(f"Expected dict but received {type(data).__name__}: {str(data)[:100]}")
        return {}


def _validate_list_data(data: Any) -> list[dict[str, Any]]:
    """
    Validate and clean list data.

    Ensures the data is a list and filters out malformed entries.
    Each list item should be a dictionary; non-dict items are filtered.

    Args:
        data: Data to validate

    Returns:
        List of dictionaries or empty list if validation fails
    """
    if isinstance(data, list):
        return _clean_list_items(data)
    else:
        logger.debug(f"Expected list but received {type(data).__name__}: {str(data)[:100]}")
        return []


def _validate_str_data(data: Any) -> str:
    """
    Validate string data.

    Ensures the data is a string and performs sanitization.

    Args:
        data: Data to validate

    Returns:
        String or empty string if validation fails
    """
    if isinstance(data, str):
        return sanitize_r2_output(data)
    elif isinstance(data, bytes):
        # Convert bytes to string
        try:
            return sanitize_r2_output(data.decode("utf-8", errors="replace"))
        except Exception as e:
            logger.debug(f"Failed to decode bytes to string: {e}")
            return ""
    else:
        logger.debug(f"Expected str but received {type(data).__name__}: {str(data)[:100]}")
        return ""


def _validate_bytes_data(data: Any) -> bytes:
    """
    Validate bytes data.

    Ensures the data is bytes.

    Args:
        data: Data to validate

    Returns:
        Bytes or empty bytes if validation fails
    """
    if isinstance(data, bytes):
        return data
    elif isinstance(data, str):
        # Convert string to bytes
        try:
            return data.encode("utf-8")
        except Exception as e:
            logger.debug(f"Failed to encode string to bytes: {e}")
            return b""
    else:
        logger.debug(f"Expected bytes but received {type(data).__name__}")
        return b""


def _clean_list_items(data: list[Any]) -> list[dict[str, Any]]:
    """
    Clean list items and filter out malformed entries.

    Iterates through list items, validating each as a dictionary and
    performing cleaning operations. Non-dictionary items are filtered out.

    Args:
        data: List to clean

    Returns:
        List containing only valid dictionary items
    """
    cleaned = []
    for idx, item in enumerate(data):
        if isinstance(item, dict):
            _clean_dict_values(item)
            cleaned.append(item)
        else:
            logger.debug(
                f"Filtering malformed list item at index {idx}: "
                f"{type(item).__name__} - {str(item)[:100]}"
            )
    return cleaned


def _clean_dict_values(data: dict[str, Any]) -> None:
    """
    Clean HTML entities and malformed strings from dictionary values.

    Performs in-place cleaning of dictionary values, particularly
    targeting HTML entities commonly found in radare2 output.

    Args:
        data: Dictionary to clean (modified in-place)
    """
    for key, value in data.items():
        if isinstance(value, str):
            # Clean HTML entities
            cleaned = value.replace("&nbsp;", " ").replace("&amp;", "&")
            cleaned = cleaned.replace("&lt;", "<").replace("&gt;", ">")
            cleaned = cleaned.replace("&quot;", '"').replace("&#39;", "'")

            if cleaned != value:
                data[key] = cleaned


def sanitize_r2_output(output: str) -> str:
    """
    Sanitize and normalize radare2 text output.

    Performs comprehensive cleaning of text output from radare2 commands,
    removing control characters, normalizing whitespace, and stripping
    ANSI escape codes.

    Args:
        output: Raw text output from r2pipe command

    Returns:
        Sanitized and normalized text output

    Example:
        >>> raw = "Section .text\\x1b[0m\\n  Size: 0x1000"
        >>> clean = sanitize_r2_output(raw)
        >>> assert "\\x1b" not in clean
    """
    if not output:
        return ""

    # Remove ANSI escape codes
    import re

    ansi_escape = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
    output = ansi_escape.sub("", output)

    # Remove other control characters except newline and tab
    output = "".join(char for char in output if char.isprintable() or char in "\n\t")

    # Normalize whitespace
    output = output.strip()

    # Clean HTML entities (common in r2 output)
    output = output.replace("&nbsp;", " ").replace("&amp;", "&")
    output = output.replace("&lt;", "<").replace("&gt;", ">")
    output = output.replace("&quot;", '"').replace("&#39;", "'")

    return output


def is_valid_r2_response(response: Any) -> bool:
    """
    Check if an r2pipe response is valid and usable.

    Validates that a response from radare2 contains actual data and is
    not an error condition or empty result.

    Args:
        response: Response from r2pipe command

    Returns:
        True if response is valid, False otherwise

    Example:
        >>> response = r2.cmdj("ij")
        >>> if is_valid_r2_response(response):
        ...     process_data(response)
    """
    # None or empty responses are invalid
    if response is None:
        return False

    # Check type-specific validity
    if isinstance(response, dict | list):
        return len(response) > 0
    elif isinstance(response, str):
        # Empty strings or error messages are invalid
        if not response or response.strip() == "":
            return False
        # Check for common r2 error patterns
        error_patterns = [
            "Cannot open",
            "File format not recognized",
            "Invalid command",
            "Error:",
            "Failed to",
        ]
        return not any(pattern in response for pattern in error_patterns)
    elif isinstance(response, bytes):
        return len(response) > 0
    else:
        # For other types, consider non-None as valid
        return True


def validate_address(address: Any) -> int:
    """
    Validate and convert an address value to integer.

    Handles various address formats from radare2 (hex strings, integers)
    and ensures the result is a valid non-negative integer.

    Args:
        address: Address value from r2pipe (int, str, or hex string)

    Returns:
        Valid integer address

    Raises:
        ValueError: If address cannot be converted to valid integer

    Example:
        >>> addr1 = validate_address("0x401000")
        >>> addr2 = validate_address(0x401000)
        >>> assert addr1 == addr2 == 4198400
    """
    if isinstance(address, int):
        if address < 0:
            raise ValueError(f"Address cannot be negative: {address}")
        return address
    elif isinstance(address, str):
        # Try to parse hex or decimal string
        address = address.strip()
        try:
            if address.startswith("0x") or address.startswith("0X"):
                result = int(address, 16)
            else:
                result = int(address)

            if result < 0:
                raise ValueError(f"Address cannot be negative: {result}")
            return result
        except ValueError as e:
            raise ValueError(f"Invalid address format: {address}") from e
    else:
        raise ValueError(f"Address must be int or str, got {type(address).__name__}")


def validate_size(size: Any) -> int:
    """
    Validate and convert a size value to integer.

    Ensures the size is a valid positive integer.

    Args:
        size: Size value from r2pipe (int or str)

    Returns:
        Valid positive integer size

    Raises:
        ValueError: If size cannot be converted to valid positive integer

    Example:
        >>> size1 = validate_size("0x100")
        >>> size2 = validate_size(256)
        >>> assert size1 == size2 == 256
    """
    if isinstance(size, int):
        if size <= 0:
            raise ValueError(f"Size must be positive: {size}")
        return size
    elif isinstance(size, str):
        # Try to parse hex or decimal string
        size = size.strip()
        try:
            result = int(size, 16) if size.startswith("0x") or size.startswith("0X") else int(size)

            if result <= 0:
                raise ValueError(f"Size must be positive: {result}")
            return result
        except ValueError as e:
            raise ValueError(f"Invalid size format: {size}") from e
    else:
        raise ValueError(f"Size must be int or str, got {type(size).__name__}")
