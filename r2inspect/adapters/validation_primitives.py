"""Validation primitives for adapter-facing r2pipe data."""

from __future__ import annotations

import re
from typing import Any


def clean_dict_values(data: dict[str, Any]) -> None:
    for key, value in data.items():
        if isinstance(value, str):
            cleaned = value.replace("&nbsp;", " ").replace("&amp;", "&")
            cleaned = cleaned.replace("&lt;", "<").replace("&gt;", ">")
            cleaned = cleaned.replace("&quot;", '"').replace("&#39;", "'")
            if cleaned != value:
                data[key] = cleaned


def clean_list_items(data: list[Any], logger: Any) -> list[dict[str, Any]]:
    cleaned: list[dict[str, Any]] = []
    for idx, item in enumerate(data):
        if isinstance(item, dict):
            clean_dict_values(item)
            cleaned.append(item)
        else:
            logger.debug(
                f"Filtering malformed list item at index {idx}: "
                f"{type(item).__name__} - {str(item)[:100]}"
            )
    return cleaned


def sanitize_output(output: str) -> str:
    if not output:
        return ""
    ansi_escape = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
    output = ansi_escape.sub("", output)
    output = "".join(char for char in output if char.isprintable() or char in "\n\t")
    output = output.strip()
    output = output.replace("&nbsp;", " ").replace("&amp;", "&")
    output = output.replace("&lt;", "<").replace("&gt;", ">")
    output = output.replace("&quot;", '"').replace("&#39;", "'")
    return output


def validate_dict_data(data: Any, logger: Any) -> dict[str, Any]:
    if isinstance(data, dict):
        clean_dict_values(data)
        return data
    logger.debug("Expected dict but received %s: %s", type(data).__name__, str(data)[:100])
    return {}


def validate_list_data(data: Any, logger: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return clean_list_items(data, logger)
    logger.debug("Expected list but received %s: %s", type(data).__name__, str(data)[:100])
    return []


def validate_str_data(data: Any, logger: Any) -> str:
    if isinstance(data, str):
        return sanitize_output(data)
    if isinstance(data, bytes):
        try:
            return sanitize_output(data.decode("utf-8", errors="replace"))
        except Exception as exc:
            logger.debug("Failed to decode bytes to string: %s", exc)
            return ""
    logger.debug("Expected str but received %s: %s", type(data).__name__, str(data)[:100])
    return ""


def validate_bytes_data(data: Any, logger: Any) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        try:
            return data.encode("utf-8")
        except Exception as exc:
            logger.debug("Failed to encode string to bytes: %s", exc)
            return b""
    logger.debug("Expected bytes but received %s", type(data).__name__)
    return b""


def validate_address(address: Any) -> int:
    if isinstance(address, int):
        if address < 0:
            raise ValueError(f"Address cannot be negative: {address}")
        return address
    if isinstance(address, str):
        address = address.strip()
        try:
            result = int(address, 16) if address.startswith(("0x", "0X")) else int(address)
            if result < 0:
                raise ValueError(f"Address cannot be negative: {result}")
            return result
        except ValueError as exc:
            raise ValueError(f"Invalid address format: {address}") from exc
    raise ValueError(f"Address must be int or str, got {type(address).__name__}")


def validate_size(size: Any) -> int:
    if isinstance(size, int):
        if size <= 0:
            raise ValueError(f"Size must be positive: {size}")
        return size
    if isinstance(size, str):
        size = size.strip()
        try:
            result = int(size, 16) if size.startswith(("0x", "0X")) else int(size)
            if result <= 0:
                raise ValueError(f"Size must be positive: {result}")
            return result
        except ValueError as exc:
            raise ValueError(f"Invalid size format: {size}") from exc
    raise ValueError(f"Size must be int or str, got {type(size).__name__}")


def is_valid_response(response: Any) -> bool:
    if response is None:
        return False
    if isinstance(response, dict | list):
        return len(response) > 0
    if isinstance(response, str):
        if not response or response.strip() == "":
            return False
        error_patterns = [
            "Cannot open",
            "File format not recognized",
            "Invalid command",
            "Error:",
            "Failed to",
        ]
        return not any(pattern in response for pattern in error_patterns)
    if isinstance(response, bytes):
        return len(response) > 0
    return True
