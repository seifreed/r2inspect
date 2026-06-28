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


_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

# ASCII control codes that ``str.isprintable()`` rejects, minus the tab and
# newline the sanitizer keeps. For pure-ASCII text, deleting exactly these via
# ``str.translate`` reproduces ``isprintable() or char in "\n\t"`` at C speed,
# avoiding a Python-level ``isprintable()`` call per character on every r2
# response (the dominant non-r2 CPU cost on large binaries).
_ASCII_CONTROL_DELETE: dict[int, None] = {cp: None for cp in range(0x20) if cp not in (0x09, 0x0A)}
_ASCII_CONTROL_DELETE[0x7F] = None


def _strip_nonprintable(output: str) -> str:
    if output.isascii():
        return output.translate(_ASCII_CONTROL_DELETE)
    return "".join(char for char in output if char.isprintable() or char in "\n\t")


def sanitize_output(output: str) -> str:
    if not output:
        return ""
    output = _ANSI_ESCAPE.sub("", output)
    output = _strip_nonprintable(output)
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


def _parse_int_value(value: Any, *, label: str, allow_zero: bool) -> int:
    if isinstance(value, int):
        parsed = value
        from_string = False
    elif isinstance(value, str):
        value = value.strip()
        try:
            parsed = int(value, 16) if value.startswith(("0x", "0X")) else int(value)
        except ValueError as exc:
            raise ValueError(f"Invalid {label} format: {value}") from exc
        from_string = True
    else:
        raise ValueError(f"{label.capitalize()} must be int or str, got {type(value).__name__}")

    if parsed < 0 or (not allow_zero and parsed == 0):
        if from_string:
            raise ValueError(f"Invalid {label} format: {value}")
        comparator = "cannot be negative" if allow_zero else "must be positive"
        raise ValueError(f"{label.capitalize()} {comparator}: {parsed}")
    return parsed


def validate_address(address: Any) -> int:
    return _parse_int_value(address, label="address", allow_zero=True)


def validate_size(size: Any) -> int:
    return _parse_int_value(size, label="size", allow_zero=False)


def _has_payload(response: Any) -> bool:
    return bool(response)


def is_valid_response(response: Any) -> bool:
    if response is None:
        return False
    if isinstance(response, dict | list):
        return _has_payload(response)
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
        return _has_payload(response)
    return True
