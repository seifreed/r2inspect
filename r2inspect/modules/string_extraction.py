#!/usr/bin/env python3
"""String extraction helpers."""

from __future__ import annotations

from typing import Any


def extract_strings_from_entries(
    entries: list[dict[str, Any]] | None, min_length: int
) -> list[str]:
    if not entries:
        return []
    strings = []
    for entry in entries:
        string_val = entry.get("string", "")
        if string_val and len(string_val) >= min_length:
            strings.append(string_val)
    return strings


def extract_ascii_from_bytes(data: list[int], min_length: int = 4, limit: int = 50) -> list[str]:
    strings: list[str] = []
    current: list[str] = []

    for byte in data:
        try:
            byte_val = int(byte) if not isinstance(byte, int) else byte
        except (ValueError, TypeError):
            continue

        if 0x20 <= byte_val <= 0x7E:
            current.append(chr(byte_val))
        else:
            if len(current) >= min_length:
                strings.append("".join(current))
            current = []

    if len(current) >= min_length:
        strings.append("".join(current))

    return strings[:limit]


def split_null_terminated(text: str, min_length: int = 4, limit: int = 50) -> list[str]:
    if not text:
        return []
    parts = [s for s in text.split("\0") if s and len(s) >= min_length]
    return parts[:limit]
