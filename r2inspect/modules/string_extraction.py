#!/usr/bin/env python3
"""String extraction helpers."""

from __future__ import annotations

from typing import Any

from ..domain.services.binary_helpers import extract_printable_strings


def extract_strings_from_entries(
    entries: list[dict[str, Any]] | None, min_length: int
) -> list[str]:
    if not entries:
        return []
    strings = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        string_val = entry.get("string", "")
        if isinstance(string_val, str) and len(string_val) >= min_length:
            strings.append(string_val)
    return strings


def extract_ascii_from_bytes(data: list[int], min_length: int = 4, limit: int = 50) -> list[str]:
    return extract_printable_strings(data, min_length=min_length, limit=limit)


def split_null_terminated(text: str, min_length: int = 4, limit: int = 50) -> list[str]:
    if not text:
        return []
    parts = [s for s in text.split("\0") if s and len(s) >= min_length]
    return parts[:limit]
