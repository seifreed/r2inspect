#!/usr/bin/env python3
"""Mach-O parsing helpers."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

SDK_VERSION_MAP = {
    "10.15": "2019",
    "11.0": "2020",
    "12.0": "2021",
    "13.0": "2022",
    "14.0": "2023",
    "15.0": "2024",
}


def estimate_from_sdk_version(sdk_version: str) -> str | None:
    version_match = re.search(r"(\d+\.\d+)", sdk_version)
    if version_match:
        version = version_match.group(1)
        if version in SDK_VERSION_MAP:
            return f"~{SDK_VERSION_MAP[version]} (SDK {sdk_version})"
    return None


def platform_from_version_min(header_type: str) -> str | None:
    if "MACOSX" in header_type:
        return "macOS"
    if "IPHONEOS" in header_type:
        return "iOS"
    if "TVOS" in header_type:
        return "tvOS"
    if "WATCHOS" in header_type:
        return "watchOS"
    return None


def dylib_timestamp_to_string(timestamp: int) -> tuple[str | None, int | None]:
    if not timestamp or timestamp <= 0:
        return None, None
    try:
        compile_date = datetime.fromtimestamp(timestamp)
        return compile_date.strftime("%a %b %d %H:%M:%S %Y"), timestamp
    except Exception:
        return None, timestamp


def build_load_commands(headers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "type": header.get("type", "Unknown"),
            "size": header.get("size", 0),
            "offset": header.get("offset", 0),
            "data": header,
        }
        for header in headers
    ]


def build_sections(sections_info: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": section.get("name", "Unknown"),
            "segment": section.get("segment", "Unknown"),
            "type": section.get("type", "Unknown"),
            "flags": section.get("flags", ""),
            "size": section.get("size", 0),
            "vaddr": section.get("vaddr", 0),
            "paddr": section.get("paddr", 0),
        }
        for section in sections_info
    ]
