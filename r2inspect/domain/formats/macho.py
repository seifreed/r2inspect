#!/usr/bin/env python3
"""Mach-O parsing helpers."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from ...abstractions.coercion_support import coerce_int_or_none

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
        # Forensic build timestamps must be timezone-independent: a naive
        # fromtimestamp() renders in the analyst's local zone, so the same
        # dylib yields a different date on different machines (and lands on the
        # wrong calendar day west of UTC). Pin to UTC like the rest of the
        # codebase's timestamps.
        compile_date = datetime.fromtimestamp(timestamp, UTC)
        return compile_date.strftime("%a %b %d %H:%M:%S %Y UTC"), timestamp
    except (OSError, OverflowError, ValueError):
        return None, timestamp


def _pf_field(header: dict[str, Any], field_name: str) -> Any:
    """Return the value of a named parsed-field (``pf``) entry of an r2 ihj item."""
    pf = header.get("pf")
    if not isinstance(pf, list):
        return None
    for entry in pf:
        if isinstance(entry, dict) and entry.get("name") == field_name:
            return entry.get("value")
    return None


def load_command_type(header: dict[str, Any]) -> str:
    """Extract the ``LC_*`` type from an r2 ihj load-command item.

    r2 does not expose a top-level ``type`` key; it labels the load command via
    the ``pf`` "cmd" field (``label``) and encodes it in ``name`` as
    ``load_command_<n>_LC_<TYPE>``.
    """
    pf = header.get("pf")
    if isinstance(pf, list):
        for entry in pf:
            if isinstance(entry, dict) and entry.get("name") == "cmd":
                label = entry.get("label")
                if isinstance(label, str) and label.startswith("LC_"):
                    return label
    name = header.get("name", "")
    match = re.search(r"LC_[A-Z0-9_]+", name) if isinstance(name, str) else None
    return match.group(0) if match else "Unknown"


def build_load_commands(headers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "type": load_command_type(header),
            "size": coerce_int_or_none(_pf_field(header, "cmdsize"))
            or coerce_int_or_none(header.get("size", 0)),
            "offset": coerce_int_or_none(header.get("paddr", header.get("offset", 0))),
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
            "size": coerce_int_or_none(section.get("size", 0)),
            "vaddr": coerce_int_or_none(section.get("vaddr", 0)),
            "paddr": coerce_int_or_none(section.get("paddr", 0)),
        }
        for section in sections_info
    ]
