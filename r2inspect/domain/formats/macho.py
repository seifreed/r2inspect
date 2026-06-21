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


def _pf_entry(header: dict[str, Any], field_name: str) -> dict[str, Any] | None:
    """Return the named parsed-field (``pf``) entry of an r2 ihj item."""
    pf = header.get("pf")
    if not isinstance(pf, list):
        return None
    for entry in pf:
        if isinstance(entry, dict) and entry.get("name") == field_name:
            return entry
    return None


def _pf_field(header: dict[str, Any], field_name: str) -> Any:
    """Return the value of a named parsed-field (``pf``) entry of an r2 ihj item."""
    entry = _pf_entry(header, field_name)
    return entry.get("value") if entry is not None else None


def format_macho_version(value: Any) -> str:
    """Decode a Mach-O version field (X.Y.Z packed as ``0xXXXXYYZZ``)."""
    if value is None:
        return "Unknown"
    packed = coerce_int_or_none(value)
    if packed is None:
        return "Unknown"
    return f"{(packed >> 16) & 0xFFFF}.{(packed >> 8) & 0xFF}.{packed & 0xFF}"


def format_macho_uuid(values: Any) -> str | None:
    """Format the 16 raw bytes of an LC_UUID ``pf`` field as a canonical UUID."""
    if not isinstance(values, list) or len(values) != 16:
        return None
    try:
        raw = bytes(int(v) & 0xFF for v in values)
    except (TypeError, ValueError):
        return None
    digits = raw.hex()
    return f"{digits[0:8]}-{digits[8:12]}-{digits[12:16]}-{digits[16:20]}-{digits[20:32]}"


def extract_uuid(headers: list[dict[str, Any]]) -> str | None:
    """Return the canonical LC_UUID from r2 ihj load-command items."""
    for header in headers:
        if load_command_type(header) == "LC_UUID":
            entry = _pf_entry(header, "uuid")
            if entry is not None:
                return format_macho_uuid(entry.get("values"))
    return None


def _dylib_subfields(header: dict[str, Any]) -> dict[str, Any]:
    """Flatten the nested ``dylib`` pf sub-struct of an LC_*_DYLIB load command."""
    dylib = _pf_field(header, "dylib")
    result: dict[str, Any] = {}
    if isinstance(dylib, list):
        for entry in dylib:
            if isinstance(entry, dict) and isinstance(entry.get("name"), str):
                result[entry["name"]] = entry.get("value")
    return result


def extract_dylib_info(headers: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract LC_ID_DYLIB name / versions / timestamp from r2 ihj load commands."""
    for header in headers:
        if load_command_type(header) != "LC_ID_DYLIB":
            continue
        sub = _dylib_subfields(header)
        info: dict[str, Any] = {}
        compile_time, raw_timestamp = dylib_timestamp_to_string(
            coerce_int_or_none(sub.get("timestamp")) or 0
        )
        if compile_time:
            info["compile_time"] = compile_time
        if raw_timestamp:
            info["dylib_timestamp"] = str(raw_timestamp)
        name = sub.get("name")
        info["dylib_name"] = name if isinstance(name, str) and name else "Unknown"
        info["dylib_version"] = format_macho_version(sub.get("current_version"))
        info["dylib_compatibility"] = format_macho_version(sub.get("compatibility_version"))
        return info
    return {}


def extract_version_min(headers: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract LC_VERSION_MIN_* min-OS / SDK from r2 ihj load commands."""
    for header in headers:
        header_type = load_command_type(header)
        if "LC_VERSION_MIN" not in header_type:
            continue
        info: dict[str, Any] = {
            "version_min_type": header_type,
            "min_version": format_macho_version(_pf_field(header, "version")),
            # r2 labels the SDK field "reserved" in the version_min pf struct.
            "sdk_version": format_macho_version(_pf_field(header, "reserved")),
        }
        platform = platform_from_version_min(header_type)
        if platform:
            info["platform"] = platform
        return info
    return {}


def extract_build_version(headers: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract LC_BUILD_VERSION platform / min-OS / SDK from r2 ihj load commands."""
    for header in headers:
        if load_command_type(header) != "LC_BUILD_VERSION":
            continue
        platform_entry = _pf_entry(header, "platform")
        platform = platform_entry.get("label") if platform_entry else None
        info: dict[str, Any] = {
            "platform": platform or "Unknown",
            "min_os_version": format_macho_version(_pf_field(header, "minos")),
            "sdk_version": format_macho_version(_pf_field(header, "sdk")),
        }
        if info["sdk_version"] != "Unknown":
            info["sdk_version_info"] = info["sdk_version"]
            estimate = estimate_from_sdk_version(info["sdk_version"])
            if estimate:
                info["compile_time"] = estimate
        return info
    return {}


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
