#!/usr/bin/env python3
"""PE info domain helpers."""

from __future__ import annotations

from typing import Any

PE32_PLUS = "PE32+"


def determine_pe_file_type(
    bin_info: dict[str, Any], _filepath: str | None, file_desc: str | None
) -> str:
    file_type = str(bin_info.get("class", "Unknown"))
    if file_type not in {PE32_PLUS, "PE32", "PE", "Unknown"}:
        return file_type

    if file_desc:
        desc = file_desc.lower()
        if "dll" in desc:
            return "DLL"
        if "executable" in desc and "dll" not in desc:
            return "EXE"
        if "driver" in desc or "sys" in desc:
            return "SYS"

    return str(bin_info.get("class", "PE"))


def determine_pe_format(bin_info: dict[str, Any], pe_header: dict[str, Any] | None) -> str:
    format_name = str(bin_info.get("format", "Unknown"))
    if format_name and format_name != "Unknown":
        return format_name

    bits = bin_info.get("bits", 0)
    if bits == 32:
        return "PE32"
    if bits == 64:
        return PE32_PLUS

    if pe_header:
        opt_header = pe_header.get("optional_header", {})
        magic = opt_header.get("Magic", 0)
        if magic == 0x10B:
            return "PE32"
        if magic == 0x20B:
            return PE32_PLUS
    return "PE"


def normalize_pe_format(format_name: str) -> str:
    """Normalize PE format labels to the generic 'PE' bucket."""
    if not format_name or format_name == "Unknown":
        return "PE"
    upper = format_name.upper()
    if "PE" in upper:
        return "PE"
    return format_name


def compute_entry_point(bin_info: dict[str, Any], entry_info: list[dict[str, Any]] | None) -> int:
    entry_point = 0
    if "baddr" in bin_info and "boffset" in bin_info:
        entry_point = bin_info.get("baddr", 0) + bin_info.get("boffset", 0)

    if entry_info:
        entry_point = entry_info[0].get("vaddr", entry_point)

    return entry_point


def apply_optional_header_info(
    info: dict[str, Any], pe_header: dict[str, Any] | None
) -> dict[str, Any]:
    if not pe_header:
        return info

    updated = dict(info)
    opt_header = pe_header.get("optional_header", {})
    image_base = opt_header.get("ImageBase", updated.get("image_base", 0))
    if image_base:
        updated["image_base"] = image_base
    entry_rva = opt_header.get("AddressOfEntryPoint", 0)
    if entry_rva:
        updated["entry_point"] = entry_rva + updated.get("image_base", 0)

    return updated


def characteristics_from_header(
    pe_header: dict[str, Any] | None,
) -> dict[str, bool] | None:
    if not pe_header:
        return None
    file_header = pe_header.get("file_header", {})
    characteristics_flags = file_header.get("Characteristics", 0)
    if not isinstance(characteristics_flags, int):
        return None
    return {
        "is_dll": bool(characteristics_flags & 0x2000),
        "is_executable": bool(characteristics_flags & 0x0002),
    }


def normalize_resource_entries(resources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": resource.get("name", "Unknown"),
            "type": resource.get("type", "Unknown"),
            "size": resource.get("size", 0),
            "lang": resource.get("lang", "Unknown"),
        }
        for resource in resources
    ]


def parse_version_info_text(version_result: str) -> dict[str, str]:
    version_info: dict[str, str] = {}
    for line in version_result.strip().split("\n"):
        if "=" in line:
            key, value = line.split("=", 1)
            version_info[key.strip()] = value.strip()
    return version_info


def characteristics_from_bin(bin_info: dict[str, Any], filepath: str | None) -> dict[str, bool]:
    file_type = bin_info.get("type", "").lower()
    class_type = bin_info.get("class", "").lower()
    path = (filepath or "").lower()

    is_dll = (
        "dll" in file_type
        or "dll" in class_type
        or "dynamic library" in file_type
        or path.endswith(".dll")
    )

    is_executable = (
        "executable" in file_type or "exe" in file_type or path.endswith(".exe") or (not is_dll)
    )

    return {"is_dll": is_dll, "is_executable": is_executable}


def build_subsystem_info(subsystem: str) -> dict[str, Any]:
    info: dict[str, Any] = {"subsystem": subsystem}
    lower = subsystem.lower()
    if "console" in lower:
        info["gui_app"] = False
    elif "windows" in lower:
        info["gui_app"] = True
    else:
        info["gui_app"] = None
    return info
