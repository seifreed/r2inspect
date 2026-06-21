#!/usr/bin/env python3
"""PE info domain helpers."""

from __future__ import annotations

from typing import Any

from ...abstractions.coercion_support import coerce_int_or_none, coerce_list

PE32_PLUS = "PE32+"


def find_pe_data_directory(ihj: Any, name: str) -> dict[str, Any] | None:
    """Locate a PE data directory in radare2's structured ``ihj`` field list.

    radare2's ``iDj`` is NOT a data-directory command (it returns ``{}``); the
    directories are exposed in ``ihj`` as two field entries per directory:
    ``IMAGE_DIRECTORY_ENTRY_<NAME>`` (the address) and
    ``SIZE_IMAGE_DIRECTORY_ENTRY_<NAME>`` (the size). ``name`` is the bare
    suffix, e.g. ``"SECURITY"`` or ``"LOAD_CONFIG"``.

    Returns ``{"name", "vaddr", "paddr", "size"}`` or ``None`` when absent. The
    address is kept under both ``vaddr`` and ``paddr``: the SECURITY directory's
    stored address is already a file offset (PE spec), and r2 loads PE images at
    base 0 so RVAs equal the read offset used elsewhere in the codebase.
    """
    addr_key = f"IMAGE_DIRECTORY_ENTRY_{name}"
    size_key = f"SIZE_IMAGE_DIRECTORY_ENTRY_{name}"
    addr: Any = None
    size: Any = None
    for item in coerce_list(ihj):
        if not isinstance(item, dict):
            continue
        field = item.get("name")
        if field == addr_key:
            addr = item.get("value")
        elif field == size_key:
            size = item.get("value")
    address = coerce_int_or_none(addr)
    if address is None or address == 0:
        return None
    return {
        "name": name,
        "vaddr": address,
        "paddr": address,
        "size": coerce_int_or_none(size) or 0,
    }


def determine_pe_file_type(
    bin_info: dict[str, Any], _filepath: str | None, file_desc: str | None
) -> str:
    raw_class = bin_info.get("class", "Unknown")
    file_type = raw_class if isinstance(raw_class, str) and raw_class else "Unknown"
    if file_type not in {PE32_PLUS, "PE32", "PE", "Unknown"}:
        return file_type

    if isinstance(file_desc, str) and file_desc:
        desc = file_desc.lower()
        if "dll" in desc:
            return "DLL"
        if "executable" in desc and "dll" not in desc:
            return "EXE"
        if "driver" in desc or "sys" in desc:
            return "SYS"

    if raw_class == "Unknown":
        return "Unknown"
    return file_type if file_type != "Unknown" else "PE"


def determine_pe_format(bin_info: dict[str, Any], pe_header: dict[str, Any] | None) -> str:
    raw_format = bin_info.get("format", "Unknown")
    format_name = raw_format if isinstance(raw_format, str) and raw_format else "Unknown"
    if format_name and format_name != "Unknown":
        return format_name

    bits = coerce_int_or_none(bin_info.get("bits", 0))
    if bits == 32:
        return "PE32"
    if bits == 64:
        return PE32_PLUS

    if pe_header:
        opt_header = pe_header.get("optional_header", {})
        if not isinstance(opt_header, dict):
            opt_header = {}
        magic = opt_header.get("Magic", 0)
        if magic == 0x10B:
            return "PE32"
        if magic == 0x20B:
            return PE32_PLUS
    return "PE"


def normalize_pe_format(format_name: str) -> str:
    """Normalize PE format labels to the generic 'PE' bucket."""
    if not isinstance(format_name, str) or not format_name or format_name == "Unknown":
        return "PE"
    upper = format_name.upper()
    if "PE" in upper:
        return "PE"
    return format_name


def compute_entry_point(bin_info: dict[str, Any], entry_info: list[dict[str, Any]] | None) -> int:
    entry_point = 0
    if "baddr" in bin_info and "boffset" in bin_info:
        base = coerce_int_or_none(bin_info.get("baddr", 0))
        offset = coerce_int_or_none(bin_info.get("boffset", 0))
        if base is not None and offset is not None:
            entry_point = base + offset

    if entry_info:
        first_entry = entry_info[0]
        if isinstance(first_entry, dict):
            entry_vaddr = coerce_int_or_none(first_entry.get("vaddr", entry_point))
            if entry_vaddr is not None:
                entry_point = entry_vaddr

    return entry_point


def apply_optional_header_info(
    info: dict[str, Any], pe_header: dict[str, Any] | None
) -> dict[str, Any]:
    if not isinstance(pe_header, dict) or not pe_header:
        return info

    updated = dict(info)
    opt_header = pe_header.get("optional_header", {})
    if not isinstance(opt_header, dict):
        return updated
    image_base = coerce_int_or_none(opt_header.get("ImageBase", updated.get("image_base", 0)))
    if image_base is not None and image_base > 0:
        updated["image_base"] = image_base
    entry_rva = coerce_int_or_none(opt_header.get("AddressOfEntryPoint", 0))
    current_image_base = coerce_int_or_none(updated.get("image_base", 0)) or 0
    if entry_rva is not None and entry_rva > 0:
        updated["entry_point"] = entry_rva + current_image_base

    return updated


def characteristics_from_header(
    pe_header: dict[str, Any] | None,
) -> dict[str, bool] | None:
    if not pe_header:
        return None
    file_header = pe_header.get("file_header", {})
    if not isinstance(file_header, dict):
        return None
    characteristics_flags = file_header.get("Characteristics", 0)
    if not isinstance(characteristics_flags, int):
        return None
    return {
        "is_dll": bool(characteristics_flags & 0x2000),
        "is_executable": bool(characteristics_flags & 0x0002),
    }


def normalize_resource_entries(resources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        normalized.append(
            {
                "name": resource.get("name") or "Unknown",
                "type": resource.get("type") or "Unknown",
                "size": resource.get("size") or 0,
                "lang": resource.get("lang") or "Unknown",
            }
        )
    return normalized


def parse_version_info_text(version_result: str) -> dict[str, str]:
    version_info: dict[str, str] = {}
    if not isinstance(version_result, str):
        return version_info
    for line in version_result.strip().split("\n"):
        if "=" in line:
            key, value = line.split("=", 1)
            version_info[key.strip()] = value.strip()
    return version_info


def characteristics_from_bin(bin_info: dict[str, Any], filepath: str | None) -> dict[str, bool]:
    type_value = bin_info.get("type", "")
    class_value = bin_info.get("class", "")
    file_type = type_value.lower() if isinstance(type_value, str) else ""
    class_type = class_value.lower() if isinstance(class_value, str) else ""
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
    subsystem_text = (
        subsystem
        if isinstance(subsystem, str)
        else ("Unknown" if subsystem is None else str(subsystem))
    )
    info: dict[str, Any] = {"subsystem": subsystem_text}
    lower = subsystem_text.lower()
    if "console" in lower:
        info["gui_app"] = False
    elif "windows" in lower:
        info["gui_app"] = True
    else:
        info["gui_app"] = None
    return info
