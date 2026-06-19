#!/usr/bin/env python3
"""Helper functions for packer detection."""

from __future__ import annotations

from collections.abc import Callable
from collections.abc import Iterable
import logging
from typing import Any

from ...abstractions.coercion_support import coerce_int
from .binary_helpers import shannon_entropy

logger = logging.getLogger(__name__)


def find_packer_signature(
    search_hex_fn: Callable[[str], str], packer_signatures: dict[str, list[bytes]]
) -> dict[str, str] | None:
    if not isinstance(packer_signatures, dict):
        return None
    for packer_name, signatures in packer_signatures.items():
        if not isinstance(signatures, (list, tuple, set)):
            continue
        for signature in signatures:
            if not isinstance(signature, (bytes, bytearray)):
                continue
            if _search_signature_hex(search_hex_fn, signature.hex()):
                return {
                    "type": packer_name,
                    "signature": signature.decode("utf-8", errors="ignore"),
                }
    return None


def find_packer_string(
    strings_result: list[dict[str, Any]] | None,
    packer_signatures: dict[str, list[bytes]],
) -> dict[str, str] | None:
    if not strings_result:
        return None
    for string_info in strings_result:
        if not isinstance(string_info, dict):
            continue
        string_value = string_info.get("string", "")
        if not isinstance(string_value, str):
            continue
        string_val = string_value.lower()
        for packer_name in packer_signatures:
            if packer_name.lower() in string_val:
                return {"type": packer_name, "signature": string_val}
    return None


def analyze_entropy(
    sections: list[dict[str, Any]] | None,
    read_bytes_fn: Callable[[int, int], bytes],
    entropy_threshold: float,
) -> dict[str, Any]:
    entropy_info: dict[str, Any] = {}
    if not sections:
        return entropy_info

    valid_sections = [section for section in sections if isinstance(section, dict)]
    high_entropy_sections = 0
    total_sections = len(valid_sections)

    for section in valid_sections:
        section_name = section.get("name") or "unknown"
        entropy = calculate_section_entropy(read_bytes_fn, section)

        entropy_info[section_name] = {
            "entropy": entropy,
            "size": coerce_int(section.get("size")),
            "high_entropy": entropy > entropy_threshold,
        }

        if entropy > entropy_threshold:
            high_entropy_sections += 1

    entropy_info["summary"] = {
        "high_entropy_sections": high_entropy_sections,
        "total_sections": total_sections,
        "high_entropy_ratio": high_entropy_sections / total_sections if total_sections > 0 else 0,
    }
    return entropy_info


def calculate_section_entropy(
    read_bytes_fn: Callable[[int, int], bytes], section: dict[str, Any]
) -> float:
    try:
        vaddr = coerce_int(section.get("vaddr"))
        size = coerce_int(section.get("size"))

        if size == 0 or size > 50000000:
            return 0.0

        data = read_bytes_fn(vaddr, size) if size else b""
        if not data:
            return 0.0

        return shannon_entropy(data)
    except Exception as exc:
        logger.error("Error calculating section entropy: %s", exc)
        return 0.0


def analyze_sections(sections: list[dict[str, Any]] | None) -> dict[str, Any]:
    section_info = {
        "suspicious_sections": [],
        "section_count": 0,
        "executable_sections": 0,
        "writable_executable": 0,
    }

    if not sections:
        return section_info

    valid_sections = [section for section in sections if isinstance(section, dict)]
    section_info["section_count"] = len(valid_sections)
    for section in valid_sections:
        update_section_info(section_info, section)
    return section_info


def update_section_info(section_info: dict[str, Any], section: dict[str, Any]) -> None:
    name = section.get("name") or ""
    flags = str(section.get("flags") or "")
    size = coerce_int(section.get("size"))

    if "x" in flags:
        section_info["executable_sections"] += 1
        if "w" in flags:
            section_info["writable_executable"] += 1
            section_info["suspicious_sections"].append(
                {"name": name, "reason": "Writable and executable", "flags": flags}
            )

    if is_suspicious_section_name(name):
        section_info["suspicious_sections"].append(
            {"name": name, "reason": "Suspicious section name", "flags": flags}
        )

    if size < 100:
        section_info["suspicious_sections"].append(
            {"name": name, "reason": "Very small section", "size": size}
        )
    elif size > 10000000:
        section_info["suspicious_sections"].append(
            {"name": name, "reason": "Very large section", "size": size}
        )


def is_suspicious_section_name(name: str) -> bool:
    suspicious_names = [".upx", ".aspack", ".themida", ".vmp", ".packed"]
    return isinstance(name, str) and any(sus_name in name.lower() for sus_name in suspicious_names)


def count_imports(imports: list[dict[str, Any]] | None) -> int:
    if isinstance(imports, list):
        return len(imports)
    if isinstance(imports, (dict, str, bytes)) or not isinstance(imports, Iterable):
        return 0
    return sum(1 for imp in imports if isinstance(imp, dict))


def overlay_info(
    file_info: dict[str, Any] | None, sections: list[dict[str, Any]] | None
) -> dict[str, Any]:
    if not file_info:
        return {}
    # The overlay lives in the file after the last section's on-disk data, so
    # this must work in file space: the total file size is r2's core.size (not
    # bin.size, which is absent for PE), and each section ends at paddr + size
    # (its file offset), not vaddr + size (a virtual address far larger than
    # the file, which made overlay_size always negative).
    core_info = file_info.get("core", {})
    file_size = coerce_int(core_info.get("size") if isinstance(core_info, dict) else 0)
    if not sections or not file_size:
        return {}

    last_section_end = 0
    for section in sections:
        if not isinstance(section, dict):
            continue
        section_end = coerce_int(section.get("paddr")) + coerce_int(section.get("size"))
        last_section_end = max(last_section_end, section_end)

    overlay_size = file_size - last_section_end
    return {
        "has_overlay": overlay_size > 0,
        "overlay_size": overlay_size,
        "overlay_ratio": overlay_size / file_size if file_size > 0 else 0,
    }


def _search_signature_hex(search_hex_fn: Callable[[str], str], hex_sig: str) -> bool:
    result = search_hex_fn(hex_sig)
    return bool(isinstance(result, str) and result.strip())
