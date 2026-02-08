#!/usr/bin/env python3
"""Helper functions for packer detection."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .domain_helpers import shannon_entropy


def find_packer_signature(
    search_hex_fn: Callable[[str], str], packer_signatures: dict[str, list[bytes]]
) -> dict[str, str] | None:
    for packer_name, signatures in packer_signatures.items():
        for signature in signatures:
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
        string_val = string_info.get("string", "").lower()
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

    high_entropy_sections = 0
    total_sections = len(sections)

    for section in sections:
        section_name = str(section.get("name", "unknown"))
        entropy = calculate_section_entropy(read_bytes_fn, section)

        entropy_info[section_name] = {
            "entropy": entropy,
            "size": section.get("size", 0),
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
        vaddr = section.get("vaddr", 0)
        size = section.get("size", 0)

        if size == 0 or size > 10000000:
            return 0.0

        data = read_bytes_fn(vaddr, size) if size else b""
        if not data:
            return 0.0

        return shannon_entropy(data)
    except Exception:
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

    section_info["section_count"] = len(sections)
    for section in sections:
        update_section_info(section_info, section)
    return section_info


def update_section_info(section_info: dict[str, Any], section: dict[str, Any]) -> None:
    name = str(section.get("name", ""))
    flags = str(section.get("flags", ""))
    size = section.get("size", 0)

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
    return len(imports) if imports else 0


def overlay_info(
    file_info: dict[str, Any] | None, sections: list[dict[str, Any]] | None
) -> dict[str, Any]:
    if not file_info or "bin" not in file_info:
        return {}
    bin_info = file_info["bin"]
    file_size = bin_info.get("size", 0)
    if not sections:
        return {}

    last_section_end = 0
    for section in sections:
        section_end = section.get("vaddr", 0) + section.get("size", 0)
        last_section_end = max(last_section_end, section_end)

    overlay_size = file_size - last_section_end
    return {
        "has_overlay": overlay_size > 0,
        "overlay_size": overlay_size,
        "overlay_ratio": overlay_size / file_size if file_size > 0 else 0,
    }


def _search_signature_hex(search_hex_fn: Callable[[str], str], hex_sig: str) -> bool:
    result = search_hex_fn(hex_sig)
    return bool(result and result.strip())
