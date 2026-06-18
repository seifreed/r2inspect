#!/usr/bin/env python3
"""Domain-level helpers shared by analyzers."""

import math
from typing import Any


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    data_len = len(data)
    for count in counts:
        if count:
            p = count / data_len
            entropy -= p * math.log2(p)
    return entropy


def entropy_from_ints(data: list[int]) -> float:
    if not data:
        return 0.0
    valid_bytes = bytes(value for value in data if isinstance(value, int) and 0 <= value <= 255)
    return shannon_entropy(valid_bytes)


def clamp_score(score: int, minimum: int = 0, maximum: int = 100) -> int:
    if score < minimum:
        return minimum
    if score > maximum:
        return maximum
    return score


def count_suspicious_imports(imports: list[dict[str, Any]], suspicious: set[str]) -> int:
    if not isinstance(imports, list):
        return 0
    try:
        suspicious_names = {name for name in suspicious if isinstance(name, str)}
    except TypeError:
        return 0
    return sum(
        1 for imp in imports if isinstance(imp, dict) and imp.get("name") in suspicious_names
    )


def normalize_section_name(name: str | None) -> str:
    return name.lower() if isinstance(name, str) else ""


def clean_function_name(name: str) -> str:
    """Unescape the HTML entities radare2 emits in function names."""
    return name.replace("&nbsp;", " ").replace("&amp;", "&")


def extract_printable_strings(
    data: bytes | list[int], *, min_length: int, limit: int | None = None
) -> list[str]:
    """Collect runs of printable ASCII at least ``min_length`` long from bytes."""
    strings: list[str] = []
    current: list[str] = []
    for byte in data:
        try:
            byte_val = int(byte) if not isinstance(byte, int) else byte
        except (ValueError, TypeError):
            continue
        if 32 <= byte_val <= 126:
            current.append(chr(byte_val))
            continue
        if len(current) >= min_length:
            strings.append("".join(current))
        current = []
    if len(current) >= min_length:
        strings.append("".join(current))
    return strings if limit is None else strings[:limit]


STANDARD_PE_SECTIONS = [
    ".text",
    ".data",
    ".rdata",
    ".bss",
    ".idata",
    ".edata",
    ".rsrc",
    ".reloc",
    ".debug",
    ".pdata",
    ".xdata",
]


def suspicious_section_name_indicator(name: str, suspicious: list[str]) -> str | None:
    if not isinstance(name, str):
        return None
    lowered = name.lower()
    for sus_name in suspicious:
        if not isinstance(sus_name, str):
            continue
        if sus_name in lowered:
            return f"Suspicious section name: {sus_name}"
    return None
