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
    return shannon_entropy(bytes(data))


def clamp_score(score: int, minimum: int = 0, maximum: int = 100) -> int:
    if score < minimum:
        return minimum
    if score > maximum:
        return maximum
    return score


def count_suspicious_imports(imports: list[dict[str, Any]], suspicious: set[str]) -> int:
    return sum(1 for imp in imports if imp.get("name") in suspicious)


def normalize_section_name(name: str | None) -> str:
    return name.lower() if isinstance(name, str) else ""


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
    lowered = name.lower()
    for sus_name in suspicious:
        if sus_name in lowered:
            return f"Suspicious section name: {sus_name}"
    return None
