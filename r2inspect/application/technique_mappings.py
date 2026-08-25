"""Small, explicit ATT&CK and MBC mappings for normalized findings."""

from __future__ import annotations

from typing import Final

MAPPINGS: Final[dict[str, tuple[tuple[str, ...], tuple[str, ...]]]] = {
    "packer": (("T1027",), ("F0001",)),
    "crypto": (("T1027.013",), ("F0005",)),
    "anti.analysis": (("T1497", "T1622"), ("B0004",)),
    "anti.debug": (("T1622",), ("B0001",)),
    "anti.vm": (("T1497.001",), ("B0002",)),
    "anti.sandbox": (("T1497.001",), ("B0003",)),
    "yara.match": ((), ()),
}


def map_techniques(category: str, rule_id: str = "") -> tuple[list[str], list[str]]:
    normalized = f"{category}.{rule_id}".lower().replace("_", ".")
    for key, mapping in MAPPINGS.items():
        if key in normalized:
            return list(mapping[0]), list(mapping[1])
    return [], []


__all__ = ["map_techniques"]
