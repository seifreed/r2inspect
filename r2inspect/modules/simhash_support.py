"""Helper operations for SimHash analyzer."""

from __future__ import annotations

import re
from typing import Any, cast


def collect_string_features(
    analyzer: Any, strings_data: list[Any], string_features: list[str]
) -> None:
    for string_entry in strings_data:
        if not isinstance(string_entry, dict) or "string" not in string_entry:
            continue
        string_value = string_entry["string"]
        if len(string_value) < analyzer.min_string_length:
            continue
        if not analyzer._is_useful_string(string_value):
            continue
        analyzer._add_string_feature_set(string_features, string_value)


def add_string_feature_set(analyzer: Any, string_features: list[str], string_value: str) -> None:
    string_features.append(f"STR:{string_value}")
    length_category = analyzer._get_length_category(len(string_value))
    string_features.append(f"STRLEN:{length_category}")
    string_type = analyzer._classify_string_type(string_value)
    if string_type:
        string_features.append(f"STRTYPE:{string_type}")


def append_data_section_string(analyzer: Any, section: Any, data_strings: list[str]) -> None:
    if not isinstance(section, dict) or not section.get("name", "").startswith(".data"):
        return
    section_addr = section.get("vaddr", 0)
    section_size = section.get("size", 0)
    if not (section_addr and section_size):
        return
    if analyzer.adapter is None or not hasattr(analyzer.adapter, "read_bytes"):
        return
    data = analyzer.adapter.read_bytes(section_addr, min(section_size, 1024))
    for value in analyzer._extract_printable_strings(data):
        data_strings.append(f"DATASTR:{value}")


def is_useful_string(string_value: str) -> bool:
    if not string_value:
        return False
    useless_patterns = [
        r"^\s*$",
        r"^[0-9]+$",
        r"^[a-f0-9]{8,}$",
    ]
    for pattern in useless_patterns:
        if re.match(pattern, string_value, re.IGNORECASE):
            return False
    printable_ratio = sum(1 for c in string_value if c.isprintable()) / len(string_value)
    return printable_ratio > 0.8


def find_similar_functions(
    simhash_available: bool,
    simhash_type: Any,
    function_features: dict[str, dict[str, Any]],
    max_distance: int,
    build_similarity_groups: Any,
) -> list[dict[str, Any]]:
    if not simhash_available:
        return []

    def _distance(left_hash: int, right_hash: int) -> int:
        return cast(int, simhash_type(left_hash).distance(simhash_type(right_hash)))

    return cast(
        list[dict[str, Any]],
        build_similarity_groups(
            function_features,
            max_distance=max_distance,
            distance_fn=_distance,
        ),
    )


def calculate_similarity(
    analyzer: Any,
    simhash_available: bool,
    simhash_type: Any,
    other_simhash_value: int,
    hash_type: str,
    interpret_similarity_distance: Any,
) -> dict[str, Any]:
    if not simhash_available:
        return {"error": "simhash library not available"}
    results = analyzer.analyze()
    if not results.get("available"):
        return {"error": "SimHash analysis not available"}
    current_hash = None
    if hash_type == "combined" and results.get("combined_simhash"):
        current_hash = results["combined_simhash"]["hash"]
    elif hash_type == "combined" and results.get("hash_value"):
        hash_value = results["hash_value"]
        current_hash = int(hash_value, 16) if isinstance(hash_value, str) else hash_value
    elif hash_type == "strings" and results.get("strings_simhash"):
        current_hash = results["strings_simhash"]["hash"]
    elif hash_type == "opcodes" and results.get("opcodes_simhash"):
        current_hash = results["opcodes_simhash"]["hash"]
    if current_hash is None:
        return {"error": f"No {hash_type} SimHash available"}
    current_simhash = simhash_type(current_hash)
    other_simhash = simhash_type(other_simhash_value)
    distance = current_simhash.distance(other_simhash)
    return {
        "distance": distance,
        "similarity_level": interpret_similarity_distance(distance),
        "current_hash": hex(current_hash),
        "other_hash": hex(other_simhash_value),
        "hash_type": hash_type,
    }
