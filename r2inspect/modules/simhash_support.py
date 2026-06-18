"""Helper operations for SimHash analyzer.

The analyzer-facing helpers are Template-Methods over the SimHash analyzer's
overridable steps, so they depend on the explicit :class:`SimHashHost`
protocol (shared with ``simhash_data_access_support`` and
``simhash_features``) rather than an untyped host.
"""

from __future__ import annotations

import re
from typing import Any, Protocol, cast

from ..interfaces.binary_analyzer import BinaryAnalyzerInterface


def _to_int(value: Any) -> int | None:
    try:
        if isinstance(value, str):
            return int(value, 0)
        return int(value or 0)
    except (TypeError, ValueError):
        return None


class SimHashHost(Protocol):
    """Overridable collaboration contract the SimHash helpers depend on."""

    min_string_length: int
    max_instructions_per_function: int
    adapter: BinaryAnalyzerInterface | None

    def analyze(self) -> dict[str, Any]: ...
    def _cmd_list(self, command: str) -> list[Any]: ...
    def _is_useful_string(self, string_value: str) -> bool: ...
    def _add_string_feature_set(self, string_features: list[str], string_value: str) -> None: ...
    def _get_length_category(self, length: int) -> str: ...
    def _classify_string_type(self, string_value: str) -> str | None: ...
    def _extract_printable_strings(self, data: bytes) -> list[str]: ...
    def _get_strings_data(self) -> list[Any]: ...
    def _collect_string_features(
        self, strings_data: list[Any], string_features: list[str]
    ) -> None: ...
    def _extract_data_section_strings(self) -> list[str]: ...
    def _get_functions(self) -> list[Any]: ...
    def _extract_function_opcodes(self, func_addr: int, func_name: str) -> list[str]: ...
    def _extract_ops_from_disasm(self, disasm: Any) -> list[Any]: ...
    def _extract_opcodes_from_ops(self, ops: list[Any]) -> list[str]: ...


def collect_string_features(
    host: SimHashHost, strings_data: list[Any], string_features: list[str]
) -> None:
    for string_entry in strings_data:
        if not isinstance(string_entry, dict) or "string" not in string_entry:
            continue
        string_value = string_entry["string"]
        if not isinstance(string_value, str):
            continue
        if len(string_value) < host.min_string_length:
            continue
        if not host._is_useful_string(string_value):
            continue
        host._add_string_feature_set(string_features, string_value)


def add_string_feature_set(
    host: SimHashHost, string_features: list[str], string_value: str
) -> None:
    string_features.append(f"STR:{string_value}")
    length_category = host._get_length_category(len(string_value))
    string_features.append(f"STRLEN:{length_category}")
    string_type = host._classify_string_type(string_value)
    if string_type:
        string_features.append(f"STRTYPE:{string_type}")


def append_data_section_string(host: SimHashHost, section: Any, data_strings: list[str]) -> None:
    if not isinstance(section, dict):
        return
    section_name = section.get("name", "")
    if not isinstance(section_name, str) or not section_name.startswith(".data"):
        return
    section_addr = _to_int(section.get("vaddr", 0))
    section_size = _to_int(section.get("size", 0))
    if section_addr is None or section_size is None:
        return
    if not (section_addr and section_size):
        return
    if host.adapter is None or not hasattr(host.adapter, "read_bytes"):
        return
    data = host.adapter.read_bytes(section_addr, min(section_size, 1024))
    for value in host._extract_printable_strings(data):
        data_strings.append(f"DATASTR:{value}")


def is_useful_string(string_value: str) -> bool:
    if not isinstance(string_value, str) or not string_value:
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


def _resolve_current_hash(results: dict[str, Any], hash_type: str) -> int | None:
    if hash_type == "combined":
        if results.get("combined_simhash"):
            return cast(int, results["combined_simhash"]["hash"])
        hash_value = results.get("hash_value")
        if hash_value:
            return int(hash_value, 16) if isinstance(hash_value, str) else cast(int, hash_value)
        return None
    section = results.get(f"{hash_type}_simhash")
    if section:
        return cast(int, section["hash"])
    return None


def calculate_similarity(
    host: SimHashHost,
    simhash_available: bool,
    simhash_type: Any,
    other_simhash_value: int,
    hash_type: str,
    interpret_similarity_distance: Any,
) -> dict[str, Any]:
    if not simhash_available:
        return {"error": "simhash library not available"}
    results = host.analyze()
    if not results.get("available"):
        return {"error": "SimHash analysis not available"}
    current_hash = _resolve_current_hash(results, hash_type)
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
