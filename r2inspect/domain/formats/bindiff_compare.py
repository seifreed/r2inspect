"""Comparison helpers for BinDiff domain analysis."""

from __future__ import annotations

from typing import Any

from .similarity import jaccard_similarity, normalized_difference_similarity


def compare_rolling_hashes(a_hashes: list[int], b_hashes: list[int]) -> float:
    if not a_hashes or not b_hashes:
        return 0.0
    a_set = set(a_hashes)
    b_set = set(b_hashes)
    intersection = len(a_set & b_set)
    union = len(a_set | b_set)
    return intersection / union if union > 0 else 0.0


def compare_structural_features(a_struct: dict[str, Any], b_struct: dict[str, Any]) -> float:
    score = 0.0
    total_weight = 0.0

    if a_struct.get("file_type") == b_struct.get("file_type"):
        score += 0.2
    total_weight += 0.2

    if a_struct.get("architecture") == b_struct.get("architecture"):
        score += 0.2
    total_weight += 0.2

    a_sections = set(a_struct.get("section_names", []))
    b_sections = set(b_struct.get("section_names", []))
    if a_sections or b_sections:
        score += jaccard_similarity(a_sections, b_sections) * 0.3
    total_weight += 0.3

    a_imports = set(a_struct.get("imported_dlls", []))
    b_imports = set(b_struct.get("imported_dlls", []))
    if a_imports or b_imports:
        score += jaccard_similarity(a_imports, b_imports) * 0.3
    total_weight += 0.3

    return score / total_weight if total_weight > 0 else 0.0


def compare_function_features(a_func: dict[str, Any], b_func: dict[str, Any]) -> float:
    score = 0.0
    total_weight = 0.0

    a_count = a_func.get("function_count", 0)
    b_count = b_func.get("function_count", 0)
    count_sim = normalized_difference_similarity(a_count, b_count)
    if count_sim:
        score += count_sim * 0.4
    total_weight += 0.4

    a_names = set(a_func.get("function_names", []))
    b_names = set(b_func.get("function_names", []))
    if a_names or b_names:
        score += jaccard_similarity(a_names, b_names) * 0.6
    total_weight += 0.6

    return score / total_weight if total_weight > 0 else 0.0


def compare_string_features(a_str: dict[str, Any], b_str: dict[str, Any]) -> float:
    if a_str.get("string_signature") == b_str.get("string_signature"):
        return 1.0

    score = 0.0
    total_weight = 0.0

    a_apis = set(a_str.get("api_strings", []))
    b_apis = set(b_str.get("api_strings", []))
    if a_apis or b_apis:
        score += jaccard_similarity(a_apis, b_apis) * 0.4
    total_weight += 0.4

    a_paths = set(a_str.get("path_strings", []))
    b_paths = set(b_str.get("path_strings", []))
    if a_paths or b_paths:
        score += jaccard_similarity(a_paths, b_paths) * 0.3
    total_weight += 0.3

    a_reg = set(a_str.get("registry_strings", []))
    b_reg = set(b_str.get("registry_strings", []))
    if a_reg or b_reg:
        score += jaccard_similarity(a_reg, b_reg) * 0.3
    total_weight += 0.3

    return score / total_weight if total_weight > 0 else 0.0


def compare_byte_features(a_bytes: dict[str, Any], b_bytes: dict[str, Any]) -> float:
    score = 0.0
    total_weight = 0.0

    a_hash = a_bytes.get("rolling_hash")
    b_hash = b_bytes.get("rolling_hash")
    if a_hash and b_hash:
        hash_sim = compare_rolling_hashes(a_hash, b_hash)
        score += hash_sim * 1.0
    total_weight += 1.0

    return score / total_weight if total_weight > 0 else 0.0


def compare_behavioral_features(a_behav: dict[str, Any], b_behav: dict[str, Any]) -> float:
    score = 0.0
    total_weight = 0.0

    indicators = [
        "crypto_indicators",
        "network_indicators",
        "persistence_indicators",
        "suspicious_apis",
        "crypto_apis",
        "network_apis",
    ]

    for indicator in indicators:
        a_val = a_behav.get(indicator, 0)
        b_val = b_behav.get(indicator, 0)
        if a_val > 0 or b_val > 0:
            sim = normalized_difference_similarity(a_val, b_val)
            score += sim
            total_weight += 1.0

    return score / total_weight if total_weight > 0 else 0.0


def calculate_overall_similarity(
    structural: float,
    function: float,
    string: float,
    byte: float,
    behavioral: float,
) -> float:
    weights = {
        "structural": 0.2,
        "function": 0.3,
        "string": 0.2,
        "byte": 0.15,
        "behavioral": 0.15,
    }
    total_weight = sum(weights.values())
    if total_weight <= 0:  # pragma: no cover
        return 0.0
    weighted = (
        structural * weights["structural"]
        + function * weights["function"]
        + string * weights["string"]
        + byte * weights["byte"]
        + behavioral * weights["behavioral"]
    )
    return round(weighted / total_weight, 3)
