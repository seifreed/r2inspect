"""Domain services for Binbloom-style analysis."""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from typing import Any


def build_binbloom_result(
    analyzer_name: str,
    *,
    capacity: int,
    error_rate: float,
) -> dict[str, Any]:
    """Build the default Binbloom result payload."""
    return {
        "available": False,
        "analyzer": analyzer_name,
        "library_available": True,
        "function_blooms": {},
        "function_signatures": {},
        "total_functions": 0,
        "analyzed_functions": 0,
        "capacity": capacity,
        "error_rate": error_rate,
        "binary_bloom": None,
        "binary_signature": None,
        "similar_functions": [],
        "unique_signatures": 0,
        "bloom_stats": {},
        "error": None,
        "execution_time": 0.0,
    }


def create_instruction_signature(
    instructions: list[str],
    *,
    hash_fn: Any = hashlib.sha256,
) -> str:
    """Create a deterministic signature from normalized instructions."""
    signature_components = build_signature_components(instructions)
    combined = "||".join(signature_components)
    return str(hash_fn(combined.encode("utf-8")).hexdigest())


def build_signature_components(instructions: list[str]) -> list[str]:
    """Build the logical components used to create a signature."""
    unique_instructions = sorted(set(instructions))
    freq_patterns = _build_frequency_patterns(instructions, unique_instructions)
    unique_bigrams = _build_unique_bigrams(instructions)
    return [
        "UNIQ:" + "|".join(unique_instructions),
        "FREQ:" + "|".join(freq_patterns),
        "BIGR:" + "|".join(unique_bigrams[:20]),
    ]


def _build_frequency_patterns(instructions: list[str], unique_instructions: list[str]) -> list[str]:
    freq_counter = Counter(instructions)
    return [f"{instr}:{freq_counter[instr]}" for instr in unique_instructions]


def _build_unique_bigrams(instructions: list[str]) -> list[str]:
    bigrams = [f"{instructions[i]}→{instructions[i + 1]}" for i in range(len(instructions) - 1)]
    return sorted(set(bigrams))


def count_unique_signatures(function_signatures: dict[str, dict[str, Any]]) -> int:
    """Count unique function signatures."""
    return len({sig["signature"] for sig in function_signatures.values()})


def build_similar_function_groups(
    function_signatures: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Group functions that share the same signature."""
    signature_groups: dict[str, list[str]] = defaultdict(list)
    for func_name, func_data in function_signatures.items():
        signature = func_data["signature"]
        clean_func_name = func_name.replace("&nbsp;", " ").replace("&amp;", "&")
        signature_groups[signature].append(clean_func_name)

    similar_groups: list[dict[str, Any]] = []
    for signature, func_names in signature_groups.items():
        if len(func_names) > 1:
            similar_groups.append(
                {
                    "signature": signature[:16] + "..." if len(signature) > 16 else signature,
                    "functions": func_names,
                    "count": len(func_names),
                }
            )

    similar_groups.sort(key=lambda item: item["count"], reverse=True)
    return similar_groups


def accumulate_bloom_bits(function_blooms: dict[str, Any]) -> tuple[int, int]:
    """Accumulate total bits set and total capacity for bloom filters."""
    total_bits_set = 0
    total_capacity = 0
    for bloom_filter in function_blooms.values():
        bit_sequence = _get_bloom_bits(bloom_filter)
        if bit_sequence is None:
            continue
        bits_set = sum(bit_sequence)
        total_bits_set += bits_set
        total_capacity += len(bit_sequence)
    return total_bits_set, total_capacity


def calculate_bloom_stats(
    function_blooms: dict[str, Any],
    *,
    capacity: int,
    error_rate: float,
) -> dict[str, Any]:
    """Calculate aggregate statistics about a set of bloom filters."""
    if not function_blooms:
        return {}

    total_bits_set, total_capacity = accumulate_bloom_bits(function_blooms)
    return {
        "total_filters": len(function_blooms),
        "configured_capacity": capacity,
        "configured_error_rate": error_rate,
        "average_fill_rate": (total_bits_set / total_capacity) if total_capacity > 0 else 0.0,
    }


def calculate_bloom_similarity(bloom1: Any, bloom2: Any) -> float:
    """Calculate Jaccard similarity between two bloom filters."""
    bit_array_1 = _get_bloom_bits(bloom1)
    bit_array_2 = _get_bloom_bits(bloom2)
    if bit_array_1 is None or bit_array_2 is None:
        return 0.0

    bits1 = {i for i, bit in enumerate(bit_array_1) if bit}
    bits2 = {i for i, bit in enumerate(bit_array_2) if bit}

    if not bits1 and not bits2:
        return 1.0
    if not bits1 or not bits2:
        return 0.0

    intersection = len(bits1.intersection(bits2))
    union = len(bits1.union(bits2))
    return intersection / union if union > 0 else 0.0


def _get_bloom_bits(bloom_filter: Any) -> Any | None:
    bit_sequence = getattr(bloom_filter, "bit_array", None)
    if bit_sequence is None:
        bit_sequence = getattr(bloom_filter, "bitarray", None)
    return bit_sequence
