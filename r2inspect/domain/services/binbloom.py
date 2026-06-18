"""Domain services for Binbloom-style analysis."""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from collections.abc import Iterable
from typing import Any

from .binary_helpers import clean_function_name


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
    if not isinstance(instructions, list):
        instructions = []
    instructions = [instr for instr in instructions if isinstance(instr, str) and instr]
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
    if not isinstance(instructions, list):
        return []
    bigrams = [f"{instructions[i]}→{instructions[i + 1]}" for i in range(len(instructions) - 1)]
    return sorted(set(bigrams))


def count_unique_signatures(function_signatures: dict[str, dict[str, Any]]) -> int:
    """Count unique function signatures."""
    signatures: set[str] = set()
    for sig in function_signatures.values():
        if not isinstance(sig, dict):
            continue
        signature = sig.get("signature")
        if isinstance(signature, str) and signature:
            signatures.add(signature)
    return len(signatures)


def build_similar_groups(signature_groups: dict[str, list[str]]) -> list[dict[str, Any]]:
    """Build similarity-group records for signatures shared by more than one function."""
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
    return similar_groups


def build_similar_function_groups(
    function_signatures: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Group functions that share the same signature."""
    signature_groups: dict[str, list[str]] = defaultdict(list)
    for func_name, func_data in function_signatures.items():
        if not isinstance(func_data, dict):
            continue
        signature = func_data.get("signature")
        if not isinstance(signature, str) or not signature:
            continue
        signature_groups[signature].append(clean_function_name(func_name))

    similar_groups = build_similar_groups(signature_groups)
    similar_groups.sort(key=lambda item: item["count"], reverse=True)
    return similar_groups


def accumulate_bloom_bits(function_blooms: dict[str, Any]) -> tuple[int, int]:
    """Accumulate total bits set and total capacity for bloom filters."""
    total_bits_set = 0
    total_capacity = 0
    for bloom_filter in function_blooms.values():
        bit_sequence = get_bloom_bits(bloom_filter)
        if isinstance(bit_sequence, (str, bytes, bytearray)) or not isinstance(bit_sequence, Iterable):
            continue
        bits = list(bit_sequence)
        if not all(isinstance(bit, (bool, int)) for bit in bits):
            continue
        bits_set = sum(1 for bit in bits if bit)
        total_bits_set += bits_set
        total_capacity += len(bits)
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


def _jaccard_similarity(bits1: set[int], bits2: set[int]) -> float:
    if not bits1 and not bits2:
        return 1.0
    return len(bits1 & bits2) / len(bits1 | bits2)


def calculate_bloom_similarity(bloom1: Any, bloom2: Any) -> float:
    """Calculate Jaccard similarity between two bloom filters."""
    bit_array_1 = get_bloom_bits(bloom1)
    bit_array_2 = get_bloom_bits(bloom2)
    if (
        isinstance(bit_array_1, (str, bytes, bytearray))
        or isinstance(bit_array_2, (str, bytes, bytearray))
        or not isinstance(bit_array_1, Iterable)
        or not isinstance(bit_array_2, Iterable)
    ):
        return 0.0
    bits1_raw = list(bit_array_1)
    bits2_raw = list(bit_array_2)
    if not all(isinstance(bit, (bool, int)) for bit in bits1_raw + bits2_raw):
        return 0.0

    bits1 = {i for i, bit in enumerate(bits1_raw) if bit}
    bits2 = {i for i, bit in enumerate(bits2_raw) if bit}
    return _jaccard_similarity(bits1, bits2)


def get_bloom_bits(bloom_filter: Any) -> Any | None:
    bit_sequence = getattr(bloom_filter, "bit_array", None)
    if bit_sequence is None:
        bit_sequence = getattr(bloom_filter, "bitarray", None)
    return bit_sequence
