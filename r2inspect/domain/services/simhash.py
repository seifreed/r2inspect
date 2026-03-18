"""Domain services for SimHash feature aggregation and interpretation."""

from __future__ import annotations

from collections import Counter
from typing import Any


def build_feature_stats(strings_features: list[str], opcodes_features: list[str]) -> dict[str, Any]:
    """Build aggregate feature statistics for SimHash analysis."""
    combined_features = strings_features + opcodes_features
    feature_stats: dict[str, Any] = {
        "total_strings": len(strings_features),
        "total_opcodes": len(opcodes_features),
        "total_features": len(combined_features),
        "unique_strings": len(set(strings_features)) if strings_features else 0,
        "unique_opcodes": len(set(opcodes_features)) if opcodes_features else 0,
    }
    if combined_features:
        feature_counter = Counter(combined_features)
        feature_stats["most_common_features"] = feature_counter.most_common(10)
        feature_stats["feature_diversity"] = len(set(combined_features)) / len(combined_features)
    return feature_stats


def build_similarity_groups(
    function_features: dict[str, dict[str, Any]],
    *,
    max_distance: int,
    distance_fn: Any,
) -> list[dict[str, Any]]:
    """Find groups of similar functions based on a distance function."""
    similar_groups: list[dict[str, Any]] = []
    processed_functions = set()
    func_names = list(function_features.keys())

    for i, func1_name in enumerate(func_names):
        if func1_name in processed_functions:
            continue

        func1_data = function_features[func1_name]
        similar_funcs = [func1_name]
        processed_functions.add(func1_name)

        for func2_name in func_names[i + 1 :]:
            if func2_name in processed_functions:
                continue
            func2_data = function_features[func2_name]
            distance = distance_fn(func1_data["simhash"], func2_data["simhash"])
            if distance <= max_distance:
                similar_funcs.append(func2_name)
                processed_functions.add(func2_name)

        if len(similar_funcs) > 1:
            similar_groups.append(
                {
                    "functions": similar_funcs,
                    "count": len(similar_funcs),
                    "representative_hash": hex(func1_data["simhash"]),
                    "max_distance": max_distance,
                }
            )

    similar_groups.sort(key=lambda item: int(item.get("count", 0)), reverse=True)
    return similar_groups


def interpret_similarity_distance(distance: int) -> str:
    """Interpret a SimHash Hamming distance into a coarse similarity label."""
    if distance == 0:
        return "identical"
    if distance <= 5:
        return "very_similar"
    if distance <= 15:
        return "similar"
    if distance <= 25:
        return "somewhat_similar"
    return "different"


def get_length_category(length: int) -> str:
    if length < 8:
        return "short"
    if length < 32:
        return "medium"
    if length < 128:
        return "long"
    return "very_long"


def classify_opcode_type(mnemonic: str) -> str:
    if mnemonic in ["jmp", "je", "jne", "jz", "jnz", "jg", "jl", "jge", "jle", "call", "ret"]:
        return "control"
    if mnemonic in ["mov", "lea", "push", "pop", "xchg"]:
        return "data"
    if mnemonic in ["add", "sub", "mul", "div", "inc", "dec", "neg"]:
        return "arithmetic"
    if mnemonic in ["and", "or", "xor", "not", "shl", "shr", "rol", "ror"]:
        return "logical"
    if mnemonic in ["cmp", "test"]:
        return "compare"
    if mnemonic.startswith("str") or mnemonic.startswith("rep"):
        return "string"
    return "other"


def extract_printable_strings(data: bytes, *, min_length: int) -> list[str]:
    strings: list[str] = []
    current: list[str] = []
    for byte in data:
        if 32 <= byte <= 126:
            current.append(chr(byte))
            continue
        if len(current) >= min_length:
            strings.append("".join(current))
        current = []
    if len(current) >= min_length:
        strings.append("".join(current))
    return strings


def extract_opcodes_from_ops(ops: list[Any], *, max_instructions: int) -> list[str]:
    opcodes: list[str] = []
    for i, op in enumerate(ops):
        if i >= max_instructions:
            break
        if not isinstance(op, dict):
            continue
        mnemonic = _resolve_mnemonic(op)
        if not mnemonic:
            continue
        opcodes.append(f"OP:{mnemonic}")
        opcodes.append(f"OPTYPE:{classify_opcode_type(mnemonic)}")
        previous = _previous_mnemonic(ops, i)
        if previous:
            opcodes.append(f"BIGRAM:{previous}→{mnemonic}")
    return opcodes


def _resolve_mnemonic(op: dict[str, Any]) -> str | None:
    mnemonic_value = op.get("mnemonic")
    if not isinstance(mnemonic_value, str) or not mnemonic_value.strip():
        opcode_value = op.get("opcode")
        if isinstance(opcode_value, str) and opcode_value.strip():
            mnemonic_value = opcode_value.split()[0]
        else:
            return None
    mnemonic = mnemonic_value.strip().lower()
    return mnemonic or None


def _previous_mnemonic(ops: list[Any], index: int) -> str | None:
    if index <= 0 or index >= len(ops):
        return None
    prev_op = ops[index - 1]
    if isinstance(prev_op, dict) and "mnemonic" in prev_op:
        return str(prev_op["mnemonic"]).strip().lower()
    return None
