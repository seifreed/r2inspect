"""Pure domain services for function analysis."""

from __future__ import annotations

import hashlib
from typing import Any


def _coerce_function_size(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def extract_mnemonics_from_ops(ops: list[Any]) -> list[str]:
    """Extract instruction mnemonics from radare2 op dictionaries."""
    mnemonics: list[str] = []
    for op in ops:
        if not isinstance(op, dict):
            continue
        mnemonic_value = op.get("mnemonic")
        if isinstance(mnemonic_value, str) and mnemonic_value.strip():
            mnemonics.append(mnemonic_value.strip())
            continue
        opcode = op.get("opcode")
        if isinstance(opcode, str) and opcode.strip():
            mnemonic = opcode.strip().split()[0]
            if mnemonic:
                mnemonics.append(mnemonic)
    return mnemonics


def extract_mnemonics_from_text(text: str | None) -> list[str]:
    """Extract instruction mnemonics from plain-text disassembly."""
    if not text or not text.strip():
        return []
    mnemonics: list[str] = []
    for line in text.strip().split("\n"):
        line = line.strip()
        if line:
            parts = line.split()
            if not parts:
                continue
            mnemonic_index = 1 if parts[0].lower().startswith("0x") and len(parts) > 1 else 0
            mnemonic = parts[mnemonic_index]
            if mnemonic:
                mnemonics.append(mnemonic)
    return mnemonics


def machoc_hash_from_mnemonics(mnemonics: list[str]) -> str | None:
    """Build a MACHOC hash from a mnemonic sequence."""
    if not mnemonics:
        return None
    signature = ",".join(mnemonics)
    return hashlib.sha256(signature.encode("utf-8")).hexdigest()


def build_function_stats(functions: list[dict[str, Any]] | None) -> dict[str, Any]:
    """Summarize function inventory and sizing information."""
    if not functions:
        return {}

    total_functions = len(functions)
    sizes = [
        _coerce_function_size(func.get("size"))
        for func in functions
        if _coerce_function_size(func.get("size")) > 0
    ]
    stats: dict[str, Any] = {
        "total_functions": total_functions,
        "functions_with_size": len(sizes),
    }

    if sizes:
        stats.update(
            {
                "avg_function_size": sum(sizes) / len(sizes),
                "min_function_size": min(sizes),
                "max_function_size": max(sizes),
                "total_code_size": sum(sizes),
            }
        )

    function_types: dict[str, int] = {}
    for func in functions:
        func_type = func.get("type", "unknown")
        function_types[func_type] = function_types.get(func_type, 0) + 1
    stats["function_types"] = function_types

    if sizes:
        functions_with_sizes: list[tuple[str, int]] = [
            (
                str(f.get("name", f"func_{f.get('offset', '?')}")),
                _coerce_function_size(f.get("size")),
            )
            for f in functions
            if _coerce_function_size(f.get("size")) > 0
        ]
        functions_with_sizes.sort(key=lambda item: item[1], reverse=True)
        stats["largest_functions"] = functions_with_sizes[:10]

    return stats


def group_functions_by_machoc_hash(machoc_hashes: dict[str, str] | None) -> dict[str, list[str]]:
    """Group functions that share the same MACHOC hash."""
    if not machoc_hashes:
        return {}

    hash_to_functions: dict[str, list[str]] = {}
    for func_name, machoc_hash in machoc_hashes.items():
        hash_to_functions.setdefault(machoc_hash, []).append(func_name)

    return {
        hash_value: functions
        for hash_value, functions in hash_to_functions.items()
        if len(functions) > 1
    }


def build_machoc_summary(machoc_hashes: dict[str, str] | None) -> dict[str, Any]:
    """Build a high-level MACHOC similarity summary."""
    if not machoc_hashes:
        return {"error": "No MACHOC hashes available"}

    similarities = group_functions_by_machoc_hash(machoc_hashes)
    summary: dict[str, Any] = {
        "total_functions_hashed": len(machoc_hashes),
        "unique_machoc_hashes": len(set(machoc_hashes.values())),
        "duplicate_function_groups": len(similarities),
        "total_duplicate_functions": sum(len(funcs) for funcs in similarities.values()),
    }

    if similarities:
        summary["similarities"] = similarities
        pattern_counts: list[tuple[int, str]] = [
            (len(funcs), hash_value[:16]) for hash_value, funcs in similarities.items()
        ]
        pattern_counts.sort(reverse=True)
        summary["most_common_patterns"] = pattern_counts[:5]

    return summary


def calculate_cyclomatic_complexity_from_blocks(blocks: list[dict[str, Any]] | None) -> int:
    """Compute cyclomatic complexity from basic blocks."""
    if not blocks:
        return 0

    edges = 0
    nodes = len(blocks)
    for block in blocks:
        if isinstance(block, dict) and "jump" in block:
            edges += 1
        if isinstance(block, dict) and "fail" in block:
            edges += 1

    return max(edges - nodes + 2, 1)


def classify_function_type(func_name: str | None, func: dict[str, Any]) -> str:
    """Classify a function using stable naming and size heuristics."""
    if not func_name:
        return "unknown"

    name = func_name.lower()
    if name.startswith("lib") or any(
        token in name for token in ["msvcrt", "kernel32", "ntdll", "user32"]
    ):
        return "library"
    if "thunk" in name or name.startswith("j_") or _coerce_function_size(func.get("size")) < 10:
        return "thunk"
    if any(keyword in name for keyword in ["main", "sub_", "fcn.", "func_"]):
        return "user"
    return "unknown"
