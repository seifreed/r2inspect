#!/usr/bin/env python3
"""Shared helpers for Binbloom analysis."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, cast

from ..domain.services.binbloom import build_signature_components
from ..infrastructure.logging import get_logger
from .binbloom_extraction_support import (
    extract_instruction_mnemonics as _extract_instruction_mnemonics_impl,
    extract_mnemonics_from_pdfj as _extract_mnemonics_from_pdfj_impl,
    extract_mnemonics_from_pdj as _extract_mnemonics_from_pdj_impl,
    extract_mnemonics_from_text as _extract_mnemonics_from_text_impl,
)
from .binbloom_similarity_support import (
    calculate_bloom_stats as _calculate_bloom_stats_impl,
    compare_bloom_filters as _compare_bloom_filters_impl,
    deserialize_bloom as _deserialize_bloom_impl,
)

logger = get_logger(__name__)

try:
    from pybloom_live import BloomFilter
except ImportError:  # pragma: no cover
    BloomFilter = None


class BinbloomMixin:
    """Instruction extraction, serialization, and comparison helpers."""

    adapter: Any

    def _build_bloom_filter(
        self, instructions: list[str], capacity: int, error_rate: float
    ) -> BloomFilter:
        bloom_filter = BloomFilter(capacity=capacity, error_rate=error_rate)
        for instruction in instructions:
            bloom_filter.add(instruction)
        self._add_instruction_patterns(bloom_filter, instructions)
        return bloom_filter

    def _add_instruction_patterns(self, bloom_filter: BloomFilter, instructions: list[str]) -> None:
        for i in range(len(instructions) - 1):
            bloom_filter.add(f"{instructions[i]}→{instructions[i + 1]}")

        from collections import Counter

        freq_counter = Counter(instructions)
        for instr, count in freq_counter.items():
            if count > 1:
                bloom_filter.add(f"{instr}*{count}")

    def _extract_instruction_mnemonics(self, func_addr: int, func_name: str) -> list[str]:
        return _extract_instruction_mnemonics_impl(self, func_addr, func_name, logger)

    def _extract_mnemonics_from_pdfj(self, func_addr: int, func_name: str) -> list[str]:
        return _extract_mnemonics_from_pdfj_impl(self, func_addr, func_name, logger)

    def _extract_mnemonics_from_pdj(self, func_addr: int, func_name: str) -> list[str]:
        return _extract_mnemonics_from_pdj_impl(self, func_addr, func_name, logger)

    def _extract_mnemonics_from_text(self, func_addr: int, func_name: str) -> list[str]:
        return _extract_mnemonics_from_text_impl(self, func_addr, func_name, logger)

    def _collect_mnemonics_from_ops(self, ops: list[Any]) -> list[str]:
        mnemonics: list[str] = []
        for op in ops:
            if not isinstance(op, dict) or "mnemonic" not in op:
                continue
            clean_mnemonic = self._normalize_mnemonic(op.get("mnemonic"))
            if clean_mnemonic:
                mnemonics.append(clean_mnemonic)
        return mnemonics

    @staticmethod
    def _normalize_mnemonic(mnemonic: str | None) -> str | None:
        if not mnemonic:
            return None
        clean_mnemonic = mnemonic.strip().lower()
        return clean_mnemonic or None

    def _bloom_to_signature(self, instructions: list[str]) -> str:
        try:
            combined = "||".join(self._build_signature_components(instructions))
            return hashlib.sha256(combined.encode("utf-8")).hexdigest()
        except Exception as exc:
            logger.error("Error creating signature from Bloom filter: %s", exc)
            return ""

    def _build_signature_components(self, instructions: list[str]) -> list[str]:
        return build_signature_components(instructions)

    def _build_frequency_patterns(
        self, instructions: list[str], unique_instructions: list[str]
    ) -> list[str]:
        from collections import Counter

        freq_counter = Counter(instructions)
        return [f"{instr}:{freq_counter[instr]}" for instr in unique_instructions]

    def _build_unique_bigrams(self, instructions: list[str]) -> list[str]:
        bigrams: list[str] = []
        for i in range(len(instructions) - 1):
            bigrams.append(f"{instructions[i]}→{instructions[i + 1]}")
        return sorted(set(bigrams))

    def _create_binary_bloom(
        self, all_instructions: set[str], capacity: int, error_rate: float
    ) -> BloomFilter | None:
        try:
            bloom_filter = BloomFilter(capacity=capacity, error_rate=error_rate)
            for instruction in all_instructions:
                bloom_filter.add(instruction)
            return bloom_filter
        except Exception as exc:
            logger.error("Error creating binary Bloom filter: %s", exc)
            return None

    def _serialize_blooms(self, function_blooms: dict[str, BloomFilter]) -> dict[str, str]:
        serialized: dict[str, str] = {}
        try:
            for func_name, bloom_filter in function_blooms.items():
                serialized[func_name] = self._serialize_bloom(bloom_filter)
        except Exception as exc:
            logger.error("Error serializing Bloom filters: %s", exc)
        return serialized

    def _serialize_bloom(self, bloom_filter: BloomFilter) -> str:
        try:
            data = {
                "version": 1,
                "error_rate": bloom_filter.error_rate,
                "capacity": bloom_filter.capacity,
                "count": bloom_filter.count,
                "bitarray": bloom_filter.bitarray.tolist(),
            }
            json_str = json.dumps(data, separators=(",", ":"))
            return base64.b64encode(json_str.encode("utf-8")).decode("utf-8")
        except Exception as exc:
            logger.error("Error serializing Bloom filter: %s", exc)
            return ""

    def _find_similar_functions(
        self, function_signatures: dict[str, dict[str, Any]]
    ) -> list[dict[str, Any]]:
        try:
            signature_groups = self._group_functions_by_signature(function_signatures)
            similar_groups = self._build_similar_groups(signature_groups)
            similar_groups.sort(key=lambda item: item["count"], reverse=True)
            return similar_groups
        except Exception as exc:
            logger.error("Error finding similar functions: %s", exc)
            return []

    def _group_functions_by_signature(
        self, function_signatures: dict[str, dict[str, Any]]
    ) -> dict[str, list[str]]:
        from collections import defaultdict

        signature_groups: dict[str, list[str]] = defaultdict(list)
        for func_name, func_data in function_signatures.items():
            signature = func_data["signature"]
            clean_func_name = func_name.replace("&nbsp;", " ").replace("&amp;", "&")
            signature_groups[signature].append(clean_func_name)
        return signature_groups

    @staticmethod
    def _build_similar_groups(signature_groups: dict[str, list[str]]) -> list[dict[str, Any]]:
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

    def _calculate_bloom_stats(
        self, function_blooms: dict[str, BloomFilter], capacity: int, error_rate: float
    ) -> dict[str, Any]:
        return _calculate_bloom_stats_impl(self, function_blooms, capacity, error_rate, logger)

    def _accumulate_bloom_bits(self, function_blooms: dict[str, BloomFilter]) -> tuple[int, int]:
        total_bits_set = 0
        total_capacity = 0
        for bloom_filter in function_blooms.values():
            bit_sequence = self._get_bloom_bits(bloom_filter)
            if bit_sequence is None:
                continue
            bits_set = sum(bit_sequence)
            total_bits_set += bits_set
            total_capacity += len(bit_sequence)
        return total_bits_set, total_capacity

    def compare_bloom_filters(self, bloom1: BloomFilter, bloom2: BloomFilter) -> float:
        return _compare_bloom_filters_impl(self, bloom1, bloom2, logger)

    @staticmethod
    def _get_bloom_bits(bloom_filter: BloomFilter) -> Any | None:
        bit_sequence = getattr(bloom_filter, "bit_array", None)
        if bit_sequence is None:
            bit_sequence = getattr(bloom_filter, "bitarray", None)
        return bit_sequence

    @staticmethod
    def deserialize_bloom(bloom_b64: str) -> BloomFilter | None:
        return _deserialize_bloom_impl(bloom_b64, BloomFilter, logger)
