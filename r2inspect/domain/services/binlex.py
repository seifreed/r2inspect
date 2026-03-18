#!/usr/bin/env python3
"""Pure domain helpers for Binlex lexical analysis."""

from __future__ import annotations

import hashlib
from typing import Any

HTML_NBSP = "&nbsp;"
HTML_AMP = "&amp;"


def normalize_mnemonic(mnemonic: str | None) -> str | None:
    if not mnemonic:
        return None
    clean_mnemonic = mnemonic.strip().lower()
    clean_mnemonic = clean_mnemonic.replace(HTML_NBSP, " ").replace(HTML_AMP, "&")
    if clean_mnemonic and not clean_mnemonic.startswith("&"):
        return clean_mnemonic
    return None


def extract_mnemonic_from_op(op: dict[str, Any]) -> str | None:
    mnemonic = op.get("mnemonic")
    if isinstance(mnemonic, str) and mnemonic:
        return mnemonic
    opcode = op.get("opcode")
    if isinstance(opcode, str):
        opcode = opcode.strip()
        if opcode:
            return opcode.split()[0]
    return None


def extract_tokens_from_ops(ops: list[Any]) -> list[str]:
    tokens: list[str] = []
    for op in ops:
        if not isinstance(op, dict):
            continue
        clean_mnemonic = normalize_mnemonic(extract_mnemonic_from_op(op))
        if clean_mnemonic:
            tokens.append(clean_mnemonic)
    return tokens


def extract_tokens_from_text(instructions_text: str) -> list[str]:
    if not instructions_text or not instructions_text.strip():
        return []
    tokens: list[str] = []
    for line in instructions_text.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        clean_mnemonic = normalize_mnemonic(line.split()[0])
        if clean_mnemonic:
            tokens.append(clean_mnemonic)
    return tokens


def generate_ngrams(tokens: list[str], n: int) -> list[str]:
    if len(tokens) < n:
        return []
    return [" ".join(tokens[i : i + n]) for i in range(len(tokens) - n + 1)]


def create_signature(ngrams: list[str]) -> str:
    return hashlib.sha256("|".join(sorted(ngrams)).encode("utf-8")).hexdigest()


def calculate_binary_signature(
    function_signatures: dict[str, dict[int, dict[str, Any]]],
    ngram_sizes: list[int],
) -> dict[int, str]:
    binary_signatures = {}
    for n in ngram_sizes:
        signatures = [
            func_sigs[n]["signature"]
            for func_sigs in function_signatures.values()
            if n in func_sigs and "signature" in func_sigs[n]
        ]
        if signatures:
            binary_signatures[n] = hashlib.sha256(
                "|".join(sorted(signatures)).encode("utf-8")
            ).hexdigest()
    return binary_signatures
