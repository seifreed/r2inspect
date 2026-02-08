#!/usr/bin/env python3
"""Function analysis domain helpers."""

from __future__ import annotations

import hashlib
from typing import Any


def extract_mnemonics_from_ops(ops: list[dict[str, Any]]) -> list[str]:
    mnemonics: list[str] = []
    for op in ops:
        if isinstance(op, dict) and "opcode" in op:
            opcode = op["opcode"]
            if opcode and opcode.strip():
                mnemonic = opcode.strip().split()[0]
                if mnemonic:
                    mnemonics.append(mnemonic)
    return mnemonics


def extract_mnemonics_from_text(text: str) -> list[str]:
    if not text or not text.strip():
        return []
    mnemonics: list[str] = []
    for line in text.strip().split("\n"):
        line = line.strip()
        if line:
            mnemonic = line.split()[0]
            if mnemonic:
                mnemonics.append(mnemonic)
    return mnemonics


def machoc_hash_from_mnemonics(mnemonics: list[str]) -> str | None:
    if not mnemonics:
        return None
    signature = ",".join(mnemonics)
    return hashlib.sha256(signature.encode("utf-8")).hexdigest()
