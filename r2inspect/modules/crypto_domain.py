#!/usr/bin/env python3
"""Domain helpers for crypto detection."""

from __future__ import annotations

import re
from typing import Any

CRYPTO_PATTERNS = {
    "AES": [
        r"\baes\b",
        r"\brijndael\b",
        r"advanced.encryption.standard",
        r"aes[_-]?(128|192|256)",
        r"aes[_-]?cbc",
        r"aes[_-]?ecb",
    ],
    "DES": [r"\bdes\b", r"3des", r"triple.des", r"data.encryption.standard"],
    "RSA": [r"\brsa\b", r"rsa[_-]?key", r"public.key", r"private.key"],
    "MD5": [r"\bmd5\b", r"md5.hash", r"message.digest.5"],
    "SHA": [
        r"\bsha[_-]?1\b",
        r"\bsha[_-]?256\b",
        r"\bsha[_-]?512\b",
        r"secure.hash",
        r"sha[_-]?hash",
    ],
    "RC4": [r"\brc4\b", r"\barcfour\b"],
    "Blowfish": [r"\bblowfish\b"],
    "Base64": [r"\bbase64\b", r"base.64"],
    "OpenSSL": [r"\bopenssl\b", r"\bevp_\w+", r"ssl.ctx"],
    "BCrypt": [r"\bbcrypt\b", r"bcrypt\w+", r"cng.dll"],
    "CryptoAPI": [r"crypt32\.dll", r"advapi32\.dll", r"cryptoapi"],
}

NOISE_PATTERNS = [
    r"vector.deleting.destructor",
    r"scalar.deleting.destructor",
    r"std::",
    r"class",
    r"struct",
    r"__",
    r"@@",
    r"\?",
    r"vtable",
]


def detect_algorithms_from_strings(
    strings_result: list[dict[str, Any]], detected_algos: dict[str, list]
) -> None:
    for string_info in strings_result:
        string_val = string_info.get("string", "").lower()
        if not _is_candidate_string(string_val):
            continue
        _match_patterns(string_info, string_val, detected_algos)


def _is_candidate_string(string_val: str) -> bool:
    if len(string_val) < 3:
        return False
    try:
        return not any(re.search(noise, string_val, re.IGNORECASE) for noise in NOISE_PATTERNS)
    except re.error:
        return False


def _match_patterns(
    string_info: dict[str, Any], string_val: str, detected_algos: dict[str, list]
) -> None:
    for algo_name, patterns in CRYPTO_PATTERNS.items():
        if _matches_any_pattern(string_val, patterns):
            _add_detection(detected_algos, algo_name, string_info, string_val)


def _matches_any_pattern(string_val: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        try:
            if re.search(pattern, string_val, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def _add_detection(
    detected_algos: dict[str, list],
    algo_name: str,
    string_info: dict[str, Any],
    string_val: str,
) -> None:
    detected_algos.setdefault(algo_name, []).append(
        {
            "evidence_type": "String Reference",
            "evidence": string_val,
            "confidence": 0.4,
            "address": hex(string_info.get("vaddr", 0)),
        }
    )


def consolidate_detections(detected_algos: dict[str, list]) -> list[dict[str, Any]]:
    algorithms: list[dict[str, Any]] = []
    for algo_name, evidences in detected_algos.items():
        max_confidence = max(e["confidence"] for e in evidences)
        evidence_types = {e["evidence_type"] for e in evidences}
        if len(evidence_types) > 1:
            max_confidence = min(max_confidence + 0.2, 0.95)
        algorithms.append(
            {
                "algorithm": algo_name,
                "confidence": max_confidence,
                "evidence_count": len(evidences),
                "evidence_types": list(evidence_types),
                "evidences": evidences[:3],
            }
        )
    return algorithms
