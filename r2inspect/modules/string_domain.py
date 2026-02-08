#!/usr/bin/env python3
"""Domain helpers for string analysis."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable
from typing import Any

SUSPICIOUS_PATTERNS = {
    "urls": r"https?://[^\s]+",
    "ips": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    "emails": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "registry": r"HKEY_[A-Z_]+\\[\\A-Za-z0-9_\-]+",
    "files": r"[A-Za-z]:\\[\\A-Za-z0-9_\-\.]+\.[A-Za-z]{2,4}",
    "api_calls": r"(VirtualAlloc|WriteProcessMemory|CreateRemoteThread|LoadLibrary)",
    "crypto": r"(AES|DES|RSA|MD5|SHA1|SHA256|RC4)",
    "mutex": r"(Global\\|Local\\)[A-Za-z0-9_\-]+",
    "base64": r"[A-Za-z0-9+/]{20,}={0,2}",
}


def filter_strings(strings: list[str], min_length: int, max_length: int) -> list[str]:
    filtered = []
    for string in strings:
        if len(string) < min_length or len(string) > max_length:
            continue
        cleaned = "".join(c for c in string if c.isprintable())
        if len(cleaned) >= min_length:
            filtered.append(cleaned)
    return filtered


def parse_search_results(result: str) -> list[str]:
    addresses = []
    lines = result.strip().split("\n")
    for line in lines:
        if line.startswith("0x"):
            addresses.append(line.split()[0])
    return addresses


def xor_string(text: str, key: int) -> str:
    return "".join(chr(ord(c) ^ key) for c in text)


def build_xor_matches(
    search_string: str, search_hex_fn: Callable[[str], str]
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for key in range(1, 256):
        xor_result = xor_string(search_string, key)
        hex_pattern = xor_result.encode().hex()
        result = search_hex_fn(hex_pattern)
        if result and result.strip():
            matches.append(
                {
                    "original_string": search_string,
                    "xor_key": key,
                    "xor_result": xor_result,
                    "addresses": parse_search_results(result),
                }
            )
    return matches


def find_suspicious(strings: list[str]) -> list[dict[str, Any]]:
    suspicious: list[dict[str, Any]] = []
    for string in strings:
        for pattern_name, pattern in SUSPICIOUS_PATTERNS.items():
            matches = re.findall(pattern, string, re.IGNORECASE)
            if matches:
                suspicious.append({"string": string, "type": pattern_name, "matches": matches})
    return suspicious


def decode_base64(string: str) -> dict[str, Any] | None:
    if not is_base64(string):
        return None
    try:
        decoded_bytes = base64.b64decode(string)
        decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
        if decoded_str and decoded_str.isprintable():
            return {"original": string, "decoded": decoded_str, "encoding": "base64"}
    except (UnicodeDecodeError, binascii.Error):
        return None
    return None


def decode_hex(string: str) -> dict[str, Any] | None:
    if not is_hex(string):
        return None
    try:
        decoded_bytes = bytes.fromhex(string)
        decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
        if decoded_str and decoded_str.isprintable():
            return {"original": string, "decoded": decoded_str, "encoding": "hex"}
    except UnicodeDecodeError:
        return None
    return None


def is_base64(s: str) -> bool:
    if len(s) < 8 or len(s) % 4 != 0:
        return False
    return re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s) is not None


def is_hex(s: str) -> bool:
    if len(s) < 4 or len(s) % 2 != 0:
        return False
    return re.fullmatch(r"[0-9a-fA-F]+", s) is not None
