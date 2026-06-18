"""Decoding and validation helpers for Rich Header analysis."""

from __future__ import annotations

import struct
from typing import Any


def parse_clear_data_entries(clear_data: bytes) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for i in range(0, len(clear_data), 8):
        if i + 8 > len(clear_data):
            break
        prodid, count = struct.unpack("<II", clear_data[i : i + 8])
        if count > 0:
            product_id = prodid & 0xFFFF
            build_number = (prodid >> 16) & 0xFFFF
            entries.append(
                {
                    "product_id": product_id,
                    "build_number": build_number,
                    "count": count,
                    "prodid": prodid,
                }
            )
    return entries


def decode_rich_header(encoded_data: bytes, xor_key: int) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    if not encoded_data:
        return entries
    for i in range(4, len(encoded_data) - 4, 8):
        if i + 8 > len(encoded_data):
            break
        entry_bytes = encoded_data[i : i + 8]
        if len(entry_bytes) < 8:
            break
        prodid_encoded, count_encoded = struct.unpack("<II", entry_bytes)
        prodid = prodid_encoded ^ xor_key
        count = count_encoded ^ xor_key
        if count > 0:
            entries.append(
                {
                    "prodid": prodid,
                    "product_id": prodid & 0xFFFF,
                    "build_number": (prodid >> 16) & 0xFFFF,
                    "count": count,
                    "prodid_encoded": prodid_encoded,
                    "count_encoded": count_encoded,
                }
            )
    return entries


def validate_decoded_entries(decoded_entries: list[dict[str, Any]]) -> bool:
    if not decoded_entries:
        return False
    valid_entries = 0
    for entry in decoded_entries:
        if not isinstance(entry, dict):
            continue
        prodid = entry.get("prodid", 0)
        count = entry.get("count", 0)
        if not isinstance(prodid, int) or not isinstance(count, int):
            continue
        product_id = prodid & 0xFFFF
        if 0 < count < 10000 and 0 <= prodid <= 0xFFFFFFFF and 0 <= product_id <= 0xFFFF:
            valid_entries += 1
    return valid_entries > 0


def build_rich_header_result(decoded_entries: list[dict[str, Any]], xor_key: int) -> dict[str, Any]:
    checksum = 0
    if not isinstance(decoded_entries, list):
        return {"xor_key": xor_key, "checksum": checksum, "entries": []}
    for entry in decoded_entries:
        if not isinstance(entry, dict):
            continue
        prodid = entry.get("prodid", 0)
        count = entry.get("count", 0)
        if not isinstance(prodid, int) or not isinstance(count, int):
            continue
        checksum ^= prodid
        checksum ^= count
    return {
        "xor_key": xor_key,
        "checksum": checksum,
        "entries": decoded_entries,
    }
