#!/usr/bin/env python3
"""Branch-path tests for r2inspect/modules/rich_header_domain.py.

Covers missing lines: 225, 256, 282-296, 304-306, 310-318, 322-326, 337-349.
"""

from __future__ import annotations

import hashlib
import struct

import pytest

from r2inspect.modules.rich_header_domain import (
    build_rich_header_result,
    calculate_richpe_hash,
    decode_rich_header,
    get_compiler_description,
    parse_clear_data_entries,
    validate_decoded_entries,
)


# ---------------------------------------------------------------------------
# parse_clear_data_entries - line 225: break when partial chunk at end
# ---------------------------------------------------------------------------


def test_parse_clear_data_entries_partial_trailing_bytes_triggers_break():
    """12-byte input: one full 8-byte entry then 4 trailing bytes hit the break."""
    full_entry = struct.pack("<II", 0x00930001, 5)
    trailing = b"\x00\x00\x00\x00"
    result = parse_clear_data_entries(full_entry + trailing)
    assert len(result) == 1
    assert result[0]["count"] == 5


def test_parse_clear_data_entries_non_multiple_of_8():
    """7-byte input: range produces i=0 which is i+8=8 > 7, triggers break immediately."""
    data = b"\x01\x00\x00\x00\x0a\x00\x00"
    result = parse_clear_data_entries(data)
    assert result == []


# ---------------------------------------------------------------------------
# get_compiler_description - line 256: return inside the for-loop
# ---------------------------------------------------------------------------


def test_get_compiler_description_utc_prefix_returns_inner_desc():
    result = get_compiler_description("Utc1900_CPP", 1234)
    assert "Microsoft C/C++ Compiler" in result
    assert "1234" in result


def test_get_compiler_description_linker_prefix_returns_inner_desc():
    result = get_compiler_description("Linker900", 9000)
    assert "Microsoft Linker" in result
    assert "9000" in result


def test_get_compiler_description_masm_prefix_returns_inner_desc():
    result = get_compiler_description("Masm1000", 100)
    assert "Microsoft Macro Assembler" in result


def test_get_compiler_description_cvtres_prefix_returns_inner_desc():
    result = get_compiler_description("Cvtres700", 7)
    assert "Microsoft Resource Converter" in result


def test_get_compiler_description_export_prefix_returns_inner_desc():
    result = get_compiler_description("Export800", 8)
    assert "Microsoft Export Tool" in result


def test_get_compiler_description_implib_prefix_returns_inner_desc():
    result = get_compiler_description("Implib900", 9)
    assert "Microsoft Import Library Tool" in result


def test_get_compiler_description_cvtomf_prefix_returns_inner_desc():
    result = get_compiler_description("Cvtomf800", 800)
    assert "Microsoft OMF Converter" in result


def test_get_compiler_description_aliasobj_prefix_returns_inner_desc():
    result = get_compiler_description("AliasObj80", 80)
    assert "Microsoft Alias Object Tool" in result


def test_get_compiler_description_visualbasic_prefix_returns_inner_desc():
    result = get_compiler_description("VisualBasic60", 60)
    assert "Microsoft Visual Basic" in result


def test_get_compiler_description_cvtpgd_prefix_returns_inner_desc():
    result = get_compiler_description("Cvtpgd1300", 1300)
    assert "Microsoft Profile Guided Optimization Tool" in result


# ---------------------------------------------------------------------------
# decode_rich_header - lines 282-296: function body
# ---------------------------------------------------------------------------


def test_decode_rich_header_body_with_single_entry():
    """Calling decode_rich_header covers its entire function body."""
    xor_key = 0xAABBCCDD
    prodid = 0x00930060
    count = 7
    encoded_data = b"DanS" + struct.pack("<II", prodid ^ xor_key, count ^ xor_key)
    result = decode_rich_header(encoded_data, xor_key)
    assert len(result) == 1
    assert result[0]["prodid"] == prodid
    assert result[0]["count"] == count
    assert result[0]["prodid_encoded"] == prodid ^ xor_key
    assert result[0]["count_encoded"] == count ^ xor_key


def test_decode_rich_header_body_with_multiple_entries():
    xor_key = 0x12345678
    encoded_data = b"DanS"
    expected = []
    for i in range(3):
        prodid = 0x00930001 + i
        count = 2 + i
        encoded_data += struct.pack("<II", prodid ^ xor_key, count ^ xor_key)
        expected.append((prodid, count))
    result = decode_rich_header(encoded_data, xor_key)
    assert len(result) == 3
    for i, (eprodid, ecount) in enumerate(expected):
        assert result[i]["prodid"] == eprodid
        assert result[i]["count"] == ecount


def test_decode_rich_header_empty_data_returns_empty_list():
    """Empty data hits the early return at line 284."""
    result = decode_rich_header(b"", 0xDEADBEEF)
    assert result == []


def test_decode_rich_header_skips_zero_count_entries():
    xor_key = 0x11223344
    prodid = 0x00930001
    count_zero = 0
    encoded_data = b"DanS" + struct.pack("<II", prodid ^ xor_key, count_zero ^ xor_key)
    result = decode_rich_header(encoded_data, xor_key)
    assert result == []


# ---------------------------------------------------------------------------
# decode_rich_header - line 288: break when i+8 > len
# ---------------------------------------------------------------------------


def test_decode_rich_header_break_when_entry_does_not_fit():
    """10-byte input: loop starts at i=4, i+8=12 > 10, hits break at line 288."""
    xor_key = 0xAABBCCDD
    data = b"DanS" + b"\x01\x02\x03\x04\x05\x06"
    result = decode_rich_header(data, xor_key)
    assert result == []


# ---------------------------------------------------------------------------
# decode_rich_header - lines 304-305: exception handler
# ---------------------------------------------------------------------------


class _ExplodingBytesLike:
    """Bytes-like object that raises ValueError on slice access to trigger exception handler."""

    def __bool__(self) -> bool:
        return True

    def __len__(self) -> int:
        return 20

    def __getitem__(self, key: object) -> object:
        raise ValueError("simulated error to cover exception handler")


def test_decode_rich_header_exception_handler_returns_empty_list():
    """Passing a faulty bytes-like object triggers the except block at lines 304-305."""
    result = decode_rich_header(_ExplodingBytesLike(), 0x12345678)  # type: ignore[arg-type]
    assert result == []


# ---------------------------------------------------------------------------
# validate_decoded_entries - lines 310-318: function body
# ---------------------------------------------------------------------------


def test_validate_decoded_entries_valid_entries_returns_true():
    entries = [{"prodid": 0x0001, "count": 5}]
    assert validate_decoded_entries(entries) is True


def test_validate_decoded_entries_empty_returns_false():
    assert validate_decoded_entries([]) is False


def test_validate_decoded_entries_all_invalid_counts_returns_false():
    entries = [{"prodid": 0x0001, "count": 0}]
    assert validate_decoded_entries(entries) is False


def test_validate_decoded_entries_count_too_high_returns_false():
    entries = [{"prodid": 0x0001, "count": 99999}]
    assert validate_decoded_entries(entries) is False


def test_validate_decoded_entries_prodid_too_high_returns_false():
    entries = [{"prodid": 0x20000, "count": 1}]
    assert validate_decoded_entries(entries) is False


def test_validate_decoded_entries_mixed_valid_invalid():
    entries = [
        {"prodid": 0x0001, "count": 1},
        {"prodid": 0x20000, "count": 1},
    ]
    assert validate_decoded_entries(entries) is True


def test_validate_decoded_entries_boundary_values():
    entries = [
        {"prodid": 0xFFFF, "count": 9999},
    ]
    assert validate_decoded_entries(entries) is True


# ---------------------------------------------------------------------------
# build_rich_header_result - lines 322-326: function body
# ---------------------------------------------------------------------------


def test_build_rich_header_result_basic():
    entries = [{"prodid": 0x0001, "count": 10}]
    result = build_rich_header_result(entries, 0x12345678)
    assert result["xor_key"] == 0x12345678
    assert result["entries"] is entries
    assert result["checksum"] == 0x0001 ^ 10


def test_build_rich_header_result_empty_entries():
    result = build_rich_header_result([], 0xDEADBEEF)
    assert result["checksum"] == 0
    assert result["entries"] == []
    assert result["xor_key"] == 0xDEADBEEF


def test_build_rich_header_result_multiple_entries_checksum():
    entries = [
        {"prodid": 0x0001, "count": 10},
        {"prodid": 0x0002, "count": 5},
    ]
    result = build_rich_header_result(entries, 0)
    expected = 0x0001 ^ 10 ^ 0x0002 ^ 5
    assert result["checksum"] == expected


# ---------------------------------------------------------------------------
# calculate_richpe_hash - lines 337-349: richpe_hash and entries paths
# ---------------------------------------------------------------------------


def test_calculate_richpe_hash_returns_existing_richpe_hash_string():
    existing = "abcdef1234567890abcdef1234567890"
    result = calculate_richpe_hash({"richpe_hash": existing})
    assert result == existing


def test_calculate_richpe_hash_returns_none_for_empty_entries():
    result = calculate_richpe_hash({"entries": []})
    assert result is None


def test_calculate_richpe_hash_computes_hash_from_entries():
    entries = [{"prodid": 0x00930001, "count": 3}]
    result = calculate_richpe_hash({"entries": entries})
    clear_bytes = bytearray()
    clear_bytes.extend(struct.pack("<I", 0x00930001))
    clear_bytes.extend(struct.pack("<I", 3))
    expected = hashlib.md5(clear_bytes, usedforsecurity=False).hexdigest()
    assert result == expected


def test_calculate_richpe_hash_richpe_hash_preferred_over_entries():
    existing = "cafecafe12341234cafecafe12341234"
    entries = [{"prodid": 0x0001, "count": 1}]
    result = calculate_richpe_hash({"richpe_hash": existing, "entries": entries})
    assert result == existing


def test_calculate_richpe_hash_entries_multiple():
    entries = [
        {"prodid": 0x00930001, "count": 1},
        {"prodid": 0x00A00002, "count": 2},
    ]
    result = calculate_richpe_hash({"entries": entries})
    clear_bytes = bytearray()
    for entry in entries:
        clear_bytes.extend(struct.pack("<I", entry["prodid"]))
        clear_bytes.extend(struct.pack("<I", entry["count"]))
    expected = hashlib.md5(clear_bytes, usedforsecurity=False).hexdigest()
    assert result == expected
