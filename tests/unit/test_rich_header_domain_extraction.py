#!/usr/bin/env python3
"""Comprehensive tests for r2inspect/modules/rich_header_domain.py - Rich Header parsing."""

from __future__ import annotations

import hashlib
import struct

import pytest

from r2inspect.modules.rich_header_domain import (
    COMPILER_PRODUCTS,
    build_rich_header_result,
    calculate_richpe_hash,
    decode_rich_header,
    get_compiler_description,
    parse_clear_data_entries,
    parse_compiler_entries,
    validate_decoded_entries,
)


def test_parse_clear_data_entries_single_entry():
    clear_data = struct.pack("<II", 0x00930001, 10)
    
    result = parse_clear_data_entries(clear_data)
    
    assert len(result) == 1
    assert result[0]["product_id"] == 0x0001
    assert result[0]["build_number"] == 0x0093
    assert result[0]["count"] == 10


def test_parse_clear_data_entries_multiple_entries():
    clear_data = struct.pack("<II", 0x00930001, 5) + struct.pack("<II", 0x00A00002, 3)
    
    result = parse_clear_data_entries(clear_data)
    
    assert len(result) == 2
    assert result[0]["count"] == 5
    assert result[1]["count"] == 3


def test_parse_clear_data_entries_zero_count():
    clear_data = struct.pack("<II", 0x00930001, 0)
    
    result = parse_clear_data_entries(clear_data)
    
    assert len(result) == 0


def test_parse_clear_data_entries_empty_data():
    result = parse_clear_data_entries(b"")
    
    assert result == []


def test_parse_clear_data_entries_partial_data():
    clear_data = struct.pack("<I", 0x00930001)
    
    result = parse_clear_data_entries(clear_data)
    
    assert result == []


def test_parse_clear_data_entries_large_count():
    clear_data = struct.pack("<II", 0x00930001, 1000)
    
    result = parse_clear_data_entries(clear_data)
    
    assert len(result) == 1
    assert result[0]["count"] == 1000


def test_get_compiler_description_utc():
    result = get_compiler_description("Utc1310_C", 12345)
    
    assert "Microsoft C/C++ Compiler" in result
    assert "12345" in result


def test_get_compiler_description_linker():
    result = get_compiler_description("Linker800", 5000)
    
    assert "Microsoft Linker" in result
    assert "5000" in result


def test_get_compiler_description_masm():
    result = get_compiler_description("Masm900", 1234)
    
    assert "Microsoft Macro Assembler" in result
    assert "1234" in result


def test_get_compiler_description_cvtres():
    result = get_compiler_description("Cvtres700", 9876)
    
    assert "Microsoft Resource Converter" in result
    assert "9876" in result


def test_get_compiler_description_export():
    result = get_compiler_description("Export800", 111)
    
    assert "Microsoft Export Tool" in result
    assert "111" in result


def test_get_compiler_description_implib():
    result = get_compiler_description("Implib900", 222)
    
    assert "Microsoft Import Library Tool" in result
    assert "222" in result


def test_get_compiler_description_cvtomf():
    result = get_compiler_description("Cvtomf800", 333)
    
    assert "Microsoft OMF Converter" in result
    assert "333" in result


def test_get_compiler_description_aliasobj():
    result = get_compiler_description("AliasObj80", 444)
    
    assert "Microsoft Alias Object Tool" in result
    assert "444" in result


def test_get_compiler_description_visualbasic():
    result = get_compiler_description("VisualBasic60", 555)
    
    assert "Microsoft Visual Basic" in result
    assert "555" in result


def test_get_compiler_description_cvtpgd():
    result = get_compiler_description("Cvtpgd1400", 666)
    
    assert "Microsoft Profile Guided Optimization Tool" in result
    assert "666" in result


def test_get_compiler_description_unknown():
    result = get_compiler_description("UnknownCompiler", 777)
    
    assert "UnknownCompiler" in result
    assert "777" in result


def test_parse_compiler_entries_single():
    entries = [
        {"prodid": 0x00930001, "count": 10}
    ]
    
    result = parse_compiler_entries(entries)
    
    assert len(result) == 1
    assert result[0]["product_id"] == 0x0001
    assert result[0]["build_number"] == 0x0093
    assert result[0]["count"] == 10
    assert "compiler_name" in result[0]
    assert "description" in result[0]


def test_parse_compiler_entries_multiple():
    entries = [
        {"prodid": 0x00930001, "count": 5},
        {"prodid": 0x00A00002, "count": 3},
    ]
    
    result = parse_compiler_entries(entries)
    
    assert len(result) == 2
    assert result[0]["product_id"] == 0x0001
    assert result[1]["product_id"] == 0x0002


def test_parse_compiler_entries_known_product():
    entries = [
        {"prodid": (0x0093 << 16) | 0x0060, "count": 1}
    ]
    
    result = parse_compiler_entries(entries)
    
    assert result[0]["compiler_name"] == COMPILER_PRODUCTS.get(0x0060, "Unknown")


def test_parse_compiler_entries_unknown_product():
    entries = [
        {"prodid": 0xFFFF9999, "count": 1}
    ]
    
    result = parse_compiler_entries(entries)
    
    assert "Unknown_0x" in result[0]["compiler_name"]


def test_parse_compiler_entries_empty():
    result = parse_compiler_entries([])
    
    assert result == []


def test_decode_rich_header_basic():
    xor_key = 0x12345678
    prodid = 0x00930001
    count = 10
    encoded_data = b"DanS" + struct.pack("<II", prodid ^ xor_key, count ^ xor_key)
    
    result = decode_rich_header(encoded_data, xor_key)
    
    assert len(result) == 1
    assert result[0]["prodid"] == prodid
    assert result[0]["count"] == count


def test_decode_rich_header_multiple_entries():
    xor_key = 0x12345678
    encoded_data = b"DanS"
    for i in range(3):
        prodid = 0x00930001 + i
        count = 10 + i
        encoded_data += struct.pack("<II", prodid ^ xor_key, count ^ xor_key)
    
    result = decode_rich_header(encoded_data, xor_key)
    
    assert len(result) == 3


def test_decode_rich_header_empty():
    result = decode_rich_header(b"", 0x12345678)
    
    assert result == []


def test_decode_rich_header_too_short():
    result = decode_rich_header(b"DanS", 0x12345678)
    
    assert result == []


def test_decode_rich_header_zero_count():
    xor_key = 0x12345678
    encoded_data = b"DanS" + struct.pack("<II", 0x00930001 ^ xor_key, 0 ^ xor_key)
    
    result = decode_rich_header(encoded_data, xor_key)
    
    assert len(result) == 0


def test_decode_rich_header_partial_entry():
    xor_key = 0x12345678
    encoded_data = b"DanS" + struct.pack("<I", 0x00930001 ^ xor_key)
    
    result = decode_rich_header(encoded_data, xor_key)
    
    assert result == []


def test_decode_rich_header_exception():
    result = decode_rich_header(b"malformed", 0x12345678)
    
    assert result == []


def test_validate_decoded_entries_valid():
    entries = [
        {"prodid": 0x0001, "count": 10},
        {"prodid": 0x0002, "count": 5},
    ]
    
    result = validate_decoded_entries(entries)
    
    assert result is True


def test_validate_decoded_entries_empty():
    result = validate_decoded_entries([])
    
    assert result is False


def test_validate_decoded_entries_invalid_count_too_high():
    entries = [
        {"prodid": 0x0001, "count": 20000}
    ]
    
    result = validate_decoded_entries(entries)
    
    assert result is False


def test_validate_decoded_entries_invalid_count_zero():
    entries = [
        {"prodid": 0x0001, "count": 0}
    ]
    
    result = validate_decoded_entries(entries)
    
    assert result is False


def test_validate_decoded_entries_invalid_prodid():
    entries = [
        {"prodid": 0x20000, "count": 10}
    ]
    
    result = validate_decoded_entries(entries)
    
    assert result is False


def test_validate_decoded_entries_mixed_valid_invalid():
    entries = [
        {"prodid": 0x0001, "count": 10},
        {"prodid": 0x20000, "count": 5},
    ]
    
    result = validate_decoded_entries(entries)
    
    assert result is True


def test_build_rich_header_result_basic():
    entries = [
        {"prodid": 0x0001, "count": 10},
        {"prodid": 0x0002, "count": 5},
    ]
    xor_key = 0x12345678
    
    result = build_rich_header_result(entries, xor_key)
    
    assert result["xor_key"] == xor_key
    assert "checksum" in result
    assert result["entries"] == entries


def test_build_rich_header_result_checksum():
    entries = [
        {"prodid": 0x0001, "count": 10},
    ]
    xor_key = 0x12345678
    
    result = build_rich_header_result(entries, xor_key)
    
    expected_checksum = 0x0001 ^ 10
    assert result["checksum"] == expected_checksum


def test_build_rich_header_result_empty_entries():
    result = build_rich_header_result([], 0x12345678)
    
    assert result["checksum"] == 0
    assert result["entries"] == []


def test_calculate_richpe_hash_from_clear_data_bytes():
    clear_data = struct.pack("<II", 0x00930001, 10)
    rich_data = {"clear_data_bytes": clear_data}
    
    result = calculate_richpe_hash(rich_data)
    
    expected = hashlib.md5(clear_data, usedforsecurity=False).hexdigest()
    assert result == expected


def test_calculate_richpe_hash_from_existing_hash():
    existing_hash = "1234567890abcdef1234567890abcdef"
    rich_data = {"richpe_hash": existing_hash}
    
    result = calculate_richpe_hash(rich_data)
    
    assert result == existing_hash


def test_calculate_richpe_hash_from_entries():
    entries = [
        {"prodid": 0x00930001, "count": 10},
        {"prodid": 0x00A00002, "count": 5},
    ]
    rich_data = {"entries": entries}
    
    result = calculate_richpe_hash(rich_data)
    
    clear_bytes = bytearray()
    for entry in entries:
        clear_bytes.extend(struct.pack("<I", entry["prodid"]))
        clear_bytes.extend(struct.pack("<I", entry["count"]))
    expected = hashlib.md5(clear_bytes, usedforsecurity=False).hexdigest()
    
    assert result == expected


def test_calculate_richpe_hash_no_data():
    rich_data = {}
    
    result = calculate_richpe_hash(rich_data)
    
    assert result is None


def test_calculate_richpe_hash_empty_entries():
    rich_data = {"entries": []}
    
    result = calculate_richpe_hash(rich_data)
    
    assert result is None


def test_compiler_products_dictionary_coverage():
    assert 0x0000 in COMPILER_PRODUCTS
    assert 0x0060 in COMPILER_PRODUCTS
    assert 0x0093 in COMPILER_PRODUCTS
    assert 0x9CB4 in COMPILER_PRODUCTS
    assert 0x9E37 in COMPILER_PRODUCTS


def test_parse_clear_data_entries_prodid_structure():
    prodid = (0x1234 << 16) | 0x5678
    clear_data = struct.pack("<II", prodid, 10)
    
    result = parse_clear_data_entries(clear_data)
    
    assert result[0]["product_id"] == 0x5678
    assert result[0]["build_number"] == 0x1234


def test_decode_rich_header_preserves_encoded_values():
    xor_key = 0x12345678
    prodid = 0x00930001
    count = 10
    encoded_data = b"DanS" + struct.pack("<II", prodid ^ xor_key, count ^ xor_key)
    
    result = decode_rich_header(encoded_data, xor_key)
    
    assert result[0]["prodid_encoded"] == prodid ^ xor_key
    assert result[0]["count_encoded"] == count ^ xor_key


def test_validate_decoded_entries_boundary_values():
    entries = [
        {"prodid": 1, "count": 1},
        {"prodid": 0xFFFF, "count": 9999},
    ]
    
    result = validate_decoded_entries(entries)
    
    assert result is True


def test_build_rich_header_result_multiple_entry_checksum():
    entries = [
        {"prodid": 0x0001, "count": 10},
        {"prodid": 0x0002, "count": 5},
        {"prodid": 0x0003, "count": 3},
    ]
    xor_key = 0x12345678
    
    result = build_rich_header_result(entries, xor_key)
    
    expected_checksum = 0x0001 ^ 10 ^ 0x0002 ^ 5 ^ 0x0003 ^ 3
    assert result["checksum"] == expected_checksum


def test_parse_compiler_entries_full_prodid():
    entries = [
        {"prodid": 0x12345678, "count": 1}
    ]
    
    result = parse_compiler_entries(entries)
    
    assert result[0]["full_prodid"] == 0x12345678


def test_calculate_richpe_hash_precedence():
    clear_data = struct.pack("<II", 0x00930001, 10)
    existing_hash = "1234567890abcdef1234567890abcdef"
    entries = [{"prodid": 0x00930001, "count": 10}]
    
    rich_data = {
        "clear_data_bytes": clear_data,
        "richpe_hash": existing_hash,
        "entries": entries
    }
    
    result = calculate_richpe_hash(rich_data)
    
    expected = hashlib.md5(clear_data, usedforsecurity=False).hexdigest()
    assert result == expected
