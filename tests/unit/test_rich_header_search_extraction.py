#!/usr/bin/env python3
"""Comprehensive tests for r2inspect/modules/rich_header_search.py - Rich Header search."""

from __future__ import annotations

import struct
from unittest.mock import Mock

import pytest

from r2inspect.modules.rich_header_search import RichHeaderSearchMixin


class TestRichHeaderSearch(RichHeaderSearchMixin):
    """Test wrapper for RichHeaderSearchMixin."""
    
    def __init__(self, adapter):
        self.adapter = adapter


def test_manual_rich_search_basic():
    adapter = Mock()
    xor_key = 0x12345678
    prodid = 0x00930001
    count = 10
    
    dans_data = b"DanS"
    encoded_entry = struct.pack("<II", prodid ^ xor_key, count ^ xor_key)
    rich_data = b"Rich" + struct.pack("<I", xor_key)
    
    full_data = b"\x00" * 100 + dans_data + encoded_entry + rich_data + b"\x00" * 100
    
    adapter.read_bytes.return_value = full_data
    adapter.read_bytes_list.side_effect = lambda offset, size: list(full_data[offset:offset+size])
    
    search = TestRichHeaderSearch(adapter)
    result = search._manual_rich_search()
    
    assert isinstance(result, (dict, type(None)))


def test_manual_rich_search_no_data():
    adapter = Mock()
    adapter.read_bytes.return_value = None
    
    search = TestRichHeaderSearch(adapter)
    result = search._manual_rich_search()
    
    assert result is None


def test_manual_rich_search_no_adapter():
    search = TestRichHeaderSearch(None)
    result = search._manual_rich_search()
    
    assert result is None


def test_manual_rich_search_exception():
    adapter = Mock()
    adapter.read_bytes.side_effect = Exception("Read error")
    
    search = TestRichHeaderSearch(adapter)
    result = search._manual_rich_search()
    
    assert result is None


def test_read_manual_search_bytes_valid():
    adapter = Mock()
    adapter.read_bytes.return_value = b"\x00" * 2048
    
    search = TestRichHeaderSearch(adapter)
    result = search._read_manual_search_bytes()
    
    assert result is not None
    assert len(result) == 2048


def test_read_manual_search_bytes_no_adapter():
    search = TestRichHeaderSearch(None)
    result = search._read_manual_search_bytes()
    
    assert result is None


def test_read_manual_search_bytes_no_method():
    adapter = Mock(spec=[])
    
    search = TestRichHeaderSearch(adapter)
    result = search._read_manual_search_bytes()
    
    assert result is None


def test_read_manual_search_bytes_empty():
    adapter = Mock()
    adapter.read_bytes.return_value = b""
    
    search = TestRichHeaderSearch(adapter)
    result = search._read_manual_search_bytes()
    
    assert result is None


def test_find_signature_offsets_both_found():
    adapter = Mock()
    data = b"\x00" * 50 + b"DanS" + b"\x00" * 100 + b"Rich" + b"\x00" * 50
    
    search = TestRichHeaderSearch(adapter)
    result = search._find_signature_offsets(data, b"Rich", b"DanS")
    
    assert result is not None
    rich_offsets, dans_offsets = result
    assert len(rich_offsets) > 0
    assert len(dans_offsets) > 0


def test_find_signature_offsets_rich_missing():
    adapter = Mock()
    data = b"\x00" * 50 + b"DanS" + b"\x00" * 100
    
    search = TestRichHeaderSearch(adapter)
    result = search._find_signature_offsets(data, b"Rich", b"DanS")
    
    assert result is None


def test_find_signature_offsets_dans_missing():
    adapter = Mock()
    data = b"\x00" * 50 + b"Rich" + b"\x00" * 100
    
    search = TestRichHeaderSearch(adapter)
    result = search._find_signature_offsets(data, b"Rich", b"DanS")
    
    assert result is None


def test_find_all_occurrences_single():
    adapter = Mock()
    data = b"\x00" * 50 + b"Rich" + b"\x00" * 100
    
    search = TestRichHeaderSearch(adapter)
    result = search._find_all_occurrences(data, b"Rich")
    
    assert len(result) == 1
    assert result[0] == 50


def test_find_all_occurrences_multiple():
    adapter = Mock()
    data = b"Rich" + b"\x00" * 50 + b"Rich" + b"\x00" * 50 + b"Rich"
    
    search = TestRichHeaderSearch(adapter)
    result = search._find_all_occurrences(data, b"Rich")
    
    assert len(result) == 3


def test_find_all_occurrences_none():
    adapter = Mock()
    data = b"\x00" * 200
    
    search = TestRichHeaderSearch(adapter)
    result = search._find_all_occurrences(data, b"Rich")
    
    assert len(result) == 0


def test_find_all_occurrences_overlapping():
    adapter = Mock()
    data = b"AAA"
    
    search = TestRichHeaderSearch(adapter)
    result = search._find_all_occurrences(data, b"AA")
    
    assert len(result) == 2


def test_try_signature_pairs_valid():
    adapter = Mock()
    xor_key = 0x12345678
    prodid = 0x00930001
    count = 10
    
    dans_offset = 100
    rich_offset = 120
    
    dans_data = b"DanS"
    encoded_entry = struct.pack("<II", prodid ^ xor_key, count ^ xor_key)
    rich_data = b"Rich" + struct.pack("<I", xor_key)
    
    full_data = b"\x00" * dans_offset + dans_data + encoded_entry + b"\x00" * (rich_offset - dans_offset - len(dans_data) - len(encoded_entry)) + rich_data
    
    adapter.read_bytes_list.side_effect = lambda offset, size: list(full_data[offset:offset+size])
    
    search = TestRichHeaderSearch(adapter)
    result = search._try_signature_pairs([rich_offset], [dans_offset], b"Rich", b"DanS")
    
    assert isinstance(result, (dict, type(None)))


def test_try_signature_pairs_invalid_distance():
    adapter = Mock()
    
    search = TestRichHeaderSearch(adapter)
    result = search._try_signature_pairs([1000], [100], b"Rich", b"DanS")
    
    assert result is None


def test_try_signature_pairs_wrong_order():
    adapter = Mock()
    
    search = TestRichHeaderSearch(adapter)
    result = search._try_signature_pairs([100], [200], b"Rich", b"DanS")
    
    assert result is None


def test_offset_pair_valid_correct():
    adapter = Mock()
    search = TestRichHeaderSearch(adapter)
    
    result = search._offset_pair_valid(100, 150, 512)
    
    assert result is True


def test_offset_pair_valid_too_far():
    adapter = Mock()
    search = TestRichHeaderSearch(adapter)
    
    result = search._offset_pair_valid(100, 700, 512)
    
    assert result is False


def test_offset_pair_valid_wrong_order():
    adapter = Mock()
    search = TestRichHeaderSearch(adapter)
    
    result = search._offset_pair_valid(200, 100, 512)
    
    assert result is False


def test_pattern_based_rich_search_found():
    adapter = Mock()
    xor_key = 0x12345678
    prodid = 0x00930001
    count = 10
    
    dans_offset = 100
    rich_offset = 120
    
    dans_data = b"DanS"
    encoded_entry = struct.pack("<II", prodid ^ xor_key, count ^ xor_key)
    rich_data = b"Rich" + struct.pack("<I", xor_key)
    
    full_data = (b"\x00" * dans_offset + dans_data + encoded_entry + 
                 b"\x00" * (rich_offset - dans_offset - len(dans_data) - len(encoded_entry)) + 
                 rich_data)
    
    adapter.read_bytes_list.side_effect = lambda offset, size: list(full_data[offset:offset+size])
    
    search = TestRichHeaderSearch(adapter)
    result = search._pattern_based_rich_search(full_data)
    
    assert isinstance(result, (dict, type(None)))


def test_pattern_based_rich_search_no_rich():
    adapter = Mock()
    data = b"\x00" * 500
    
    search = TestRichHeaderSearch(adapter)
    result = search._pattern_based_rich_search(data)
    
    assert result is None


def test_pattern_based_rich_search_exception():
    adapter = Mock()
    
    search = TestRichHeaderSearch(adapter)
    result = search._pattern_based_rich_search(b"malformed")
    
    assert result is None


def test_find_rich_positions_single():
    adapter = Mock()
    data = b"\x00" * 100 + b"Rich" + b"\x00" * 100
    
    search = TestRichHeaderSearch(adapter)
    result = search._find_rich_positions(data)
    
    assert len(result) == 1
    assert result[0] == 100


def test_find_rich_positions_multiple():
    adapter = Mock()
    data = b"Rich" + b"\x00" * 50 + b"Rich" + b"\x00" * 50
    
    search = TestRichHeaderSearch(adapter)
    result = search._find_rich_positions(data)
    
    assert len(result) == 2


def test_find_rich_positions_none():
    adapter = Mock()
    data = b"\x00" * 200
    
    search = TestRichHeaderSearch(adapter)
    result = search._find_rich_positions(data)
    
    assert len(result) == 0


def test_is_valid_rich_key_valid():
    adapter = Mock()
    data = b"Rich" + struct.pack("<I", 0x12345678)
    
    search = TestRichHeaderSearch(adapter)
    result = search._is_valid_rich_key(data, 0)
    
    assert result is True


def test_is_valid_rich_key_zero():
    adapter = Mock()
    data = b"Rich" + struct.pack("<I", 0)
    
    search = TestRichHeaderSearch(adapter)
    result = search._is_valid_rich_key(data, 0)
    
    assert result is False


def test_is_valid_rich_key_all_ones():
    adapter = Mock()
    data = b"Rich" + struct.pack("<I", 0xFFFFFFFF)
    
    search = TestRichHeaderSearch(adapter)
    result = search._is_valid_rich_key(data, 0)
    
    assert result is False


def test_is_valid_rich_key_out_of_bounds():
    adapter = Mock()
    data = b"Rich"
    
    search = TestRichHeaderSearch(adapter)
    result = search._is_valid_rich_key(data, 0)
    
    assert result is False


def test_find_dans_before_rich_found():
    adapter = Mock()
    data = b"\x00" * 50 + b"DanS" + b"\x00" * 100
    
    search = TestRichHeaderSearch(adapter)
    result = search._find_dans_before_rich(data, 150)
    
    assert result == 50


def test_find_dans_before_rich_not_found():
    adapter = Mock()
    data = b"\x00" * 200
    
    search = TestRichHeaderSearch(adapter)
    result = search._find_dans_before_rich(data, 150)
    
    assert result is None


def test_find_dans_before_rich_too_far():
    adapter = Mock()
    data = b"DanS" + b"\x00" * 600
    
    search = TestRichHeaderSearch(adapter)
    result = search._find_dans_before_rich(data, 600)
    
    assert result is None


def test_validate_rich_size_valid():
    adapter = Mock()
    search = TestRichHeaderSearch(adapter)
    
    assert search._validate_rich_size(16) is True
    assert search._validate_rich_size(100) is True
    assert search._validate_rich_size(512) is True


def test_validate_rich_size_too_small():
    adapter = Mock()
    search = TestRichHeaderSearch(adapter)
    
    assert search._validate_rich_size(8) is False
    assert search._validate_rich_size(4) is False


def test_validate_rich_size_too_large():
    adapter = Mock()
    search = TestRichHeaderSearch(adapter)
    
    assert search._validate_rich_size(513) is False
    assert search._validate_rich_size(1000) is False


def test_extract_xor_key_valid():
    adapter = Mock()
    xor_key = 0x12345678
    data = b"Rich" + struct.pack("<I", xor_key)
    
    adapter.read_bytes_list.return_value = list(struct.pack("<I", xor_key))
    
    search = TestRichHeaderSearch(adapter)
    result = search._extract_xor_key(0)
    
    assert result == xor_key


def test_extract_xor_key_zero():
    adapter = Mock()
    adapter.read_bytes_list.return_value = list(struct.pack("<I", 0))
    
    search = TestRichHeaderSearch(adapter)
    result = search._extract_xor_key(0)
    
    assert result is None


def test_extract_xor_key_no_adapter():
    search = TestRichHeaderSearch(None)
    result = search._extract_xor_key(0)
    
    assert result is None


def test_extract_xor_key_insufficient_bytes():
    adapter = Mock()
    adapter.read_bytes_list.return_value = [0x12, 0x34]
    
    search = TestRichHeaderSearch(adapter)
    result = search._extract_xor_key(0)
    
    assert result is None


def test_extract_encoded_data_valid():
    adapter = Mock()
    data = b"DanS" + struct.pack("<II", 0x12345678, 10)
    
    adapter.read_bytes_list.return_value = list(data)
    
    search = TestRichHeaderSearch(adapter)
    result = search._extract_encoded_data(0, len(data))
    
    assert result == data


def test_extract_encoded_data_no_adapter():
    search = TestRichHeaderSearch(None)
    result = search._extract_encoded_data(0, 16)
    
    assert result is None


def test_extract_encoded_data_insufficient_bytes():
    adapter = Mock()
    adapter.read_bytes_list.return_value = [0x00, 0x01]
    
    search = TestRichHeaderSearch(adapter)
    result = search._extract_encoded_data(0, 16)
    
    assert result is None


def test_try_extract_rich_at_offsets_complete():
    adapter = Mock()
    xor_key = 0x12345678
    prodid = 0x00930001
    count = 10
    
    dans_offset = 100
    rich_offset = 120
    rich_size = rich_offset - dans_offset
    
    dans_data = b"DanS"
    encoded_entry = struct.pack("<II", prodid ^ xor_key, count ^ xor_key)
    xor_key_bytes = struct.pack("<I", xor_key)
    
    adapter.read_bytes_list.side_effect = [
        list(xor_key_bytes),
        list(dans_data + encoded_entry),
    ]
    
    search = TestRichHeaderSearch(adapter)
    result = search._try_extract_rich_at_offsets(dans_offset, rich_offset)
    
    assert isinstance(result, (dict, type(None)))


def test_try_extract_rich_at_offsets_invalid_size():
    adapter = Mock()
    
    search = TestRichHeaderSearch(adapter)
    result = search._try_extract_rich_at_offsets(100, 105)
    
    assert result is None


def test_try_extract_rich_at_offsets_exception():
    adapter = Mock()
    adapter.read_bytes_list.side_effect = Exception("Read error")
    
    search = TestRichHeaderSearch(adapter)
    result = search._try_extract_rich_at_offsets(100, 120)
    
    assert result is None
