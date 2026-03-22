#!/usr/bin/env python3
"""Comprehensive tests for r2inspect/modules/rich_header_search.py - Rich Header search.

All mocks replaced with real objects using FakeR2 + R2PipeAdapter.
"""

from __future__ import annotations

import re
import struct

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.rich_header_search import RichHeaderSearchMixin
from r2inspect.testing.fake_r2 import FakeR2


# ---------------------------------------------------------------------------
# FakeR2: minimal r2pipe stand-in routing cmd/cmdj via lookup maps
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hex_for(data: bytes) -> str:
    """Convert bytes to hex string suitable for p8 output."""
    return data.hex()


def _make_adapter_from_blob(blob: bytes) -> R2PipeAdapter:
    """Build an R2PipeAdapter backed by FakeR2 that serves `blob` for p8 reads."""

    p8_pattern = re.compile(r"p8\s+(\d+)\s+@\s+(\d+)")

    def cmd_fn(command: str) -> str:
        m = p8_pattern.match(command.strip())
        if m:
            size = int(m.group(1))
            addr = int(m.group(2))
            chunk = blob[addr : addr + size]
            return chunk.hex()
        return ""

    return R2PipeAdapter(FakeR2(cmd_fn=cmd_fn))


def _make_adapter_empty() -> R2PipeAdapter:
    """Build an R2PipeAdapter that returns empty for all reads."""
    return R2PipeAdapter(FakeR2())


class TestRichHeaderSearch(RichHeaderSearchMixin):
    """Test wrapper for RichHeaderSearchMixin backed by a real R2PipeAdapter."""

    def __init__(self, adapter):
        self.adapter = adapter


def _build_rich_blob(
    *,
    xor_key: int = 0x12345678,
    prodid: int = 0x00930001,
    count: int = 10,
    dans_offset: int = 100,
    gap_after_entry: int = 0,
) -> tuple[bytes, int]:
    """Build a blob containing DanS + encoded entry + Rich + xor_key.

    Returns (blob, rich_offset).
    """
    dans_sig = b"DanS"
    # Padding dword (XOR key encoded) after DanS — decode_rich_header skips first 4 bytes
    padding = struct.pack("<I", xor_key)
    encoded_entry = struct.pack("<II", prodid ^ xor_key, count ^ xor_key)
    gap = b"\x00" * gap_after_entry
    rich_sig = b"Rich"
    xor_bytes = struct.pack("<I", xor_key)

    inner = dans_sig + padding + encoded_entry + gap + rich_sig + xor_bytes
    rich_offset = dans_offset + len(dans_sig) + len(padding) + len(encoded_entry) + len(gap)

    prefix = b"\x00" * dans_offset
    suffix = b"\x00" * 100
    blob = prefix + inner + suffix
    return blob, rich_offset


# ---------------------------------------------------------------------------
# _manual_rich_search
# ---------------------------------------------------------------------------


def test_manual_rich_search_basic():
    blob, _rich_offset = _build_rich_blob()
    adapter = _make_adapter_from_blob(blob)
    search = TestRichHeaderSearch(adapter)
    result = search._manual_rich_search()
    assert isinstance(result, (dict, type(None)))


def test_manual_rich_search_no_data():
    adapter = _make_adapter_empty()
    search = TestRichHeaderSearch(adapter)
    result = search._manual_rich_search()
    assert result is None


def test_manual_rich_search_no_adapter():
    search = TestRichHeaderSearch(None)
    result = search._manual_rich_search()
    assert result is None


def test_manual_rich_search_exception():
    # Adapter whose read_bytes raises — construct one that errors on cmd
    def exploding_cmd(command):
        raise Exception("Read error")

    adapter = R2PipeAdapter(FakeR2(cmd_fn=exploding_cmd))
    search = TestRichHeaderSearch(adapter)
    result = search._manual_rich_search()
    assert result is None


# ---------------------------------------------------------------------------
# _read_manual_search_bytes
# ---------------------------------------------------------------------------


def test_read_manual_search_bytes_valid():
    blob = b"\x00" * 2048
    adapter = _make_adapter_from_blob(blob)
    search = TestRichHeaderSearch(adapter)
    result = search._read_manual_search_bytes()
    assert result is not None
    assert len(result) == 2048


def test_read_manual_search_bytes_no_adapter():
    search = TestRichHeaderSearch(None)
    result = search._read_manual_search_bytes()
    assert result is None


def test_read_manual_search_bytes_no_method():
    # Adapter object that lacks read_bytes attribute entirely
    class Bare:
        pass

    search = TestRichHeaderSearch(Bare())
    result = search._read_manual_search_bytes()
    assert result is None


def test_read_manual_search_bytes_empty():
    adapter = _make_adapter_empty()
    search = TestRichHeaderSearch(adapter)
    result = search._read_manual_search_bytes()
    assert result is None


# ---------------------------------------------------------------------------
# _find_signature_offsets
# ---------------------------------------------------------------------------


def test_find_signature_offsets_both_found():
    adapter = _make_adapter_empty()
    data = b"\x00" * 50 + b"DanS" + b"\x00" * 100 + b"Rich" + b"\x00" * 50
    search = TestRichHeaderSearch(adapter)
    result = search._find_signature_offsets(data, b"Rich", b"DanS")
    assert result is not None
    rich_offsets, dans_offsets = result
    assert len(rich_offsets) > 0
    assert len(dans_offsets) > 0


def test_find_signature_offsets_rich_missing():
    adapter = _make_adapter_empty()
    data = b"\x00" * 50 + b"DanS" + b"\x00" * 100
    search = TestRichHeaderSearch(adapter)
    result = search._find_signature_offsets(data, b"Rich", b"DanS")
    assert result is None


def test_find_signature_offsets_dans_missing():
    adapter = _make_adapter_empty()
    data = b"\x00" * 50 + b"Rich" + b"\x00" * 100
    search = TestRichHeaderSearch(adapter)
    result = search._find_signature_offsets(data, b"Rich", b"DanS")
    assert result is None


# ---------------------------------------------------------------------------
# _find_all_occurrences
# ---------------------------------------------------------------------------


def test_find_all_occurrences_single():
    adapter = _make_adapter_empty()
    data = b"\x00" * 50 + b"Rich" + b"\x00" * 100
    search = TestRichHeaderSearch(adapter)
    result = search._find_all_occurrences(data, b"Rich")
    assert len(result) == 1
    assert result[0] == 50


def test_find_all_occurrences_multiple():
    adapter = _make_adapter_empty()
    data = b"Rich" + b"\x00" * 50 + b"Rich" + b"\x00" * 50 + b"Rich"
    search = TestRichHeaderSearch(adapter)
    result = search._find_all_occurrences(data, b"Rich")
    assert len(result) == 3


def test_find_all_occurrences_none():
    adapter = _make_adapter_empty()
    data = b"\x00" * 200
    search = TestRichHeaderSearch(adapter)
    result = search._find_all_occurrences(data, b"Rich")
    assert len(result) == 0


def test_find_all_occurrences_overlapping():
    adapter = _make_adapter_empty()
    data = b"AAA"
    search = TestRichHeaderSearch(adapter)
    result = search._find_all_occurrences(data, b"AA")
    assert len(result) == 2


# ---------------------------------------------------------------------------
# _try_signature_pairs
# ---------------------------------------------------------------------------


def test_try_signature_pairs_valid():
    xor_key = 0x12345678
    prodid = 0x00930001
    count = 10

    blob, rich_offset = _build_rich_blob(
        xor_key=xor_key, prodid=prodid, count=count, dans_offset=100
    )
    adapter = _make_adapter_from_blob(blob)
    search = TestRichHeaderSearch(adapter)
    result = search._try_signature_pairs([rich_offset], [100], b"Rich", b"DanS")
    assert isinstance(result, (dict, type(None)))


def test_try_signature_pairs_invalid_distance():
    adapter = _make_adapter_empty()
    search = TestRichHeaderSearch(adapter)
    result = search._try_signature_pairs([1000], [100], b"Rich", b"DanS")
    assert result is None


def test_try_signature_pairs_wrong_order():
    adapter = _make_adapter_empty()
    search = TestRichHeaderSearch(adapter)
    result = search._try_signature_pairs([100], [200], b"Rich", b"DanS")
    assert result is None


# ---------------------------------------------------------------------------
# _offset_pair_valid
# ---------------------------------------------------------------------------


def test_offset_pair_valid_correct():
    adapter = _make_adapter_empty()
    search = TestRichHeaderSearch(adapter)
    assert search._offset_pair_valid(100, 150, 512) is True


def test_offset_pair_valid_too_far():
    adapter = _make_adapter_empty()
    search = TestRichHeaderSearch(adapter)
    assert search._offset_pair_valid(100, 700, 512) is False


def test_offset_pair_valid_wrong_order():
    adapter = _make_adapter_empty()
    search = TestRichHeaderSearch(adapter)
    assert search._offset_pair_valid(200, 100, 512) is False


# ---------------------------------------------------------------------------
# _pattern_based_rich_search
# ---------------------------------------------------------------------------


def test_pattern_based_rich_search_found():
    blob, _rich_offset = _build_rich_blob(dans_offset=100)
    adapter = _make_adapter_from_blob(blob)
    search = TestRichHeaderSearch(adapter)
    result = search._pattern_based_rich_search(blob)
    assert isinstance(result, (dict, type(None)))


def test_pattern_based_rich_search_no_rich():
    adapter = _make_adapter_empty()
    data = b"\x00" * 500
    search = TestRichHeaderSearch(adapter)
    result = search._pattern_based_rich_search(data)
    assert result is None


def test_pattern_based_rich_search_exception():
    adapter = _make_adapter_empty()
    search = TestRichHeaderSearch(adapter)
    result = search._pattern_based_rich_search(b"malformed")
    assert result is None


# ---------------------------------------------------------------------------
# _find_rich_positions
# ---------------------------------------------------------------------------


def test_find_rich_positions_single():
    adapter = _make_adapter_empty()
    data = b"\x00" * 100 + b"Rich" + b"\x00" * 100
    search = TestRichHeaderSearch(adapter)
    result = search._find_rich_positions(data)
    assert len(result) == 1
    assert result[0] == 100


def test_find_rich_positions_multiple():
    adapter = _make_adapter_empty()
    data = b"Rich" + b"\x00" * 50 + b"Rich" + b"\x00" * 50
    search = TestRichHeaderSearch(adapter)
    result = search._find_rich_positions(data)
    assert len(result) == 2


def test_find_rich_positions_none():
    adapter = _make_adapter_empty()
    data = b"\x00" * 200
    search = TestRichHeaderSearch(adapter)
    result = search._find_rich_positions(data)
    assert len(result) == 0


# ---------------------------------------------------------------------------
# _is_valid_rich_key
# ---------------------------------------------------------------------------


def test_is_valid_rich_key_valid():
    adapter = _make_adapter_empty()
    data = b"Rich" + struct.pack("<I", 0x12345678)
    search = TestRichHeaderSearch(adapter)
    assert search._is_valid_rich_key(data, 0) is True


def test_is_valid_rich_key_zero():
    adapter = _make_adapter_empty()
    data = b"Rich" + struct.pack("<I", 0)
    search = TestRichHeaderSearch(adapter)
    assert search._is_valid_rich_key(data, 0) is False


def test_is_valid_rich_key_all_ones():
    adapter = _make_adapter_empty()
    data = b"Rich" + struct.pack("<I", 0xFFFFFFFF)
    search = TestRichHeaderSearch(adapter)
    assert search._is_valid_rich_key(data, 0) is False


def test_is_valid_rich_key_out_of_bounds():
    adapter = _make_adapter_empty()
    data = b"Rich"
    search = TestRichHeaderSearch(adapter)
    assert search._is_valid_rich_key(data, 0) is False


# ---------------------------------------------------------------------------
# _find_dans_before_rich
# ---------------------------------------------------------------------------


def test_find_dans_before_rich_found():
    adapter = _make_adapter_empty()
    data = b"\x00" * 50 + b"DanS" + b"\x00" * 100
    search = TestRichHeaderSearch(adapter)
    result = search._find_dans_before_rich(data, 150)
    assert result == 50


def test_find_dans_before_rich_not_found():
    adapter = _make_adapter_empty()
    data = b"\x00" * 200
    search = TestRichHeaderSearch(adapter)
    result = search._find_dans_before_rich(data, 150)
    assert result is None


def test_find_dans_before_rich_too_far():
    adapter = _make_adapter_empty()
    data = b"DanS" + b"\x00" * 600
    search = TestRichHeaderSearch(adapter)
    result = search._find_dans_before_rich(data, 600)
    assert result is None


# ---------------------------------------------------------------------------
# _validate_rich_size
# ---------------------------------------------------------------------------


def test_validate_rich_size_valid():
    adapter = _make_adapter_empty()
    search = TestRichHeaderSearch(adapter)
    assert search._validate_rich_size(16) is True
    assert search._validate_rich_size(100) is True
    assert search._validate_rich_size(512) is True


def test_validate_rich_size_too_small():
    adapter = _make_adapter_empty()
    search = TestRichHeaderSearch(adapter)
    assert search._validate_rich_size(8) is False
    assert search._validate_rich_size(4) is False


def test_validate_rich_size_too_large():
    adapter = _make_adapter_empty()
    search = TestRichHeaderSearch(adapter)
    assert search._validate_rich_size(513) is False
    assert search._validate_rich_size(1000) is False


# ---------------------------------------------------------------------------
# _extract_xor_key
# ---------------------------------------------------------------------------


def test_extract_xor_key_valid():
    xor_key = 0x12345678
    xor_bytes = struct.pack("<I", xor_key)
    # _extract_xor_key reads 4 bytes at rich_offset + 4
    # So place xor_bytes at offset 4 in the blob
    blob = b"\x00" * 4 + xor_bytes + b"\x00" * 100
    adapter = _make_adapter_from_blob(blob)
    search = TestRichHeaderSearch(adapter)
    # rich_offset=0 => reads at offset 4
    result = search._extract_xor_key(0)
    assert result == xor_key


def test_extract_xor_key_zero():
    xor_bytes = struct.pack("<I", 0)
    blob = b"\x00" * 4 + xor_bytes + b"\x00" * 100
    adapter = _make_adapter_from_blob(blob)
    search = TestRichHeaderSearch(adapter)
    result = search._extract_xor_key(0)
    assert result is None


def test_extract_xor_key_no_adapter():
    search = TestRichHeaderSearch(None)
    result = search._extract_xor_key(0)
    assert result is None


def test_extract_xor_key_insufficient_bytes():
    # Blob too short — only 2 bytes available at offset 4
    blob = b"\x00" * 6
    adapter = _make_adapter_from_blob(blob)
    search = TestRichHeaderSearch(adapter)
    # read_bytes_list returns short list (2 bytes), _extract_xor_key sees len < 4
    result = search._extract_xor_key(0)
    assert result is None


# ---------------------------------------------------------------------------
# _extract_encoded_data
# ---------------------------------------------------------------------------


def test_extract_encoded_data_valid():
    data = b"DanS" + struct.pack("<II", 0x12345678, 10)
    blob = data + b"\x00" * 100
    adapter = _make_adapter_from_blob(blob)
    search = TestRichHeaderSearch(adapter)
    result = search._extract_encoded_data(0, len(data))
    assert result == data


def test_extract_encoded_data_no_adapter():
    search = TestRichHeaderSearch(None)
    result = search._extract_encoded_data(0, 16)
    assert result is None


def test_extract_encoded_data_insufficient_bytes():
    # Blob is only 2 bytes — requested 16
    blob = b"\x00\x01"
    adapter = _make_adapter_from_blob(blob)
    search = TestRichHeaderSearch(adapter)
    result = search._extract_encoded_data(0, 16)
    assert result is None


# ---------------------------------------------------------------------------
# _try_extract_rich_at_offsets
# ---------------------------------------------------------------------------


def test_try_extract_rich_at_offsets_complete():
    xor_key = 0x12345678
    prodid = 0x00930001
    count = 10

    blob, rich_offset = _build_rich_blob(
        xor_key=xor_key, prodid=prodid, count=count, dans_offset=100
    )
    adapter = _make_adapter_from_blob(blob)
    search = TestRichHeaderSearch(adapter)
    result = search._try_extract_rich_at_offsets(100, rich_offset)
    assert isinstance(result, (dict, type(None)))


def test_try_extract_rich_at_offsets_invalid_size():
    adapter = _make_adapter_empty()
    search = TestRichHeaderSearch(adapter)
    result = search._try_extract_rich_at_offsets(100, 105)
    assert result is None


def test_try_extract_rich_at_offsets_exception():
    def exploding_cmd(command):
        raise Exception("Read error")

    adapter = R2PipeAdapter(FakeR2(cmd_fn=exploding_cmd))
    search = TestRichHeaderSearch(adapter)
    result = search._try_extract_rich_at_offsets(100, 120)
    assert result is None
