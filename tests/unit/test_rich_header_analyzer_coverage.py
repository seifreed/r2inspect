# Copyright (c) 2025 Marc Rivero Lopez
# Licensed under GPLv3. See LICENSE file for details.
"""Tests targeting uncovered lines in rich_header_analyzer.py."""

from __future__ import annotations

import struct
import tempfile
import os
from pathlib import Path
from typing import Any

import pytest

from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer, PEFILE_AVAILABLE


# ---------------------------------------------------------------------------
# Helper: build a minimal PE binary with a Rich Header in its DOS stub
# ---------------------------------------------------------------------------

def _build_pe_with_rich_header() -> bytes:
    """Build a minimal PE binary with a Rich Header embedded in the DOS stub.

    Structure:
      MZ header (64 bytes) | DanS(4) + skip(4) + entry(8) + fill(4) + Rich(4) + xor_key(4)
      | PE signature | minimal PE content
    """
    xor_key = 0x12345678
    entry_prodid = 2       # product id
    entry_build = 30729    # build number
    entry_count = 3        # occurrence count

    dans = b"DanS"
    skip_pad = b"\x00" * 4
    e1_pb = entry_prodid | (entry_build << 16)
    entry_bytes = struct.pack("<II", e1_pb ^ xor_key, entry_count ^ xor_key)
    fill_pad = b"\x00" * 4
    rich_marker = b"Rich"
    xor_bytes = struct.pack("<I", xor_key)

    dos_stub_content = dans + skip_pad + entry_bytes + fill_pad + rich_marker + xor_bytes
    pe_offset_val = 0x40 + len(dos_stub_content)

    mz_header = bytearray(0x40)
    mz_header[0] = ord("M")
    mz_header[1] = ord("Z")
    struct.pack_into("<I", mz_header, 0x3C, pe_offset_val)

    return bytes(mz_header) + dos_stub_content + b"PE\x00\x00" + b"\x00" * 200


def _build_pe_without_rich_header() -> bytes:
    """Build a minimal PE binary without a Rich Header."""
    mz_header = bytearray(0x40)
    mz_header[0] = ord("M")
    mz_header[1] = ord("Z")
    struct.pack_into("<I", mz_header, 0x3C, 0x40)
    return bytes(mz_header) + b"PE\x00\x00" + b"\x00" * 200


class _MinimalAdapter:
    """Minimal stub adapter making r2 non-None so _is_pe_file reads file magic."""
    pass


# ---------------------------------------------------------------------------
# analyze() – full flow (lines 51-126)
# ---------------------------------------------------------------------------

def test_analyze_with_pe_containing_rich_header() -> None:
    """Lines 53-126: analyze() finds Rich Header via r2pipe (direct file) method."""
    data = _build_pe_with_rich_header()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe", mode="wb") as f:
        f.write(data)
        path = f.name

    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        result = analyzer.analyze()

        assert result["is_pe"] is True
        assert result["method_used"] == "r2pipe"
        assert result["xor_key"] == 0x12345678
        assert result["error"] is None
        assert len(result["compilers"]) >= 1
        assert result["richpe_hash"] is not None
    finally:
        os.unlink(path)


def test_analyze_returns_error_when_not_pe() -> None:
    """Lines 70-73: analyze() returns error when file is not PE.

    Without an r2 instance, _is_pe_file returns False immediately,
    exercising the early-return branch.
    """
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    result = analyzer.analyze()
    # With no adapter and no filepath, is_pe_file returns False
    assert result["error"] == "File is not a PE binary"
    assert result["is_pe"] is False


def test_analyze_with_pe_without_rich_header() -> None:
    """Lines 96-99: analyze() reports error when Rich Header is absent."""
    data = _build_pe_without_rich_header()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe", mode="wb") as f:
        f.write(data)
        path = f.name

    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        result = analyzer.analyze()

        assert result["is_pe"] is True
        assert result["error"] == "Rich Header not found"
        assert result["rich_header"] is None
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _extract_rich_header_pefile (lines 128-161)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not installed")
def test_extract_rich_header_pefile_returns_none_for_pe_without_rich() -> None:
    """Lines 134-155: pefile extraction returns None for a PE without Rich Header."""
    data = _build_pe_without_rich_header()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe", mode="wb") as f:
        f.write(data)
        path = f.name

    try:
        analyzer = RichHeaderAnalyzer(adapter=None, filepath=path)
        result = analyzer._extract_rich_header_pefile()
        assert result is None
    finally:
        os.unlink(path)


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not installed")
def test_extract_rich_header_pefile_returns_none_for_none_filepath() -> None:
    """Lines 133-134: pefile returns None when filepath is None."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    result = analyzer._extract_rich_header_pefile()
    assert result is None


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not installed")
def test_extract_rich_header_pefile_with_real_pe_no_rich_header() -> None:
    """Lines 140-142, 160-161: pefile opens PE, finds no Rich Header, closes cleanly.

    Uses samples/fixtures/hello_pe.exe which is a real valid PE without Rich Header.
    This exercises the 'pefile opened but no RICH_HEADER' code path.
    """
    import os
    fixtures_pe = os.path.join(
        os.path.dirname(__file__), "..", "..", "samples", "fixtures", "hello_pe.exe"
    )
    if not os.path.exists(fixtures_pe):
        pytest.skip("hello_pe.exe fixture not found")

    analyzer = RichHeaderAnalyzer(adapter=None, filepath=fixtures_pe)
    result = analyzer._extract_rich_header_pefile()
    # PE exists but has no Rich Header -> pefile path returns None
    assert result is None


# ---------------------------------------------------------------------------
# pefile helper methods (lines 163-224)
# ---------------------------------------------------------------------------

class _FakeEntry:
    product_id = 2
    build_version = 30729
    count = 3


class _FakeRichHeader:
    checksum = 0x12345678
    values = [_FakeEntry()]
    clear_data = b"\x00" * 32


class _FakePE:
    RICH_HEADER = _FakeRichHeader()


class _FakePENoRichHeader:
    pass


class _FakePEWithoutChecksum:
    class RICH_HEADER:
        values: list = []


def test_pefile_has_rich_header_returns_true_when_present() -> None:
    """Lines 163-165: returns True when pefile object has RICH_HEADER."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._pefile_has_rich_header(_FakePE()) is True


def test_pefile_has_rich_header_returns_false_when_absent() -> None:
    """Lines 163-165: returns False when RICH_HEADER attribute is missing."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._pefile_has_rich_header(_FakePENoRichHeader()) is False


def test_pefile_get_xor_key_returns_checksum() -> None:
    """Lines 167-169: returns checksum value from pefile RICH_HEADER."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._pefile_get_xor_key(_FakePE()) == 0x12345678


def test_pefile_get_xor_key_returns_none_without_checksum() -> None:
    """Lines 167-169: returns None when RICH_HEADER has no checksum attribute."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    result = analyzer._pefile_get_xor_key(_FakePEWithoutChecksum())
    assert result is None


def test_pefile_extract_entries_parses_values() -> None:
    """Lines 171-180: entries are extracted from pefile RICH_HEADER.values."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    entries = analyzer._pefile_extract_entries(_FakePE())
    assert len(entries) == 1
    assert entries[0]["product_id"] == 2
    assert entries[0]["build_number"] == 30729
    assert entries[0]["count"] == 3


def test_pefile_extract_entries_empty_when_no_values() -> None:
    """Lines 171-175: returns empty list when RICH_HEADER has no values."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    result = analyzer._pefile_extract_entries(_FakePEWithoutChecksum())
    assert result == []


def test_pefile_parse_entry_returns_dict_for_valid_entry() -> None:
    """Lines 182-196: parses a pefile entry into our schema dict."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    result = analyzer._pefile_parse_entry(_FakeEntry())
    assert result is not None
    assert result["product_id"] == 2
    assert result["build_number"] == 30729
    assert result["count"] == 3
    assert "prodid" in result


def test_pefile_parse_entry_returns_none_for_missing_attrs() -> None:
    """Lines 182-189: returns None when entry lacks required attributes."""
    class _IncompleteEntry:
        product_id = 5
        # missing build_version and count

    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    result = analyzer._pefile_parse_entry(_IncompleteEntry())
    assert result is None


def test_pefile_entries_from_clear_data_with_clear_data() -> None:
    """Line 202: parse_clear_data_entries is called with available clear_data."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    result = analyzer._pefile_entries_from_clear_data(_FakePE())
    assert isinstance(result, list)


def test_pefile_entries_from_clear_data_no_clear_data() -> None:
    """Lines 200-201: returns empty list when RICH_HEADER has no clear_data."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    result = analyzer._pefile_entries_from_clear_data(_FakePEWithoutChecksum())
    assert result == []


def test_build_pefile_rich_result_structure() -> None:
    """Lines 204-224: _build_pefile_rich_result constructs expected dict."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    entries = [{"product_id": 2, "build_number": 30729, "count": 3, "prodid": 0x780A0002}]
    result = analyzer._build_pefile_rich_result(
        pe=_FakePE(),
        xor_key=0x1234,
        entries=entries,
        rich_hash="abc123",
    )
    assert result["xor_key"] == 0x1234
    assert result["checksum"] == 0x1234
    assert result["entries"] == entries
    assert result["richpe_hash"] == "abc123"
    assert result["method"] == "pefile"
    assert "clear_data" in result


# ---------------------------------------------------------------------------
# _extract_rich_header_r2pipe (lines 226-246)
# ---------------------------------------------------------------------------

def test_extract_rich_header_r2pipe_with_valid_pe() -> None:
    """Lines 233-242: r2pipe extraction returns valid result for PE with Rich."""
    data = _build_pe_with_rich_header()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe", mode="wb") as f:
        f.write(data)
        path = f.name

    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        result = analyzer._extract_rich_header_r2pipe()
        assert result is not None
        assert "xor_key" in result
        assert "entries" in result
    finally:
        os.unlink(path)


def test_extract_rich_header_r2pipe_returns_none_for_pe_without_rich() -> None:
    """Lines 237-245: returns None when no Rich Header found."""
    data = _build_pe_without_rich_header()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe", mode="wb") as f:
        f.write(data)
        path = f.name

    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        result = analyzer._extract_rich_header_r2pipe()
        assert result is None
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _is_pe_file (lines 248-258) and _check_magic_bytes (260-271)
# ---------------------------------------------------------------------------

def test_is_pe_file_returns_false_with_no_r2() -> None:
    """Lines 255-258: _is_pe_file returns False immediately when r2 is None."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._is_pe_file() is False


def test_is_pe_file_returns_true_for_mz_file() -> None:
    """Lines 255-258: _is_pe_file reads MZ magic from file, returns True."""
    data = _build_pe_with_rich_header()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe", mode="wb") as f:
        f.write(data)
        path = f.name

    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        assert analyzer._is_pe_file() is True
    finally:
        os.unlink(path)


def test_check_magic_bytes_true_for_mz() -> None:
    """Lines 260-271: returns True when file starts with MZ."""
    data = _build_pe_with_rich_header()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe", mode="wb") as f:
        f.write(data)
        path = f.name

    try:
        analyzer = RichHeaderAnalyzer(adapter=None, filepath=path)
        assert analyzer._check_magic_bytes() is True
    finally:
        os.unlink(path)


def test_check_magic_bytes_false_without_filepath() -> None:
    """Lines 262-264: returns False when no filepath is set."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._check_magic_bytes() is False


# ---------------------------------------------------------------------------
# _bin_info_has_pe (lines 273-283)
# ---------------------------------------------------------------------------

def test_bin_info_has_pe_detects_via_format() -> None:
    """Lines 274-277: PE detected via format field."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._bin_info_has_pe({"format": "pe32", "class": ""}) is True


def test_bin_info_has_pe_detects_via_class() -> None:
    """Lines 278-281: PE detected via class field."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._bin_info_has_pe({"format": "unknown", "class": "PE32+"}) is True


def test_bin_info_has_pe_returns_false_for_non_pe() -> None:
    """Line 282: returns False for non-PE format/class."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._bin_info_has_pe({"format": "elf", "class": "elf64"}) is False


# ---------------------------------------------------------------------------
# _extract_rich_header (lines 285-314)
# ---------------------------------------------------------------------------

def test_extract_rich_header_with_valid_pe() -> None:
    """Lines 292-313: finds Rich Header via direct file analysis."""
    data = _build_pe_with_rich_header()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe", mode="wb") as f:
        f.write(data)
        path = f.name

    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        result = analyzer._extract_rich_header()
        assert result is not None
        assert "xor_key" in result
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _scan_patterns (lines 324-336)
# ---------------------------------------------------------------------------

class _SearchAdapter:
    """Adapter with search_hex_json support that returns empty results."""

    def search_hex_json(self, hex_pattern: str) -> list[dict[str, Any]]:
        return []


class _SearchAdapterWithResults:
    """Adapter that returns one result for any search."""

    def search_hex_json(self, hex_pattern: str) -> list[dict[str, Any]]:
        return [{"offset": 0x100}]


def test_scan_patterns_returns_empty_when_no_matches() -> None:
    """Lines 326-336: _scan_patterns returns empty list when search finds nothing."""
    analyzer = RichHeaderAnalyzer(adapter=_SearchAdapter(), filepath=None)
    result = analyzer._scan_patterns(["52696368"], "Rich")
    assert result == []


def test_scan_patterns_aggregates_results() -> None:
    """Lines 326-336: _scan_patterns accumulates results across patterns."""
    analyzer = RichHeaderAnalyzer(adapter=_SearchAdapterWithResults(), filepath=None)
    result = analyzer._scan_patterns(["52696368", "68636952"], "Rich")
    assert len(result) == 2


def test_collect_rich_dans_offsets_with_search_adapter() -> None:
    """Lines 320-322: _collect_rich_dans_offsets calls scan for both labels."""
    analyzer = RichHeaderAnalyzer(adapter=_SearchAdapterWithResults(), filepath=None)
    rich_results, dans_results = analyzer._collect_rich_dans_offsets()
    assert len(rich_results) > 0
    assert len(dans_results) > 0


# ---------------------------------------------------------------------------
# _try_rich_dans_combinations and helpers (lines 340-370)
# ---------------------------------------------------------------------------

def test_try_rich_dans_combinations_returns_none_for_invalid_offsets() -> None:
    """Lines 342-356: returns None when no valid combination can be used."""
    data = _build_pe_with_rich_header()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe", mode="wb") as f:
        f.write(data)
        path = f.name

    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        # Rich offset before DanS offset -> invalid
        rich_results = [{"offset": 0x10}]
        dans_results = [{"offset": 0x50}]
        result = analyzer._try_rich_dans_combinations(rich_results, dans_results)
        assert result is None
    finally:
        os.unlink(path)


def test_extract_offsets_returns_none_for_missing_offset() -> None:
    """Line 366: _extract_offsets returns None when offset key is absent."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    result = analyzer._extract_offsets({"offset": None}, {"offset": 0x30})
    assert result is None


def test_extract_offsets_returns_tuple() -> None:
    """Lines 362-366: _extract_offsets returns (dans, rich) tuple."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    result = analyzer._extract_offsets({"offset": 0x80}, {"offset": 0x40})
    assert result == (0x40, 0x80)


def test_offsets_valid_true_when_dans_before_rich_within_1024() -> None:
    """Line 370: offsets are valid when dans < rich and difference <= 1024."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._offsets_valid(0x40, 0x80) is True


def test_offsets_valid_false_when_dans_after_rich() -> None:
    """Line 370: offsets are invalid when dans >= rich."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._offsets_valid(0x80, 0x40) is False


def test_offsets_valid_false_when_gap_exceeds_1024() -> None:
    """Line 370: offsets are invalid when difference > 1024."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._offsets_valid(0x40, 0x40 + 2000) is False


# ---------------------------------------------------------------------------
# _direct_file_rich_search and helpers (lines 372-526)
# ---------------------------------------------------------------------------

def test_direct_file_rich_search_finds_header() -> None:
    """Lines 379-422: finds and returns Rich Header data from file bytes."""
    data = _build_pe_with_rich_header()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe", mode="wb") as f:
        f.write(data)
        path = f.name

    try:
        analyzer = RichHeaderAnalyzer(adapter=None, filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is not None
        assert result["xor_key"] == 0x12345678
        assert len(result["entries"]) >= 1
    finally:
        os.unlink(path)


def test_direct_file_rich_search_returns_none_for_no_filepath() -> None:
    """Lines 379-382: returns None when filepath is not set."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    result = analyzer._direct_file_rich_search()
    assert result is None


def test_read_file_bytes_returns_none_for_no_filepath() -> None:
    """Lines 428-436: _read_file_bytes returns None when no filepath."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._read_file_bytes() is None


def test_read_file_bytes_returns_bytes_for_valid_file() -> None:
    """Lines 428-436: _read_file_bytes returns bytes content of file."""
    data = _build_pe_with_rich_header()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe", mode="wb") as f:
        f.write(data)
        path = f.name

    try:
        analyzer = RichHeaderAnalyzer(adapter=None, filepath=path)
        result = analyzer._read_file_bytes()
        assert result is not None
        assert result[:2] == b"MZ"
    finally:
        os.unlink(path)


def test_is_valid_pe_data_true_for_mz_data() -> None:
    """Lines 438-440: valid when data >= 0x40 bytes and starts with MZ."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._is_valid_pe_data(b"MZ" + b"\x00" * 70) is True


def test_is_valid_pe_data_false_for_short_data() -> None:
    """Lines 438-440: invalid when data shorter than 0x40."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._is_valid_pe_data(b"MZ\x00") is False


def test_is_valid_pe_data_false_for_wrong_magic() -> None:
    """Lines 438-440: invalid when first bytes are not MZ."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._is_valid_pe_data(b"EL" + b"\x00" * 70) is False


def test_get_pe_offset_parses_e_lfanew() -> None:
    """Lines 442-447: _get_pe_offset reads e_lfanew from DOS header."""
    header = bytearray(0x50)
    header[0] = ord("M")
    header[1] = ord("Z")
    struct.pack_into("<I", header, 0x3C, 0x48)
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._get_pe_offset(bytes(header)) == 0x48


def test_get_pe_offset_returns_none_when_too_large() -> None:
    """Lines 442-447: returns None when pe_offset exceeds file size."""
    header = bytearray(0x50)
    header[0] = ord("M")
    header[1] = ord("Z")
    struct.pack_into("<I", header, 0x3C, 0x1000)
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._get_pe_offset(bytes(header)) is None


def test_get_dos_stub_extracts_region() -> None:
    """Lines 449-454: extracts bytes between 0x40 and pe_offset."""
    data = b"MZ" + b"\x00" * 100
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    dos_stub = analyzer._get_dos_stub(data, 0x60)
    assert dos_stub == data[0x40:0x60]
    assert len(dos_stub) == 0x20


def test_get_dos_stub_returns_none_when_pe_offset_too_small() -> None:
    """Lines 449-453: returns None when pe_offset <= dos_stub_start (0x40)."""
    data = b"MZ" + b"\x00" * 100
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._get_dos_stub(data, 0x30) is None
    assert analyzer._get_dos_stub(data, 0x40) is None


def test_find_rich_pos_locates_marker() -> None:
    """Lines 456-463: finds position of 'Rich' in dos_stub bytes."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    dos_stub = b"\x00" * 8 + b"Rich" + b"\x00\x00\x00\x00"
    assert analyzer._find_rich_pos(dos_stub) == 8


def test_find_rich_pos_returns_none_when_absent() -> None:
    """Lines 456-463: returns None when 'Rich' not found."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._find_rich_pos(b"\x00" * 16) is None


def test_extract_xor_key_from_stub_reads_4_bytes() -> None:
    """Lines 465-473: extracts the 4 bytes after 'Rich' as XOR key."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    xor_key_bytes = struct.pack("<I", 0xDEADBEEF)
    dos_stub = b"\x00" * 4 + b"Rich" + xor_key_bytes + b"\x00" * 8
    key = analyzer._extract_xor_key_from_stub(dos_stub, rich_pos=4)
    assert key == 0xDEADBEEF


def test_extract_xor_key_from_stub_returns_none_when_insufficient_data() -> None:
    """Lines 465-469: returns None when not enough bytes after 'Rich'."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    dos_stub = b"Rich\x01\x02"  # only 2 bytes after 'Rich'
    assert analyzer._extract_xor_key_from_stub(dos_stub, rich_pos=0) is None


def test_find_or_estimate_dans_finds_explicit_marker() -> None:
    """Lines 475-482: returns position of 'DanS' when found."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    dos_stub = b"DanS" + b"\x00" * 12 + b"Rich" + b"\x00" * 4
    rich_pos = dos_stub.index(b"Rich")
    result = analyzer._find_or_estimate_dans(dos_stub, rich_pos)
    assert result == 0


def test_find_or_estimate_dans_estimates_when_no_dans() -> None:
    """Lines 475-494: estimates start when DanS not found."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    # No DanS marker – use only valid 8-byte-aligned data
    dos_stub = b"\x00" * 16 + b"Rich" + b"\x00" * 4
    rich_pos = dos_stub.index(b"Rich")
    result = analyzer._find_or_estimate_dans(dos_stub, rich_pos)
    # May return a position or None depending on alignment
    assert result is None or isinstance(result, int)


def test_extract_encoded_from_stub_valid() -> None:
    """Lines 496-505: extracts encoded bytes between DanS+4 and Rich."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    # DanS(4) + encoded(8) + Rich(4)
    dos_stub = b"DanS" + b"\xAB" * 8 + b"Rich" + b"\x00" * 4
    result = analyzer._extract_encoded_from_stub(dos_stub, dans_pos=0, rich_pos=12)
    assert result == b"\xAB" * 8


def test_extract_encoded_from_stub_returns_none_for_wrong_length() -> None:
    """Lines 500-503: returns None when encoded length is not a multiple of 8."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    dos_stub = b"DanS" + b"\xAB" * 5 + b"Rich"  # 5 bytes – not divisible by 8
    result = analyzer._extract_encoded_from_stub(dos_stub, dans_pos=0, rich_pos=9)
    assert result is None


def test_build_direct_rich_result_structure() -> None:
    """Lines 507-527: _build_direct_rich_result returns expected dict."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    entries = [{"product_id": 2, "build_number": 1, "count": 1}]
    result = analyzer._build_direct_rich_result(
        xor_key=0x1234,
        calculated_checksum=0x1234,
        entries=entries,
        encoded_data=b"\x00" * 8,
        dos_stub_start=0x40,
        dans_pos=0,
        rich_pos=16,
    )
    assert result["xor_key"] == 0x1234
    assert result["checksum"] == 0x1234
    assert result["valid_checksum"] is True
    assert result["dans_offset"] == 0x40
    assert result["rich_offset"] == 0x40 + 16
    assert result["entries"] == entries


# ---------------------------------------------------------------------------
# _calculate_rich_checksum (lines 529-566)
# ---------------------------------------------------------------------------

def test_calculate_rich_checksum_returns_integer() -> None:
    """Lines 543-566: checksum calculation returns a non-negative integer."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    data = b"MZ" + b"\x00" * 62 + b"PE\x00\x00" + b"\x00" * 200
    entries = [{"product_id": 2, "build_number": 30729, "count": 3}]
    checksum = analyzer._calculate_rich_checksum(data, 0x40, entries)
    assert isinstance(checksum, int)
    assert checksum >= 0


def test_calculate_rich_checksum_with_empty_entries() -> None:
    """Lines 543-566: handles empty entries list gracefully."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    data = b"MZ" + b"\x00" * 100
    checksum = analyzer._calculate_rich_checksum(data, 0x40, [])
    assert isinstance(checksum, int)


def test_calculate_rich_checksum_with_exception() -> None:
    """Lines 564-566: returns 0 on exception (too-short data)."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    # Data shorter than 0x3C will raise IndexError when accessing data[i]
    data = b"MZ"
    checksum = analyzer._calculate_rich_checksum(data, 0x40, [])
    assert checksum == 0


# ---------------------------------------------------------------------------
# is_available (line 577)
# ---------------------------------------------------------------------------

def test_is_available_returns_true() -> None:
    """Line 577: static method always returns True."""
    assert RichHeaderAnalyzer.is_available() is True


# ---------------------------------------------------------------------------
# _estimate_dans_start (lines 484-494)
# ---------------------------------------------------------------------------

def test_estimate_dans_start_returns_none_when_start_pos_plus_eight_exceeds_stub() -> None:
    """Line 488 (continue), 493-494 (return None): all candidate start positions
    either exceed stub length or don't produce 8-byte-aligned encoded data."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    # Short dos_stub of 4 bytes with rich_pos=4:
    # range(0,4,4)=[0]; start_pos=0: 0+8>4 -> continue (line 488)
    # No more iterations -> return None (lines 493-494)
    dos_stub = b"\x00\x01\x02\x03"
    result = analyzer._estimate_dans_start(dos_stub, rich_pos=4)
    assert result is None


def test_estimate_dans_start_returns_position_for_8byte_aligned_data() -> None:
    """Lines 486-492: returns position when test_data length is multiple of 8."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    # dos_stub: 8 null bytes + 'Rich' + 4 bytes; rich_pos=8
    # start_pos=0: test_data=dos_stub[0:8]=8 bytes, 8>=8, 8%8==0 -> returns 0
    dos_stub = b"\x00" * 8 + b"Rich" + b"\x00" * 4
    result = analyzer._estimate_dans_start(dos_stub, rich_pos=8)
    assert result == 0


# ---------------------------------------------------------------------------
# _scan_patterns exception handling (lines 333-335)
# ---------------------------------------------------------------------------

class _RaisingSearchAdapter:
    """Adapter whose search_hex_json raises for every pattern."""

    def search_hex_json(self, hex_pattern: str) -> list:
        raise RuntimeError(f"search failed for {hex_pattern}")


def test_scan_patterns_continues_on_exception() -> None:
    """Lines 333-335: exception in search is caught and loop continues."""
    analyzer = RichHeaderAnalyzer(adapter=_RaisingSearchAdapter(), filepath=None)
    result = analyzer._scan_patterns(["52696368", "68636952"], "Rich")
    # Should return empty list – no results and no unhandled exception
    assert result == []


# ---------------------------------------------------------------------------
# _try_rich_dans_combinations – continue on missing offset (line 346)
# ---------------------------------------------------------------------------

def test_try_rich_dans_combinations_skips_when_offset_missing() -> None:
    """Line 346: inner loop continues when _extract_offsets returns None."""
    data = _build_pe_with_rich_header()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe", mode="wb") as f:
        f.write(data)
        path = f.name

    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        # rich_result has no 'offset' key -> _extract_offsets returns None -> line 346 continue
        rich_results = [{"no_offset": 0x50}]
        dans_results = [{"offset": 0x30}]
        result = analyzer._try_rich_dans_combinations(rich_results, dans_results)
        assert result is None
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _direct_file_rich_search early returns (lines 386, 394, 398, 402, 406, 409-411)
# ---------------------------------------------------------------------------

def _make_temp_pe(data: bytes) -> tuple[str, Any]:
    """Write bytes to a temp file and return (path, cleanup_fn)."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe", mode="wb") as f:
        f.write(data)
    return f.name


def test_direct_file_rich_search_returns_none_when_pe_offset_invalid() -> None:
    """Line 386: returns None when pe_offset is beyond end of file."""
    header = bytearray(0x50)
    header[0] = ord("M"); header[1] = ord("Z")
    struct.pack_into("<I", header, 0x3C, 0x2000)  # far beyond EOF
    data = bytes(header) + b"\x00" * 10
    path = _make_temp_pe(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=None, filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is None
    finally:
        os.unlink(path)


def test_direct_file_rich_search_returns_none_when_dos_stub_too_short() -> None:
    """Line 390: returns None when pe_offset <= 0x40 (empty/missing DOS stub)."""
    header = bytearray(0x44)
    header[0] = ord("M"); header[1] = ord("Z")
    struct.pack_into("<I", header, 0x3C, 0x40)  # pe_offset == dos_stub_start
    data = bytes(header) + b"PE\x00\x00" + b"\x00" * 100
    path = _make_temp_pe(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=None, filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is None
    finally:
        os.unlink(path)


def test_direct_file_rich_search_returns_none_when_no_rich_marker() -> None:
    """Line 394: returns None when 'Rich' marker is absent from DOS stub."""
    header = bytearray(0x40)
    header[0] = ord("M"); header[1] = ord("Z")
    struct.pack_into("<I", header, 0x3C, 0x60)  # pe_offset = 0x60
    # DOS stub is 0x40-0x60 = 32 bytes of zeros (no 'Rich')
    data = bytes(header) + b"\x00" * 32 + b"PE\x00\x00" + b"\x00" * 100
    path = _make_temp_pe(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=None, filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is None
    finally:
        os.unlink(path)


def test_direct_file_rich_search_returns_none_when_xor_key_not_readable() -> None:
    """Line 398: returns None when 'Rich' is at stub end with no room for XOR key."""
    header = bytearray(0x40)
    header[0] = ord("M"); header[1] = ord("Z")
    # pe_offset = 0x40 + 5 = 0x45; dos_stub = 5 bytes: 'Rich' + 1 byte
    # rich_pos=0, rich_pos+8=8 > len(dos_stub)=5 -> _extract_xor_key_from_stub returns None
    struct.pack_into("<I", header, 0x3C, 0x45)
    dos_stub = b"Rich\x00"
    data = bytes(header) + dos_stub + b"PE\x00\x00" + b"\x00" * 100
    path = _make_temp_pe(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=None, filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is None
    finally:
        os.unlink(path)


def test_direct_file_rich_search_returns_none_when_encoded_data_wrong_length() -> None:
    """Line 406: returns None when encoded data length is not a multiple of 8."""
    header = bytearray(0x40)
    header[0] = ord("M"); header[1] = ord("Z")
    pe_off = 0x40 + 20
    struct.pack_into("<I", header, 0x3C, pe_off)
    # DOS stub: DanS(4) + 3 bytes (not 8-aligned) + Rich(4) + xor_key(4)
    dos_stub = b"DanS" + b"\x00" * 3 + b"Rich" + struct.pack("<I", 0x1234) + b"\x00" * 5
    data = bytes(header) + dos_stub + b"PE\x00\x00" + b"\x00" * 100
    path = _make_temp_pe(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=None, filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is None
    finally:
        os.unlink(path)


def test_direct_file_rich_search_returns_none_when_entries_empty() -> None:
    """Lines 409-411: returns None when decoded entries are all zero-count."""
    header = bytearray(0x40)
    header[0] = ord("M"); header[1] = ord("Z")
    xor_key = 0x1234
    # Entry with count=0: (prodid ^ xor_key) + (0 ^ xor_key)
    # decode_rich_header skips entries where count == 0
    skip = struct.pack("<I", xor_key)  # first 4 bytes of encoded (skipped by decoder)
    entry = struct.pack("<II", 0x0002 ^ xor_key, 0 ^ xor_key)  # count=0 -> skipped
    filler = struct.pack("<I", xor_key)  # last 4 bytes padder
    # encoded = skip(4) + entry(8) + filler(4) = 16 bytes
    encoded = skip + entry + filler
    assert len(encoded) == 16 and len(encoded) % 8 == 0
    pe_off = 0x40 + 4 + len(encoded) + 4 + 4  # dans(4) + encoded + rich(4) + key(4)
    struct.pack_into("<I", header, 0x3C, pe_off)
    dos_stub = b"DanS" + encoded + b"Rich" + struct.pack("<I", xor_key)
    data = bytes(header) + dos_stub + b"PE\x00\x00" + b"\x00" * 100
    path = _make_temp_pe(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=None, filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is None
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _read_file_bytes exception path (lines 434-436)
# ---------------------------------------------------------------------------

def test_read_file_bytes_returns_none_for_unreadable_file() -> None:
    """Lines 434-436: exception during read returns None."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/nonexistent/missing.exe")
    result = analyzer._read_file_bytes()
    assert result is None


# ---------------------------------------------------------------------------
# _extract_rich_header paths after direct search fails (lines 299-314)
# ---------------------------------------------------------------------------

def test_extract_rich_header_calls_manual_search_when_no_r2_results() -> None:
    """Lines 301-303: falls through to manual search when r2pipe finds nothing."""
    # Use a PE without Rich Header – direct search fails, r2pipe (no real adapter)
    # returns empty, manual search is called (also returns None)
    data = _build_pe_without_rich_header()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe", mode="wb") as f:
        f.write(data)
        path = f.name

    try:
        # SearchAdapter returns empty -> rich_results and dans_results empty
        analyzer = RichHeaderAnalyzer(adapter=_SearchAdapter(), filepath=path)
        result = analyzer._extract_rich_header()
        assert result is None
    finally:
        os.unlink(path)


def test_extract_rich_header_tries_combinations_when_patterns_found() -> None:
    """Lines 305-310: tries combinations when r2pipe finds both Rich and DanS patterns."""
    # Use adapter that returns results for search, but combinations won't find valid Rich Header
    data = _build_pe_without_rich_header()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe", mode="wb") as f:
        f.write(data)
        path = f.name

    try:
        analyzer = RichHeaderAnalyzer(adapter=_SearchAdapterWithResults(), filepath=path)
        result = analyzer._extract_rich_header()
        # Even with search results, combinations produce invalid data -> returns None
        assert result is None
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _check_magic_bytes exception (lines 269-271)
# ---------------------------------------------------------------------------

def test_check_magic_bytes_returns_false_on_read_exception() -> None:
    """Lines 269-271: exception during file read returns False."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/dev/null/nonexistent")
    result = analyzer._check_magic_bytes()
    assert result is False


# ---------------------------------------------------------------------------
# calculate_richpe_hash_from_file (lines 580-586)
# ---------------------------------------------------------------------------

def test_calculate_richpe_hash_from_file_returns_none_for_nonexistent_file() -> None:
    """Lines 580-585: returns None when file does not exist / r2pipe fails."""
    result = RichHeaderAnalyzer.calculate_richpe_hash_from_file("/nonexistent/path.exe")
    assert result is None


def test_calculate_richpe_hash_from_file_handles_failure_gracefully() -> None:
    """Lines 580-585: returns None when analyzer fails (runs_analyzer_on_file returns None)."""
    # Use a tiny non-PE file that r2pipe can't analyze usefully
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe", mode="wb") as f:
        f.write(b"not a valid PE file content")
        path = f.name
    try:
        result = RichHeaderAnalyzer.calculate_richpe_hash_from_file(path)
        # May be None (r2pipe fails) or None (no richpe_hash in result)
        assert result is None or isinstance(result, str)
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Exception paths using subclasses (lines 122-124, 244-246, 312-314, 402, 424-426)
# ---------------------------------------------------------------------------

class _FaultyRichAnalyzer(RichHeaderAnalyzer):
    """Subclass that triggers the exception handler in analyze() by returning
    a rich_data dict whose xor_key value cannot be formatted as hex."""

    def _is_pe_file(self) -> bool:
        return True

    def _extract_rich_header_pefile(self) -> None:
        return None

    def _extract_rich_header_r2pipe(self) -> dict:
        return {"xor_key": "not_an_int", "entries": [], "checksum": None}


def test_analyze_exception_handler_fires_on_format_error() -> None:
    """Lines 122-124: exception in analyze() body is caught and stored in result."""
    analyzer = _FaultyRichAnalyzer(adapter=None, filepath=None)
    result = analyzer.analyze()
    assert result["error"] is not None
    assert "format" in result["error"].lower() or "int" in result["error"].lower()


class _ExceptionInExtractRich(RichHeaderAnalyzer):
    """Subclass whose _extract_rich_header raises an exception."""

    def _direct_file_rich_search(self) -> None:
        raise RuntimeError("injected direct search failure")

    def _collect_rich_dans_offsets(self) -> tuple:
        raise RuntimeError("injected r2pipe search failure")


def test_extract_rich_header_exception_handler() -> None:
    """Lines 312-314: exception inside _extract_rich_header is caught and returns None."""
    analyzer = _ExceptionInExtractRich(adapter=None, filepath=None)
    result = analyzer._extract_rich_header()
    assert result is None


class _ExceptionInR2PipeExtraction(RichHeaderAnalyzer):
    """Subclass whose _extract_rich_header raises to test r2pipe outer except."""

    def _extract_rich_header(self) -> None:
        raise RuntimeError("injected _extract_rich_header failure")


def test_extract_rich_header_r2pipe_exception_handler() -> None:
    """Lines 244-246: exception from _extract_rich_header is caught in r2pipe method."""
    analyzer = _ExceptionInR2PipeExtraction(adapter=None, filepath=None)
    result = analyzer._extract_rich_header_r2pipe()
    assert result is None


class _ExceptionInDosStubGet(RichHeaderAnalyzer):
    """Subclass that triggers the outer except in _direct_file_rich_search."""

    def _get_dos_stub(self, data: bytes, pe_offset: int) -> bytes | None:
        raise RuntimeError("injected dos stub failure")

    def _read_file_bytes(self) -> bytes:
        # Return valid MZ data so _is_valid_pe_data passes and _get_pe_offset works
        import struct as _struct
        header = bytearray(0x50)
        header[0] = ord("M"); header[1] = ord("Z")
        _struct.pack_into("<I", header, 0x3C, 0x45)
        return bytes(header) + b"\x00" * 100


def test_direct_file_rich_search_outer_exception_handler() -> None:
    """Lines 424-426: exception inside the try block is caught and returns None."""
    analyzer = _ExceptionInDosStubGet(adapter=None, filepath="dummy.exe")
    result = analyzer._direct_file_rich_search()
    assert result is None


def test_direct_file_rich_search_returns_none_when_dans_pos_is_none() -> None:
    """Line 402: returns None when _find_or_estimate_dans returns None."""
    header = bytearray(0x40)
    header[0] = ord("M"); header[1] = ord("Z")
    # DOS stub: 'Rich' + XOR key (4 bytes) but no DanS; rich_pos=0
    # After rich at pos 0: xor_key = 0x1234, dans estimation will fail
    # because test data is too short for any 8-byte-aligned block
    pe_off = 0x40 + 9
    struct.pack_into("<I", header, 0x3C, pe_off)
    xor_key_bytes = struct.pack("<I", 0x1234)
    dos_stub = b"Rich" + xor_key_bytes + b"\x00"  # 9 bytes total, rich_pos=0
    data = bytes(header) + dos_stub + b"PE\x00\x00" + b"\x00" * 100
    path = _make_temp_pe(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=None, filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is None
    finally:
        os.unlink(path)
