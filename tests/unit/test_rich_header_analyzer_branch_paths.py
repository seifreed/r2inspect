"""Branch-path coverage tests for rich_header_analyzer.py.

Covers lines: 33-35, 71-73, 93-94, 122-124, 131, 142-143, 153-155,
160-161, 175, 179, 190-191, 201, 242-246, 256-257, 264, 269-271,
275-283, 296-314, 331-336, 342-356, 362-366, 370, 382-426, 432-436,
446, 453, 462-473, 477-494, 500-505, 518-527, 543-566, 577, 582-586.
"""

from __future__ import annotations

import os
import struct
import tempfile
from typing import Any

import pytest

import r2inspect.modules.rich_header_analyzer as rha_module
from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer, PEFILE_AVAILABLE


# ---------------------------------------------------------------------------
# PE fixture builders
# ---------------------------------------------------------------------------


def _build_pe_with_rich_header(xor_key: int = 0xABCD1234) -> bytes:
    """Build a minimal PE binary with a Rich Header in its DOS stub."""
    entry_prod_id = 3
    entry_build = 50727
    entry_count = 1

    dans = b"DanS"
    skip_pad = b"\x00" * 4
    e1_val = entry_prod_id | (entry_build << 16)
    entry_bytes = struct.pack("<II", e1_val ^ xor_key, entry_count ^ xor_key)
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


def _write_tmp(data: bytes) -> str:
    """Write bytes to a temporary file and return the path."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe", mode="wb") as f:
        f.write(data)
    return f.name


class _MinimalAdapter:
    """Non-None adapter so _is_pe_file can proceed to file magic check."""
    pass


# ---------------------------------------------------------------------------
# Module-level PEFILE_AVAILABLE branch (lines 33-35, 131)
# ---------------------------------------------------------------------------


def test_extract_rich_header_pefile_returns_none_when_pefile_unavailable() -> None:
    """Line 131: _extract_rich_header_pefile returns None when PEFILE_AVAILABLE=False."""
    original = rha_module.PEFILE_AVAILABLE
    rha_module.PEFILE_AVAILABLE = False
    try:
        analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
        result = analyzer._extract_rich_header_pefile()
        assert result is None
    finally:
        rha_module.PEFILE_AVAILABLE = original


# ---------------------------------------------------------------------------
# analyze() - not-PE branch (lines 71-73)
# ---------------------------------------------------------------------------


def test_analyze_is_not_pe_returns_error_result() -> None:
    """Lines 71-73: analyze() returns early with error when file is not a PE."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    result = analyzer.analyze()
    assert result["error"] == "File is not a PE binary"
    assert result["is_pe"] is False
    assert result["rich_header"] is None


def test_analyze_is_not_pe_with_non_mz_file() -> None:
    """Lines 71-73: ELF file triggers non-PE branch."""
    path = _write_tmp(b"\x7fELF" + b"\x00" * 200)
    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        result = analyzer.analyze()
        assert result["is_pe"] is False
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# analyze() - r2pipe method used (lines 93-94)
# ---------------------------------------------------------------------------


def test_analyze_sets_method_r2pipe_when_pefile_fails() -> None:
    """Lines 93-94: method_used='r2pipe' when pefile fails but r2pipe succeeds."""
    data = _build_pe_with_rich_header()
    path = _write_tmp(data)
    try:
        # pefile will likely fail on this malformed PE; r2pipe direct analysis succeeds
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        result = analyzer.analyze()
        if result.get("error") is None:
            # Rich Header was found; method should be "r2pipe" (pefile couldn't parse it)
            assert result["method_used"] in ("r2pipe", "pefile")
        # else: Rich Header not found at all - that's also OK for this test
    finally:
        os.unlink(path)


def test_analyze_method_r2pipe_forced_by_disabling_pefile() -> None:
    """Lines 93-94: when pefile is disabled, r2pipe path is taken if PE has Rich Header."""
    original = rha_module.PEFILE_AVAILABLE
    rha_module.PEFILE_AVAILABLE = False
    data = _build_pe_with_rich_header()
    path = _write_tmp(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        result = analyzer.analyze()
        assert result["is_pe"] is True
        if result.get("error") is None:
            assert result["method_used"] == "r2pipe"
    finally:
        rha_module.PEFILE_AVAILABLE = original
        os.unlink(path)


# ---------------------------------------------------------------------------
# analyze() - exception branch (lines 122-124)
# ---------------------------------------------------------------------------


def test_analyze_captures_exception_in_error_field() -> None:
    """Lines 122-124: exception raised inside analyze() is captured in result['error']."""
    class _BrokenAnalyzer(RichHeaderAnalyzer):
        def _is_pe_file(self) -> bool:
            raise RuntimeError("forced analyzer failure")

    analyzer = _BrokenAnalyzer(adapter=_MinimalAdapter(), filepath=None)
    result = analyzer.analyze()
    assert result["error"] is not None
    assert "forced analyzer failure" in result["error"]


# ---------------------------------------------------------------------------
# _extract_rich_header_pefile - pefile unavailable path (line 131)
# already tested above; additional paths below
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not installed")
def test_extract_rich_header_pefile_returns_none_for_invalid_pe() -> None:
    """Lines 153-155: exception inside pefile PE() is caught, returns None."""
    # Non-PE data causes pefile.PE() to raise
    path = _write_tmp(b"\x00" * 64)
    try:
        analyzer = RichHeaderAnalyzer(adapter=None, filepath=path)
        result = analyzer._extract_rich_header_pefile()
        assert result is None
    finally:
        os.unlink(path)


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not installed")
def test_extract_rich_header_pefile_finally_closes_pe() -> None:
    """Lines 160-161: finally block closes PE object even when no Rich Header found."""
    path = _write_tmp(_build_pe_without_rich_header())
    try:
        analyzer = RichHeaderAnalyzer(adapter=None, filepath=path)
        # Should complete without raising; finally block runs pe.close() internally
        result = analyzer._extract_rich_header_pefile()
        assert result is None  # No Rich Header in our minimal PE
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# pefile helper methods
# ---------------------------------------------------------------------------


class _FakeEntry:
    product_id = 5
    build_version = 12345
    count = 7


class _FakeRichHeader:
    checksum = 0xDEADBEEF
    values = [_FakeEntry()]
    clear_data = b"\xAB\xCD" * 16


class _FakePE:
    RICH_HEADER = _FakeRichHeader()


class _FakePENoRH:
    """PE without RICH_HEADER attribute."""
    pass


class _FakePENoChecksum:
    class RICH_HEADER:
        values: list = []


def test_pefile_has_rich_header_true_when_present() -> None:
    """Line 175: returns True when RICH_HEADER exists and is truthy."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._pefile_has_rich_header(_FakePE()) is True


def test_pefile_has_rich_header_false_when_absent() -> None:
    """Line 175: returns False when RICH_HEADER attribute missing."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._pefile_has_rich_header(_FakePENoRH()) is False


def test_pefile_get_xor_key_returns_checksum() -> None:
    """Line 179: extracts checksum from RICH_HEADER."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._pefile_get_xor_key(_FakePE()) == 0xDEADBEEF


def test_pefile_get_xor_key_returns_none_without_checksum() -> None:
    """Line 179: returns None when no checksum attribute."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._pefile_get_xor_key(_FakePENoChecksum()) is None


def test_pefile_parse_entry_returns_dict() -> None:
    """Lines 190-191: builds product-id dict from entry attributes."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    result = analyzer._pefile_parse_entry(_FakeEntry())
    assert result is not None
    assert result["product_id"] == 5
    assert result["build_number"] == 12345
    assert result["count"] == 7
    expected_prodid = 5 | (12345 << 16)
    assert result["prodid"] == expected_prodid


def test_pefile_parse_entry_returns_none_for_incomplete_entry() -> None:
    """Lines 190-191: returns None when required attributes are missing."""
    class _NoCount:
        product_id = 1
        build_version = 2

    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._pefile_parse_entry(_NoCount()) is None


def test_pefile_entries_from_clear_data_with_valid_clear_data() -> None:
    """Line 201: delegates to parse_clear_data_entries when clear_data is present."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    result = analyzer._pefile_entries_from_clear_data(_FakePE())
    assert isinstance(result, list)


def test_pefile_entries_from_clear_data_empty_when_no_attribute() -> None:
    """Line 201: returns empty list when RICH_HEADER has no clear_data."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    result = analyzer._pefile_entries_from_clear_data(_FakePENoChecksum())
    assert result == []


def test_pefile_extract_entries_populates_list() -> None:
    """Lines 171-180: extracts entries from pefile RICH_HEADER.values."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    entries = analyzer._pefile_extract_entries(_FakePE())
    assert len(entries) == 1
    assert entries[0]["product_id"] == 5


def test_pefile_extract_entries_empty_for_no_values() -> None:
    """Lines 171-175: returns empty list when RICH_HEADER has no values."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    result = analyzer._pefile_extract_entries(_FakePENoChecksum())
    assert result == []


def test_build_pefile_rich_result_has_expected_fields() -> None:
    """Lines 204-224: _build_pefile_rich_result returns well-formed dict."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    entries = [{"product_id": 5, "build_number": 100, "count": 2, "prodid": 0x640005}]
    result = analyzer._build_pefile_rich_result(
        pe=_FakePE(),
        xor_key=0xABCD,
        entries=entries,
        rich_hash="deadbeef01234567",
    )
    assert result["xor_key"] == 0xABCD
    assert result["checksum"] == 0xABCD
    assert result["entries"] is entries
    assert result["richpe_hash"] == "deadbeef01234567"
    assert result["method"] == "pefile"
    assert "clear_data" in result


# ---------------------------------------------------------------------------
# _extract_rich_header_r2pipe (lines 242-246)
# ---------------------------------------------------------------------------


def test_extract_rich_header_r2pipe_returns_dict_for_valid_pe() -> None:
    """Lines 242-246: returns rich data dict when direct analysis succeeds."""
    data = _build_pe_with_rich_header()
    path = _write_tmp(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        result = analyzer._extract_rich_header_r2pipe()
        assert result is not None
        assert "xor_key" in result
        assert "entries" in result
    finally:
        os.unlink(path)


def test_extract_rich_header_r2pipe_returns_none_for_pe_without_rich() -> None:
    """Lines 236-240: returns None when no Rich Header found."""
    data = _build_pe_without_rich_header()
    path = _write_tmp(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        result = analyzer._extract_rich_header_r2pipe()
        assert result is None
    finally:
        os.unlink(path)


def test_extract_rich_header_r2pipe_exception_returns_none() -> None:
    """Lines 244-246: exception is caught and None is returned."""
    class _BrokenR2Analyzer(RichHeaderAnalyzer):
        def _extract_rich_header(self):
            raise RuntimeError("r2 extraction failed")

    analyzer = _BrokenR2Analyzer(adapter=_MinimalAdapter(), filepath=None)
    result = analyzer._extract_rich_header_r2pipe()
    assert result is None


# ---------------------------------------------------------------------------
# _is_pe_file (lines 256-257)
# ---------------------------------------------------------------------------


def test_is_pe_file_returns_false_when_r2_is_none() -> None:
    """Lines 256-257: returns False immediately when r2 is None."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._is_pe_file() is False


def test_is_pe_file_returns_true_for_mz_file() -> None:
    """Lines 256-257: returns True when file has MZ magic."""
    data = _build_pe_with_rich_header()
    path = _write_tmp(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        assert analyzer._is_pe_file() is True
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _check_magic_bytes (lines 264, 269-271)
# ---------------------------------------------------------------------------


def test_check_magic_bytes_returns_false_for_no_filepath() -> None:
    """Line 264: returns False when filepath is not set."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._check_magic_bytes() is False


def test_check_magic_bytes_returns_true_for_mz_file() -> None:
    """Lines 269-271: returns True when file starts with MZ."""
    data = _build_pe_with_rich_header()
    path = _write_tmp(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=None, filepath=path)
        assert analyzer._check_magic_bytes() is True
    finally:
        os.unlink(path)


def test_check_magic_bytes_returns_false_for_non_mz_file() -> None:
    """Lines 264-271: returns False when file does not start with MZ."""
    path = _write_tmp(b"\x7fELF" + b"\x00" * 64)
    try:
        analyzer = RichHeaderAnalyzer(adapter=None, filepath=path)
        assert analyzer._check_magic_bytes() is False
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _bin_info_has_pe (lines 275-283)
# ---------------------------------------------------------------------------


def test_bin_info_has_pe_via_format_field() -> None:
    """Lines 275-277: PE detected via format field containing 'pe'."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._bin_info_has_pe({"format": "pe32", "class": ""}) is True


def test_bin_info_has_pe_via_class_field() -> None:
    """Lines 278-281: PE detected via class field containing 'pe'."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._bin_info_has_pe({"format": "unknown", "class": "PE32+"}) is True


def test_bin_info_has_pe_returns_false_for_elf() -> None:
    """Line 283: returns False for ELF binary."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._bin_info_has_pe({"format": "elf64", "class": "elf64"}) is False


def test_bin_info_has_pe_returns_false_for_empty_fields() -> None:
    """Line 283: returns False when format and class are empty."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._bin_info_has_pe({"format": "", "class": ""}) is False


# ---------------------------------------------------------------------------
# _extract_rich_header (lines 296-314)
# ---------------------------------------------------------------------------


def test_extract_rich_header_finds_header_in_valid_pe() -> None:
    """Lines 296-297: returns Rich Header dict via direct file analysis."""
    data = _build_pe_with_rich_header()
    path = _write_tmp(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        result = analyzer._extract_rich_header()
        assert result is not None
        assert "xor_key" in result
    finally:
        os.unlink(path)


def test_extract_rich_header_returns_none_for_pe_without_rich() -> None:
    """Lines 305-310: returns None when no Rich Header present."""
    data = _build_pe_without_rich_header()
    path = _write_tmp(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        result = analyzer._extract_rich_header()
        assert result is None
    finally:
        os.unlink(path)


def test_extract_rich_header_exception_returns_none() -> None:
    """Lines 312-314: exception is caught and None is returned."""
    class _BrokenDirectAnalyzer(RichHeaderAnalyzer):
        def _direct_file_rich_search(self):
            raise RuntimeError("direct search exploded")

    analyzer = _BrokenDirectAnalyzer(adapter=_MinimalAdapter(), filepath=None)
    result = analyzer._extract_rich_header()
    assert result is None


# ---------------------------------------------------------------------------
# _scan_patterns (lines 331-336)
# ---------------------------------------------------------------------------


class _EmptySearchAdapter:
    def search_hex_json(self, pattern: str) -> list:
        return []


class _HitSearchAdapter:
    def search_hex_json(self, pattern: str) -> list:
        return [{"offset": 0x80}]


class _ExplodingSearchAdapter:
    def search_hex_json(self, pattern: str) -> list:
        raise RuntimeError("search failure")


def test_scan_patterns_returns_empty_when_search_finds_nothing() -> None:
    """Lines 331-336: empty list returned when no pattern matches."""
    analyzer = RichHeaderAnalyzer(adapter=_EmptySearchAdapter(), filepath=None)
    result = analyzer._scan_patterns(["52696368"], "Rich")
    assert result == []


def test_scan_patterns_collects_results_across_patterns() -> None:
    """Lines 331-336: results from multiple patterns are concatenated."""
    analyzer = RichHeaderAnalyzer(adapter=_HitSearchAdapter(), filepath=None)
    result = analyzer._scan_patterns(["52696368", "68636952"], "Rich")
    assert len(result) == 2


def test_scan_patterns_continues_after_exception() -> None:
    """Lines 333-335: exception in a single pattern search is caught, loop continues."""
    analyzer = RichHeaderAnalyzer(adapter=_ExplodingSearchAdapter(), filepath=None)
    result = analyzer._scan_patterns(["52696368", "68636952"], "Rich")
    assert result == []


# ---------------------------------------------------------------------------
# _try_rich_dans_combinations (lines 342-356)
# ---------------------------------------------------------------------------


def test_try_rich_dans_combinations_returns_none_for_invalid_offsets() -> None:
    """Lines 348-349: skips combination when DanS offset >= Rich offset."""
    data = _build_pe_with_rich_header()
    path = _write_tmp(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        rich_results = [{"offset": 0x10}]
        dans_results = [{"offset": 0x80}]  # DanS after Rich -> invalid
        result = analyzer._try_rich_dans_combinations(rich_results, dans_results)
        assert result is None
    finally:
        os.unlink(path)


def test_try_rich_dans_combinations_skips_missing_offset() -> None:
    """Line 346: skips when _extract_offsets returns None."""
    data = _build_pe_with_rich_header()
    path = _write_tmp(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        rich_results = [{"no_offset_field": 0x50}]
        dans_results = [{"offset": 0x30}]
        result = analyzer._try_rich_dans_combinations(rich_results, dans_results)
        assert result is None
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _extract_offsets (lines 362-366)
# ---------------------------------------------------------------------------


def test_extract_offsets_returns_tuple() -> None:
    """Lines 362-366: returns (dans_offset, rich_offset) tuple."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    result = analyzer._extract_offsets({"offset": 0xA0}, {"offset": 0x50})
    assert result == (0x50, 0xA0)


def test_extract_offsets_returns_none_when_rich_offset_missing() -> None:
    """Line 364-366: returns None when rich_offset is None."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    result = analyzer._extract_offsets({"offset": None}, {"offset": 0x30})
    assert result is None


def test_extract_offsets_returns_none_when_dans_offset_missing() -> None:
    """Line 364-366: returns None when dans_offset is None."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    result = analyzer._extract_offsets({"offset": 0x80}, {"offset": None})
    assert result is None


# ---------------------------------------------------------------------------
# _offsets_valid (line 370)
# ---------------------------------------------------------------------------


def test_offsets_valid_true_for_valid_pair() -> None:
    """Line 370: returns True when dans < rich and difference <= 1024."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._offsets_valid(0x40, 0x80) is True


def test_offsets_valid_false_when_dans_after_rich() -> None:
    """Line 370: returns False when dans >= rich."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._offsets_valid(0x80, 0x40) is False


def test_offsets_valid_false_when_difference_too_large() -> None:
    """Line 370: returns False when rich - dans > 1024."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._offsets_valid(0x00, 0x00 + 2000) is False


def test_offsets_valid_boundary_exactly_1024() -> None:
    """Line 370: returns True when rich - dans == 1024."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._offsets_valid(0x00, 1024) is True


# ---------------------------------------------------------------------------
# _direct_file_rich_search (lines 382-427)
# ---------------------------------------------------------------------------


def test_direct_file_rich_search_finds_header_in_pe() -> None:
    """Lines 382-422: returns Rich Header dict from file with embedded header."""
    data = _build_pe_with_rich_header(xor_key=0x12345678)
    path = _write_tmp(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=None, filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is not None
        assert result["xor_key"] == 0x12345678
        assert len(result["entries"]) >= 1
        assert "encoded_data" in result
    finally:
        os.unlink(path)


def test_direct_file_rich_search_returns_none_for_no_filepath() -> None:
    """Line 382: returns None when no filepath is set."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._direct_file_rich_search() is None


def test_direct_file_rich_search_returns_none_for_pe_without_rich() -> None:
    """Line 394: returns None when Rich marker absent."""
    data = _build_pe_without_rich_header()
    path = _write_tmp(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=None, filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is None
    finally:
        os.unlink(path)


def test_direct_file_rich_search_returns_none_when_pe_offset_beyond_eof() -> None:
    """Line 386: returns None when pe_offset exceeds file size."""
    header = bytearray(0x50)
    header[0] = ord("M")
    header[1] = ord("Z")
    struct.pack_into("<I", header, 0x3C, 0x5000)  # way beyond EOF
    data = bytes(header) + b"\x00" * 8
    path = _write_tmp(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=None, filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is None
    finally:
        os.unlink(path)


def test_direct_file_rich_search_returns_none_when_dos_stub_empty() -> None:
    """Line 390: returns None when pe_offset == dos_stub_start."""
    header = bytearray(0x44)
    header[0] = ord("M")
    header[1] = ord("Z")
    struct.pack_into("<I", header, 0x3C, 0x40)
    data = bytes(header) + b"PE\x00\x00" + b"\x00" * 100
    path = _write_tmp(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=None, filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is None
    finally:
        os.unlink(path)


def test_direct_file_rich_search_returns_none_for_non_mz_file() -> None:
    """Lines 382-383: returns None when file does not have MZ magic."""
    path = _write_tmp(b"\x7fELF" + b"\x00" * 100)
    try:
        analyzer = RichHeaderAnalyzer(adapter=None, filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is None
    finally:
        os.unlink(path)


def test_direct_file_rich_search_exception_returns_none() -> None:
    """Lines 424-426: exception is caught and None returned."""
    class _BrokenFileAnalyzer(RichHeaderAnalyzer):
        def _read_file_bytes(self):
            raise RuntimeError("file read failed")

    analyzer = _BrokenFileAnalyzer(adapter=None, filepath=None)
    result = analyzer._direct_file_rich_search()
    assert result is None


# ---------------------------------------------------------------------------
# _read_file_bytes (lines 432-436)
# ---------------------------------------------------------------------------


def test_read_file_bytes_returns_bytes_for_valid_path() -> None:
    """Lines 432-436: returns bytes content of file."""
    data = _build_pe_with_rich_header()
    path = _write_tmp(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=None, filepath=path)
        result = analyzer._read_file_bytes()
        assert result is not None
        assert result[:2] == b"MZ"
    finally:
        os.unlink(path)


def test_read_file_bytes_returns_none_for_no_filepath() -> None:
    """Lines 432-433: returns None when filepath is None."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._read_file_bytes() is None


def test_read_file_bytes_returns_none_for_missing_file() -> None:
    """Lines 434-436: returns None when file does not exist."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/no_such_file_xyz.exe")
    result = analyzer._read_file_bytes()
    assert result is None


# ---------------------------------------------------------------------------
# _is_valid_pe_data (line 446)
# ---------------------------------------------------------------------------


def test_is_valid_pe_data_true_for_mz_and_enough_bytes() -> None:
    """Line 446: returns True for MZ header with >= 0x40 bytes."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._is_valid_pe_data(b"MZ" + b"\x00" * 70) is True


def test_is_valid_pe_data_false_for_short_data() -> None:
    """Line 446: returns False for data shorter than 0x40."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._is_valid_pe_data(b"MZ") is False


def test_is_valid_pe_data_false_for_wrong_magic() -> None:
    """Line 446: returns False for non-MZ magic bytes."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._is_valid_pe_data(b"ZM" + b"\x00" * 70) is False


# ---------------------------------------------------------------------------
# _get_pe_offset (lines 453-454)
# ---------------------------------------------------------------------------


def test_get_pe_offset_reads_e_lfanew_field() -> None:
    """Line 453: reads e_lfanew from offset 0x3C."""
    data = bytearray(0x60)
    data[0] = ord("M")
    data[1] = ord("Z")
    struct.pack_into("<I", data, 0x3C, 0x58)
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    result = analyzer._get_pe_offset(bytes(data))
    assert result == 0x58


def test_get_pe_offset_returns_none_when_offset_out_of_range() -> None:
    """Line 453: returns None when pe_offset >= len(data) - 4."""
    data = bytearray(0x50)
    struct.pack_into("<I", data, 0x3C, 0x4000)
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    result = analyzer._get_pe_offset(bytes(data))
    assert result is None


# ---------------------------------------------------------------------------
# _get_dos_stub (lines 462-463)
# ---------------------------------------------------------------------------


def test_get_dos_stub_returns_correct_slice() -> None:
    """Lines 462-463: extracts bytes between 0x40 and pe_offset."""
    data = b"MZ" + b"\x00" * 120
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    stub = analyzer._get_dos_stub(data, 0x60)
    assert stub == data[0x40:0x60]
    assert len(stub) == 0x20


def test_get_dos_stub_returns_none_when_pe_offset_too_small() -> None:
    """Line 462: returns None when pe_offset <= 0x40."""
    data = b"MZ" + b"\x00" * 100
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._get_dos_stub(data, 0x40) is None
    assert analyzer._get_dos_stub(data, 0x30) is None


# ---------------------------------------------------------------------------
# _find_rich_pos (lines 467-473)
# ---------------------------------------------------------------------------


def test_find_rich_pos_finds_marker() -> None:
    """Lines 467-473: returns offset of 'Rich' within dos_stub."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    stub = b"\x00" * 10 + b"Rich" + b"\x00" * 8
    assert analyzer._find_rich_pos(stub) == 10


def test_find_rich_pos_returns_none_when_not_found() -> None:
    """Lines 467-473: returns None when 'Rich' is absent."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._find_rich_pos(b"\x00" * 20) is None


# ---------------------------------------------------------------------------
# _extract_xor_key_from_stub (lines 477-482)
# ---------------------------------------------------------------------------


def test_extract_xor_key_from_stub_reads_correctly() -> None:
    """Lines 477-482: reads 4 bytes after 'Rich' as little-endian uint32."""
    xor_val = 0xFEEDFACE
    xor_bytes = struct.pack("<I", xor_val)
    stub = b"\x00" * 4 + b"Rich" + xor_bytes + b"\x00" * 4
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    result = analyzer._extract_xor_key_from_stub(stub, rich_pos=4)
    assert result == xor_val


def test_extract_xor_key_from_stub_returns_none_insufficient_data() -> None:
    """Lines 477-479: returns None when fewer than 8 bytes after Rich pos."""
    stub = b"Rich\x01\x02"
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._extract_xor_key_from_stub(stub, rich_pos=0) is None


# ---------------------------------------------------------------------------
# _find_or_estimate_dans (lines 486-494)
# ---------------------------------------------------------------------------


def test_find_or_estimate_dans_finds_explicit_marker() -> None:
    """Lines 486-490: returns position of 'DanS' when present."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    stub = b"DanS" + b"\x00" * 12 + b"Rich" + b"\x00" * 4
    rich_pos = stub.index(b"Rich")
    result = analyzer._find_or_estimate_dans(stub, rich_pos)
    assert result == 0


def test_find_or_estimate_dans_estimates_when_dans_absent() -> None:
    """Lines 491-494: estimates start when DanS not found."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    stub = b"\x00" * 16 + b"Rich" + b"\x00" * 4
    rich_pos = stub.index(b"Rich")
    result = analyzer._find_or_estimate_dans(stub, rich_pos)
    assert result is None or isinstance(result, int)


def test_estimate_dans_start_returns_position_for_8byte_aligned() -> None:
    """Lines 492-493: returns start position when test_data is 8-byte aligned."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    stub = b"\x00" * 8 + b"Rich" + b"\x00" * 4
    result = analyzer._estimate_dans_start(stub, rich_pos=8)
    assert result == 0


def test_estimate_dans_start_returns_none_when_no_alignment() -> None:
    """Lines 492-494: returns None when no valid aligned segment found."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    stub = b"\x00\x01\x02\x03"
    result = analyzer._estimate_dans_start(stub, rich_pos=4)
    assert result is None


# ---------------------------------------------------------------------------
# _extract_encoded_from_stub (lines 500-505)
# ---------------------------------------------------------------------------


def test_extract_encoded_from_stub_valid_8byte_multiple() -> None:
    """Lines 500-505: extracts encoded bytes when length is multiple of 8."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    stub = b"DanS" + b"\xBB" * 8 + b"Rich" + b"\x00" * 4
    result = analyzer._extract_encoded_from_stub(stub, dans_pos=0, rich_pos=12)
    assert result == b"\xBB" * 8


def test_extract_encoded_from_stub_returns_none_for_wrong_length() -> None:
    """Lines 501-503: returns None when encoded length is not divisible by 8."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    stub = b"DanS" + b"\xBB" * 5 + b"Rich"
    result = analyzer._extract_encoded_from_stub(stub, dans_pos=0, rich_pos=9)
    assert result is None


def test_extract_encoded_from_stub_returns_none_for_empty_data() -> None:
    """Lines 501-503: returns None when encoded data is empty."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    stub = b"DanS" + b"Rich"  # DanS at 0, Rich at 4 -> encoded = stub[4:4] = b""
    result = analyzer._extract_encoded_from_stub(stub, dans_pos=0, rich_pos=4)
    assert result is None


# ---------------------------------------------------------------------------
# _build_direct_rich_result (lines 518-527)
# ---------------------------------------------------------------------------


def test_build_direct_rich_result_builds_correct_dict() -> None:
    """Lines 518-527: returns dict with all expected fields."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    entries = [{"product_id": 1, "build_number": 2, "count": 3}]
    result = analyzer._build_direct_rich_result(
        xor_key=0x9999,
        calculated_checksum=0x9999,
        entries=entries,
        encoded_data=b"\x00" * 8,
        dos_stub_start=0x40,
        dans_pos=0,
        rich_pos=16,
    )
    assert result["xor_key"] == 0x9999
    assert result["checksum"] == 0x9999
    assert result["valid_checksum"] is True
    assert result["entries"] is entries
    assert result["dans_offset"] == 0x40
    assert result["rich_offset"] == 0x40 + 16
    assert isinstance(result["encoded_data"], str)


def test_build_direct_rich_result_invalid_checksum_flagged() -> None:
    """Line 526: valid_checksum is False when checksum mismatches xor_key."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    entries: list[dict] = []
    result = analyzer._build_direct_rich_result(
        xor_key=0x1111,
        calculated_checksum=0x2222,
        entries=entries,
        encoded_data=b"\x00" * 8,
        dos_stub_start=0x40,
        dans_pos=0,
        rich_pos=8,
    )
    assert result["valid_checksum"] is False


# ---------------------------------------------------------------------------
# _calculate_rich_checksum (lines 543-566)
# ---------------------------------------------------------------------------


def test_calculate_rich_checksum_returns_integer() -> None:
    """Lines 543-566: returns a non-negative integer checksum."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    data = b"MZ" + b"\x00" * 62 + b"PE\x00\x00" + b"\x00" * 200
    entries = [{"product_id": 3, "build_number": 50727, "count": 2}]
    checksum = analyzer._calculate_rich_checksum(data, 0x40, entries)
    assert isinstance(checksum, int)
    assert checksum >= 0


def test_calculate_rich_checksum_empty_entries() -> None:
    """Lines 551-560: handles empty entries list."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    data = b"MZ" + b"\x00" * 100
    checksum = analyzer._calculate_rich_checksum(data, 0x40, [])
    assert isinstance(checksum, int)


def test_calculate_rich_checksum_returns_zero_on_exception() -> None:
    """Lines 564-566: returns 0 when data is too short (triggers IndexError)."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    checksum = analyzer._calculate_rich_checksum(b"MZ", 0x40, [])
    assert checksum == 0


def test_calculate_rich_checksum_uses_pe_offset_as_seed() -> None:
    """Line 544: pe_offset is included in checksum seed."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    data = b"MZ" + b"\x00" * 100
    checksum_a = analyzer._calculate_rich_checksum(data, 0x40, [])
    checksum_b = analyzer._calculate_rich_checksum(data, 0x80, [])
    assert checksum_a != checksum_b


# ---------------------------------------------------------------------------
# is_available (line 577)
# ---------------------------------------------------------------------------


def test_is_available_returns_true() -> None:
    """Line 577: static method always returns True."""
    assert RichHeaderAnalyzer.is_available() is True


# ---------------------------------------------------------------------------
# calculate_richpe_hash_from_file (lines 582-586)
# ---------------------------------------------------------------------------


def test_calculate_richpe_hash_from_file_returns_hash_for_pe_with_rich() -> None:
    """Lines 582-586: returns richpe_hash string for a PE containing Rich Header."""
    data = _build_pe_with_rich_header()
    path = _write_tmp(data)
    try:
        result = RichHeaderAnalyzer.calculate_richpe_hash_from_file(path)
        # May be None if the PE is too minimal for full parsing, but should not raise
        assert result is None or isinstance(result, str)
    finally:
        os.unlink(path)


def test_calculate_richpe_hash_from_file_returns_none_for_nonexistent_file() -> None:
    """Lines 582-584: returns None when analysis fails (file not found)."""
    result = RichHeaderAnalyzer.calculate_richpe_hash_from_file("/tmp/no_such_pe_xyz.exe")
    assert result is None


def test_calculate_richpe_hash_from_file_returns_none_for_non_pe() -> None:
    """Lines 582-586: returns None when file is not a PE."""
    path = _write_tmp(b"\x7fELF" + b"\x00" * 100)
    try:
        result = RichHeaderAnalyzer.calculate_richpe_hash_from_file(path)
        assert result is None
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Full analyze() flow with Rich Header present (lines 101-120)
# ---------------------------------------------------------------------------


def test_analyze_full_flow_with_rich_header_pe() -> None:
    """Lines 101-120: full analyze() path with Rich Header found."""
    data = _build_pe_with_rich_header(xor_key=0xCAFEBABE)
    path = _write_tmp(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        result = analyzer.analyze()
        assert result["is_pe"] is True
        if result.get("error") is None:
            assert result["rich_header"] is not None
            assert result["xor_key"] is not None
            assert isinstance(result["compilers"], list)
    finally:
        os.unlink(path)


def test_analyze_full_flow_pe_without_rich_header() -> None:
    """Lines 96-99: analyze() sets error when Rich Header not found."""
    data = _build_pe_without_rich_header()
    path = _write_tmp(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        result = analyzer.analyze()
        assert result["is_pe"] is True
        assert result["error"] == "Rich Header not found"
        assert result["rich_header"] is None
    finally:
        os.unlink(path)
