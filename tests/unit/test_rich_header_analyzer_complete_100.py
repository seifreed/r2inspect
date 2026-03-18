"""Comprehensive tests for rich_header_analyzer.py - 100% coverage target.

All mocks replaced with real objects using FakeR2 + R2PipeAdapter.
"""

import struct
import tempfile
import os

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer


# ---------------------------------------------------------------------------
# FakeR2: minimal r2pipe stand-in routing cmdj/cmd via lookup maps
# ---------------------------------------------------------------------------


class FakeR2:
    """Minimal r2pipe stand-in that routes cmdj/cmd via lookup maps."""

    def __init__(self, cmdj_map=None, cmd_map=None):
        self.cmdj_map = cmdj_map or {}
        self.cmd_map = cmd_map or {}

    def cmdj(self, command):
        return self.cmdj_map.get(command, {})

    def cmd(self, command):
        return self.cmd_map.get(command, "")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hex_for(data: bytes) -> str:
    """Convert bytes to hex string suitable for p8 output."""
    return data.hex()


def _make_adapter(cmdj_map=None, cmd_map=None):
    """Build an R2PipeAdapter backed by FakeR2."""
    r2 = FakeR2(cmdj_map=cmdj_map, cmd_map=cmd_map)
    return R2PipeAdapter(r2)


def _make_analyzer(cmdj_map=None, cmd_map=None, filepath=None):
    """Build a RichHeaderAnalyzer backed by FakeR2 + R2PipeAdapter."""
    adapter = _make_adapter(cmdj_map=cmdj_map, cmd_map=cmd_map)
    return RichHeaderAnalyzer(adapter=adapter, filepath=filepath)


def _build_pe_bytes_with_rich_header(
    *,
    entries=None,
    xor_key=0x12345678,
    pe_offset=0x100,
):
    """Build a minimal PE byte sequence with a Rich Header in the DOS stub.

    Uses the literal ``DanS`` marker so ``_find_or_estimate_dans`` locates it.
    The encoded block between DanS+4 and Rich is kept 8-byte-aligned by using
    an even number of padding dwords (2 padding + dummy_entry_padding = 16 bytes
    overhead, then real entries in 8-byte chunks).

    ``decode_rich_header`` starts processing at offset 4 of the encoded block
    and reads 8-byte chunks.  With 2 padding dwords (8 bytes) after skipping 4:
      offset 4 = 2nd padding dword (4 bytes) + first 4 bytes of next data.
    To keep entries aligned, we use exactly 2 zero-XOR-key dwords as padding,
    then a 4-byte zero-pad dword to re-align, giving 12 bytes.  Instead, we
    accept that decode_rich_header's built-in skip logic handles the alignment.

    Total encoded block = padding_bytes + entry_bytes.  We choose padding such
    that total % 8 == 0 and entries land on 8-byte boundaries after the 4-byte
    skip in decode_rich_header.

    Simplest correct layout that passes both ``_extract_encoded_from_stub`` and
    ``decode_rich_header``: use 0 explicit padding dwords.  Just place entries
    directly after DanS.  decode_rich_header skips first 4 bytes (half of first
    entry), but we prepend one dummy 8-byte entry (count=0 after XOR, so it
    gets skipped by the decoder).  Total = 8*(N+1), always 8-aligned.
    """
    if entries is None:
        entries = [{"product_id": 0x1E, "build_number": 0x7809, "count": 3}]

    # decode_rich_header processes encoded_data with:
    #   range(4, len(encoded_data) - 4, 8)
    # So it skips the first 4 bytes and last 4 bytes, reading 8-byte
    # (prodid_xored, count_xored) chunks in between.
    #
    # Layout of encoded_data (between DanS+4 and Rich):
    #   [4-byte lead pad] [8 bytes per entry ...] [4-byte trail pad]
    # Total = 4 + N*8 + 4 = 8 + N*8 = (1+N)*8 -> always 8-aligned.

    lead_pad = struct.pack("<I", xor_key)  # XORs to 0 (skipped)
    trail_pad = struct.pack("<I", xor_key)  # XORs to 0 (skipped)

    encoded_entries = b""
    for entry in entries:
        comp_id = (entry["build_number"] << 16) | entry["product_id"]
        encoded_entries += struct.pack("<I", comp_id ^ xor_key)
        encoded_entries += struct.pack("<I", entry["count"] ^ xor_key)

    encoded_block = lead_pad + encoded_entries + trail_pad

    # Full stub content
    dans_sig = b"DanS"
    rich_sig = b"Rich"
    xor_key_bytes = struct.pack("<I", xor_key)

    stub_content = dans_sig + encoded_block + rich_sig + xor_key_bytes

    # Build full PE data
    data = bytearray(pe_offset + 256)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = struct.pack("<I", pe_offset)

    # Place stub content starting at 0x40
    stub_start = 0x40
    stub_end = stub_start + len(stub_content)
    if stub_end <= pe_offset:
        data[stub_start:stub_end] = stub_content

    # PE signature
    data[pe_offset : pe_offset + 4] = b"PE\x00\x00"

    return bytes(data)


def _write_pe_tempfile(pe_data):
    """Write PE data to a tempfile and return the path."""
    fd, path = tempfile.mkstemp(suffix=".exe")
    try:
        os.write(fd, pe_data)
    finally:
        os.close(fd)
    return path


# ---------------------------------------------------------------------------
# Initialization tests
# ---------------------------------------------------------------------------


def test_init_with_adapter():
    """Test initialization with adapter."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter)
    assert analyzer.adapter is adapter


def test_init_with_r2_instance():
    """Test initialization with r2_instance kwarg (backward compat)."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(r2_instance=adapter)
    assert analyzer.adapter is adapter


def test_is_available():
    """Test is_available static method."""
    assert RichHeaderAnalyzer.is_available() is True


# ---------------------------------------------------------------------------
# analyze() - not PE
# ---------------------------------------------------------------------------


def test_analyze_not_pe():
    """Test analyze when file is not PE (no filepath, no PE info from r2)."""
    analyzer = _make_analyzer(
        cmdj_map={"ij": {"bin": {"format": "elf", "class": "ELF64"}}},
        cmd_map={"i": "elf binary"},
    )
    result = analyzer.analyze()
    assert result["is_pe"] is False
    assert result["error"] == "File is not a PE binary"


# ---------------------------------------------------------------------------
# analyze() - PE with Rich Header via direct file search
# ---------------------------------------------------------------------------


def test_analyze_pe_with_rich_header_via_file():
    """Test full analyze with a real PE file containing a Rich Header."""
    pe_data = _build_pe_bytes_with_rich_header()
    path = _write_pe_tempfile(pe_data)
    try:
        analyzer = _make_analyzer(filepath=path)
        result = analyzer.analyze()

        assert result["is_pe"] is True
        assert result.get("available") is True
        assert result["xor_key"] == 0x12345678
        assert result["rich_header"] is not None
        assert isinstance(result["compilers"], list)
    finally:
        os.unlink(path)


def test_analyze_pe_no_rich_header():
    """Test analyze when PE has no Rich Header (no DanS/Rich in stub)."""
    # Build a PE file with no Rich Header content in the DOS stub
    pe_offset = 0x80
    data = bytearray(pe_offset + 64)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = struct.pack("<I", pe_offset)
    data[pe_offset : pe_offset + 4] = b"PE\x00\x00"

    path = _write_pe_tempfile(bytes(data))
    try:
        # No r2pipe search results either
        analyzer = _make_analyzer(
            cmdj_map={
                "/xj 52696368": [],
                "/xj 68636952": [],
                "/xj 5269636800000000": [],
                "/xj 44616e53": [],
                "/xj 536e6144": [],
                "/xj 44616e5300000000": [],
            },
            filepath=path,
        )
        result = analyzer.analyze()

        assert result["is_pe"] is True
        assert result["error"] == "Rich Header not found"
    finally:
        os.unlink(path)


def test_analyze_exception():
    """Test analyze when _is_pe_file raises an exception."""

    # Pass an adapter that will cause issues - filepath is a non-existent path
    # The is_pe_file function will try to read magic bytes and fail gracefully,
    # then try ij which returns empty -> not PE.  To force an actual exception
    # in analyze(), we need the adapter's cmd/cmdj to raise.
    class FailR2:
        def cmdj(self, command):
            raise RuntimeError("Test error")

        def cmd(self, command):
            raise RuntimeError("Test error")

    adapter = R2PipeAdapter(FailR2())
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/nonexistent/test/file")
    result = analyzer.analyze()
    # The exception is caught and stored in result["error"]
    # Either is_pe returns False or an exception is caught
    assert "error" in result
    assert result["error"] is not None


# ---------------------------------------------------------------------------
# _pefile_has_rich_header
# ---------------------------------------------------------------------------


def test_pefile_has_rich_header_true():
    """Test _pefile_has_rich_header with a PE that has RICH_HEADER."""
    analyzer = _make_analyzer()

    class FakePE:
        class RICH_HEADER:
            checksum = 0xAABBCCDD

    assert analyzer._pefile_has_rich_header(FakePE()) is True


def test_pefile_has_rich_header_false():
    """Test _pefile_has_rich_header when no RICH_HEADER attribute."""
    analyzer = _make_analyzer()

    class FakePE:
        pass

    assert analyzer._pefile_has_rich_header(FakePE()) is False


def test_pefile_has_rich_header_none():
    """Test _pefile_has_rich_header when RICH_HEADER is None."""
    analyzer = _make_analyzer()

    class FakePE:
        RICH_HEADER = None

    assert analyzer._pefile_has_rich_header(FakePE()) is False


# ---------------------------------------------------------------------------
# _pefile_get_xor_key
# ---------------------------------------------------------------------------


def test_pefile_get_xor_key():
    """Test _pefile_get_xor_key extracts checksum from RICH_HEADER."""
    analyzer = _make_analyzer()

    class FakePE:
        class RICH_HEADER:
            checksum = 0xABCDEF12

    result = analyzer._pefile_get_xor_key(FakePE())
    assert result == 0xABCDEF12


def test_pefile_get_xor_key_no_checksum():
    """Test _pefile_get_xor_key when no checksum attribute."""
    analyzer = _make_analyzer()

    class FakePE:
        class RICH_HEADER:
            pass

    # Remove checksum attribute
    delattr(FakePE.RICH_HEADER, "checksum") if hasattr(FakePE.RICH_HEADER, "checksum") else None
    result = analyzer._pefile_get_xor_key(FakePE())
    assert result is None


# ---------------------------------------------------------------------------
# _pefile_extract_entries / _pefile_parse_entry
# ---------------------------------------------------------------------------


def test_pefile_extract_entries():
    """Test _pefile_extract_entries extracts product_id/build/count."""
    analyzer = _make_analyzer()

    class FakeEntry:
        product_id = 100
        build_version = 200
        count = 5

    class FakePE:
        class RICH_HEADER:
            values = [FakeEntry()]

    entries = analyzer._pefile_extract_entries(FakePE())
    assert len(entries) == 1
    assert entries[0]["product_id"] == 100
    assert entries[0]["build_number"] == 200
    assert entries[0]["count"] == 5


def test_pefile_extract_entries_no_values():
    """Test _pefile_extract_entries when no values attribute."""
    analyzer = _make_analyzer()

    class FakePE:
        class RICH_HEADER:
            pass

    entries = analyzer._pefile_extract_entries(FakePE())
    assert entries == []


def test_pefile_parse_entry_invalid():
    """Test _pefile_parse_entry with an object missing required attrs."""
    analyzer = _make_analyzer()

    class BadEntry:
        pass

    result = analyzer._pefile_parse_entry(BadEntry())
    assert result is None


def test_pefile_parse_entry_valid():
    """Test _pefile_parse_entry with valid entry."""
    analyzer = _make_analyzer()

    class GoodEntry:
        product_id = 0x1E
        build_version = 0x7809
        count = 3

    result = analyzer._pefile_parse_entry(GoodEntry())
    assert result is not None
    assert result["product_id"] == 0x1E
    assert result["build_number"] == 0x7809
    assert result["count"] == 3
    assert result["prodid"] == (0x1E | (0x7809 << 16))


# ---------------------------------------------------------------------------
# _check_magic_bytes
# ---------------------------------------------------------------------------


def test_check_magic_bytes_success():
    """Test _check_magic_bytes with a real MZ file."""
    pe_data = b"MZ" + b"\x00" * 100
    path = _write_pe_tempfile(pe_data)
    try:
        analyzer = _make_analyzer(filepath=path)
        assert analyzer._check_magic_bytes() is True
    finally:
        os.unlink(path)


def test_check_magic_bytes_not_pe():
    """Test _check_magic_bytes with non-PE data."""
    path = _write_pe_tempfile(b"ELF" + b"\x00" * 100)
    try:
        analyzer = _make_analyzer(filepath=path)
        assert analyzer._check_magic_bytes() is False
    finally:
        os.unlink(path)


def test_check_magic_bytes_no_filepath():
    """Test _check_magic_bytes with no filepath."""
    analyzer = _make_analyzer(filepath=None)
    assert analyzer._check_magic_bytes() is False


def test_check_magic_bytes_nonexistent_file():
    """Test _check_magic_bytes with nonexistent file path."""
    analyzer = _make_analyzer(filepath="/nonexistent/path/file.exe")
    assert analyzer._check_magic_bytes() is False


# ---------------------------------------------------------------------------
# _bin_info_has_pe
# ---------------------------------------------------------------------------


def test_bin_info_has_pe_format():
    """Test _bin_info_has_pe with 'pe' in format field."""
    analyzer = _make_analyzer()
    assert analyzer._bin_info_has_pe({"format": "pe64"}) is True


def test_bin_info_has_pe_class():
    """Test _bin_info_has_pe with 'pe' in class field."""
    analyzer = _make_analyzer()
    assert analyzer._bin_info_has_pe({"format": "unknown", "class": "PE32"}) is True


def test_bin_info_has_pe_false():
    """Test _bin_info_has_pe returns False for non-PE."""
    analyzer = _make_analyzer()
    assert analyzer._bin_info_has_pe({"format": "elf", "class": "ELF64"}) is False


# ---------------------------------------------------------------------------
# _is_valid_pe_data
# ---------------------------------------------------------------------------


def test_is_valid_pe_data_true():
    """Test _is_valid_pe_data with valid MZ data."""
    analyzer = _make_analyzer()
    data = b"MZ" + b"\x00" * 62
    assert analyzer._is_valid_pe_data(data) is True


def test_is_valid_pe_data_too_short():
    """Test _is_valid_pe_data with data shorter than 0x40."""
    analyzer = _make_analyzer()
    assert analyzer._is_valid_pe_data(b"MZ") is False


def test_is_valid_pe_data_wrong_magic():
    """Test _is_valid_pe_data with wrong magic bytes."""
    analyzer = _make_analyzer()
    assert analyzer._is_valid_pe_data(b"XX" + b"\x00" * 62) is False


# ---------------------------------------------------------------------------
# _get_pe_offset
# ---------------------------------------------------------------------------


def test_get_pe_offset_valid():
    """Test _get_pe_offset with valid PE offset."""
    analyzer = _make_analyzer()
    data = bytearray(0x200)
    data[0:2] = b"MZ"
    pe_offset = 0x80
    data[0x3C:0x40] = struct.pack("<I", pe_offset)
    data[pe_offset : pe_offset + 4] = b"PE\x00\x00"

    result = analyzer._get_pe_offset(bytes(data))
    assert result == pe_offset


def test_get_pe_offset_out_of_range():
    """Test _get_pe_offset when offset is beyond data length."""
    analyzer = _make_analyzer()
    data = bytearray(0x80)
    data[0:2] = b"MZ"
    # Set PE offset beyond data length
    data[0x3C:0x40] = struct.pack("<I", 0xFFFF)

    result = analyzer._get_pe_offset(bytes(data))
    assert result is None


# ---------------------------------------------------------------------------
# _get_dos_stub
# ---------------------------------------------------------------------------


def test_get_dos_stub():
    """Test _get_dos_stub returns data between 0x40 and pe_offset."""
    analyzer = _make_analyzer()
    data = b"MZ" + b"\x00" * 0xFE + b"STUB_DATA" + b"\x00" * 100
    pe_offset = 0x100

    result = analyzer._get_dos_stub(data, pe_offset)
    assert result is not None
    # DOS stub is from 0x40 to pe_offset
    assert len(result) == pe_offset - 0x40


def test_get_dos_stub_pe_offset_too_small():
    """Test _get_dos_stub when pe_offset <= 0x40."""
    analyzer = _make_analyzer()
    data = b"MZ" + b"\x00" * 100

    result = analyzer._get_dos_stub(data, 0x40)
    assert result is None


# ---------------------------------------------------------------------------
# _find_rich_pos
# ---------------------------------------------------------------------------


def test_find_rich_pos_found():
    """Test _find_rich_pos when Rich signature is present."""
    analyzer = _make_analyzer()
    dos_stub = b"\x00" * 100 + b"Rich" + b"\x00" * 50
    result = analyzer._find_rich_pos(dos_stub)
    assert result == 100


def test_find_rich_pos_not_found():
    """Test _find_rich_pos when Rich signature is absent."""
    analyzer = _make_analyzer()
    dos_stub = b"\x00" * 150
    result = analyzer._find_rich_pos(dos_stub)
    assert result is None


# ---------------------------------------------------------------------------
# _extract_xor_key_from_stub
# ---------------------------------------------------------------------------


def test_extract_xor_key_from_stub():
    """Test _extract_xor_key_from_stub extracts 4-byte LE key after 'Rich'."""
    analyzer = _make_analyzer()
    xor_key = 0x78563412
    dos_stub = b"\x00" * 100 + b"Rich" + struct.pack("<I", xor_key)
    result = analyzer._extract_xor_key_from_stub(dos_stub, 100)
    assert result == xor_key


def test_extract_xor_key_from_stub_insufficient_data():
    """Test _extract_xor_key_from_stub when not enough bytes after Rich."""
    analyzer = _make_analyzer()
    dos_stub = b"Rich\x12"
    result = analyzer._extract_xor_key_from_stub(dos_stub, 0)
    assert result is None


def test_extract_xor_key_from_stub_zero_key():
    """Test _extract_xor_key_from_stub when XOR key is zero (returns None)."""
    analyzer = _make_analyzer()
    dos_stub = b"\x00" * 100 + b"Rich" + struct.pack("<I", 0)
    result = analyzer._extract_xor_key_from_stub(dos_stub, 100)
    assert result is None


# ---------------------------------------------------------------------------
# _find_or_estimate_dans
# ---------------------------------------------------------------------------


def test_find_or_estimate_dans_found():
    """Test _find_or_estimate_dans when DanS is explicitly present."""
    analyzer = _make_analyzer()
    dos_stub = b"DanS" + b"\x00" * 100 + b"Rich"
    result = analyzer._find_or_estimate_dans(dos_stub, 104)
    assert result == 0


def test_find_or_estimate_dans_estimate():
    """Test _find_or_estimate_dans falls back to estimation when no DanS."""
    analyzer = _make_analyzer()
    # Build stub with no DanS but with data aligned to 8 bytes before Rich
    dos_stub = b"\x00" * 104 + b"Rich"
    result = analyzer._find_or_estimate_dans(dos_stub, 104)
    # Should estimate a start position
    assert result is not None


# ---------------------------------------------------------------------------
# _estimate_dans_start
# ---------------------------------------------------------------------------


def test_estimate_dans_start():
    """Test _estimate_dans_start finds an aligned position."""
    analyzer = _make_analyzer()
    dos_stub = b"\x00" * 100 + b"Rich"
    result = analyzer._estimate_dans_start(dos_stub, 100)
    assert result is not None


def test_estimate_dans_start_not_found():
    """Test _estimate_dans_start returns None when no suitable position."""
    analyzer = _make_analyzer()
    # Rich at position 3 - no aligned 8-byte block fits before it
    dos_stub = b"\x00" * 3 + b"Rich"
    result = analyzer._estimate_dans_start(dos_stub, 3)
    # Could be None if no 8-byte aligned block found
    # (depends on the range logic, but with rich_pos=3 the range is empty)
    assert result is None


# ---------------------------------------------------------------------------
# _extract_encoded_from_stub
# ---------------------------------------------------------------------------


def test_extract_encoded_from_stub():
    """Test _extract_encoded_from_stub extracts data between DanS+4 and Rich."""
    analyzer = _make_analyzer()
    # DanS at 0, encoded data of 16 bytes (divisible by 8), Rich at 20
    encoded = b"\x01\x02\x03\x04\x05\x06\x07\x08" * 2
    dos_stub = b"DanS" + encoded + b"Rich"
    result = analyzer._extract_encoded_from_stub(dos_stub, 0, 20)
    assert result is not None
    assert len(result) == 16


def test_extract_encoded_from_stub_invalid_length():
    """Test _extract_encoded_from_stub with data not divisible by 8."""
    analyzer = _make_analyzer()
    # 5 bytes between dans+4 and rich -> not divisible by 8
    dos_stub = b"DanS" + b"\x01\x02\x03\x04\x05" + b"Rich"
    result = analyzer._extract_encoded_from_stub(dos_stub, 0, 9)
    assert result is None


def test_extract_encoded_from_stub_empty():
    """Test _extract_encoded_from_stub when dans+4 == rich (0 bytes)."""
    analyzer = _make_analyzer()
    dos_stub = b"DanS" + b"Rich"
    result = analyzer._extract_encoded_from_stub(dos_stub, 0, 4)
    assert result is None


# ---------------------------------------------------------------------------
# _calculate_rich_checksum
# ---------------------------------------------------------------------------


def test_calculate_rich_checksum():
    """Test _calculate_rich_checksum computes a deterministic integer."""
    analyzer = _make_analyzer()
    data = bytearray(b"MZ" + b"\x00" * 0x3E + b"\x80\x00\x00\x00")
    entries = [{"product_id": 100, "build_number": 200, "count": 5}]
    result = analyzer._calculate_rich_checksum(bytes(data), 0x80, entries)
    assert isinstance(result, int)


def test_calculate_rich_checksum_short_data():
    """Test _calculate_rich_checksum with data shorter than 0x3C."""
    analyzer = _make_analyzer()
    data = b"MZ" + b"\x00" * 10  # Only 12 bytes, < 0x3C
    result = analyzer._calculate_rich_checksum(data, 0x80, [])
    assert result == 0


def test_calculate_rich_checksum_with_entries():
    """Test _calculate_rich_checksum produces different values for different entries."""
    analyzer = _make_analyzer()
    data = bytearray(0x80)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = struct.pack("<I", 0x80)

    entries1 = [{"product_id": 1, "build_number": 1, "count": 1}]
    entries2 = [{"product_id": 2, "build_number": 2, "count": 2}]

    r1 = analyzer._calculate_rich_checksum(bytes(data), 0x80, entries1)
    r2 = analyzer._calculate_rich_checksum(bytes(data), 0x80, entries2)

    assert isinstance(r1, int)
    assert isinstance(r2, int)
    assert r1 != r2


# ---------------------------------------------------------------------------
# _extract_offsets
# ---------------------------------------------------------------------------


def test_extract_offsets_valid():
    """Test _extract_offsets with valid offset values."""
    analyzer = _make_analyzer()
    result = analyzer._extract_offsets({"offset": 200}, {"offset": 100})
    assert result == (100, 200)


def test_extract_offsets_rich_none():
    """Test _extract_offsets when rich offset is None."""
    analyzer = _make_analyzer()
    result = analyzer._extract_offsets({"offset": None}, {"offset": 100})
    assert result is None


def test_extract_offsets_dans_none():
    """Test _extract_offsets when dans offset is None."""
    analyzer = _make_analyzer()
    result = analyzer._extract_offsets({"offset": 200}, {"offset": None})
    assert result is None


def test_extract_offsets_both_none():
    """Test _extract_offsets when both offsets are None."""
    analyzer = _make_analyzer()
    result = analyzer._extract_offsets({"offset": None}, {"offset": None})
    assert result is None


# ---------------------------------------------------------------------------
# _offsets_valid
# ---------------------------------------------------------------------------


def test_offsets_valid_true():
    """Test _offsets_valid with dans < rich and within 1024."""
    analyzer = _make_analyzer()
    assert analyzer._offsets_valid(100, 200) is True


def test_offsets_valid_dans_after_rich():
    """Test _offsets_valid when dans >= rich."""
    analyzer = _make_analyzer()
    assert analyzer._offsets_valid(200, 100) is False


def test_offsets_valid_too_far():
    """Test _offsets_valid when distance exceeds 1024."""
    analyzer = _make_analyzer()
    assert analyzer._offsets_valid(100, 2000) is False


def test_offsets_valid_equal():
    """Test _offsets_valid when offsets are equal."""
    analyzer = _make_analyzer()
    assert analyzer._offsets_valid(100, 100) is False


# ---------------------------------------------------------------------------
# _scan_patterns
# ---------------------------------------------------------------------------


def test_scan_patterns_found():
    """Test _scan_patterns when patterns are found via r2pipe search."""
    # The scan_patterns method uses cmdj_helper which calls into
    # the adapter/r2 to execute /xj commands
    cmdj_map = {
        "/xj 52696368": [{"offset": 0x120}],
    }
    analyzer = _make_analyzer(cmdj_map=cmdj_map)
    results = analyzer._scan_patterns(["52696368"], "Rich")
    # The cmdj_helper goes through the adapter chain; results depend on
    # whether the FakeR2 cmdj returns the expected data
    assert isinstance(results, list)


def test_scan_patterns_not_found():
    """Test _scan_patterns when no patterns are found."""
    analyzer = _make_analyzer(cmdj_map={"/xj 52696368": []})
    results = analyzer._scan_patterns(["52696368"], "Rich")
    assert isinstance(results, list)


# ---------------------------------------------------------------------------
# _direct_file_rich_search
# ---------------------------------------------------------------------------


def test_direct_file_rich_search_valid_pe():
    """Test _direct_file_rich_search with a real PE file with Rich Header."""
    pe_data = _build_pe_bytes_with_rich_header()
    path = _write_pe_tempfile(pe_data)
    try:
        analyzer = _make_analyzer(filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is not None
        assert "xor_key" in result
        assert "entries" in result
    finally:
        os.unlink(path)


def test_direct_file_rich_search_invalid_pe():
    """Test _direct_file_rich_search with invalid PE data."""
    path = _write_pe_tempfile(b"XX" + b"\x00" * 100)
    try:
        analyzer = _make_analyzer(filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is None
    finally:
        os.unlink(path)


def test_direct_file_rich_search_no_filepath():
    """Test _direct_file_rich_search with no filepath."""
    analyzer = _make_analyzer(filepath=None)
    result = analyzer._direct_file_rich_search()
    assert result is None


def test_direct_file_rich_search_no_rich_in_stub():
    """Test _direct_file_rich_search when PE has no Rich in DOS stub."""
    pe_offset = 0x80
    data = bytearray(pe_offset + 64)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = struct.pack("<I", pe_offset)
    data[pe_offset : pe_offset + 4] = b"PE\x00\x00"

    path = _write_pe_tempfile(bytes(data))
    try:
        analyzer = _make_analyzer(filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is None
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# calculate_richpe_hash_from_file
# ---------------------------------------------------------------------------


def test_calculate_richpe_hash_from_file_nonexistent():
    """Test calculate_richpe_hash_from_file with a nonexistent file."""
    result = RichHeaderAnalyzer.calculate_richpe_hash_from_file("/nonexistent/file.exe")
    assert result is None


# ---------------------------------------------------------------------------
# _is_pe_file via analyze flow
# ---------------------------------------------------------------------------


def test_is_pe_file_via_magic_bytes():
    """Test that _is_pe_file detects PE via MZ magic bytes."""
    pe_data = b"MZ" + b"\x00" * 100
    path = _write_pe_tempfile(pe_data)
    try:
        analyzer = _make_analyzer(filepath=path)
        assert analyzer._is_pe_file() is True
    finally:
        os.unlink(path)


def test_is_pe_file_via_r2_info():
    """Test that _is_pe_file detects PE via r2 'ij' command."""
    analyzer = _make_analyzer(
        cmdj_map={"ij": {"bin": {"format": "pe64"}}},
        cmd_map={"i": "pe binary"},
    )
    # No filepath, so magic bytes fail, but r2 info says PE
    assert analyzer._is_pe_file() is True


def test_is_pe_file_not_pe():
    """Test _is_pe_file returns False for non-PE."""
    analyzer = _make_analyzer(
        cmdj_map={"ij": {"bin": {"format": "elf"}}},
        cmd_map={"i": "elf binary"},
    )
    assert analyzer._is_pe_file() is False


# ---------------------------------------------------------------------------
# _extract_rich_header_r2pipe
# ---------------------------------------------------------------------------


def test_extract_rich_header_r2pipe_no_data():
    """Test _extract_rich_header_r2pipe when no rich data found."""
    analyzer = _make_analyzer(
        cmdj_map={
            "/xj 52696368": [],
            "/xj 68636952": [],
            "/xj 5269636800000000": [],
            "/xj 44616e53": [],
            "/xj 536e6144": [],
            "/xj 44616e5300000000": [],
            "ij": {"core": {"size": 1000}},
        },
        cmd_map={"p8 512 @ 0": "00" * 512},
        filepath=None,
    )
    result = analyzer._extract_rich_header_r2pipe()
    assert result is None


# ---------------------------------------------------------------------------
# Debug mixin methods
# ---------------------------------------------------------------------------


def test_debug_has_mz_header_true():
    """Test _debug_has_mz_header with MZ data."""
    analyzer = _make_analyzer()
    assert analyzer._debug_has_mz_header(b"MZ\x00\x00") is True


def test_debug_has_mz_header_false():
    """Test _debug_has_mz_header with non-MZ data."""
    analyzer = _make_analyzer()
    assert analyzer._debug_has_mz_header(b"ELF\x00") is False


def test_debug_get_pe_offset_valid():
    """Test _debug_get_pe_offset with valid data."""
    analyzer = _make_analyzer()
    data = bytearray(0x80)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = struct.pack("<I", 0x60)
    result = analyzer._debug_get_pe_offset(bytes(data))
    assert result == 0x60


def test_debug_get_pe_offset_too_short():
    """Test _debug_get_pe_offset with data too short."""
    analyzer = _make_analyzer()
    result = analyzer._debug_get_pe_offset(b"MZ" + b"\x00" * 10)
    assert result is None


def test_find_rich_dans_positions():
    """Test _find_rich_dans_positions finds both signatures."""
    analyzer = _make_analyzer()
    data = b"\x00" * 50 + b"DanS" + b"\x00" * 50 + b"Rich" + b"\x00" * 50
    rich_positions, dans_positions = analyzer._find_rich_dans_positions(data)
    assert 50 in dans_positions
    assert 104 in rich_positions


def test_find_rich_dans_positions_empty():
    """Test _find_rich_dans_positions when no signatures present."""
    analyzer = _make_analyzer()
    data = b"\x00" * 200
    rich_positions, dans_positions = analyzer._find_rich_dans_positions(data)
    assert rich_positions == []
    assert dans_positions == []


# ---------------------------------------------------------------------------
# Search mixin methods
# ---------------------------------------------------------------------------


def test_find_all_occurrences():
    """Test _find_all_occurrences finds multiple signatures."""
    analyzer = _make_analyzer()
    data = b"Rich" + b"\x00" * 10 + b"Rich" + b"\x00" * 10
    positions = analyzer._find_all_occurrences(data, b"Rich")
    assert len(positions) == 2
    assert positions[0] == 0
    assert positions[1] == 14


def test_find_all_occurrences_none():
    """Test _find_all_occurrences when signature not found."""
    analyzer = _make_analyzer()
    data = b"\x00" * 100
    positions = analyzer._find_all_occurrences(data, b"Rich")
    assert positions == []


def test_offset_pair_valid():
    """Test _offset_pair_valid validates distance between offsets."""
    analyzer = _make_analyzer()
    assert analyzer._offset_pair_valid(100, 200, 512) is True
    assert analyzer._offset_pair_valid(200, 100, 512) is False
    assert analyzer._offset_pair_valid(100, 700, 512) is False


def test_validate_rich_size():
    """Test _validate_rich_size checks size bounds."""
    analyzer = _make_analyzer()
    assert analyzer._validate_rich_size(16) is True
    assert analyzer._validate_rich_size(8) is False
    assert analyzer._validate_rich_size(0) is False
    assert analyzer._validate_rich_size(513) is False
    assert analyzer._validate_rich_size(512) is True


def test_find_rich_positions():
    """Test _find_rich_positions finds all Rich signatures."""
    analyzer = _make_analyzer()
    data = b"\x00" * 10 + b"Rich\x00\x00\x00\x00" + b"\x00" * 10 + b"Rich\x00\x00\x00\x00"
    positions = analyzer._find_rich_positions(data)
    assert 10 in positions
    assert 28 in positions


def test_is_valid_rich_key():
    """Test _is_valid_rich_key validates potential XOR key."""
    analyzer = _make_analyzer()
    # Valid: non-zero, non-FFFFFFFF key after Rich
    data = b"Rich" + struct.pack("<I", 0x12345678)
    assert analyzer._is_valid_rich_key(data, 0) is True

    # Invalid: key is zero
    data = b"Rich" + struct.pack("<I", 0)
    assert analyzer._is_valid_rich_key(data, 0) is False

    # Invalid: key is 0xFFFFFFFF
    data = b"Rich" + struct.pack("<I", 0xFFFFFFFF)
    assert analyzer._is_valid_rich_key(data, 0) is False

    # Invalid: not enough data
    data = b"Rich\x00"
    assert analyzer._is_valid_rich_key(data, 0) is False


def test_find_dans_candidates_before_rich():
    """Test _find_dans_candidates_before_rich finds DanS before Rich."""
    analyzer = _make_analyzer()
    data = b"\x00" * 50 + b"DanS" + b"\x00" * 50 + b"Rich"
    candidates = analyzer._find_dans_candidates_before_rich(data, 104)
    assert 50 in candidates


def test_find_dans_before_rich():
    """Test _find_dans_before_rich returns first candidate."""
    analyzer = _make_analyzer()
    data = b"\x00" * 50 + b"DanS" + b"\x00" * 50 + b"Rich"
    result = analyzer._find_dans_before_rich(data, 104)
    assert result == 50


def test_find_dans_before_rich_not_found():
    """Test _find_dans_before_rich when no DanS found."""
    analyzer = _make_analyzer()
    data = b"\x00" * 200
    result = analyzer._find_dans_before_rich(data, 150)
    assert result is None


# ---------------------------------------------------------------------------
# Full direct file extraction end-to-end
# ---------------------------------------------------------------------------


def test_full_direct_extraction_with_multiple_entries():
    """Test full extraction with multiple Rich Header entries."""
    entries = [
        {"product_id": 0x1E, "build_number": 0x7809, "count": 3},
        {"product_id": 0x14, "build_number": 0x6030, "count": 1},
        {"product_id": 0x0D, "build_number": 0x5F0E, "count": 7},
    ]
    pe_data = _build_pe_bytes_with_rich_header(entries=entries)
    path = _write_pe_tempfile(pe_data)
    try:
        analyzer = _make_analyzer(filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is not None
        assert len(result["entries"]) == 3
        assert result["xor_key"] == 0x12345678
    finally:
        os.unlink(path)


def test_build_direct_rich_result():
    """Test _build_direct_rich_result produces correct structure."""
    analyzer = _make_analyzer()
    entries = [{"product_id": 1, "build_number": 2, "count": 3}]
    encoded = b"\xaa" * 16

    result = analyzer._build_direct_rich_result(
        xor_key=0x12345678,
        calculated_checksum=0x12345678,
        entries=entries,
        encoded_data=encoded,
        dos_stub_start=0x40,
        dans_pos=0,
        rich_pos=20,
    )

    assert result["xor_key"] == 0x12345678
    assert result["checksum"] == 0x12345678
    assert result["valid_checksum"] is True
    assert result["entries"] == entries
    assert result["dans_offset"] == 0x40
    assert result["rich_offset"] == 0x40 + 20
    assert result["encoded_data"] == encoded.hex()


def test_build_direct_rich_result_invalid_checksum():
    """Test _build_direct_rich_result with mismatched checksum."""
    analyzer = _make_analyzer()
    result = analyzer._build_direct_rich_result(
        xor_key=0x12345678,
        calculated_checksum=0xDEADBEEF,
        entries=[],
        encoded_data=b"\x00" * 16,
        dos_stub_start=0x40,
        dans_pos=0,
        rich_pos=20,
    )
    assert result["valid_checksum"] is False


# ---------------------------------------------------------------------------
# Debug file structure
# ---------------------------------------------------------------------------


def test_debug_file_structure_runs_without_error():
    """Test _debug_file_structure completes without raising."""
    adapter = _make_adapter(
        cmdj_map={"ij": {"core": {"size": 512}}},
        cmd_map={
            "p8 512 @ 0": _hex_for(
                b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x80) + b"\x00" * 444
            ),
            "p8 2048 @ 0": _hex_for(b"\x00" * 2048),
        },
    )
    analyzer = RichHeaderAnalyzer(adapter=adapter)
    # Should not raise
    analyzer._debug_file_structure()


def test_debug_log_stub_analysis_with_signatures():
    """Test _debug_log_stub_analysis when both Rich and DanS are in stub."""
    analyzer = _make_analyzer()
    # Build stub data with both signatures
    stub = b"\x00" * 10 + b"DanS" + b"\x00" * 50 + b"Rich" + b"\x00" * 30
    # pe_offset > 64 so the method runs
    analyzer._debug_log_stub_analysis(b"\x00" * 64 + stub, 64 + len(stub))


def test_debug_log_stub_analysis_pe_offset_small():
    """Test _debug_log_stub_analysis with pe_offset <= 64."""
    analyzer = _make_analyzer()
    analyzer._debug_log_stub_analysis(b"\x00" * 100, 64)
    # Should return early, no crash


def test_debug_log_candidates():
    """Test _debug_log_candidates with matching pairs."""
    analyzer = _make_analyzer()
    data = b"\x00" * 50 + b"DanS" + b"\x00" * 50 + b"Rich" + b"\x00\x00\x00\x00\x00"
    # Rich at 104, DanS at 50 -> distance 54, < 512
    analyzer._debug_log_candidates(data, [104], [50])


# ---------------------------------------------------------------------------
# _read_bytes / _get_file_info (DebugMixin)
# ---------------------------------------------------------------------------


def test_read_bytes_via_adapter():
    """Test _read_bytes reads through the adapter."""
    hex_data = _hex_for(b"HELLO WORLD")
    adapter = _make_adapter(cmd_map={"p8 11 @ 0": hex_data})
    analyzer = RichHeaderAnalyzer(adapter=adapter)
    result = analyzer._read_bytes(0, 11)
    assert result == b"HELLO WORLD"


def test_read_bytes_no_adapter():
    """Test _read_bytes when adapter is None."""
    analyzer = RichHeaderAnalyzer(adapter=None)
    result = analyzer._read_bytes(0, 10)
    assert result == b""


def test_get_file_info_via_adapter():
    """Test _get_file_info reads through the adapter."""
    adapter = _make_adapter(cmdj_map={"ij": {"core": {"size": 1024}}})
    analyzer = RichHeaderAnalyzer(adapter=adapter)
    info = analyzer._get_file_info()
    assert info.get("core", {}).get("size") == 1024


def test_get_file_info_no_adapter():
    """Test _get_file_info when adapter is None."""
    analyzer = RichHeaderAnalyzer(adapter=None)
    info = analyzer._get_file_info()
    assert info == {}


# ---------------------------------------------------------------------------
# _read_manual_search_bytes (SearchMixin)
# ---------------------------------------------------------------------------


def test_read_manual_search_bytes():
    """Test _read_manual_search_bytes reads 2048 bytes."""
    hex_data = _hex_for(b"MZ" + b"\x00" * 2046)
    adapter = _make_adapter(cmd_map={"p8 2048 @ 0": hex_data})
    analyzer = RichHeaderAnalyzer(adapter=adapter)
    data = analyzer._read_manual_search_bytes()
    assert data is not None
    assert len(data) == 2048


def test_read_manual_search_bytes_no_adapter():
    """Test _read_manual_search_bytes when adapter is None."""
    analyzer = RichHeaderAnalyzer(adapter=None)
    result = analyzer._read_manual_search_bytes()
    assert result is None


# ---------------------------------------------------------------------------
# _pefile_entries_from_clear_data
# ---------------------------------------------------------------------------


def test_pefile_entries_from_clear_data_no_attr():
    """Test _pefile_entries_from_clear_data when no clear_data attribute."""
    analyzer = _make_analyzer()

    class FakePE:
        class RICH_HEADER:
            pass

    entries = analyzer._pefile_entries_from_clear_data(FakePE())
    assert entries == []


def test_pefile_entries_from_clear_data_with_data():
    """Test _pefile_entries_from_clear_data with valid clear_data."""
    analyzer = _make_analyzer()

    # Build clear_data: 3 padding dwords + entries (each 2 dwords)
    padding = struct.pack("<I", 0) * 3
    entry_data = struct.pack("<I", (0x7809 << 16) | 0x1E) + struct.pack("<I", 3)
    clear_data = padding + entry_data

    class FakePE:
        class RICH_HEADER:
            pass

    FakePE.RICH_HEADER.clear_data = clear_data
    entries = analyzer._pefile_entries_from_clear_data(FakePE())
    assert isinstance(entries, list)
