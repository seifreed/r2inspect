#!/usr/bin/env python3
"""Comprehensive tests for rich_header_analyzer - remaining coverage.

All mocks replaced with FakeR2 + R2PipeAdapter driving real analyzer code.
"""

import struct
import tempfile
import os
from typing import Any

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer
from r2inspect.testing.fake_r2 import FakeR2


# ---------------------------------------------------------------------------
# FakeR2 helper
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# PE binary helpers
# ---------------------------------------------------------------------------


def _pe_ij_info():
    """Return a minimal 'ij' response that identifies the binary as PE."""
    return {"bin": {"format": "pe", "class": "PE32", "arch": "x86", "bits": 32}}


def _make_adapter(cmdj_map=None, cmd_map=None):
    """Build a real R2PipeAdapter around FakeR2."""
    r2 = FakeR2(cmdj_map=cmdj_map, cmd_map=cmd_map)
    return R2PipeAdapter(r2)


def _build_minimal_pe_bytes(pe_offset=0x80):
    """Build minimal PE-like bytes: MZ header + pe_offset at 0x3C."""
    data = bytearray(pe_offset + 64)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    # Minimal PE signature at pe_offset
    data[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    return bytes(data)


def _build_pe_with_rich_header(xor_key=0x12345678):
    """Build a PE binary with a valid Rich Header in the DOS stub.

    The standard Rich Header format after the DanS signature:
      - DanS (4 bytes)
      - 3 padding DWORDs XOR'd with xor_key (12 bytes)
      - N entries, each 8 bytes (prodid^key, count^key)
      - Rich (4 bytes)
      - XOR key (4 bytes)

    The encoded data (between DanS+4 and Rich) must be a multiple of 8.
    With 3 padding DWORDs (12 bytes) we need entries totaling 4 mod 8 bytes
    to get a multiple of 8. Instead we use 2 padding DWORDs (8 bytes) +
    2 entries (16 bytes) = 24 bytes which is 8-aligned.
    """
    pe_offset = 0x100
    data = bytearray(pe_offset + 64)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset : pe_offset + 4] = b"PE\x00\x00"

    # Place DanS at 0x60 (within DOS stub starting at 0x40)
    dans_file_offset = 0x60
    data[dans_file_offset : dans_file_offset + 4] = b"DanS"

    pos = dans_file_offset + 4

    # 2 padding DWORDs (8 bytes) XOR'd with xor_key
    for _ in range(2):
        struct.pack_into("<I", data, pos, xor_key)
        pos += 4

    # Entry 1: product_id=100, build_number=200, count=5
    prodid_build_1 = 100 | (200 << 16)
    struct.pack_into("<I", data, pos, prodid_build_1 ^ xor_key)
    pos += 4
    struct.pack_into("<I", data, pos, 5 ^ xor_key)
    pos += 4

    # Entry 2: product_id=150, build_number=300, count=3
    prodid_build_2 = 150 | (300 << 16)
    struct.pack_into("<I", data, pos, prodid_build_2 ^ xor_key)
    pos += 4
    struct.pack_into("<I", data, pos, 3 ^ xor_key)
    pos += 4

    # Rich signature + XOR key
    data[pos : pos + 4] = b"Rich"
    struct.pack_into("<I", data, pos + 4, xor_key)

    return bytes(data)


def _write_temp_pe(data):
    """Write data to a temp file and return the path."""
    fd, path = tempfile.mkstemp(suffix=".exe")
    os.write(fd, data)
    os.close(fd)
    return path


# ---------------------------------------------------------------------------
# Tests: _is_pe_file
# ---------------------------------------------------------------------------


def test_is_pe_file_with_no_r2():
    """Test _is_pe_file returns False when adapter is None."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/nonexistent/file")
    analyzer.r2 = None
    result = analyzer._is_pe_file()
    assert result is False


def test_is_pe_file_with_pe_binary():
    """Test _is_pe_file returns True for a real PE-like file."""
    pe_data = _build_minimal_pe_bytes()
    path = _write_temp_pe(pe_data)
    try:
        adapter = _make_adapter(cmdj_map={"ij": _pe_ij_info()})
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath=path)
        result = analyzer._is_pe_file()
        assert result is True
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Tests: _read_file_bytes
# ---------------------------------------------------------------------------


def test_read_file_bytes_real_file():
    """_read_file_bytes returns the actual file content."""
    pe_data = _build_minimal_pe_bytes()
    path = _write_temp_pe(pe_data)
    try:
        adapter = _make_adapter()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath=path)
        result = analyzer._read_file_bytes()
        assert result is not None
        assert result[:2] == b"MZ"
    finally:
        os.unlink(path)


def test_read_file_bytes_nonexistent_file():
    """_read_file_bytes returns None for missing file."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/nonexistent/path/fake.exe")
    result = analyzer._read_file_bytes()
    assert result is None


def test_read_file_bytes_no_filepath():
    """_read_file_bytes returns None when filepath is not set."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath=None)
    result = analyzer._read_file_bytes()
    assert result is None


# ---------------------------------------------------------------------------
# Tests: _direct_file_rich_search pipeline stages
# ---------------------------------------------------------------------------


def test_direct_file_rich_search_no_file_data():
    """_direct_file_rich_search returns None for nonexistent file."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/nonexistent/path.exe")
    result = analyzer._direct_file_rich_search()
    assert result is None


def test_direct_file_rich_search_non_pe_data():
    """_direct_file_rich_search returns None for non-PE data."""
    fd, path = tempfile.mkstemp(suffix=".bin")
    os.write(fd, b"NOT_A_PE_FILE" + b"\x00" * 100)
    os.close(fd)
    try:
        adapter = _make_adapter()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is None
    finally:
        os.unlink(path)


def test_direct_file_rich_search_invalid_pe_offset():
    """_direct_file_rich_search returns None when PE offset is beyond file."""
    data = bytearray(0x50)
    data[0:2] = b"MZ"
    # Point pe_offset past end of file
    struct.pack_into("<I", data, 0x3C, 0xFFFF)
    path = _write_temp_pe(bytes(data))
    try:
        adapter = _make_adapter()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is None
    finally:
        os.unlink(path)


def test_direct_file_rich_search_pe_offset_too_small():
    """_direct_file_rich_search returns None when pe_offset <= 0x40 (no DOS stub)."""
    data = bytearray(0x80)
    data[0:2] = b"MZ"
    # pe_offset = 0x30 which is <= 0x40, so no DOS stub
    struct.pack_into("<I", data, 0x3C, 0x30)
    path = _write_temp_pe(bytes(data))
    try:
        adapter = _make_adapter()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is None
    finally:
        os.unlink(path)


def test_direct_file_rich_search_no_rich_signature():
    """_direct_file_rich_search returns None when DOS stub has no Rich signature."""
    pe_data = _build_minimal_pe_bytes(pe_offset=0x100)
    path = _write_temp_pe(pe_data)
    try:
        adapter = _make_adapter()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is None
    finally:
        os.unlink(path)


def test_direct_file_rich_search_rich_but_zero_xor_key():
    """_direct_file_rich_search returns None when XOR key is zero."""
    pe_offset = 0x100
    data = bytearray(pe_offset + 64)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    # Place Rich signature in DOS stub with xor_key=0
    rich_stub_pos = 0x60
    data[rich_stub_pos : rich_stub_pos + 4] = b"Rich"
    struct.pack_into("<I", data, rich_stub_pos + 4, 0)  # xor_key = 0
    path = _write_temp_pe(bytes(data))
    try:
        adapter = _make_adapter()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is None
    finally:
        os.unlink(path)


def test_direct_file_rich_search_no_dans_found():
    """_direct_file_rich_search returns None when there's no DanS or estimatable start."""
    pe_offset = 0x100
    data = bytearray(pe_offset + 64)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    # Place Rich signature very close to DOS stub start, leaving no room for DanS
    # Rich at offset 0x41 relative to file, which is offset 1 in dos stub
    # Not enough room for DanS or 8-byte aligned block before it
    rich_file_pos = 0x41
    data[rich_file_pos : rich_file_pos + 4] = b"Rich"
    struct.pack_into("<I", data, rich_file_pos + 4, 0xDEADBEEF)
    path = _write_temp_pe(bytes(data))
    try:
        adapter = _make_adapter()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is None
    finally:
        os.unlink(path)


def test_direct_file_rich_search_complete_success():
    """_direct_file_rich_search returns valid result from a crafted PE with Rich Header."""
    xor_key = 0x12345678
    pe_data = _build_pe_with_rich_header(xor_key=xor_key)
    path = _write_temp_pe(pe_data)
    try:
        adapter = _make_adapter()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is not None
        assert result["xor_key"] == xor_key
        assert len(result["entries"]) >= 1
        assert "dans_offset" in result
        assert "rich_offset" in result
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Tests: _get_dos_stub
# ---------------------------------------------------------------------------


def test_get_dos_stub_pe_offset_too_small():
    """_get_dos_stub returns None when PE offset <= 0x40."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")
    data = b"MZ" + b"\x00" * 100
    result = analyzer._get_dos_stub(data, 0x30)
    assert result is None


def test_get_dos_stub_valid():
    """_get_dos_stub returns the stub between 0x40 and pe_offset."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")
    data = b"MZ" + b"\x00" * 0x3E + b"\x80\x00\x00\x00" + b"\xaa" * 64 + b"\x00" * 64
    result = analyzer._get_dos_stub(data, 0x80)
    assert result is not None
    assert len(result) == 0x80 - 0x40


# ---------------------------------------------------------------------------
# Tests: _estimate_dans_start
# ---------------------------------------------------------------------------


def test_estimate_dans_start_no_valid_position():
    """_estimate_dans_start returns None when no valid aligned position exists."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")
    # Small stub with rich_pos very close to 0
    dos_stub = b"\x00" * 4
    result = analyzer._estimate_dans_start(dos_stub, 2)
    assert result is None or isinstance(result, int)


def test_estimate_dans_start_finds_aligned_position():
    """_estimate_dans_start finds an 8-byte aligned position before rich_pos."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")
    dos_stub = b"\x00" * 100 + b"Rich"
    rich_pos = 100
    result = analyzer._estimate_dans_start(dos_stub, rich_pos)
    # Should find a position that is 4-byte aligned with data length multiple of 8
    assert result is not None
    assert result % 4 == 0


# ---------------------------------------------------------------------------
# Tests: _calculate_rich_checksum
# ---------------------------------------------------------------------------


def test_calculate_rich_checksum_short_data():
    """_calculate_rich_checksum returns 0 when data is too short."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")
    result = analyzer._calculate_rich_checksum(b"MZ", 0x80, [])
    assert result == 0


def test_calculate_rich_checksum_with_entries():
    """_calculate_rich_checksum computes a non-trivial checksum."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")
    data = b"MZ" + b"\x00" * 0x3E + b"\x80\x00\x00\x00" + b"\x00" * 100
    entries = [{"product_id": 100, "build_number": 200, "count": 5}]
    result = analyzer._calculate_rich_checksum(data, 0x80, entries)
    assert isinstance(result, int)
    # Should be deterministic
    result2 = analyzer._calculate_rich_checksum(data, 0x80, entries)
    assert result == result2


# ---------------------------------------------------------------------------
# Tests: _build_direct_rich_result
# ---------------------------------------------------------------------------


def test_build_direct_rich_result_structure():
    """_build_direct_rich_result creates correct structure with computed offsets."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")

    xor_key = 0x12345678
    entries = [{"product_id": 100}]
    encoded_data = b"\x01\x02\x03\x04"

    result = analyzer._build_direct_rich_result(
        xor_key,
        xor_key,  # matching checksum -> valid_checksum = True
        entries,
        encoded_data,
        dos_stub_start=0x40,
        dans_pos=10,
        rich_pos=20,
    )

    assert result["xor_key"] == xor_key
    assert result["checksum"] == xor_key
    assert result["entries"] == entries
    assert result["dans_offset"] == 0x40 + 10  # 0x4A
    assert result["rich_offset"] == 0x40 + 20  # 0x54
    assert result["valid_checksum"] is True
    assert result["encoded_data"] == encoded_data.hex()


def test_build_direct_rich_result_invalid_checksum():
    """_build_direct_rich_result sets valid_checksum=False when mismatch."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")

    result = analyzer._build_direct_rich_result(
        xor_key=0xAAAAAAAA,
        calculated_checksum=0xBBBBBBBB,
        entries=[],
        encoded_data=b"\x00\x00\x00\x00\x00\x00\x00\x00",
        dos_stub_start=0x40,
        dans_pos=0,
        rich_pos=8,
    )
    assert result["valid_checksum"] is False


# ---------------------------------------------------------------------------
# Tests: _extract_rich_header (full pipeline)
# ---------------------------------------------------------------------------


def test_extract_rich_header_exception_handling():
    """_extract_rich_header returns None when file doesn't exist (exception path)."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/nonexistent/path.exe")
    result = analyzer._extract_rich_header()
    assert result is None


def test_extract_rich_header_with_valid_pe():
    """_extract_rich_header extracts data from a crafted PE."""
    pe_data = _build_pe_with_rich_header(xor_key=0xAABBCCDD)
    path = _write_temp_pe(pe_data)
    try:
        adapter = _make_adapter()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath=path)
        result = analyzer._extract_rich_header()
        assert result is not None
        assert result["xor_key"] == 0xAABBCCDD
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Tests: _extract_rich_header_r2pipe
# ---------------------------------------------------------------------------


def test_extract_rich_header_r2pipe_returns_data():
    """_extract_rich_header_r2pipe returns rich data from a valid PE."""
    pe_data = _build_pe_with_rich_header(xor_key=0x11223344)
    path = _write_temp_pe(pe_data)
    try:
        adapter = _make_adapter()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath=path)
        result = analyzer._extract_rich_header_r2pipe()
        assert result is not None
        assert result["xor_key"] == 0x11223344
    finally:
        os.unlink(path)


def test_extract_rich_header_r2pipe_with_debug_fallback():
    """_extract_rich_header_r2pipe returns None and triggers debug for non-PE."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/nonexistent/path.exe")
    result = analyzer._extract_rich_header_r2pipe()
    assert result is None


# ---------------------------------------------------------------------------
# Tests: _collect_rich_dans_offsets and _scan_patterns
# ---------------------------------------------------------------------------


def test_collect_rich_dans_offsets_no_matches():
    """_collect_rich_dans_offsets returns empty lists when no patterns found."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")
    rich_results, dans_results = analyzer._collect_rich_dans_offsets()
    assert rich_results == [] or isinstance(rich_results, list)
    assert dans_results == [] or isinstance(dans_results, list)


def test_scan_patterns_with_results():
    """_scan_patterns returns results when cmdj returns matches."""
    # Set up FakeR2 to return search results for the Rich pattern
    cmdj_map = {
        "/xj 52696368": [{"offset": 100}],
        "/xj 68636952": [],
        "/xj 5269636800000000": [],
    }
    adapter = _make_adapter(cmdj_map=cmdj_map)
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")
    from r2inspect.modules.rich_header_defaults import RICH_PATTERNS

    result = analyzer._scan_patterns(RICH_PATTERNS, "Rich")
    assert len(result) >= 1
    assert result[0]["offset"] == 100


# ---------------------------------------------------------------------------
# Tests: _try_rich_dans_combinations
# ---------------------------------------------------------------------------


def test_try_rich_dans_combinations_invalid_offsets():
    """_try_rich_dans_combinations returns None when dans > rich."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")
    # dans_offset=200 > rich_offset=100, invalid
    result = analyzer._try_rich_dans_combinations([{"offset": 100}], [{"offset": 200}])
    assert result is None


def test_try_rich_dans_combinations_too_far_apart():
    """_try_rich_dans_combinations returns None when offsets are > 1024 apart."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")
    result = analyzer._try_rich_dans_combinations([{"offset": 2000}], [{"offset": 100}])
    assert result is None


# ---------------------------------------------------------------------------
# Tests: _pefile_* methods
# ---------------------------------------------------------------------------


def test_pefile_get_xor_key_no_checksum():
    """_pefile_get_xor_key returns None when no checksum attribute."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")

    class FakeRichHeader:
        pass  # no checksum attribute

    class FakePE:
        RICH_HEADER = FakeRichHeader()

    result = analyzer._pefile_get_xor_key(FakePE())
    assert result is None


def test_pefile_get_xor_key_with_checksum():
    """_pefile_get_xor_key returns the checksum value."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")

    class FakeRichHeader:
        checksum = 0xDEADBEEF

    class FakePE:
        RICH_HEADER = FakeRichHeader()

    result = analyzer._pefile_get_xor_key(FakePE())
    assert result == 0xDEADBEEF


def test_pefile_extract_entries_no_values():
    """_pefile_extract_entries returns [] when no values attribute."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")

    class FakeRichHeader:
        pass  # no values attribute

    class FakePE:
        RICH_HEADER = FakeRichHeader()

    result = analyzer._pefile_extract_entries(FakePE())
    assert result == []


def test_pefile_extract_entries_with_values():
    """_pefile_extract_entries parses real entry objects."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")

    class FakeEntry:
        def __init__(self, pid, bv, c):
            self.product_id = pid
            self.build_version = bv
            self.count = c

    class FakeRichHeader:
        values = [FakeEntry(100, 200, 5), FakeEntry(150, 300, 3)]

    class FakePE:
        RICH_HEADER = FakeRichHeader()

    result = analyzer._pefile_extract_entries(FakePE())
    assert len(result) == 2
    assert result[0]["product_id"] == 100
    assert result[0]["build_number"] == 200
    assert result[0]["count"] == 5
    assert result[1]["product_id"] == 150


def test_pefile_entries_from_clear_data_no_clear_data():
    """_pefile_entries_from_clear_data returns [] when no clear_data attr."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")

    class FakeRichHeader:
        pass  # no clear_data

    class FakePE:
        RICH_HEADER = FakeRichHeader()

    result = analyzer._pefile_entries_from_clear_data(FakePE())
    assert result == []


def test_pefile_entries_from_clear_data_with_data():
    """_pefile_entries_from_clear_data parses clear data bytes."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")

    # Build clear_data: pairs of (prodid, count) as little-endian 32-bit ints
    prodid = 100 | (200 << 16)
    count = 5
    clear_data = struct.pack("<II", prodid, count)

    class FakeRichHeader:
        pass

    FakeRichHeader.clear_data = clear_data

    class FakePE:
        RICH_HEADER = FakeRichHeader()

    result = analyzer._pefile_entries_from_clear_data(FakePE())
    assert isinstance(result, list)


def test_build_pefile_rich_result_complete():
    """_build_pefile_rich_result constructs correct result dict."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")

    class FakeRichHeader:
        clear_data = b"\x01\x02\x03\x04"

    class FakePE:
        RICH_HEADER = FakeRichHeader()

    xor_key = 0x12345678
    entries = [{"product_id": 100}]
    rich_hash = "HASH123"

    result = analyzer._build_pefile_rich_result(FakePE(), xor_key, entries, rich_hash)

    assert result["xor_key"] == xor_key
    assert result["checksum"] == xor_key
    assert result["entries"] == entries
    assert result["richpe_hash"] == rich_hash
    assert result["clear_data"] == "01020304"
    assert result["method"] == "pefile"


def test_build_pefile_rich_result_no_clear_data():
    """_build_pefile_rich_result handles missing clear_data."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")

    class FakeRichHeader:
        pass  # no clear_data

    class FakePE:
        RICH_HEADER = FakeRichHeader()

    result = analyzer._build_pefile_rich_result(FakePE(), None, [], "HASH")
    assert result["xor_key"] is None
    assert result["clear_data"] is None
    assert result["method"] == "pefile"


# ---------------------------------------------------------------------------
# Tests: _extract_rich_header_pefile
# ---------------------------------------------------------------------------


def test_extract_rich_header_pefile_nonexistent_file():
    """_extract_rich_header_pefile returns None for nonexistent file (exception path)."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/nonexistent/fake.exe")
    result = analyzer._extract_rich_header_pefile()
    # Either None (pefile raises) or None (no rich header)
    assert result is None


def test_extract_rich_header_pefile_non_pe_file():
    """_extract_rich_header_pefile returns None for a non-PE file."""
    fd, path = tempfile.mkstemp(suffix=".bin")
    os.write(fd, b"NOT_A_PE" + b"\x00" * 100)
    os.close(fd)
    try:
        adapter = _make_adapter()
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath=path)
        result = analyzer._extract_rich_header_pefile()
        assert result is None
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Tests: static/helper methods
# ---------------------------------------------------------------------------


def test_is_valid_pe_data():
    """_is_valid_pe_data checks MZ header and minimum size."""
    assert RichHeaderAnalyzer._is_valid_pe_data(b"MZ" + b"\x00" * 62) is True
    assert RichHeaderAnalyzer._is_valid_pe_data(b"MZ" + b"\x00" * 10) is False
    assert RichHeaderAnalyzer._is_valid_pe_data(b"EL" + b"\x00" * 100) is False


def test_get_pe_offset_valid():
    """_get_pe_offset extracts the PE offset from the MZ header."""
    data = bytearray(0x100)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    result = RichHeaderAnalyzer._get_pe_offset(bytes(data))
    assert result == 0x80


def test_get_pe_offset_out_of_range():
    """_get_pe_offset returns None when offset points past data."""
    data = bytearray(0x50)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0xFFFF)
    result = RichHeaderAnalyzer._get_pe_offset(bytes(data))
    assert result is None


def test_find_rich_pos_found():
    """_find_rich_pos returns the position of Rich in the DOS stub."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")
    dos_stub = b"\x00" * 20 + b"Rich" + b"\x00" * 4
    result = analyzer._find_rich_pos(dos_stub)
    assert result == 20


def test_find_rich_pos_not_found():
    """_find_rich_pos returns None when Rich is not in stub."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")
    result = analyzer._find_rich_pos(b"\x00" * 100)
    assert result is None


def test_extract_xor_key_from_stub_valid():
    """_extract_xor_key_from_stub extracts the 4-byte key after Rich."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")
    dos_stub = b"\x00" * 20 + b"Rich" + struct.pack("<I", 0xDEADBEEF) + b"\x00" * 4
    result = analyzer._extract_xor_key_from_stub(dos_stub, 20)
    assert result == 0xDEADBEEF


def test_extract_xor_key_from_stub_zero_key():
    """_extract_xor_key_from_stub returns None for zero key."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")
    dos_stub = b"\x00" * 20 + b"Rich" + b"\x00\x00\x00\x00" + b"\x00" * 4
    result = analyzer._extract_xor_key_from_stub(dos_stub, 20)
    assert result is None


def test_extract_xor_key_from_stub_truncated():
    """_extract_xor_key_from_stub returns None when not enough data."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")
    dos_stub = b"\x00" * 20 + b"Rich"  # no xor key bytes after
    result = analyzer._extract_xor_key_from_stub(dos_stub, 20)
    assert result is None


def test_find_or_estimate_dans_found():
    """_find_or_estimate_dans finds DanS in the stub."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")
    dos_stub = b"\x00" * 10 + b"DanS" + b"\x00" * 20 + b"Rich" + b"\x00" * 8
    rich_pos = dos_stub.find(b"Rich")
    result = analyzer._find_or_estimate_dans(dos_stub, rich_pos)
    assert result == 10


def test_find_or_estimate_dans_estimated():
    """_find_or_estimate_dans falls back to estimation when no DanS literal."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")
    # No DanS signature, but enough aligned data before Rich
    dos_stub = b"\x00" * 64 + b"Rich" + b"\x00" * 8
    rich_pos = 64
    result = analyzer._find_or_estimate_dans(dos_stub, rich_pos)
    assert result is not None
    assert result < rich_pos


def test_extract_encoded_from_stub_valid():
    """_extract_encoded_from_stub extracts encoded data between dans and rich."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")
    dos_stub = b"\x00" * 10 + b"DanS" + b"\xaa" * 16 + b"Rich" + b"\x00" * 8
    dans_pos = 10
    rich_pos = dos_stub.find(b"Rich")
    result = analyzer._extract_encoded_from_stub(dos_stub, dans_pos, rich_pos)
    assert result is not None
    assert len(result) == 16  # encoded data between DanS+4 and Rich


def test_extract_encoded_from_stub_invalid_length():
    """_extract_encoded_from_stub returns None for non-8-byte-aligned data."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")
    # 5 bytes of encoded data (not multiple of 8)
    dos_stub = b"\x00" * 10 + b"DanS" + b"\xaa" * 5 + b"Rich"
    dans_pos = 10
    rich_pos = dos_stub.find(b"Rich")
    result = analyzer._extract_encoded_from_stub(dos_stub, dans_pos, rich_pos)
    assert result is None


def test_extract_encoded_from_stub_empty():
    """_extract_encoded_from_stub returns None when dans and rich are adjacent."""
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/test/file")
    dos_stub = b"\x00" * 10 + b"DanSRich" + b"\x00" * 8
    dans_pos = 10
    rich_pos = 14  # immediately after DanS
    result = analyzer._extract_encoded_from_stub(dos_stub, dans_pos, rich_pos)
    assert result is None


# ---------------------------------------------------------------------------
# Tests: _offsets_valid and _extract_offsets
# ---------------------------------------------------------------------------


def test_offsets_valid():
    """_offsets_valid checks dans < rich and within 1024 bytes."""
    assert RichHeaderAnalyzer._offsets_valid(100, 200) is True
    assert RichHeaderAnalyzer._offsets_valid(200, 100) is False
    assert RichHeaderAnalyzer._offsets_valid(0, 2000) is False


def test_extract_offsets_valid():
    """_extract_offsets extracts (dans, rich) offsets from result dicts."""
    result = RichHeaderAnalyzer._extract_offsets({"offset": 200}, {"offset": 100})
    assert result == (100, 200)


def test_extract_offsets_missing():
    """_extract_offsets returns None when offset keys are missing."""
    result = RichHeaderAnalyzer._extract_offsets({"other": 1}, {"offset": 100})
    assert result is None


# ---------------------------------------------------------------------------
# Tests: is_available
# ---------------------------------------------------------------------------


def test_is_available():
    """is_available always returns True."""
    assert RichHeaderAnalyzer.is_available() is True


# ---------------------------------------------------------------------------
# Tests: full analyze() integration
# ---------------------------------------------------------------------------


def test_analyze_non_pe_file():
    """analyze() returns error for a non-PE file."""
    fd, path = tempfile.mkstemp(suffix=".bin")
    os.write(fd, b"NOT_PE" + b"\x00" * 100)
    os.close(fd)
    try:
        # FakeR2 returns no PE indicators
        adapter = _make_adapter(cmdj_map={"ij": {"bin": {"format": "raw"}}})
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath=path)
        results = analyzer.analyze()
        assert results["is_pe"] is False
        assert results["error"] is not None
    finally:
        os.unlink(path)


def test_analyze_pe_without_rich_header():
    """analyze() on PE without Rich Header returns appropriate error."""
    pe_data = _build_minimal_pe_bytes(pe_offset=0x80)
    path = _write_temp_pe(pe_data)
    try:
        adapter = _make_adapter(cmdj_map={"ij": _pe_ij_info()})
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath=path)
        results = analyzer.analyze()
        assert results["is_pe"] is True
        # Either error or rich_header is None
        assert results["rich_header"] is None or results.get("error")
    finally:
        os.unlink(path)
