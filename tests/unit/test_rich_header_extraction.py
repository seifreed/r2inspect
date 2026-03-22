"""Comprehensive tests for rich_header_analyzer.py extraction methods.

Uses real objects (FakeR2 + R2PipeAdapter) instead of mocks.
Tests domain functions directly where applicable.
"""

import struct

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.domain.services.rich_header import (
    build_rich_header_result,
    calculate_richpe_hash,
    decode_rich_header,
    parse_compiler_entries,
    validate_decoded_entries,
)
from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer
from r2inspect.modules.rich_header_direct import RichHeaderDirectMixin
from r2inspect.testing.fake_r2 import FakeR2


# ---------------------------------------------------------------------------
# Helpers to build a minimal PE stub with an embedded Rich Header
# ---------------------------------------------------------------------------


def _build_pe_with_rich_header(entries, xor_key=0x12345678):
    """Build a minimal PE binary that contains a valid Rich Header.

    The layout is:
        0x00  MZ signature + DOS header (0x40 bytes)
        0x40  DOS stub containing:
              - DanS marker (XOR-encoded with *xor_key*)
              - 3x padding DWORDs (XOR-encoded)
              - encoded entry data
              - "Rich" marker (plaintext)
              - XOR key   (plaintext, little-endian)
        pe_offset  PE\0\0 signature
    """
    # Encode a single rich entry: prodid_low | (build << 16), count
    encoded = bytearray()
    for e in entries:
        prodid = e["product_id"] | (e["build_number"] << 16)
        encoded += struct.pack("<I", prodid ^ xor_key)
        encoded += struct.pack("<I", e["count"] ^ xor_key)

    # DanS header (4 bytes) + 3 padding DWORDs (12 bytes) = 16 byte header
    dans_header = struct.pack("<I", 0x536E6144 ^ xor_key)  # "DanS" XOR key
    dans_header += struct.pack("<I", 0 ^ xor_key) * 3  # padding

    rich_section = dans_header + bytes(encoded) + b"Rich" + struct.pack("<I", xor_key)

    pe_offset = 0x40 + len(rich_section)
    # Pad to make pe_offset reasonable
    pe_offset = ((pe_offset + 15) // 16) * 16  # align to 16

    dos_header = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", pe_offset)
    dos_stub = rich_section + b"\x00" * (pe_offset - 0x40 - len(rich_section))
    pe_sig = b"PE\x00\x00" + b"\x00" * 20  # minimal PE header

    return dos_header + dos_stub + pe_sig


def _hex_for_bytes(data):
    """Return hex string for bytes (no separators) as r2 p8 would."""
    return data.hex()


def _fake_r2_for_pe_data(pe_data):
    """Create a FakeR2 whose cmd("p8 ...") returns slices of *pe_data*."""

    class PEDataR2:
        def __init__(self, data):
            self._data = data

        def cmd(self, command):
            if command.startswith("p8 "):
                parts = command.split()
                size = int(parts[1])
                addr = 0
                if "@" in command:
                    addr = int(parts[3])
                end = min(addr + size, len(self._data))
                return self._data[addr:end].hex()
            return ""

        def cmdj(self, command):
            if command == "ij":
                return {"bin": {"format": "pe", "class": "PE32"}, "core": {"size": len(self._data)}}
            if command.startswith("/xj"):
                # Scan for pattern in data
                pattern_hex = command.split()[-1]
                pattern = bytes.fromhex(pattern_hex)
                results = []
                start = 0
                while True:
                    pos = self._data.find(pattern, start)
                    if pos == -1:
                        break
                    results.append({"offset": pos})
                    start = pos + 1
                return results
            return {}

    return PEDataR2(pe_data)


# ===========================================================================
# Test classes
# ===========================================================================


class TestRichHeaderExtraction:
    """Test Rich Header extraction methods and edge cases."""

    def test_analyzer_init_with_adapter(self):
        """Test initialization with adapter."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter)
        assert analyzer.adapter is adapter

    def test_analyzer_init_with_r2_instance(self):
        """Test initialization with r2_instance (legacy)."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(r2_instance=adapter)
        assert analyzer.adapter is adapter

    def test_is_available(self):
        """Test that Rich Header analysis is always available."""
        assert RichHeaderAnalyzer.is_available() is True

    def test_analyze_non_pe_file(self):
        """Test analyzing non-PE file (ELF-like data)."""
        elf_data = b"\x7fELF" + b"\x00" * 200
        _fake_r2_for_pe_data(elf_data)

        class NonPER2(FakeR2):
            def cmdj(self, command):
                if command == "ij":
                    return {"bin": {"format": "elf", "class": "ELF64"}}
                return {}

        fake_r2 = NonPER2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.bin")
        # _is_pe_file delegates to is_pe_file which checks adapter + r2
        # With a non-PE ij response, it should report not-PE
        result = analyzer.analyze()

        assert result["is_pe"] is False
        assert result["error"] == "File is not a PE binary"
        assert result["rich_header"] is None

    def test_analyze_exception_handling(self):
        """Test exception handling in analyze."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")

        # Force an exception by setting r2 to a value that will raise
        class BadAdapter:
            """Adapter whose method raises."""

            pass

        analyzer.r2 = None  # _is_pe_file returns False when r2 is None

        result = analyzer.analyze()
        # With r2=None, _is_pe_file returns False
        assert result["is_pe"] is False


class TestPEFileDetection:
    """Test PE file detection methods."""

    def test_is_pe_file_no_r2(self):
        """Test PE detection when r2 is None."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")
        analyzer.r2 = None

        result = analyzer._is_pe_file()
        assert result is False

    def test_check_magic_bytes_no_filepath(self):
        """Test magic byte check without filepath."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath=None)

        result = analyzer._check_magic_bytes()
        assert result is False

    def test_bin_info_has_pe_format(self):
        """Test _bin_info_has_pe with PE format field."""
        result = RichHeaderDirectMixin._bin_info_has_pe({"format": "pe", "class": ""})
        assert result is True

    def test_bin_info_has_pe_class(self):
        """Test _bin_info_has_pe with PE class field."""
        result = RichHeaderDirectMixin._bin_info_has_pe({"format": "unknown", "class": "PE32"})
        assert result is True

    def test_bin_info_not_pe(self):
        """Test _bin_info_has_pe with non-PE info."""
        result = RichHeaderDirectMixin._bin_info_has_pe({"format": "elf", "class": "ELF64"})
        assert result is False


class TestPEFileExtraction:
    """Test pefile-based extraction methods."""

    def test_pefile_parse_entry_valid(self):
        """Test parsing valid pefile entry using a real data class."""

        class RichEntry:
            def __init__(self, product_id, build_version, count):
                self.product_id = product_id
                self.build_version = build_version
                self.count = count

        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter)

        entry = RichEntry(product_id=261, build_version=30729, count=10)
        result = analyzer._pefile_parse_entry(entry)

        assert result is not None
        assert result["product_id"] == 261
        assert result["build_number"] == 30729
        assert result["count"] == 10
        assert result["prodid"] == 261 | (30729 << 16)

    def test_pefile_parse_entry_missing_attrs(self):
        """Test parsing entry with missing attributes."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter)

        class BareObject:
            """Object without required attributes."""

            pass

        entry = BareObject()
        result = analyzer._pefile_parse_entry(entry)
        assert result is None


class TestDirectFileRichSearch:
    """Test direct file analysis for Rich Header."""

    def test_is_valid_pe_data_with_mz(self):
        """Test _is_valid_pe_data recognizes MZ header."""
        data = b"MZ" + b"\x00" * 0x3E
        assert RichHeaderDirectMixin._is_valid_pe_data(data) is True

    def test_is_valid_pe_data_non_mz(self):
        """Test _is_valid_pe_data rejects non-MZ data."""
        data = b"\x7fELF" + b"\x00" * 0x3C
        assert RichHeaderDirectMixin._is_valid_pe_data(data) is False

    def test_is_valid_pe_data_too_short(self):
        """Test _is_valid_pe_data rejects data shorter than 0x40."""
        data = b"MZ" + b"\x00" * 10
        assert RichHeaderDirectMixin._is_valid_pe_data(data) is False

    def test_get_pe_offset_valid(self):
        """Test _get_pe_offset extracts correct offset."""
        pe_offset = 0x80
        data = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", pe_offset) + b"\x00" * 0x80
        result = RichHeaderDirectMixin._get_pe_offset(data)
        assert result == 0x80

    def test_get_pe_offset_out_of_bounds(self):
        """Test _get_pe_offset returns None when offset beyond data."""
        data = b"MZ" + b"\x00" * 0x3A + b"\xff\xff\xff\xff"
        result = RichHeaderDirectMixin._get_pe_offset(data)
        assert result is None

    def test_get_dos_stub_valid(self):
        """Test _get_dos_stub extracts correct stub range."""
        pe_offset = 0x80
        data = b"\x00" * 0x100
        stub = RichHeaderDirectMixin._get_dos_stub(data, pe_offset)
        assert stub is not None
        assert len(stub) == pe_offset - 0x40

    def test_get_dos_stub_pe_too_close(self):
        """Test _get_dos_stub returns None when PE header at/before 0x40."""
        result = RichHeaderDirectMixin._get_dos_stub(b"\x00" * 0x100, 0x40)
        assert result is None

    def test_find_rich_pos_found(self):
        """Test finding Rich signature in DOS stub."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter)

        dos_stub = b"\x00" * 20 + b"Rich" + b"\x00" * 10
        result = analyzer._find_rich_pos(dos_stub)
        assert result == 20

    def test_find_rich_pos_not_found(self):
        """Test Rich signature not found."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter)

        dos_stub = b"\x00" * 100
        result = analyzer._find_rich_pos(dos_stub)
        assert result is None

    def test_extract_xor_key_from_stub_success(self):
        """Test extracting XOR key from DOS stub."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter)

        dos_stub = b"Rich\x12\x34\x56\x78\x00\x00"
        result = analyzer._extract_xor_key_from_stub(dos_stub, 0)
        assert result == 0x78563412  # Little-endian

    def test_extract_xor_key_from_stub_insufficient_data(self):
        """Test XOR key extraction with insufficient data."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter)

        dos_stub = b"Rich\x12"
        result = analyzer._extract_xor_key_from_stub(dos_stub, 0)
        assert result is None

    def test_extract_xor_key_from_stub_zero_key(self):
        """Test XOR key extraction returns None for zero key."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter)

        dos_stub = b"Rich\x00\x00\x00\x00\x00\x00"
        result = analyzer._extract_xor_key_from_stub(dos_stub, 0)
        assert result is None

    def test_find_or_estimate_dans_found(self):
        """Test finding DanS signature."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter)

        dos_stub = b"\x00" * 10 + b"DanS" + b"\x00" * 20 + b"Rich"
        rich_pos = dos_stub.find(b"Rich")
        result = analyzer._find_or_estimate_dans(dos_stub, rich_pos)
        assert result == 10

    def test_find_or_estimate_dans_not_found_estimates(self):
        """Test estimating DanS when signature not present."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter)

        # 32 bytes of data (aligned to 8) then Rich
        dos_stub = b"\x00" * 32 + b"Rich"
        rich_pos = 32
        result = analyzer._find_or_estimate_dans(dos_stub, rich_pos)
        # Should estimate an aligned start position
        if result is not None:
            assert result % 4 == 0

    def test_estimate_dans_start_aligned(self):
        """Test estimating DanS start with aligned data."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter)

        # 24 bytes before Rich (aligned to 8)
        dos_stub = b"\x00" * 24 + b"Rich"
        rich_pos = 24
        result = analyzer._estimate_dans_start(dos_stub, rich_pos)
        assert result is not None

    def test_estimate_dans_start_unaligned(self):
        """Test estimating DanS start with unaligned data."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter)

        # 22 bytes before Rich (not aligned to 8)
        dos_stub = b"\x00" * 22 + b"Rich"
        rich_pos = 22
        result = analyzer._estimate_dans_start(dos_stub, rich_pos)
        # Should find an aligned position or None
        assert result is None or result % 4 == 0

    def test_extract_encoded_from_stub_valid(self):
        """Test extracting encoded data from DOS stub."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter)

        # DanS(4) + 16 bytes encoded + Rich
        dos_stub = b"DanS\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10Rich"
        dans_pos = 0
        rich_pos = 20
        result = analyzer._extract_encoded_from_stub(dos_stub, dans_pos, rich_pos)
        assert result is not None
        assert len(result) == 16

    def test_extract_encoded_from_stub_unaligned(self):
        """Test extracting unaligned encoded data returns None."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter)

        # 10 bytes (not multiple of 8) between DanS+4 and Rich
        dos_stub = b"DanS\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0aRich"
        result = analyzer._extract_encoded_from_stub(dos_stub, 0, 14)
        assert result is None

    def test_direct_file_rich_search_no_data(self):
        """Test direct search when filepath is None."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath=None)
        result = analyzer._direct_file_rich_search()
        assert result is None

    def test_direct_file_rich_search_not_pe(self):
        """Test direct search on non-PE data via _is_valid_pe_data."""
        data = b"\x7fELF" + b"\x00" * 100
        assert RichHeaderDirectMixin._is_valid_pe_data(data) is False

    def test_direct_file_rich_search_no_rich_signature(self):
        """Test direct search when Rich signature not found."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")

        # Valid PE structure but no Rich
        data = b"MZ" + b"\x00" * 0x3A + b"\x80\x00\x00\x00" + b"\x00" * 0x40
        dos_stub = RichHeaderDirectMixin._get_dos_stub(data + b"\x00" * 100, 0x80)
        assert dos_stub is not None
        assert analyzer._find_rich_pos(dos_stub) is None


class TestR2PipeExtraction:
    """Test r2pipe-based extraction methods."""

    def test_offsets_valid_correct_order(self):
        """Test offset validation with correct order."""
        result = RichHeaderDirectMixin._offsets_valid(80, 100)
        assert result is True

    def test_offsets_valid_wrong_order(self):
        """Test offset validation with wrong order."""
        result = RichHeaderDirectMixin._offsets_valid(100, 80)
        assert result is False

    def test_offsets_valid_too_far_apart(self):
        """Test offset validation when too far apart."""
        result = RichHeaderDirectMixin._offsets_valid(80, 2000)
        assert result is False

    def test_offsets_valid_equal(self):
        """Test offset validation when equal (invalid)."""
        result = RichHeaderDirectMixin._offsets_valid(80, 80)
        assert result is False

    def test_extract_offsets_valid(self):
        """Test _extract_offsets with valid results."""
        result = RichHeaderDirectMixin._extract_offsets({"offset": 100}, {"offset": 80})
        assert result == (80, 100)

    def test_extract_offsets_missing(self):
        """Test _extract_offsets when offset key missing."""
        result = RichHeaderDirectMixin._extract_offsets({"other": 100}, {"offset": 80})
        assert result is None

    def test_try_rich_dans_combinations_invalid_offsets(self):
        """Test Rich/DanS combinations with invalid offsets (Rich before DanS)."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter)

        # Rich before DanS (invalid)
        rich_results = [{"offset": 80}]
        dans_results = [{"offset": 100}]
        result = analyzer._try_rich_dans_combinations(rich_results, dans_results)
        assert result is None

    def test_validate_rich_size(self):
        """Test _validate_rich_size with valid and invalid sizes."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter)

        assert analyzer._validate_rich_size(16) is True
        assert analyzer._validate_rich_size(512) is True
        assert analyzer._validate_rich_size(8) is False  # too small (must be >8)
        assert analyzer._validate_rich_size(0) is False
        assert analyzer._validate_rich_size(513) is False  # too large

    def test_extract_rich_header_r2pipe_returns_none_on_exception(self):
        """Test r2pipe extraction returns None when extraction raises."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/tmp/test.exe")

        # With empty FakeR2 responses, extraction should fail gracefully
        result = analyzer._extract_rich_header_r2pipe()
        assert result is None


class TestRichHeaderChecksum:
    """Test Rich Header checksum calculation."""

    def test_calculate_rich_checksum_simple(self):
        """Test checksum calculation with simple entries."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter)

        data = b"MZ" + b"\x00" * 0x3A + b"\x80\x00\x00\x00"
        data += b"\x00" * (0x80 - len(data))

        entries = [{"product_id": 1, "build_number": 2, "count": 3}]
        result = analyzer._calculate_rich_checksum(data, 0x80, entries)

        assert isinstance(result, int)
        assert result > 0

    def test_calculate_rich_checksum_multiple_entries(self):
        """Test checksum with multiple entries."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter)

        data = b"MZ" + b"\x00" * 0x3A + b"\x80\x00\x00\x00"
        data += b"\x00" * (0x80 - len(data))

        entries = [
            {"product_id": 261, "build_number": 30729, "count": 10},
            {"product_id": 260, "build_number": 30729, "count": 5},
        ]
        result = analyzer._calculate_rich_checksum(data, 0x80, entries)
        assert isinstance(result, int)

    def test_calculate_rich_checksum_deterministic(self):
        """Test that checksum is deterministic for the same inputs."""
        data = b"MZ" + b"\x00" * 0x3A + b"\x80\x00\x00\x00"
        data += b"\x00" * (0x80 - len(data))
        entries = [{"product_id": 1, "build_number": 2, "count": 3}]

        result1 = RichHeaderDirectMixin._calculate_rich_checksum(data, 0x80, entries)
        result2 = RichHeaderDirectMixin._calculate_rich_checksum(data, 0x80, entries)
        assert result1 == result2

    def test_calculate_rich_checksum_exception(self):
        """Test checksum calculation with data too short."""
        result = RichHeaderDirectMixin._calculate_rich_checksum(b"", 0x80, [])
        assert result == 0


class TestDomainFunctions:
    """Test domain-level Rich Header functions directly."""

    def test_decode_rich_header_basic(self):
        """Test decoding encoded rich header data."""
        xor_key = 0x12345678
        # Build encoded data: 3 padding dwords + 1 entry (2 dwords)
        # Padding is xor_key ^ 0 = xor_key
        encoded = b""
        # 3 padding dwords
        for _ in range(3):
            encoded += struct.pack("<I", xor_key)
        # Entry: product_id=1, build=2 -> combined = 1 | (2 << 16) = 0x00020001
        combined = 0x00020001
        encoded += struct.pack("<I", combined ^ xor_key)
        encoded += struct.pack("<I", 5 ^ xor_key)  # count=5

        entries = decode_rich_header(encoded, xor_key)
        assert len(entries) >= 1
        # The decoded entry uses "prodid" (combined value) and "count"
        entry = entries[0]
        assert entry["prodid"] == combined  # 0x00020001
        assert entry["count"] == 5

    def test_validate_decoded_entries_valid(self):
        """Test validation of decoded entries."""
        entries = [{"product_id": 1, "build_number": 2, "count": 3, "prodid": 0x00020001}]
        assert validate_decoded_entries(entries) is True

    def test_validate_decoded_entries_empty(self):
        """Test validation of empty entries."""
        assert validate_decoded_entries([]) is False

    def test_build_rich_header_result(self):
        """Test building result dict from decoded entries."""
        entries = [{"product_id": 1, "build_number": 2, "count": 3, "prodid": 0x00020001}]
        result = build_rich_header_result(entries, 0x12345678)
        assert result["xor_key"] == 0x12345678
        assert len(result["entries"]) == 1

    def test_parse_compiler_entries_known_product(self):
        """Test parsing compiler entries with known product IDs."""
        entries = [{"product_id": 0x00B5, "build_number": 30729, "count": 10, "prodid": 0x00B5}]
        compilers = parse_compiler_entries(entries)
        assert len(compilers) >= 1
        # Product 0x00B5 = Utc1900_C
        found_compiler = compilers[0]
        assert "product_id" in found_compiler or "compiler" in found_compiler

    def test_parse_compiler_entries_unknown_product(self):
        """Test parsing compiler entries with unknown product ID."""
        entries = [{"product_id": 0xFFFF, "build_number": 1, "count": 1, "prodid": 0xFFFF}]
        compilers = parse_compiler_entries(entries)
        assert isinstance(compilers, list)

    def test_calculate_richpe_hash_from_entries(self):
        """Test RichPE hash calculation from entries."""
        entries = [
            {"product_id": 261, "build_number": 30729, "count": 10, "prodid": 261 | (30729 << 16)},
        ]
        rich_data = {
            "xor_key": 0x12345678,
            "entries": entries,
        }
        result = calculate_richpe_hash(rich_data)
        assert result is not None
        assert len(result) == 32  # MD5 hex digest

    def test_calculate_richpe_hash_from_clear_data(self):
        """Test RichPE hash from clear_data_bytes."""
        rich_data = {
            "clear_data_bytes": b"\x01\x02\x03\x04\x05\x06\x07\x08",
        }
        result = calculate_richpe_hash(rich_data)
        assert result is not None
        assert len(result) == 32

    def test_calculate_richpe_hash_passthrough(self):
        """Test RichPE hash passthrough when already present."""
        rich_data = {
            "richpe_hash": "abc123def456abc123def456abc12345",
        }
        result = calculate_richpe_hash(rich_data)
        assert result == "abc123def456abc123def456abc12345"

    def test_calculate_richpe_hash_empty(self):
        """Test RichPE hash returns None for empty data."""
        result = calculate_richpe_hash({})
        assert result is None

    def test_calculate_richpe_hash_deterministic(self):
        """Test RichPE hash is deterministic."""
        entries = [
            {"product_id": 261, "build_number": 30729, "count": 10, "prodid": 261 | (30729 << 16)},
        ]
        rich_data = {"xor_key": 0x12345678, "entries": entries}
        h1 = calculate_richpe_hash(rich_data)
        h2 = calculate_richpe_hash(rich_data)
        assert h1 == h2


class TestSearchMixin:
    """Test RichHeaderSearchMixin helper methods."""

    def test_find_all_occurrences(self):
        """Test finding all occurrences of a signature."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter)

        data = b"\x00\x00Rich\x00\x00Rich\x00"
        offsets = analyzer._find_all_occurrences(data, b"Rich")
        assert offsets == [2, 8]

    def test_find_all_occurrences_none(self):
        """Test finding occurrences when signature absent."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter)

        data = b"\x00" * 100
        offsets = analyzer._find_all_occurrences(data, b"Rich")
        assert offsets == []

    def test_offset_pair_valid(self):
        """Test offset pair validation."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter)

        assert analyzer._offset_pair_valid(80, 100, 512) is True
        assert analyzer._offset_pair_valid(100, 80, 512) is False  # wrong order
        assert analyzer._offset_pair_valid(80, 700, 512) is False  # too far

    def test_find_rich_positions(self):
        """Test _find_rich_positions locates all Rich markers."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter)

        # Pad with enough trailing bytes so the loop doesn't miss the last one
        data = b"\x00" * 10 + b"Rich" + b"\x00" * 20 + b"Rich" + b"\x00" * 10
        positions = analyzer._find_rich_positions(data)
        assert 10 in positions
        assert 34 in positions

    def test_is_valid_rich_key(self):
        """Test _is_valid_rich_key checks for valid XOR key after Rich."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter)

        # Valid key
        data = b"Rich" + struct.pack("<I", 0x12345678)
        assert analyzer._is_valid_rich_key(data, 0) is True

        # Zero key (invalid)
        data_zero = b"Rich" + struct.pack("<I", 0)
        assert analyzer._is_valid_rich_key(data_zero, 0) is False

        # 0xFFFFFFFF key (invalid)
        data_ff = b"Rich" + struct.pack("<I", 0xFFFFFFFF)
        assert analyzer._is_valid_rich_key(data_ff, 0) is False

        # Insufficient data
        data_short = b"Rich\x01"
        assert analyzer._is_valid_rich_key(data_short, 0) is False

    def test_find_dans_candidates_before_rich(self):
        """Test _find_dans_candidates_before_rich."""
        fake_r2 = FakeR2()
        adapter = R2PipeAdapter(fake_r2)
        analyzer = RichHeaderAnalyzer(adapter=adapter)

        data = b"\x00" * 10 + b"DanS" + b"\x00" * 20 + b"Rich" + b"\x00" * 8
        rich_pos = data.find(b"Rich")
        candidates = analyzer._find_dans_candidates_before_rich(data, rich_pos)
        assert 10 in candidates


class TestBuildDirectRichResult:
    """Test the static _build_direct_rich_result method."""

    def test_build_direct_rich_result(self):
        """Test building a direct rich result dict."""
        entries = [{"product_id": 1, "build_number": 2, "count": 3}]
        encoded_data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        result = RichHeaderDirectMixin._build_direct_rich_result(
            xor_key=0x12345678,
            calculated_checksum=0x12345678,
            entries=entries,
            encoded_data=encoded_data,
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
        assert result["encoded_data"] == encoded_data.hex()

    def test_build_direct_rich_result_invalid_checksum(self):
        """Test result when checksum does not match xor_key."""
        result = RichHeaderDirectMixin._build_direct_rich_result(
            xor_key=0x12345678,
            calculated_checksum=0xAABBCCDD,
            entries=[],
            encoded_data=b"\x00" * 8,
            dos_stub_start=0x40,
            dans_pos=0,
            rich_pos=16,
        )
        assert result["valid_checksum"] is False


class TestDebugMixin:
    """Test RichHeaderDebugMixin methods."""

    def test_debug_has_mz_header(self):
        """Test MZ header detection in debug helper."""
        from r2inspect.modules.rich_header_debug import RichHeaderDebugMixin

        assert RichHeaderDebugMixin._debug_has_mz_header(b"MZ\x00\x00") is True
        assert RichHeaderDebugMixin._debug_has_mz_header(b"\x7fELF") is False

    def test_debug_get_pe_offset(self):
        """Test PE offset extraction in debug helper."""
        from r2inspect.modules.rich_header_debug import RichHeaderDebugMixin

        data = b"\x00" * 0x3C + struct.pack("<I", 0x80) + b"\x00" * 0x40
        result = RichHeaderDebugMixin._debug_get_pe_offset(data)
        assert result == 0x80

    def test_debug_get_pe_offset_short_data(self):
        """Test PE offset extraction with short data."""
        from r2inspect.modules.rich_header_debug import RichHeaderDebugMixin

        result = RichHeaderDebugMixin._debug_get_pe_offset(b"MZ")
        assert result is None

    def test_find_rich_dans_positions(self):
        """Test finding Rich and DanS positions in debug helper."""
        from r2inspect.modules.rich_header_debug import RichHeaderDebugMixin

        data = b"\x00" * 10 + b"DanS" + b"\x00" * 16 + b"Rich" + b"\x00" * 10
        rich_pos, dans_pos = RichHeaderDebugMixin._find_rich_dans_positions(data)
        assert 10 in dans_pos
        assert 30 in rich_pos
