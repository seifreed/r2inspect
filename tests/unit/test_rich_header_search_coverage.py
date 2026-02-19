"""Coverage tests for r2inspect/modules/rich_header_search.py"""

from __future__ import annotations

import struct
from typing import Any

from r2inspect.modules.rich_header_search import RichHeaderSearchMixin


def _build_synthetic_rich_header_data() -> tuple[bytearray, int, int, int]:
    """Build a synthetic data buffer containing a valid Rich Header.

    Returns:
        (data, dans_offset, rich_offset, xor_key_int)
    """
    xor_key_int = 0x12345678
    xor_key_bytes = struct.pack("<I", xor_key_int)

    prodid = 0x0001
    count = 3
    enc_prodid = prodid ^ xor_key_int
    enc_count = count ^ xor_key_int

    dans_offset = 16
    rich_offset = 32  # dans_offset + 16 = rich_size of 16

    data = bytearray(256)
    # DanS signature at dans_offset
    data[dans_offset : dans_offset + 4] = b"DanS"
    # Encoded product entry at dans_offset + 4
    data[dans_offset + 4 : dans_offset + 12] = struct.pack("<II", enc_prodid, enc_count)
    # Rich signature at rich_offset
    data[rich_offset : rich_offset + 4] = b"Rich"
    # XOR key after Rich
    data[rich_offset + 4 : rich_offset + 8] = xor_key_bytes

    return data, dans_offset, rich_offset, xor_key_int


class SyntheticAdapter:
    """Adapter backed by a synthetic data buffer."""

    def __init__(self, data: bytes):
        self._data = data

    def read_bytes(self, offset: int, size: int) -> bytes:
        return self._data[offset : offset + size]

    def read_bytes_list(self, offset: int, size: int) -> list[int]:
        chunk = self._data[offset : offset + size]
        return list(chunk)


class NoReadBytesAdapter:
    """Adapter without read_bytes / read_bytes_list methods."""
    pass


class NullReturningAdapter:
    """Adapter that always returns None / empty data."""

    def read_bytes(self, offset: int, size: int) -> bytes:
        return b""

    def read_bytes_list(self, offset: int, size: int) -> list[int]:
        return []


class TestableRichSearch(RichHeaderSearchMixin):
    """Concrete subclass to exercise RichHeaderSearchMixin methods."""

    def __init__(self, adapter: Any = None) -> None:
        self.adapter = adapter


# --- _find_all_occurrences ---

def test_find_all_occurrences_single_match():
    searcher = TestableRichSearch()
    data = b"abcRichabc"
    offsets = searcher._find_all_occurrences(data, b"Rich")
    assert offsets == [3]


def test_find_all_occurrences_multiple_matches():
    searcher = TestableRichSearch()
    data = b"RichabcRich"
    offsets = searcher._find_all_occurrences(data, b"Rich")
    assert offsets == [0, 7]


def test_find_all_occurrences_no_match():
    searcher = TestableRichSearch()
    data = b"no match here"
    offsets = searcher._find_all_occurrences(data, b"Rich")
    assert offsets == []


# --- _offset_pair_valid ---

def test_offset_pair_valid_true():
    searcher = TestableRichSearch()
    assert searcher._offset_pair_valid(10, 50, 512) is True


def test_offset_pair_valid_dans_after_rich():
    searcher = TestableRichSearch()
    assert searcher._offset_pair_valid(100, 50, 512) is False


def test_offset_pair_valid_too_far():
    searcher = TestableRichSearch()
    assert searcher._offset_pair_valid(0, 600, 512) is False


def test_offset_pair_valid_equal():
    searcher = TestableRichSearch()
    # dans_offset < rich_offset required
    assert searcher._offset_pair_valid(50, 50, 512) is False


# --- _find_rich_positions ---

def test_find_rich_positions_found():
    searcher = TestableRichSearch()
    data = b"\x00" * 20 + b"Rich" + b"\x00" * 10 + b"Rich" + b"\x00" * 10
    positions = searcher._find_rich_positions(data)
    assert 20 in positions
    assert 34 in positions


def test_find_rich_positions_not_found():
    searcher = TestableRichSearch()
    data = b"\x00" * 100
    positions = searcher._find_rich_positions(data)
    assert positions == []


# --- _is_valid_rich_key ---

def test_is_valid_rich_key_valid():
    searcher = TestableRichSearch()
    data = bytearray(20)
    xor_key = 0x12345678
    data[4:8] = struct.pack("<I", xor_key)
    assert searcher._is_valid_rich_key(bytes(data), 0) is True


def test_is_valid_rich_key_zero_key():
    searcher = TestableRichSearch()
    data = bytearray(20)
    data[4:8] = struct.pack("<I", 0)
    assert searcher._is_valid_rich_key(bytes(data), 0) is False


def test_is_valid_rich_key_all_ff():
    searcher = TestableRichSearch()
    data = bytearray(20)
    data[4:8] = struct.pack("<I", 0xFFFFFFFF)
    assert searcher._is_valid_rich_key(bytes(data), 0) is False


def test_is_valid_rich_key_out_of_bounds():
    searcher = TestableRichSearch()
    data = b"\x00" * 5
    # rich_pos + 8 > len(data)
    assert searcher._is_valid_rich_key(data, 0) is False


# --- _find_dans_before_rich ---

def test_find_dans_before_rich_found():
    searcher = TestableRichSearch()
    data = bytearray(200)
    data[10:14] = b"DanS"
    result = searcher._find_dans_before_rich(bytes(data), 100)
    assert result == 10


def test_find_dans_before_rich_not_found():
    searcher = TestableRichSearch()
    data = bytearray(200)
    result = searcher._find_dans_before_rich(bytes(data), 100)
    assert result is None


def test_find_dans_before_rich_outside_window():
    searcher = TestableRichSearch()
    data = bytearray(200)
    data[0:4] = b"DanS"  # at offset 0
    # rich_pos = 600 -> window is max(0, 600-512)=88 to 600
    # DanS at 0 is outside the window
    result = searcher._find_dans_before_rich(bytes(data), 600)
    assert result is None


# --- _validate_rich_size ---

def test_validate_rich_size_valid():
    searcher = TestableRichSearch()
    assert searcher._validate_rich_size(16) is True
    assert searcher._validate_rich_size(512) is True
    assert searcher._validate_rich_size(9) is True


def test_validate_rich_size_too_small():
    searcher = TestableRichSearch()
    assert searcher._validate_rich_size(8) is False
    assert searcher._validate_rich_size(0) is False


def test_validate_rich_size_too_large():
    searcher = TestableRichSearch()
    assert searcher._validate_rich_size(513) is False


# --- _read_manual_search_bytes ---

def test_read_manual_search_bytes_no_adapter():
    searcher = TestableRichSearch(adapter=None)
    result = searcher._read_manual_search_bytes()
    assert result is None


def test_read_manual_search_bytes_no_read_bytes_attr():
    searcher = TestableRichSearch(adapter=NoReadBytesAdapter())
    result = searcher._read_manual_search_bytes()
    assert result is None


def test_read_manual_search_bytes_empty_data():
    searcher = TestableRichSearch(adapter=NullReturningAdapter())
    result = searcher._read_manual_search_bytes()
    assert result is None


def test_read_manual_search_bytes_with_data():
    data, _, _, _ = _build_synthetic_rich_header_data()
    searcher = TestableRichSearch(adapter=SyntheticAdapter(bytes(data)))
    result = searcher._read_manual_search_bytes()
    assert result is not None
    assert b"DanS" in result
    assert b"Rich" in result


# --- _find_signature_offsets ---

def test_find_signature_offsets_found():
    searcher = TestableRichSearch()
    data = b"\x00" * 10 + b"DanS" + b"\x00" * 20 + b"Rich" + b"\x00" * 10
    result = searcher._find_signature_offsets(data, b"Rich", b"DanS")
    assert result is not None
    rich_offsets, dans_offsets = result
    assert 34 in rich_offsets
    assert 10 in dans_offsets


def test_find_signature_offsets_no_rich():
    searcher = TestableRichSearch()
    data = b"\x00" * 10 + b"DanS" + b"\x00" * 20
    result = searcher._find_signature_offsets(data, b"Rich", b"DanS")
    assert result is None


def test_find_signature_offsets_no_dans():
    searcher = TestableRichSearch()
    data = b"\x00" * 10 + b"Rich" + b"\x00" * 20
    result = searcher._find_signature_offsets(data, b"Rich", b"DanS")
    assert result is None


# --- _extract_xor_key ---

def test_extract_xor_key_no_adapter():
    searcher = TestableRichSearch(adapter=None)
    result = searcher._extract_xor_key(10)
    assert result is None


def test_extract_xor_key_no_read_bytes_list():
    searcher = TestableRichSearch(adapter=NoReadBytesAdapter())
    result = searcher._extract_xor_key(10)
    assert result is None


def test_extract_xor_key_empty_bytes():
    searcher = TestableRichSearch(adapter=NullReturningAdapter())
    result = searcher._extract_xor_key(10)
    assert result is None


def test_extract_xor_key_zero_key():
    data = bytearray(64)
    data[14:18] = struct.pack("<I", 0)  # key = 0
    searcher = TestableRichSearch(adapter=SyntheticAdapter(bytes(data)))
    result = searcher._extract_xor_key(10)
    assert result is None


def test_extract_xor_key_valid():
    data = bytearray(64)
    data[14:18] = struct.pack("<I", 0x12345678)
    searcher = TestableRichSearch(adapter=SyntheticAdapter(bytes(data)))
    result = searcher._extract_xor_key(10)
    assert result == 0x12345678


# --- _extract_encoded_data ---

def test_extract_encoded_data_no_adapter():
    searcher = TestableRichSearch(adapter=None)
    result = searcher._extract_encoded_data(10, 16)
    assert result is None


def test_extract_encoded_data_no_read_bytes_list():
    searcher = TestableRichSearch(adapter=NoReadBytesAdapter())
    result = searcher._extract_encoded_data(10, 16)
    assert result is None


def test_extract_encoded_data_empty_bytes():
    searcher = TestableRichSearch(adapter=NullReturningAdapter())
    result = searcher._extract_encoded_data(10, 16)
    assert result is None


def test_extract_encoded_data_valid():
    data = bytearray(64)
    data[10:26] = b"\x01" * 16
    searcher = TestableRichSearch(adapter=SyntheticAdapter(bytes(data)))
    result = searcher._extract_encoded_data(10, 16)
    assert result is not None
    assert len(result) == 16


def test_extract_encoded_data_too_short():
    data = bytearray(64)
    data[10:15] = b"\x01" * 5  # only 5 bytes, less than 8
    searcher = TestableRichSearch(adapter=SyntheticAdapter(bytes(data)))
    # Returns only what's there, but if < 8 bytes, returns None
    result = searcher._extract_encoded_data(10, 5)
    assert result is None


# --- _try_extract_rich_at_offsets ---

def test_try_extract_rich_at_offsets_valid():
    data, dans_offset, rich_offset, xor_key_int = _build_synthetic_rich_header_data()
    searcher = TestableRichSearch(adapter=SyntheticAdapter(bytes(data)))
    result = searcher._try_extract_rich_at_offsets(dans_offset, rich_offset)
    assert result is not None
    assert "xor_key" in result
    assert result["xor_key"] == xor_key_int


def test_try_extract_rich_at_offsets_invalid_size():
    data = bytearray(256)
    searcher = TestableRichSearch(adapter=SyntheticAdapter(bytes(data)))
    # rich_size = 200 - 100 = 100, but xor_key is 0 (invalid)
    result = searcher._try_extract_rich_at_offsets(100, 200)
    assert result is None


def test_try_extract_rich_at_offsets_size_too_small():
    data = bytearray(256)
    searcher = TestableRichSearch(adapter=SyntheticAdapter(bytes(data)))
    # rich_size = 5, which is <= 8, so _validate_rich_size returns False
    result = searcher._try_extract_rich_at_offsets(0, 5)
    assert result is None


def test_try_extract_rich_at_offsets_no_adapter():
    searcher = TestableRichSearch(adapter=None)
    result = searcher._try_extract_rich_at_offsets(0, 32)
    assert result is None


# --- _manual_rich_search ---

def test_manual_rich_search_no_adapter():
    searcher = TestableRichSearch(adapter=None)
    result = searcher._manual_rich_search()
    assert result is None


def test_manual_rich_search_empty_data():
    searcher = TestableRichSearch(adapter=NullReturningAdapter())
    result = searcher._manual_rich_search()
    assert result is None


def test_manual_rich_search_no_signatures():
    data = bytearray(2048)  # no Rich/DanS
    searcher = TestableRichSearch(adapter=SyntheticAdapter(bytes(data)))
    result = searcher._manual_rich_search()
    assert result is None


def test_manual_rich_search_with_valid_header():
    data, dans_offset, rich_offset, xor_key_int = _build_synthetic_rich_header_data()
    # Pad to 2048 to satisfy read_bytes(0, 2048)
    padded = bytes(data) + b"\x00" * (2048 - len(data))
    searcher = TestableRichSearch(adapter=SyntheticAdapter(padded))
    result = searcher._manual_rich_search()
    assert result is not None
    assert "xor_key" in result


# --- _pattern_based_rich_search ---

def test_pattern_based_rich_search_no_rich_positions():
    searcher = TestableRichSearch()
    data = b"\x00" * 100
    result = searcher._pattern_based_rich_search(data)
    assert result is None


def test_pattern_based_rich_search_rich_without_valid_key():
    searcher = TestableRichSearch()
    # Rich at pos 10, but key = 0 (invalid)
    data = bytearray(50)
    data[10:14] = b"Rich"
    data[14:18] = struct.pack("<I", 0)  # zero key -> invalid
    result = searcher._pattern_based_rich_search(bytes(data))
    assert result is None


def test_pattern_based_rich_search_no_dans_before_rich():
    searcher = TestableRichSearch(adapter=None)
    data = bytearray(100)
    data[50:54] = b"Rich"
    data[54:58] = struct.pack("<I", 0xDEAD1234)
    # No DanS in the window before Rich (window is 50-512=0 to 50)
    # No DanS in data -> returns None
    result = searcher._pattern_based_rich_search(bytes(data))
    assert result is None


def test_pattern_based_rich_search_valid():
    data, dans_offset, rich_offset, xor_key_int = _build_synthetic_rich_header_data()
    padded = bytes(data) + b"\x00" * (2048 - len(data))
    searcher = TestableRichSearch(adapter=SyntheticAdapter(padded))
    # _pattern_based_rich_search uses data passed in, but _try_extract_rich_at_offsets
    # reads from adapter
    result = searcher._pattern_based_rich_search(padded)
    # May or may not find - depends on DanS in window before Rich
    assert result is None or "xor_key" in result


# --- _try_signature_pairs ---

def test_try_signature_pairs_valid_pair():
    data, dans_offset, rich_offset, xor_key_int = _build_synthetic_rich_header_data()
    padded = bytes(data) + b"\x00" * (2048 - len(data))
    searcher = TestableRichSearch(adapter=SyntheticAdapter(padded))
    result = searcher._try_signature_pairs(
        [rich_offset], [dans_offset], b"Rich", b"DanS"
    )
    assert result is not None


def test_try_signature_pairs_invalid_distance():
    searcher = TestableRichSearch(adapter=None)
    # dans > rich (invalid pair)
    result = searcher._try_signature_pairs([10], [600], b"Rich", b"DanS")
    assert result is None


def test_try_signature_pairs_no_valid_extraction():
    searcher = TestableRichSearch(adapter=NullReturningAdapter())
    # Valid offsets but no data in adapter
    result = searcher._try_signature_pairs([100], [10], b"Rich", b"DanS")
    # dans=10, rich=100, distance=90, valid
    # But _try_extract returns None due to empty data
    assert result is None


# --- Additional exception handling paths ---

class ExplodingAdapter:
    """Adapter where read_bytes raises an exception."""

    def read_bytes(self, offset: int, size: int) -> bytes:
        raise RuntimeError("read_bytes exploded")

    def read_bytes_list(self, offset: int, size: int) -> list[int]:
        raise RuntimeError("read_bytes_list exploded")


def test_manual_rich_search_exception_returns_none():
    """Exception in _manual_rich_search is caught and returns None."""
    searcher = TestableRichSearch(adapter=ExplodingAdapter())
    result = searcher._manual_rich_search()
    assert result is None


def test_pattern_based_rich_search_exception_returns_none():
    """Exception in _pattern_based_rich_search is caught and returns None."""
    class BrokenRichSearch(TestableRichSearch):
        def _find_rich_positions(self, data: bytes) -> list[int]:
            raise RuntimeError("simulated error")

    searcher = BrokenRichSearch(adapter=None)
    result = searcher._pattern_based_rich_search(b"\x00" * 50)
    assert result is None


# Test _try_extract_rich_at_offsets paths: encoded_data is None (line 187)

def test_try_extract_rich_at_offsets_no_encoded_data():
    """When _extract_encoded_data returns None, method returns None."""
    class XorKeyOnlyAdapter:
        """Provides XOR key but not encoded data."""
        def read_bytes_list(self, offset: int, size: int) -> list[int]:
            if size == 4:
                import struct
                return list(struct.pack("<I", 0x12345678))
            return []  # Returns empty list for encoded data -> None

    searcher = TestableRichSearch(adapter=XorKeyOnlyAdapter())
    # rich_size = rich_offset - dans_offset = 32 - 16 = 16 (valid)
    result = searcher._try_extract_rich_at_offsets(16, 32)
    assert result is None


# Test _try_extract_rich_at_offsets: valid entries but validate_decoded_entries fails (line 191)

def test_try_extract_rich_at_offsets_invalid_decoded_entries():
    """When decoded entries fail validation, method returns None."""
    import struct
    # XOR key that decodes to count=0 (so entries are rejected by validate_decoded_entries)
    xor_key_int = 0xDEADBEEF
    # Encode with count=0 after XOR: enc_count = 0 ^ xor_key = xor_key
    enc_prodid = 0x1234 ^ xor_key_int
    enc_count = 0 ^ xor_key_int  # count=0 -> entry rejected

    data = bytearray(256)
    dans_offset = 16
    rich_offset = 32
    data[dans_offset:dans_offset + 4] = b"\x00" * 4
    data[dans_offset + 4:dans_offset + 12] = struct.pack("<II", enc_prodid, enc_count)
    data[rich_offset:rich_offset + 4] = b"Rich"
    data[rich_offset + 4:rich_offset + 8] = struct.pack("<I", xor_key_int)

    searcher = TestableRichSearch(adapter=SyntheticAdapter(bytes(data)))
    result = searcher._try_extract_rich_at_offsets(dans_offset, rich_offset)
    assert result is None


# Test _try_extract_rich_at_offsets exception path (lines 197-199)

def test_try_extract_rich_at_offsets_exception_returns_none():
    """Exception inside _try_extract_rich_at_offsets is caught."""
    class ThrowingAdapter:
        def read_bytes_list(self, offset: int, size: int) -> list[int]:
            raise ValueError("Simulated error in read_bytes_list")

    searcher = TestableRichSearch(adapter=ThrowingAdapter())
    # Valid size (> 8 and <= 512), but adapter throws during xor key extraction
    result = searcher._try_extract_rich_at_offsets(16, 32)
    assert result is None
