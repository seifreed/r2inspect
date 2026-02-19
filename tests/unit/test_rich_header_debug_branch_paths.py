#!/usr/bin/env python3
"""Branch-path tests for r2inspect/modules/rich_header_debug.py.

Covers missing lines: 31, 34, 35, 36, 40, 41, 48, 55, 56, 61, 62, 63,
64, 65, 68, 69, 70, 71, 73, 74, 76, 77, 78, 79, 81, 82, 84, 85, 86, 87,
88, 93, 96, 111, 113, 122, 123, 124, 127, 128, 131, 132, 133, 137.
"""

from __future__ import annotations

import struct
from typing import Any

import pytest

from r2inspect.modules.rich_header_debug import RichHeaderDebugMixin


# ---------------------------------------------------------------------------
# Concrete class using the mixin (no mocks)
# ---------------------------------------------------------------------------


class _ConcreteDebug(RichHeaderDebugMixin):
    """Minimal concrete class for exercising RichHeaderDebugMixin."""

    def __init__(self, adapter: Any = None) -> None:
        self.adapter = adapter


class _RaisingFileInfoDebug(RichHeaderDebugMixin):
    """Concrete class whose _get_file_info raises to trigger exception handler."""

    def __init__(self) -> None:
        self.adapter = None

    def _get_file_info(self) -> dict[str, Any]:
        raise RuntimeError("simulated file info error")


# ---------------------------------------------------------------------------
# Adapter helpers (plain Python classes - no mocks)
# ---------------------------------------------------------------------------


class _ByteAdapter:
    """Adapter that serves raw bytes and file info."""

    def __init__(self, data: bytes = b"", file_info: dict | None = None) -> None:
        self._data = data
        self._file_info = file_info or {}

    def read_bytes(self, address: int, size: int) -> bytes:
        return self._data[address : address + size]

    def get_file_info(self) -> dict:
        return self._file_info


class _EmptyBytesAdapter:
    """Adapter whose read_bytes returns empty bytes."""

    def read_bytes(self, address: int, size: int) -> bytes:
        return b""


# ---------------------------------------------------------------------------
# Build test data for MZ header scenarios
# ---------------------------------------------------------------------------


def _build_mz_data_with_pe_offset(pe_offset: int, extra_content: bytes = b"") -> bytes:
    """Build a minimal MZ binary blob with a specified PE offset field."""
    # Bytes 0-1: MZ
    # Bytes 2-59: zeros
    # Bytes 60-63: pe_offset (little-endian)
    # Bytes 64-pe_offset-1: stub (filled with extra_content or zeros)
    header = b"MZ" + b"\x00" * 58 + struct.pack("<I", pe_offset)
    stub_len = pe_offset - 64 if pe_offset > 64 else 0
    stub = (extra_content + b"\x00" * stub_len)[:stub_len]
    return header + stub + b"\x00" * 16


# ---------------------------------------------------------------------------
# _debug_file_structure - line 31: early return when no data
# ---------------------------------------------------------------------------


def test_debug_file_structure_returns_early_when_no_data_from_adapter():
    """adapter=None => read_bytes unavailable => data=None => hits line 31."""
    dbg = _ConcreteDebug(adapter=None)
    dbg._debug_file_structure()  # should not raise


# ---------------------------------------------------------------------------
# _debug_file_structure - lines 34-36: MZ header path
# ---------------------------------------------------------------------------


def test_debug_file_structure_processes_mz_header_data():
    """Adapter returns MZ data -> hits lines 33-38 including pe_offset branch."""
    pe_offset = 200
    data = _build_mz_data_with_pe_offset(pe_offset)
    adapter = _ByteAdapter(
        data=data * 4,  # provide enough bytes for the 512-byte read
        file_info={"core": {"size": len(data) * 4}},
    )
    dbg = _ConcreteDebug(adapter=adapter)
    dbg._debug_file_structure()  # should not raise


# ---------------------------------------------------------------------------
# _debug_file_structure - lines 40-41: exception handler
# ---------------------------------------------------------------------------


def test_debug_file_structure_exception_is_caught():
    """_get_file_info raises -> exception caught and logged at lines 40-41."""
    dbg = _RaisingFileInfoDebug()
    dbg._debug_file_structure()  # should not raise


# ---------------------------------------------------------------------------
# _debug_get_file_size - line 44 (line 31 in original numbering context)
# ---------------------------------------------------------------------------


def test_debug_get_file_size_returns_size_from_file_info():
    adapter = _ByteAdapter(file_info={"core": {"size": 12345}})
    dbg = _ConcreteDebug(adapter=adapter)
    assert dbg._debug_get_file_size() == 12345


def test_debug_get_file_size_returns_zero_when_no_adapter():
    dbg = _ConcreteDebug(adapter=None)
    assert dbg._debug_get_file_size() == 0


# ---------------------------------------------------------------------------
# _debug_read_bytes - line 34 (no adapter check), 35 (return None), 36 (read)
# ---------------------------------------------------------------------------


def test_debug_read_bytes_returns_none_when_no_adapter():
    dbg = _ConcreteDebug(adapter=None)
    result = dbg._debug_read_bytes(512)
    assert result is None


def test_debug_read_bytes_returns_data_from_adapter():
    data = b"A" * 100
    adapter = _ByteAdapter(data=data)
    dbg = _ConcreteDebug(adapter=adapter)
    result = dbg._debug_read_bytes(50)
    assert result == data[:50]


def test_debug_read_bytes_returns_none_for_empty_response():
    dbg = _ConcreteDebug(adapter=_EmptyBytesAdapter())
    result = dbg._debug_read_bytes(512)
    assert result is None


# ---------------------------------------------------------------------------
# _debug_has_mz_header - lines 54-56 (True path), 57 (False path)
# ---------------------------------------------------------------------------


def test_debug_has_mz_header_returns_true_for_mz_data():
    data = b"MZ" + b"\x00" * 100
    assert RichHeaderDebugMixin._debug_has_mz_header(data) is True


def test_debug_has_mz_header_returns_false_for_non_mz_data():
    assert RichHeaderDebugMixin._debug_has_mz_header(b"\x00\x00" + b"X" * 100) is False


# ---------------------------------------------------------------------------
# _debug_get_pe_offset - line 61-62 (short data), 63-65 (long data)
# ---------------------------------------------------------------------------


def test_debug_get_pe_offset_returns_none_for_short_data():
    data = b"MZ" + b"\x00" * 10
    assert RichHeaderDebugMixin._debug_get_pe_offset(data) is None


def test_debug_get_pe_offset_returns_offset_for_valid_data():
    expected_offset = 0xE8
    data = b"MZ" + b"\x00" * 58 + struct.pack("<I", expected_offset)
    result = RichHeaderDebugMixin._debug_get_pe_offset(data)
    assert result == expected_offset


# ---------------------------------------------------------------------------
# _debug_log_stub_analysis - line 68-69: pe_offset <= 64 early return
# ---------------------------------------------------------------------------


def test_debug_log_stub_analysis_returns_early_for_small_pe_offset():
    dbg = _ConcreteDebug()
    data = b"MZ" + b"\x00" * 200
    dbg._debug_log_stub_analysis(data, 32)  # pe_offset=32 <= 64 -> early return


# ---------------------------------------------------------------------------
# _debug_log_stub_analysis - lines 70-88: full analysis with markers
# ---------------------------------------------------------------------------


def test_debug_log_stub_analysis_no_rich_dans_hits_early_return_at_82():
    """pe_offset > 64, no Rich or DanS -> hits lines 70-82 (early return)."""
    dbg = _ConcreteDebug()
    data = b"MZ" + b"\x00" * 250
    dbg._debug_log_stub_analysis(data, 200)


def test_debug_log_stub_analysis_with_rich_marker_logs_offset():
    """Stub contains 'Rich' -> hits lines 76-77."""
    dbg = _ConcreteDebug()
    stub_prefix = b"\x00" * 20 + b"Rich" + b"\x00" * 100
    data = b"MZ" + b"\x00" * 58 + struct.pack("<I", 200) + stub_prefix
    dbg._debug_log_stub_analysis(data, 200)


def test_debug_log_stub_analysis_with_dans_marker_logs_offset():
    """Stub contains 'DanS' -> hits lines 78-79."""
    dbg = _ConcreteDebug()
    stub_prefix = b"\x00" * 20 + b"DanS" + b"\x00" * 100
    data = b"MZ" + b"\x00" * 58 + struct.pack("<I", 200) + stub_prefix
    dbg._debug_log_stub_analysis(data, 200)


def test_debug_log_stub_analysis_with_both_markers_produces_hex_dump():
    """Stub contains both 'DanS' and 'Rich' -> hits lines 84-88."""
    dbg = _ConcreteDebug()
    # DanS at stub offset 10, Rich at stub offset 30
    stub = b"\x00" * 10 + b"DanS" + b"\x00" * 12 + b"Rich" + b"\x00" * 50
    data = b"MZ" + b"\x00" * 58 + struct.pack("<I", 200) + stub
    dbg._debug_log_stub_analysis(data, 200)


# ---------------------------------------------------------------------------
# _debug_log_extended_patterns - line 93: no adapter early return
# ---------------------------------------------------------------------------


def test_debug_log_extended_patterns_returns_early_when_no_adapter():
    dbg = _ConcreteDebug(adapter=None)
    dbg._debug_log_extended_patterns()  # should not raise


# ---------------------------------------------------------------------------
# _debug_log_extended_patterns - line 96: empty data early return
# ---------------------------------------------------------------------------


def test_debug_log_extended_patterns_returns_early_for_empty_data():
    dbg = _ConcreteDebug(adapter=_EmptyBytesAdapter())
    dbg._debug_log_extended_patterns()  # should not raise


# ---------------------------------------------------------------------------
# _debug_log_extended_patterns - full path with Rich/DanS data
# ---------------------------------------------------------------------------


def test_debug_log_extended_patterns_full_path_with_rich_dans_data():
    """Adapter returns data with both markers -> all branches exercised."""
    # Build 2048 bytes with DanS at offset 80 and Rich at offset 120
    data = bytearray(2048)
    data[80:84] = b"DanS"
    data[120:124] = b"Rich"
    adapter = _ByteAdapter(data=bytes(data))
    dbg = _ConcreteDebug(adapter=adapter)
    dbg._debug_log_extended_patterns()  # should not raise


# ---------------------------------------------------------------------------
# _find_rich_dans_positions - lines 111, 113
# ---------------------------------------------------------------------------


def test_find_rich_dans_positions_finds_rich_marker():
    data = b"\x00" * 10 + b"Rich" + b"\x00" * 10
    rich_pos, dans_pos = RichHeaderDebugMixin._find_rich_dans_positions(data)
    assert 10 in rich_pos
    assert dans_pos == []


def test_find_rich_dans_positions_finds_dans_marker():
    data = b"\x00" * 5 + b"DanS" + b"\x00" * 10
    rich_pos, dans_pos = RichHeaderDebugMixin._find_rich_dans_positions(data)
    assert 5 in dans_pos
    assert rich_pos == []


def test_find_rich_dans_positions_finds_both_markers():
    data = b"\x00" * 5 + b"DanS" + b"\x00" * 10 + b"Rich" + b"\x00" * 5
    rich_pos, dans_pos = RichHeaderDebugMixin._find_rich_dans_positions(data)
    assert len(dans_pos) >= 1
    assert len(rich_pos) >= 1


# ---------------------------------------------------------------------------
# _debug_log_candidates - lines 122-128
# ---------------------------------------------------------------------------


def test_debug_log_candidates_logs_when_dans_before_rich():
    """dans_pos < rich_pos and within 512 bytes -> hits lines 122-128."""
    data = bytearray(200)
    data[10:14] = b"DanS"
    data[50:54] = b"Rich"
    RichHeaderDebugMixin._debug_log_candidates(bytes(data), [50], [10])


def test_debug_log_candidates_skips_when_rich_before_dans():
    """rich_pos < dans_pos -> inner condition False, no logging."""
    data = bytearray(200)
    data[10:14] = b"Rich"
    data[50:54] = b"DanS"
    RichHeaderDebugMixin._debug_log_candidates(bytes(data), [10], [50])


def test_debug_log_candidates_skips_when_too_far_apart():
    """Distance >= 512 -> condition False."""
    data = bytearray(1024)
    data[10:14] = b"DanS"
    data[600:604] = b"Rich"
    RichHeaderDebugMixin._debug_log_candidates(bytes(data), [600], [10])


# ---------------------------------------------------------------------------
# _read_bytes - lines 131-132: no adapter path; line 133: adapter path
# ---------------------------------------------------------------------------


def test_read_bytes_returns_empty_bytes_when_no_adapter():
    dbg = _ConcreteDebug(adapter=None)
    assert dbg._read_bytes(0, 100) == b""


def test_read_bytes_returns_data_from_adapter():
    data = b"HELLO_BYTES_DATA"
    adapter = _ByteAdapter(data=data)
    dbg = _ConcreteDebug(adapter=adapter)
    result = dbg._read_bytes(0, 5)
    assert result == b"HELLO"


# ---------------------------------------------------------------------------
# _get_file_info - line 137: no adapter path
# ---------------------------------------------------------------------------


def test_get_file_info_returns_empty_dict_when_no_adapter():
    dbg = _ConcreteDebug(adapter=None)
    assert dbg._get_file_info() == {}


def test_get_file_info_returns_data_from_adapter():
    info = {"core": {"size": 4096}}
    adapter = _ByteAdapter(file_info=info)
    dbg = _ConcreteDebug(adapter=adapter)
    assert dbg._get_file_info() == info
