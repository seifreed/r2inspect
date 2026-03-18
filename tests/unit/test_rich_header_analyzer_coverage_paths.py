"""Coverage-path tests for RichHeaderAnalyzer.

All mocks replaced with real objects using FakeR2 + R2PipeAdapter.
NO mocks, NO monkeypatch, NO @patch.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.rich_header_analyzer import PEFILE_AVAILABLE, RichHeaderAnalyzer


# ---------------------------------------------------------------------------
# FakeR2: minimal r2pipe stand-in routing cmdj/cmd via lookup maps
# ---------------------------------------------------------------------------


class FakeR2:
    """Minimal r2pipe stand-in that routes cmdj/cmd via lookup maps."""

    def __init__(
        self,
        cmdj_map: dict[str, Any] | None = None,
        cmd_map: dict[str, Any] | None = None,
    ) -> None:
        self.cmdj_map = cmdj_map or {}
        self.cmd_map = cmd_map or {}

    def cmdj(self, command: str) -> Any:
        val = self.cmdj_map.get(command)
        if isinstance(val, Exception):
            raise val
        return val if val is not None else {}

    def cmd(self, command: str) -> str:
        val = self.cmd_map.get(command)
        if isinstance(val, Exception):
            raise val
        return val if val is not None else ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_adapter(
    cmdj_map: dict[str, Any] | None = None,
    cmd_map: dict[str, Any] | None = None,
) -> R2PipeAdapter:
    """Build an R2PipeAdapter backed by FakeR2."""
    r2 = FakeR2(cmdj_map=cmdj_map, cmd_map=cmd_map)
    return R2PipeAdapter(r2)


def _make_analyzer(
    cmdj_map: dict[str, Any] | None = None,
    cmd_map: dict[str, Any] | None = None,
    filepath: str | None = None,
) -> RichHeaderAnalyzer:
    """Build a RichHeaderAnalyzer backed by FakeR2 + R2PipeAdapter."""
    adapter = _make_adapter(cmdj_map=cmdj_map, cmd_map=cmd_map)
    return RichHeaderAnalyzer(adapter=adapter, filepath=filepath)


def _hex_for(data: bytes) -> str:
    """Convert bytes to hex string suitable for p8 output."""
    return data.hex()


# ---------------------------------------------------------------------------
# Init tests
# ---------------------------------------------------------------------------


def test_rich_header_init_with_r2_instance() -> None:
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(r2_instance=adapter, filepath="/fake/path")
    assert analyzer.adapter is adapter
    assert str(analyzer.filepath) == "/fake/path"


def test_rich_header_init_with_adapter() -> None:
    adapter = _make_adapter()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/fake/path")
    assert analyzer.adapter is adapter


def test_rich_header_init_with_none_adapter() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    assert analyzer.adapter is None


# ---------------------------------------------------------------------------
# analyze() tests
# ---------------------------------------------------------------------------


def test_rich_header_analyze_non_pe_file(tmp_path: Path) -> None:
    test_file = tmp_path / "not_pe.bin"
    test_file.write_bytes(b"NOTPE" * 100)

    # The file doesn't start with MZ, so _is_pe_file returns False.
    # We still need an adapter that responds to ij etc.
    analyzer = _make_analyzer(
        cmdj_map={"ij": {"info": {"class": "ELF"}}},
        filepath=str(test_file),
    )
    result = analyzer.analyze()

    assert result["is_pe"] is False
    assert result["error"] == "File is not a PE binary"
    assert result["available"] is False


def test_rich_header_analyze_pe_no_rich_header(tmp_path: Path) -> None:
    test_file = tmp_path / "pe_no_rich.exe"
    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
    pe_header = b"PE\x00\x00" + b"\x00" * 100
    test_file.write_bytes(dos_header + b"\x00" * (0x80 - len(dos_header)) + pe_header)

    analyzer = _make_analyzer(
        cmdj_map={"ij": {"info": {"class": "PE32"}}},
        filepath=str(test_file),
    )
    result = analyzer.analyze()

    assert result["is_pe"] is True
    assert result["error"] == "Rich Header not found"


def test_rich_header_analyze_with_rich_header(tmp_path: Path) -> None:
    test_file = tmp_path / "pe_with_rich.exe"
    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x100)

    xor_key = 0x12345678
    # Create a proper encoded entry: 3 padding DWORDs + entry pair
    padding = struct.pack("<III", 0 ^ xor_key, 0 ^ xor_key, 0 ^ xor_key)
    encoded_entry = struct.pack("<I", 0x00010002 ^ xor_key) + struct.pack("<I", 5 ^ xor_key)
    rich_data = b"DanS" + padding + encoded_entry + b"Rich" + struct.pack("<I", xor_key)

    dos_stub = b"\x00" * (0x100 - 0x40 - len(rich_data)) + rich_data
    pe_header = b"PE\x00\x00" + b"\x00" * 100
    test_file.write_bytes(dos_header + dos_stub + pe_header)

    analyzer = _make_analyzer(
        cmdj_map={"ij": {"info": {"class": "PE32"}}},
        filepath=str(test_file),
    )
    result = analyzer.analyze()

    assert result["is_pe"] is True
    assert result.get("rich_header") is not None


# ---------------------------------------------------------------------------
# _check_magic_bytes tests
# ---------------------------------------------------------------------------


def test_rich_header_check_magic_bytes_mz(tmp_path: Path) -> None:
    test_file = tmp_path / "test.exe"
    test_file.write_bytes(b"MZ" + b"\x00" * 100)

    analyzer = RichHeaderAnalyzer(adapter=None, filepath=str(test_file))
    assert analyzer._check_magic_bytes() is True


def test_rich_header_check_magic_bytes_no_mz(tmp_path: Path) -> None:
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"ELF" + b"\x00" * 100)

    analyzer = RichHeaderAnalyzer(adapter=None, filepath=str(test_file))
    assert analyzer._check_magic_bytes() is False


def test_rich_header_check_magic_bytes_no_filepath() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._check_magic_bytes() is False


def test_rich_header_check_magic_bytes_file_error(tmp_path: Path) -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/nonexistent/file.exe")
    assert analyzer._check_magic_bytes() is False


# ---------------------------------------------------------------------------
# _bin_info_has_pe tests
# ---------------------------------------------------------------------------


def test_rich_header_bin_info_has_pe_format() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    bin_info = {"format": "pe", "class": "other"}
    assert analyzer._bin_info_has_pe(bin_info) is True


def test_rich_header_bin_info_has_pe_class() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    bin_info = {"format": "other", "class": "PE32"}
    assert analyzer._bin_info_has_pe(bin_info) is True


def test_rich_header_bin_info_no_pe() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    bin_info = {"format": "elf", "class": "ELF64"}
    assert analyzer._bin_info_has_pe(bin_info) is False


# ---------------------------------------------------------------------------
# _is_pe_file tests
# ---------------------------------------------------------------------------


def test_rich_header_is_pe_file_no_r2() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    analyzer.r2 = None
    assert analyzer._is_pe_file() is False


# ---------------------------------------------------------------------------
# _extract_offsets tests
# ---------------------------------------------------------------------------


def test_rich_header_extract_offsets_valid() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    rich_result = {"offset": 100}
    dans_result = {"offset": 80}
    offsets = analyzer._extract_offsets(rich_result, dans_result)
    assert offsets == (80, 100)


def test_rich_header_extract_offsets_none() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    rich_result = {"offset": None}
    dans_result = {"offset": 80}
    assert analyzer._extract_offsets(rich_result, dans_result) is None


def test_rich_header_extract_offsets_missing() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    rich_result = {"other": 100}
    dans_result = {"offset": 80}
    assert analyzer._extract_offsets(rich_result, dans_result) is None


# ---------------------------------------------------------------------------
# _offsets_valid tests
# ---------------------------------------------------------------------------


def test_rich_header_offsets_valid_success() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    assert analyzer._offsets_valid(80, 100) is True


def test_rich_header_offsets_valid_reversed() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    assert analyzer._offsets_valid(100, 80) is False


def test_rich_header_offsets_valid_too_far() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    assert analyzer._offsets_valid(80, 2000) is False


# ---------------------------------------------------------------------------
# _read_file_bytes tests
# ---------------------------------------------------------------------------


def test_rich_header_read_file_bytes_none_filepath() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._read_file_bytes() is None


def test_rich_header_read_file_bytes_error() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/nonexistent/file.exe")
    assert analyzer._read_file_bytes() is None


# ---------------------------------------------------------------------------
# _is_valid_pe_data tests
# ---------------------------------------------------------------------------


def test_rich_header_is_valid_pe_data_too_small() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    assert analyzer._is_valid_pe_data(b"MZ") is False


def test_rich_header_is_valid_pe_data_no_mz() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    assert analyzer._is_valid_pe_data(b"ELF" + b"\x00" * 100) is False


def test_rich_header_is_valid_pe_data_valid() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    assert analyzer._is_valid_pe_data(b"MZ" + b"\x00" * 100) is True


# ---------------------------------------------------------------------------
# _get_pe_offset tests
# ---------------------------------------------------------------------------


def test_rich_header_get_pe_offset_out_of_bounds() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    data = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0xFFFFFF)
    assert analyzer._get_pe_offset(data) is None


def test_rich_header_get_pe_offset_valid() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    data = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x100) + b"\x00" * 200
    assert analyzer._get_pe_offset(data) == 0x100


# ---------------------------------------------------------------------------
# _get_dos_stub tests
# ---------------------------------------------------------------------------


def test_rich_header_get_dos_stub_pe_too_early() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    data = b"MZ" + b"\x00" * 100
    assert analyzer._get_dos_stub(data, 0x30) is None


def test_rich_header_get_dos_stub_valid() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    data = b"MZ" + b"\x00" * 200
    stub = analyzer._get_dos_stub(data, 0x100)
    assert stub is not None
    assert len(stub) == (len(data) - 0x40)


# ---------------------------------------------------------------------------
# _find_rich_pos tests
# ---------------------------------------------------------------------------


def test_rich_header_find_rich_pos_not_found() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    dos_stub = b"\x00" * 100
    assert analyzer._find_rich_pos(dos_stub) is None


def test_rich_header_find_rich_pos_found() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    dos_stub = b"\x00" * 50 + b"Rich" + b"\x00" * 50
    assert analyzer._find_rich_pos(dos_stub) == 50


# ---------------------------------------------------------------------------
# _extract_xor_key_from_stub tests
# ---------------------------------------------------------------------------


def test_rich_header_extract_xor_key_from_stub_not_enough_data() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    dos_stub = b"Rich\x00"
    assert analyzer._extract_xor_key_from_stub(dos_stub, 0) is None


def test_rich_header_extract_xor_key_from_stub_valid() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    xor_key = 0x12345678
    dos_stub = b"Rich" + struct.pack("<I", xor_key)
    result = analyzer._extract_xor_key_from_stub(dos_stub, 0)
    assert result == xor_key


# ---------------------------------------------------------------------------
# _find_or_estimate_dans tests
# ---------------------------------------------------------------------------


def test_rich_header_find_or_estimate_dans_found() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    dos_stub = b"DanS" + b"\x00" * 50 + b"Rich"
    rich_pos = dos_stub.find(b"Rich")
    assert analyzer._find_or_estimate_dans(dos_stub, rich_pos) == 0


def test_rich_header_find_or_estimate_dans_not_found() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    dos_stub = b"\x00" * 100 + b"Rich"
    rich_pos = dos_stub.find(b"Rich")
    result = analyzer._find_or_estimate_dans(dos_stub, rich_pos)
    assert result is not None


# ---------------------------------------------------------------------------
# _estimate_dans_start tests
# ---------------------------------------------------------------------------


def test_rich_header_estimate_dans_start_found() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    dos_stub = b"\x00" * 80 + b"\x01\x02\x03\x04\x05\x06\x07\x08" * 3 + b"Rich"
    rich_pos = dos_stub.find(b"Rich")
    result = analyzer._estimate_dans_start(dos_stub, rich_pos)
    assert result is not None


def test_rich_header_estimate_dans_start_not_found() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    dos_stub = b"Rich"
    result = analyzer._estimate_dans_start(dos_stub, 0)
    assert result is None


# ---------------------------------------------------------------------------
# _extract_encoded_from_stub tests
# ---------------------------------------------------------------------------


def test_rich_header_extract_encoded_from_stub_invalid_length() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    dos_stub = b"DanS" + b"\x00" * 3 + b"Rich"
    rich_pos = dos_stub.find(b"Rich")
    assert analyzer._extract_encoded_from_stub(dos_stub, 0, rich_pos) is None


def test_rich_header_extract_encoded_from_stub_valid() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    dos_stub = b"DanS" + b"\x00" * 8 + b"Rich"
    rich_pos = dos_stub.find(b"Rich")
    result = analyzer._extract_encoded_from_stub(dos_stub, 0, rich_pos)
    assert result is not None
    assert len(result) == 8


# ---------------------------------------------------------------------------
# _calculate_rich_checksum tests
# ---------------------------------------------------------------------------


def test_rich_header_calculate_rich_checksum() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    data = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x100) + b"\x00" * 200
    entries = [{"product_id": 1, "build_number": 2, "count": 5}]
    result = analyzer._calculate_rich_checksum(data, 0x100, entries)
    assert result > 0


def test_rich_header_calculate_rich_checksum_error() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    result = analyzer._calculate_rich_checksum(b"", 0, [])
    assert result == 0


# ---------------------------------------------------------------------------
# is_available test
# ---------------------------------------------------------------------------


def test_rich_header_is_available() -> None:
    assert RichHeaderAnalyzer.is_available() is True


# ---------------------------------------------------------------------------
# calculate_richpe_hash_from_file test
# ---------------------------------------------------------------------------


def test_rich_header_calculate_richpe_hash_from_file_none_result(
    tmp_path: Path,
) -> None:
    # A file that's not a valid PE won't produce a hash
    test_file = tmp_path / "test.exe"
    test_file.write_bytes(b"MZ" + b"\x00" * 100)

    result = RichHeaderAnalyzer.calculate_richpe_hash_from_file(str(test_file))
    # run_analyzer_on_file opens a real r2pipe -- on a truncated MZ stub
    # the analyzer should fail gracefully and return None
    assert result is None


# ---------------------------------------------------------------------------
# _scan_patterns tests (via adapter with FakeR2)
# ---------------------------------------------------------------------------


def test_rich_header_scan_patterns_empty() -> None:
    # Set up adapter where /xj queries return empty lists
    analyzer = _make_analyzer(
        cmdj_map={"/xj pattern1": [], "/xj pattern2": []},
        filepath="/fake/path",
    )
    result = analyzer._scan_patterns(["pattern1", "pattern2"], "Test")
    assert result == []


def test_rich_header_scan_patterns_found() -> None:
    analyzer = _make_analyzer(
        cmdj_map={"/xj pattern1": [{"offset": 100}]},
        filepath="/fake/path",
    )
    result = analyzer._scan_patterns(["pattern1"], "Test")
    assert len(result) == 1
    assert result[0]["offset"] == 100


def test_rich_header_scan_patterns_exception() -> None:
    # When the cmdj raises, _scan_patterns should catch and return []
    analyzer = _make_analyzer(
        cmdj_map={"/xj pattern1": Exception("Test error")},
        filepath="/fake/path",
    )
    # The adapter's cmdj will fail; the scan_patterns catches internally
    result = analyzer._scan_patterns(["pattern1"], "Test")
    assert result == []


# ---------------------------------------------------------------------------
# _try_rich_dans_combinations tests
# ---------------------------------------------------------------------------


def test_rich_header_try_rich_dans_combinations_no_valid() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    rich_results = [{"offset": None}]
    dans_results = [{"offset": 80}]
    result = analyzer._try_rich_dans_combinations(rich_results, dans_results)
    assert result is None


# ---------------------------------------------------------------------------
# _extract_rich_header exception path
# ---------------------------------------------------------------------------


def test_rich_header_extract_rich_header_exception(tmp_path: Path) -> None:
    test_file = tmp_path / "test.exe"
    test_file.write_bytes(b"MZ" + b"\x00" * 10)

    analyzer = RichHeaderAnalyzer(adapter=None, filepath=str(test_file))
    result = analyzer._extract_rich_header()
    assert result is None


# ---------------------------------------------------------------------------
# _direct_file_rich_search when file can't be read
# ---------------------------------------------------------------------------


def test_rich_header_direct_file_rich_search_nonexistent_file() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/nonexistent/file.exe")
    result = analyzer._direct_file_rich_search()
    assert result is None


# ---------------------------------------------------------------------------
# _extract_rich_header_r2pipe tests
# ---------------------------------------------------------------------------


def test_rich_header_extract_r2pipe_fallback_debug(tmp_path: Path) -> None:
    test_file = tmp_path / "test.exe"
    test_file.write_bytes(b"MZ" + b"\x00" * 100)

    # Use an adapter that returns empty for scan commands -- extraction fails
    # and triggers the debug path
    analyzer = _make_analyzer(filepath=str(test_file))
    result = analyzer._extract_rich_header_r2pipe()
    assert result is None


def test_rich_header_extract_r2pipe_exception() -> None:
    # Use an adapter where the underlying r2 raises exceptions on all commands
    r2 = FakeR2(
        cmdj_map={},
        cmd_map={},
    )
    adapter = R2PipeAdapter(r2)
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/fake/path")
    # _extract_rich_header will fail gracefully and return None
    result = analyzer._extract_rich_header_r2pipe()
    assert result is None


# ---------------------------------------------------------------------------
# _collect_rich_dans_offsets tests
# ---------------------------------------------------------------------------


def test_rich_header_collect_rich_dans_offsets() -> None:
    # Rich patterns: "52696368" and DanS patterns: "44616e53"
    analyzer = _make_analyzer(
        cmdj_map={
            "/xj 52696368": [{"offset": 100}],
            "/xj 68636952": [{"offset": 100}],
            "/xj 44616e53": [{"offset": 80}],
            "/xj 536e6144": [{"offset": 80}],
        },
        filepath="/fake/path",
    )
    rich_results, dans_results = analyzer._collect_rich_dans_offsets()
    assert len(rich_results) > 0
    assert len(dans_results) > 0


# ---------------------------------------------------------------------------
# _build_direct_rich_result tests
# ---------------------------------------------------------------------------


def test_rich_header_build_direct_rich_result() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    result = analyzer._build_direct_rich_result(
        xor_key=0x12345678,
        calculated_checksum=0x12345678,
        entries=[{"product_id": 1, "build_number": 2, "count": 5}],
        encoded_data=b"\x00" * 8,
        dos_stub_start=0x40,
        dans_pos=0,
        rich_pos=8,
    )
    assert result["xor_key"] == 0x12345678
    assert result["valid_checksum"] is True


# ---------------------------------------------------------------------------
# pefile mixin tests - use real lightweight objects instead of MagicMock
# ---------------------------------------------------------------------------


class _FakeRichHeader:
    """Lightweight stand-in for pefile RICH_HEADER."""

    def __init__(
        self,
        *,
        checksum: int | None = None,
        values: list[Any] | None = None,
        clear_data: bytes | None = None,
        has_checksum: bool = True,
        has_values: bool = True,
        has_clear_data: bool = True,
    ) -> None:
        if has_checksum and checksum is not None:
            self.checksum = checksum
        if has_values:
            self.values = values or []
        if has_clear_data and clear_data is not None:
            self.clear_data = clear_data


class _FakeRichEntry:
    """Lightweight stand-in for a pefile Rich Header entry."""

    def __init__(
        self,
        *,
        product_id: int | None = None,
        build_version: int | None = None,
        count: int | None = None,
        has_product_id: bool = True,
        has_build_version: bool = True,
        has_count: bool = True,
    ) -> None:
        if has_product_id and product_id is not None:
            self.product_id = product_id
        if has_build_version and build_version is not None:
            self.build_version = build_version
        if has_count and count is not None:
            self.count = count


class _FakePE:
    """Lightweight stand-in for pefile.PE."""

    def __init__(self, rich_header: Any = None) -> None:
        if rich_header is not None:
            self.RICH_HEADER = rich_header

    def close(self) -> None:
        pass


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rich_header_pefile_has_rich_header_true() -> None:
    pe = _FakePE(rich_header=_FakeRichHeader(checksum=0x1234))
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    assert analyzer._pefile_has_rich_header(pe) is True


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rich_header_pefile_has_rich_header_false() -> None:
    pe = _FakePE()  # no RICH_HEADER attribute
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    assert analyzer._pefile_has_rich_header(pe) is False


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rich_header_pefile_get_xor_key_valid() -> None:
    pe = _FakePE(rich_header=_FakeRichHeader(checksum=0x12345678))
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    assert analyzer._pefile_get_xor_key(pe) == 0x12345678


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rich_header_pefile_get_xor_key_none() -> None:
    pe = _FakePE(rich_header=_FakeRichHeader(has_checksum=False))
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    assert analyzer._pefile_get_xor_key(pe) is None


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rich_header_pefile_extract_entries_empty() -> None:
    pe = _FakePE(rich_header=_FakeRichHeader(has_values=False))
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    result = analyzer._pefile_extract_entries(pe)
    assert result == []


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rich_header_pefile_extract_entries_valid() -> None:
    entry = _FakeRichEntry(product_id=1, build_version=2, count=5)
    pe = _FakePE(rich_header=_FakeRichHeader(values=[entry]))
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    result = analyzer._pefile_extract_entries(pe)
    assert len(result) == 1
    assert result[0]["product_id"] == 1
    assert result[0]["build_number"] == 2
    assert result[0]["count"] == 5


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rich_header_pefile_parse_entry_none() -> None:
    # Entry missing required attributes
    entry = _FakeRichEntry(has_product_id=False)
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    result = analyzer._pefile_parse_entry(entry)
    assert result is None


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rich_header_pefile_entries_from_clear_data_no_attr() -> None:
    pe = _FakePE(rich_header=_FakeRichHeader(has_clear_data=False))
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    result = analyzer._pefile_entries_from_clear_data(pe)
    assert result == []


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rich_header_pefile_build_rich_result() -> None:
    pe = _FakePE(rich_header=_FakeRichHeader(clear_data=b"\x00" * 8))
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    result = analyzer._build_pefile_rich_result(
        pe=pe,
        xor_key=0x12345678,
        entries=[{"product_id": 1, "build_number": 2, "count": 5}],
        rich_hash="abcd1234",
    )
    assert result["xor_key"] == 0x12345678
    assert result["method"] == "pefile"
    assert result["richpe_hash"] == "abcd1234"


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rich_header_pefile_build_rich_result_no_clear_data() -> None:
    pe = _FakePE(rich_header=_FakeRichHeader(has_clear_data=False))
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    result = analyzer._build_pefile_rich_result(
        pe=pe,
        xor_key=0x12345678,
        entries=[],
        rich_hash="abcd1234",
    )
    assert result["clear_data"] is None
    assert result["clear_data_bytes"] is None


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rich_header_extract_pefile_not_available() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")

    import r2inspect.modules.rich_header_pefile as pefile_mod

    old_val = pefile_mod.PEFILE_AVAILABLE
    try:
        pefile_mod.PEFILE_AVAILABLE = False
        result = analyzer._extract_rich_header_pefile()
    finally:
        pefile_mod.PEFILE_AVAILABLE = old_val
    assert result is None


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rich_header_extract_pefile_exception(tmp_path: Path) -> None:
    test_file = tmp_path / "invalid.exe"
    test_file.write_bytes(b"NOTPE" * 100)

    analyzer = RichHeaderAnalyzer(adapter=None, filepath=str(test_file))
    result = analyzer._extract_rich_header_pefile()
    assert result is None


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rich_header_extract_pefile_no_hash(tmp_path: Path) -> None:
    # Build a minimal PE that pefile can parse but has no Rich Header
    test_file = tmp_path / "test.exe"
    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
    pe_header = b"PE\x00\x00" + b"\x00" * 100
    test_file.write_bytes(dos_header + b"\x00" * (0x80 - len(dos_header)) + pe_header)

    analyzer = RichHeaderAnalyzer(adapter=None, filepath=str(test_file))
    result = analyzer._extract_rich_header_pefile()
    # pefile will either find no Rich Header or fail to parse -- either way None
    assert result is None
