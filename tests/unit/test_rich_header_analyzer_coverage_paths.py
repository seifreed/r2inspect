from __future__ import annotations

import struct
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from r2inspect.modules.rich_header_analyzer import PEFILE_AVAILABLE, RichHeaderAnalyzer


def test_rich_header_init_with_r2_instance() -> None:
    r2_inst = MagicMock()
    analyzer = RichHeaderAnalyzer(r2_instance=r2_inst, filepath="/fake/path")
    assert analyzer.adapter == r2_inst
    assert str(analyzer.filepath) == "/fake/path"


def test_rich_header_init_with_adapter() -> None:
    adapter = MagicMock()
    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath="/fake/path")
    assert analyzer.adapter == adapter


def test_rich_header_init_with_none_adapter() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    assert analyzer.adapter is None


def test_rich_header_analyze_non_pe_file(tmp_path: Path) -> None:
    test_file = tmp_path / "not_pe.bin"
    test_file.write_bytes(b"NOTPE" * 100)

    r2 = MagicMock()
    r2.cmdj.return_value = {"info": {"class": "ELF"}}

    analyzer = RichHeaderAnalyzer(adapter=r2, filepath=str(test_file))
    analyzer.r2 = r2
    result = analyzer.analyze()

    assert result["is_pe"] is False
    assert result["error"] == "File is not a PE binary"
    assert result["available"] is False


def test_rich_header_analyze_pe_no_rich_header(tmp_path: Path) -> None:
    test_file = tmp_path / "pe_no_rich.exe"
    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
    pe_header = b"PE\x00\x00" + b"\x00" * 100
    test_file.write_bytes(dos_header + b"\x00" * (0x80 - len(dos_header)) + pe_header)

    r2 = MagicMock()
    r2.cmdj.return_value = {"info": {"class": "PE32"}}

    analyzer = RichHeaderAnalyzer(adapter=r2, filepath=str(test_file))
    analyzer.r2 = r2
    result = analyzer.analyze()

    assert result["is_pe"] is True
    assert result["error"] == "Rich Header not found"


def test_rich_header_analyze_with_rich_header(tmp_path: Path) -> None:
    test_file = tmp_path / "pe_with_rich.exe"
    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x100)

    xor_key = 0x12345678
    encoded_entry = struct.pack("<I", 0x00010002 ^ xor_key) + struct.pack("<I", 5 ^ xor_key)
    rich_data = b"DanS" + encoded_entry + b"Rich" + struct.pack("<I", xor_key)

    dos_stub = b"\x00" * (0x100 - 0x40 - len(rich_data)) + rich_data
    pe_header = b"PE\x00\x00" + b"\x00" * 100
    test_file.write_bytes(dos_header + dos_stub + pe_header)

    r2 = MagicMock()
    r2.cmdj.return_value = {"info": {"class": "PE32"}}

    analyzer = RichHeaderAnalyzer(adapter=r2, filepath=str(test_file))
    analyzer.r2 = r2
    result = analyzer.analyze()

    assert result["is_pe"] is True
    assert result.get("rich_header") is not None


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


def test_rich_header_is_pe_file_no_r2() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    analyzer.r2 = None
    assert analyzer._is_pe_file() is False


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


def test_rich_header_offsets_valid_success() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    assert analyzer._offsets_valid(80, 100) is True


def test_rich_header_offsets_valid_reversed() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    assert analyzer._offsets_valid(100, 80) is False


def test_rich_header_offsets_valid_too_far() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    assert analyzer._offsets_valid(80, 2000) is False


def test_rich_header_read_file_bytes_none_filepath() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._read_file_bytes() is None


def test_rich_header_read_file_bytes_error() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/nonexistent/file.exe")
    assert analyzer._read_file_bytes() is None


def test_rich_header_is_valid_pe_data_too_small() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    assert analyzer._is_valid_pe_data(b"MZ") is False


def test_rich_header_is_valid_pe_data_no_mz() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    assert analyzer._is_valid_pe_data(b"ELF" + b"\x00" * 100) is False


def test_rich_header_is_valid_pe_data_valid() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    assert analyzer._is_valid_pe_data(b"MZ" + b"\x00" * 100) is True


def test_rich_header_get_pe_offset_out_of_bounds() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    data = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0xFFFFFF)
    assert analyzer._get_pe_offset(data) is None


def test_rich_header_get_pe_offset_valid() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    data = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x100) + b"\x00" * 200
    assert analyzer._get_pe_offset(data) == 0x100


def test_rich_header_get_dos_stub_pe_too_early() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    data = b"MZ" + b"\x00" * 100
    assert analyzer._get_dos_stub(data, 0x30) is None


def test_rich_header_get_dos_stub_valid() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    data = b"MZ" + b"\x00" * 200
    stub = analyzer._get_dos_stub(data, 0x100)
    assert stub is not None
    assert len(stub) == (0x100 - 0x40)


def test_rich_header_find_rich_pos_not_found() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    dos_stub = b"\x00" * 100
    assert analyzer._find_rich_pos(dos_stub) is None


def test_rich_header_find_rich_pos_found() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    dos_stub = b"\x00" * 50 + b"Rich" + b"\x00" * 50
    assert analyzer._find_rich_pos(dos_stub) == 50


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


def test_rich_header_is_available() -> None:
    assert RichHeaderAnalyzer.is_available() is True


def test_rich_header_calculate_richpe_hash_from_file_none_result(tmp_path: Path, monkeypatch: Any) -> None:
    test_file = tmp_path / "test.exe"
    test_file.write_bytes(b"MZ" + b"\x00" * 100)

    def mock_run_analyzer(*args: Any, **kwargs: Any) -> None:
        return None

    import r2inspect.modules.rich_header_analyzer
    monkeypatch.setattr(r2inspect.modules.rich_header_analyzer, "run_analyzer_on_file", mock_run_analyzer)

    result = RichHeaderAnalyzer.calculate_richpe_hash_from_file(str(test_file))
    assert result is None


def test_rich_header_scan_patterns_empty() -> None:
    r2 = MagicMock()
    r2.cmdj.return_value = []

    analyzer = RichHeaderAnalyzer(adapter=r2, filepath="/fake/path")
    analyzer.r2 = r2
    result = analyzer._scan_patterns(["pattern1", "pattern2"], "Test")
    assert result == []


def test_rich_header_scan_patterns_found() -> None:
    r2 = MagicMock()
    r2.cmdj.return_value = [{"offset": 100}]

    analyzer = RichHeaderAnalyzer(adapter=r2, filepath="/fake/path")
    analyzer.r2 = r2
    result = analyzer._scan_patterns(["pattern1"], "Test")
    assert len(result) == 1
    assert result[0]["offset"] == 100


def test_rich_header_scan_patterns_exception() -> None:
    r2 = MagicMock()
    r2.cmdj.side_effect = Exception("Test error")

    analyzer = RichHeaderAnalyzer(adapter=r2, filepath="/fake/path")
    analyzer.r2 = r2
    result = analyzer._scan_patterns(["pattern1"], "Test")
    assert result == []


def test_rich_header_try_rich_dans_combinations_no_valid() -> None:
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    rich_results = [{"offset": None}]
    dans_results = [{"offset": 80}]
    result = analyzer._try_rich_dans_combinations(rich_results, dans_results)
    assert result is None


def test_rich_header_extract_rich_header_exception(tmp_path: Path) -> None:
    test_file = tmp_path / "test.exe"
    test_file.write_bytes(b"MZ" + b"\x00" * 10)

    analyzer = RichHeaderAnalyzer(adapter=None, filepath=str(test_file))
    result = analyzer._extract_rich_header()
    assert result is None


def test_rich_header_direct_file_rich_search_exception(monkeypatch: Any) -> None:
    def mock_read_error(*args: Any, **kwargs: Any) -> None:
        raise Exception("Read error")

    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    monkeypatch.setattr(analyzer, "_read_file_bytes", mock_read_error)
    result = analyzer._direct_file_rich_search()
    assert result is None


def test_rich_header_extract_r2pipe_fallback_debug(tmp_path: Path) -> None:
    test_file = tmp_path / "test.exe"
    test_file.write_bytes(b"MZ" + b"\x00" * 100)

    r2 = MagicMock()
    r2.cmdj.return_value = []

    analyzer = RichHeaderAnalyzer(adapter=r2, filepath=str(test_file))
    analyzer.r2 = r2
    result = analyzer._extract_rich_header_r2pipe()
    assert result is None


def test_rich_header_extract_r2pipe_exception() -> None:
    r2 = MagicMock()
    r2.cmdj.side_effect = Exception("Test error")

    analyzer = RichHeaderAnalyzer(adapter=r2, filepath="/fake/path")
    analyzer.r2 = r2
    result = analyzer._extract_rich_header_r2pipe()
    assert result is None


def test_rich_header_collect_rich_dans_offsets() -> None:
    r2 = MagicMock()
    r2.cmdj.return_value = [{"offset": 100}]

    analyzer = RichHeaderAnalyzer(adapter=r2, filepath="/fake/path")
    analyzer.r2 = r2
    rich_results, dans_results = analyzer._collect_rich_dans_offsets()
    assert len(rich_results) > 0
    assert len(dans_results) > 0


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


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rich_header_pefile_has_rich_header_true() -> None:
    import pefile

    pe = MagicMock(spec=pefile.PE)
    pe.RICH_HEADER = MagicMock()

    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    assert analyzer._pefile_has_rich_header(pe) is True


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rich_header_pefile_has_rich_header_false() -> None:
    import pefile

    pe = MagicMock(spec=pefile.PE)
    delattr(pe, "RICH_HEADER")

    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    assert analyzer._pefile_has_rich_header(pe) is False


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rich_header_pefile_get_xor_key_valid() -> None:
    import pefile

    pe = MagicMock(spec=pefile.PE)
    pe.RICH_HEADER = MagicMock()
    pe.RICH_HEADER.checksum = 0x12345678

    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    assert analyzer._pefile_get_xor_key(pe) == 0x12345678


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rich_header_pefile_get_xor_key_none() -> None:
    import pefile

    pe = MagicMock(spec=pefile.PE)
    pe.RICH_HEADER = MagicMock()
    delattr(pe.RICH_HEADER, "checksum")

    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    assert analyzer._pefile_get_xor_key(pe) is None


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rich_header_pefile_extract_entries_empty() -> None:
    import pefile

    pe = MagicMock(spec=pefile.PE)
    pe.RICH_HEADER = MagicMock()
    delattr(pe.RICH_HEADER, "values")

    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    result = analyzer._pefile_extract_entries(pe)
    assert result == []


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rich_header_pefile_extract_entries_valid() -> None:
    import pefile

    pe = MagicMock(spec=pefile.PE)
    pe.RICH_HEADER = MagicMock()

    entry = MagicMock()
    entry.product_id = 1
    entry.build_version = 2
    entry.count = 5

    pe.RICH_HEADER.values = [entry]

    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    result = analyzer._pefile_extract_entries(pe)
    assert len(result) == 1
    assert result[0]["product_id"] == 1
    assert result[0]["build_number"] == 2
    assert result[0]["count"] == 5


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rich_header_pefile_parse_entry_none() -> None:
    entry = MagicMock()
    delattr(entry, "product_id")

    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    result = analyzer._pefile_parse_entry(entry)
    assert result is None


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rich_header_pefile_entries_from_clear_data_no_attr() -> None:
    import pefile

    pe = MagicMock(spec=pefile.PE)
    pe.RICH_HEADER = MagicMock()
    delattr(pe.RICH_HEADER, "clear_data")

    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/fake/path")
    result = analyzer._pefile_entries_from_clear_data(pe)
    assert result == []


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rich_header_pefile_build_rich_result() -> None:
    import pefile

    pe = MagicMock(spec=pefile.PE)
    pe.RICH_HEADER = MagicMock()
    pe.RICH_HEADER.clear_data = b"\x00" * 8

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
    import pefile

    pe = MagicMock(spec=pefile.PE)
    pe.RICH_HEADER = MagicMock()
    delattr(pe.RICH_HEADER, "clear_data")

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

    import r2inspect.modules.rich_header_analyzer
    old_val = r2inspect.modules.rich_header_analyzer.PEFILE_AVAILABLE
    r2inspect.modules.rich_header_analyzer.PEFILE_AVAILABLE = False

    result = analyzer._extract_rich_header_pefile()

    r2inspect.modules.rich_header_analyzer.PEFILE_AVAILABLE = old_val
    assert result is None


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rich_header_extract_pefile_exception(tmp_path: Path) -> None:
    test_file = tmp_path / "invalid.exe"
    test_file.write_bytes(b"NOTPE" * 100)

    analyzer = RichHeaderAnalyzer(adapter=None, filepath=str(test_file))
    result = analyzer._extract_rich_header_pefile()
    assert result is None


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
def test_rich_header_extract_pefile_no_hash(tmp_path: Path, monkeypatch: Any) -> None:
    import pefile

    test_file = tmp_path / "test.exe"
    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
    pe_header = b"PE\x00\x00" + b"\x00" * 100
    test_file.write_bytes(dos_header + b"\x00" * (0x80 - len(dos_header)) + pe_header)

    def mock_get_rich_header_hash(self: Any) -> None:
        return None

    monkeypatch.setattr(pefile.PE, "get_rich_header_hash", mock_get_rich_header_hash)

    analyzer = RichHeaderAnalyzer(adapter=None, filepath=str(test_file))
    result = analyzer._extract_rich_header_pefile()
    assert result is None
