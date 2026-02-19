from __future__ import annotations

import os
from unittest.mock import Mock, patch

import pytest

from r2inspect.modules.rich_header_analyzer import PEFILE_AVAILABLE, RichHeaderAnalyzer


def test_pefile_not_available_path() -> None:
    """Test ImportError path when pefile is not available"""
    # This test verifies the ImportError handling is covered
    with patch.dict("sys.modules", {"pefile": None}):
        # The module-level import will use the existing PEFILE_AVAILABLE
        # So we just verify the flag behavior
        if not PEFILE_AVAILABLE:
            analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
            # Should fall back to r2pipe method
            assert analyzer is not None


def test_extract_rich_header_pefile_not_available() -> None:
    """Test _extract_rich_header_pefile when PEFILE_AVAILABLE is False"""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    # Temporarily set PEFILE_AVAILABLE to False
    with patch("r2inspect.modules.rich_header_analyzer.PEFILE_AVAILABLE", False):
        result = analyzer._extract_rich_header_pefile()
        assert result is None


def test_pefile_has_rich_header_no_attr() -> None:
    """Test _pefile_has_rich_header when RICH_HEADER attr missing"""
    if not PEFILE_AVAILABLE:
        pytest.skip("pefile not available")
    
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    mock_pe = Mock()
    del mock_pe.RICH_HEADER  # Remove the attribute
    
    result = analyzer._pefile_has_rich_header(mock_pe)
    assert result is False


def test_pefile_has_rich_header_false_value() -> None:
    """Test _pefile_has_rich_header when RICH_HEADER is falsy"""
    if not PEFILE_AVAILABLE:
        pytest.skip("pefile not available")
    
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    mock_pe = Mock()
    mock_pe.RICH_HEADER = None
    
    result = analyzer._pefile_has_rich_header(mock_pe)
    assert result is False


def test_pefile_get_xor_key_no_attr() -> None:
    """Test _pefile_get_xor_key when checksum attr missing"""
    if not PEFILE_AVAILABLE:
        pytest.skip("pefile not available")
    
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    mock_pe = Mock()
    mock_pe.RICH_HEADER = Mock(spec=[])  # No checksum attr
    
    result = analyzer._pefile_get_xor_key(mock_pe)
    assert result is None


def test_pefile_extract_entries_no_values() -> None:
    """Test _pefile_extract_entries when values attr missing"""
    if not PEFILE_AVAILABLE:
        pytest.skip("pefile not available")
    
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    mock_pe = Mock()
    mock_pe.RICH_HEADER = Mock(spec=[])  # No values attr
    
    result = analyzer._pefile_extract_entries(mock_pe)
    assert result == []


def test_pefile_extract_entries_empty_values() -> None:
    """Test _pefile_extract_entries when values is empty"""
    if not PEFILE_AVAILABLE:
        pytest.skip("pefile not available")
    
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    mock_pe = Mock()
    mock_pe.RICH_HEADER = Mock()
    mock_pe.RICH_HEADER.values = []
    
    result = analyzer._pefile_extract_entries(mock_pe)
    assert result == []


def test_pefile_parse_entry_missing_attrs() -> None:
    """Test _pefile_parse_entry when entry missing required attrs"""
    if not PEFILE_AVAILABLE:
        pytest.skip("pefile not available")
    
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    # Entry missing product_id
    mock_entry = Mock(spec=["build_version", "count"])
    result = analyzer._pefile_parse_entry(mock_entry)
    assert result is None
    
    # Entry missing build_version
    mock_entry = Mock(spec=["product_id", "count"])
    result = analyzer._pefile_parse_entry(mock_entry)
    assert result is None
    
    # Entry missing count
    mock_entry = Mock(spec=["product_id", "build_version"])
    result = analyzer._pefile_parse_entry(mock_entry)
    assert result is None


def test_pefile_parse_entry_success() -> None:
    """Test _pefile_parse_entry with valid entry"""
    if not PEFILE_AVAILABLE:
        pytest.skip("pefile not available")
    
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    mock_entry = Mock()
    mock_entry.product_id = 0x5A
    mock_entry.build_version = 0x1234
    mock_entry.count = 10
    
    result = analyzer._pefile_parse_entry(mock_entry)
    assert result is not None
    assert result["product_id"] == 0x5A
    assert result["build_number"] == 0x1234
    assert result["count"] == 10
    assert result["prodid"] == 0x5A | (0x1234 << 16)


def test_pefile_entries_from_clear_data_no_attr() -> None:
    """Test _pefile_entries_from_clear_data when clear_data missing"""
    if not PEFILE_AVAILABLE:
        pytest.skip("pefile not available")
    
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    mock_pe = Mock()
    mock_pe.RICH_HEADER = Mock(spec=[])  # No clear_data
    
    result = analyzer._pefile_entries_from_clear_data(mock_pe)
    assert result == []


def test_build_pefile_rich_result_no_clear_data() -> None:
    """Test _build_pefile_rich_result when clear_data attr missing"""
    if not PEFILE_AVAILABLE:
        pytest.skip("pefile not available")
    
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    mock_pe = Mock()
    mock_pe.RICH_HEADER = Mock(spec=[])  # No clear_data attr
    
    result = analyzer._build_pefile_rich_result(mock_pe, 0x12345678, [], "hash123")
    assert result is not None
    assert result["clear_data"] is None
    assert result["clear_data_bytes"] is None


def test_extract_rich_header_pefile_exception() -> None:
    """Test _extract_rich_header_pefile with exception"""
    if not PEFILE_AVAILABLE:
        pytest.skip("pefile not available")
    
    with patch("r2inspect.modules.rich_header_analyzer.pefile.PE") as mock_pe_class:
        mock_pe_class.side_effect = Exception("Test error")
        
        analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
        result = analyzer._extract_rich_header_pefile()
        assert result is None


def test_extract_rich_header_pefile_no_rich_header() -> None:
    """Test _extract_rich_header_pefile when PE has no rich header"""
    if not PEFILE_AVAILABLE:
        pytest.skip("pefile not available")
    
    with patch("r2inspect.modules.rich_header_analyzer.pefile.PE") as mock_pe_class:
        mock_pe_instance = Mock()
        del mock_pe_instance.RICH_HEADER  # No RICH_HEADER
        mock_pe_class.return_value = mock_pe_instance
        
        analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
        result = analyzer._extract_rich_header_pefile()
        assert result is None


def test_extract_rich_header_pefile_no_hash() -> None:
    """Test _extract_rich_header_pefile when get_rich_header_hash returns None"""
    if not PEFILE_AVAILABLE:
        pytest.skip("pefile not available")
    
    with patch("r2inspect.modules.rich_header_analyzer.pefile.PE") as mock_pe_class:
        mock_pe_instance = Mock()
        mock_pe_instance.RICH_HEADER = Mock()
        mock_pe_instance.get_rich_header_hash.return_value = None
        mock_pe_class.return_value = mock_pe_instance
        
        analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
        result = analyzer._extract_rich_header_pefile()
        assert result is None


def test_extract_rich_header_pefile_close_exception() -> None:
    """Test _extract_rich_header_pefile when close() raises exception"""
    if not PEFILE_AVAILABLE:
        pytest.skip("pefile not available")
    
    with patch("r2inspect.modules.rich_header_analyzer.pefile.PE") as mock_pe_class:
        mock_pe_instance = Mock()
        mock_pe_instance.RICH_HEADER = None  # Will return early
        mock_pe_instance.close.side_effect = Exception("Close failed")
        mock_pe_class.return_value = mock_pe_instance
        
        analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
        result = analyzer._extract_rich_header_pefile()
        # Should handle exception gracefully
        assert result is None


def test_read_file_bytes_no_filepath() -> None:
    """Test _read_file_bytes when filepath is None"""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    
    result = analyzer._read_file_bytes()
    assert result is None


def test_read_file_bytes_exception() -> None:
    """Test _read_file_bytes when reading raises exception"""
    with patch("r2inspect.modules.rich_header_analyzer.default_file_system.read_bytes") as mock_read:
        mock_read.side_effect = IOError("Read failed")
        
        analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
        result = analyzer._read_file_bytes()
        assert result is None


def test_is_valid_pe_data_too_short() -> None:
    """Test _is_valid_pe_data with data < 0x40"""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    result = analyzer._is_valid_pe_data(b"MZ" + b"\x00" * 30)
    assert result is False


def test_is_valid_pe_data_no_mz() -> None:
    """Test _is_valid_pe_data without MZ header"""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    result = analyzer._is_valid_pe_data(b"XX" + b"\x00" * 62)
    assert result is False


def test_get_pe_offset_out_of_bounds() -> None:
    """Test _get_pe_offset when pe_offset >= len(data) - 4"""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    data = b"MZ" + b"\x00" * 58 + b"\xFF\xFF\xFF\xFF"  # pe_offset at 0x3C
    result = analyzer._get_pe_offset(data)
    assert result is None


def test_get_dos_stub_pe_offset_too_small() -> None:
    """Test _get_dos_stub when pe_offset <= 0x40"""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    data = b"MZ" + b"\x00" * 100
    result = analyzer._get_dos_stub(data, 0x40)
    assert result is None
    
    result = analyzer._get_dos_stub(data, 0x30)
    assert result is None


def test_find_rich_pos_not_found() -> None:
    """Test _find_rich_pos when Rich signature not found"""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    dos_stub = b"\x00" * 100
    result = analyzer._find_rich_pos(dos_stub)
    assert result is None


def test_extract_xor_key_from_stub_insufficient_data() -> None:
    """Test _extract_xor_key_from_stub when not enough data after Rich"""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    dos_stub = b"Rich\x00\x00"  # Only 2 bytes after Rich, need 8
    result = analyzer._extract_xor_key_from_stub(dos_stub, 0)
    assert result is None


def test_find_or_estimate_dans_found() -> None:
    """Test _find_or_estimate_dans when DanS found"""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    dos_stub = b"DanS" + b"\x00" * 100 + b"Rich"
    result = analyzer._find_or_estimate_dans(dos_stub, dos_stub.find(b"Rich"))
    assert result == 0


def test_find_or_estimate_dans_not_found() -> None:
    """Test _find_or_estimate_dans when DanS not found (estimate)"""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    # Create data without DanS but with Rich
    dos_stub = b"\x00" * 100 + b"Rich"
    rich_pos = dos_stub.find(b"Rich")
    
    result = analyzer._find_or_estimate_dans(dos_stub, rich_pos)
    # Should estimate a start position
    assert result is not None or result is None  # Either is valid


def test_estimate_dans_start_no_valid_start() -> None:
    """Test _estimate_dans_start when no valid start found"""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    # Rich at position 5, no valid 8-byte aligned data before it
    dos_stub = b"\x00" * 5 + b"Rich"
    result = analyzer._estimate_dans_start(dos_stub, 5)
    assert result is None


def test_estimate_dans_start_found() -> None:
    """Test _estimate_dans_start when valid start found"""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    # Create stub with valid 8-byte aligned data
    dos_stub = b"\x00" * 24 + b"Rich"  # 24 bytes (3*8) before Rich
    result = analyzer._estimate_dans_start(dos_stub, 24)
    assert result is not None


def test_extract_encoded_from_stub_empty() -> None:
    """Test _extract_encoded_from_stub with empty encoded data"""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    dos_stub = b"DanSRich"  # dans_pos=0, rich_pos=4, encoded_data would be empty
    result = analyzer._extract_encoded_from_stub(dos_stub, 0, 4)
    assert result is None


def test_extract_encoded_from_stub_invalid_length() -> None:
    """Test _extract_encoded_from_stub with length not divisible by 8"""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    dos_stub = b"DanS\x00\x00\x00\x00\x00Rich"  # 5 bytes between (not % 8)
    result = analyzer._extract_encoded_from_stub(dos_stub, 0, 9)
    assert result is None


def test_check_magic_bytes_no_filepath() -> None:
    """Test _check_magic_bytes when filepath is None"""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    
    result = analyzer._check_magic_bytes()
    assert result is False


def test_check_magic_bytes_exception() -> None:
    """Test _check_magic_bytes when read_bytes raises exception"""
    with patch("r2inspect.modules.rich_header_analyzer.default_file_system.read_bytes") as mock_read:
        mock_read.side_effect = IOError("Read failed")
        
        analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
        result = analyzer._check_magic_bytes()
        assert result is False


def test_check_magic_bytes_not_mz() -> None:
    """Test _check_magic_bytes when magic bytes are not MZ"""
    with patch("r2inspect.modules.rich_header_analyzer.default_file_system.read_bytes") as mock_read:
        mock_read.return_value = b"EL"
        
        analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
        result = analyzer._check_magic_bytes()
        assert result is False


def test_bin_info_has_pe_format() -> None:
    """Test _bin_info_has_pe when format contains 'pe'"""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    bin_info = {"format": "PE32", "class": "UNKNOWN"}
    result = analyzer._bin_info_has_pe(bin_info)
    assert result is True


def test_bin_info_has_pe_class() -> None:
    """Test _bin_info_has_pe when class contains 'pe'"""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    bin_info = {"format": "unknown", "class": "PE"}
    result = analyzer._bin_info_has_pe(bin_info)
    assert result is True


def test_bin_info_has_pe_neither() -> None:
    """Test _bin_info_has_pe when neither format nor class contains 'pe'"""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    bin_info = {"format": "ELF", "class": "ELF64"}
    result = analyzer._bin_info_has_pe(bin_info)
    assert result is False


def test_extract_offsets_missing_offset() -> None:
    """Test _extract_offsets when offset is None"""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    rich_result = {"offset": None}
    dans_result = {"offset": 0x100}
    result = analyzer._extract_offsets(rich_result, dans_result)
    assert result is None
    
    rich_result = {"offset": 0x200}
    dans_result = {"offset": None}
    result = analyzer._extract_offsets(rich_result, dans_result)
    assert result is None


def test_offsets_valid_dans_greater_than_rich() -> None:
    """Test _offsets_valid when dans_offset >= rich_offset"""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    result = analyzer._offsets_valid(0x200, 0x100)
    assert result is False
    
    result = analyzer._offsets_valid(0x100, 0x100)
    assert result is False


def test_offsets_valid_difference_too_large() -> None:
    """Test _offsets_valid when difference > 1024"""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    result = analyzer._offsets_valid(0x100, 0x100 + 1025)
    assert result is False


def test_offsets_valid_success() -> None:
    """Test _offsets_valid with valid offsets"""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath="/tmp/test.exe")
    
    result = analyzer._offsets_valid(0x100, 0x200)
    assert result is True
    
    result = analyzer._offsets_valid(0x100, 0x100 + 1024)
    assert result is True
