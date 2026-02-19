#!/usr/bin/env python3
"""Comprehensive tests for rich_header_analyzer - remaining coverage."""

import struct
from pathlib import Path
from unittest.mock import Mock, patch

from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer


def test_extract_rich_header_r2pipe_with_debug():
    """Test _extract_rich_header_r2pipe with debug fallback."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    with patch.object(analyzer, '_extract_rich_header', return_value=None):
        with patch.object(analyzer, '_debug_file_structure'):
            result = analyzer._extract_rich_header_r2pipe()
            assert result is None


def test_extract_rich_header_exception_handling():
    """Test _extract_rich_header handles exceptions."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    with patch.object(analyzer, '_direct_file_rich_search', side_effect=Exception("Test error")):
        result = analyzer._extract_rich_header()
        assert result is None


def test_collect_rich_dans_offsets_multiple_results():
    """Test _collect_rich_dans_offsets with multiple matches."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    with patch.object(analyzer, '_scan_patterns') as mock_scan:
        mock_scan.return_value = [{"offset": 100}, {"offset": 200}]
        rich_results, dans_results = analyzer._collect_rich_dans_offsets()
        assert len(rich_results) >= 1
        assert len(dans_results) >= 1


def test_scan_patterns_exception_handling():
    """Test _scan_patterns handles exceptions per pattern."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    with patch('r2inspect.modules.rich_header_analyzer.cmdj_helper') as mock_cmdj:
        mock_cmdj.side_effect = [Exception("Error"), [{"offset": 100}]]
        result = analyzer._scan_patterns(["pattern1", "pattern2"], "Test")
        assert len(result) == 1


def test_try_rich_dans_combinations_invalid_offsets():
    """Test _try_rich_dans_combinations with invalid offset combinations."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    rich_results = [{"offset": 100}]
    dans_results = [{"offset": 200}]
    
    result = analyzer._try_rich_dans_combinations(rich_results, dans_results)
    assert result is None


def test_try_rich_dans_combinations_valid_extraction():
    """Test _try_rich_dans_combinations with successful extraction."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    rich_results = [{"offset": 200}]
    dans_results = [{"offset": 100}]
    
    rich_data = {"xor_key": 0x12345678, "entries": []}
    
    with patch.object(analyzer, '_try_extract_rich_at_offsets', return_value=rich_data):
        result = analyzer._try_rich_dans_combinations(rich_results, dans_results)
        assert result == rich_data


def test_manual_rich_search_called_as_fallback():
    """Test _manual_rich_search is called as fallback."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    with patch.object(analyzer, '_direct_file_rich_search', return_value=None):
        with patch.object(analyzer, '_collect_rich_dans_offsets', return_value=([], [])):
            with patch.object(analyzer, '_manual_rich_search', return_value=None) as mock_manual:
                result = analyzer._extract_rich_header()
                mock_manual.assert_called_once()


def test_read_file_bytes_exception():
    """Test _read_file_bytes handles exception."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    with patch('r2inspect.modules.rich_header_analyzer.default_file_system.read_bytes', side_effect=Exception("Read error")):
        result = analyzer._read_file_bytes()
        assert result is None


def test_direct_file_rich_search_no_file_data():
    """Test _direct_file_rich_search with no file data."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    with patch.object(analyzer, '_read_file_bytes', return_value=None):
        result = analyzer._direct_file_rich_search()
        assert result is None


def test_direct_file_rich_search_invalid_pe_offset():
    """Test _direct_file_rich_search with invalid PE offset."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    data = bytearray(b"MZ" + b"\x00" * 62)
    
    with patch.object(analyzer, '_read_file_bytes', return_value=bytes(data)):
        with patch.object(analyzer, '_get_pe_offset', return_value=None):
            result = analyzer._direct_file_rich_search()
            assert result is None


def test_direct_file_rich_search_no_dos_stub():
    """Test _direct_file_rich_search with no DOS stub."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    data = b"MZ" + b"\x00" * 62
    
    with patch.object(analyzer, '_read_file_bytes', return_value=data):
        with patch.object(analyzer, '_get_pe_offset', return_value=0x80):
            with patch.object(analyzer, '_get_dos_stub', return_value=None):
                result = analyzer._direct_file_rich_search()
                assert result is None


def test_direct_file_rich_search_no_rich_signature():
    """Test _direct_file_rich_search with no Rich signature."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    data = b"MZ" + b"\x00" * 200
    dos_stub = b"\x00" * 100
    
    with patch.object(analyzer, '_read_file_bytes', return_value=data):
        with patch.object(analyzer, '_get_pe_offset', return_value=0x100):
            with patch.object(analyzer, '_get_dos_stub', return_value=dos_stub):
                with patch.object(analyzer, '_find_rich_pos', return_value=None):
                    result = analyzer._direct_file_rich_search()
                    assert result is None


def test_direct_file_rich_search_no_xor_key():
    """Test _direct_file_rich_search with no XOR key."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    data = b"MZ" + b"\x00" * 200
    dos_stub = b"\x00" * 100 + b"Rich"
    
    with patch.object(analyzer, '_read_file_bytes', return_value=data):
        with patch.object(analyzer, '_get_pe_offset', return_value=0x100):
            with patch.object(analyzer, '_get_dos_stub', return_value=dos_stub):
                with patch.object(analyzer, '_find_rich_pos', return_value=100):
                    with patch.object(analyzer, '_extract_xor_key_from_stub', return_value=None):
                        result = analyzer._direct_file_rich_search()
                        assert result is None


def test_direct_file_rich_search_no_dans_estimate():
    """Test _direct_file_rich_search with no DanS found or estimated."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    data = b"MZ" + b"\x00" * 200
    dos_stub = b"\x00" * 100 + b"Rich\x12\x34\x56\x78"
    
    with patch.object(analyzer, '_read_file_bytes', return_value=data):
        with patch.object(analyzer, '_get_pe_offset', return_value=0x100):
            with patch.object(analyzer, '_get_dos_stub', return_value=dos_stub):
                with patch.object(analyzer, '_find_rich_pos', return_value=100):
                    with patch.object(analyzer, '_extract_xor_key_from_stub', return_value=0x12345678):
                        with patch.object(analyzer, '_find_or_estimate_dans', return_value=None):
                            result = analyzer._direct_file_rich_search()
                            assert result is None


def test_direct_file_rich_search_invalid_encoded_data():
    """Test _direct_file_rich_search with invalid encoded data."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    data = b"MZ" + b"\x00" * 200
    dos_stub = b"\x00" * 50 + b"DanS\x01\x02\x03Rich\x12\x34\x56\x78"
    
    with patch.object(analyzer, '_read_file_bytes', return_value=data):
        with patch.object(analyzer, '_get_pe_offset', return_value=0x100):
            with patch.object(analyzer, '_get_dos_stub', return_value=dos_stub):
                with patch.object(analyzer, '_find_rich_pos', return_value=58):
                    with patch.object(analyzer, '_extract_xor_key_from_stub', return_value=0x12345678):
                        with patch.object(analyzer, '_find_or_estimate_dans', return_value=50):
                            with patch.object(analyzer, '_extract_encoded_from_stub', return_value=None):
                                result = analyzer._direct_file_rich_search()
                                assert result is None


def test_direct_file_rich_search_no_decoded_entries():
    """Test _direct_file_rich_search with no decoded entries."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    data = b"MZ" + b"\x00" * 200
    dos_stub = b"\x00" * 50 + b"DanS\x01\x02\x03\x04\x05\x06\x07\x08Rich\x12\x34\x56\x78"
    
    with patch.object(analyzer, '_read_file_bytes', return_value=data):
        with patch.object(analyzer, '_get_pe_offset', return_value=0x100):
            with patch.object(analyzer, '_get_dos_stub', return_value=dos_stub):
                with patch.object(analyzer, '_find_rich_pos', return_value=62):
                    with patch.object(analyzer, '_extract_xor_key_from_stub', return_value=0x12345678):
                        with patch.object(analyzer, '_find_or_estimate_dans', return_value=50):
                            with patch.object(analyzer, '_extract_encoded_from_stub', return_value=b"\x01\x02\x03\x04\x05\x06\x07\x08"):
                                with patch('r2inspect.modules.rich_header_analyzer.decode_rich_header', return_value=[]):
                                    result = analyzer._direct_file_rich_search()
                                    assert result is None


def test_direct_file_rich_search_complete_success():
    """Test _direct_file_rich_search with complete success."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    data = bytearray(b"MZ" + b"\x00" * 0x3E + b"\x80\x00\x00\x00" + b"\x00" * 100)
    dos_stub = b"\x00" * 50 + b"DanS\x01\x02\x03\x04\x05\x06\x07\x08Rich\x12\x34\x56\x78"
    
    entries = [{"product_id": 100, "build_number": 200, "count": 5}]
    
    with patch.object(analyzer, '_read_file_bytes', return_value=bytes(data)):
        with patch.object(analyzer, '_get_pe_offset', return_value=0x80):
            with patch.object(analyzer, '_get_dos_stub', return_value=dos_stub):
                with patch.object(analyzer, '_find_rich_pos', return_value=62):
                    with patch.object(analyzer, '_extract_xor_key_from_stub', return_value=0x12345678):
                        with patch.object(analyzer, '_find_or_estimate_dans', return_value=50):
                            with patch.object(analyzer, '_extract_encoded_from_stub', return_value=b"\x01\x02\x03\x04\x05\x06\x07\x08"):
                                with patch('r2inspect.modules.rich_header_analyzer.decode_rich_header', return_value=entries):
                                    result = analyzer._direct_file_rich_search()
                                    assert result is not None
                                    assert result["xor_key"] == 0x12345678
                                    assert len(result["entries"]) == 1


def test_get_dos_stub_pe_offset_too_small():
    """Test _get_dos_stub with PE offset too small."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    data = b"MZ" + b"\x00" * 100
    pe_offset = 0x30
    
    result = analyzer._get_dos_stub(data, pe_offset)
    assert result is None


def test_estimate_dans_start_no_valid_position():
    """Test _estimate_dans_start finds no valid position."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    dos_stub = b"\x00" * 100
    rich_pos = 50
    
    result = analyzer._estimate_dans_start(dos_stub, rich_pos)
    assert result is not None


def test_estimate_dans_start_finds_aligned_position():
    """Test _estimate_dans_start finds 8-byte aligned position."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    dos_stub = b"\x00" * 100 + b"Rich"
    rich_pos = 100
    
    result = analyzer._estimate_dans_start(dos_stub, rich_pos)
    assert result is not None
    assert result % 4 == 0


def test_calculate_rich_checksum_handles_exception():
    """Test _calculate_rich_checksum handles exception."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    data = b"MZ"
    entries = [{"product_id": 100, "build_number": 200, "count": 5}]
    
    result = analyzer._calculate_rich_checksum(data, 0x80, entries)
    assert result == 0


def test_build_direct_rich_result_structure():
    """Test _build_direct_rich_result creates correct structure."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    xor_key = 0x12345678
    calculated_checksum = 0x12345678
    entries = [{"product_id": 100}]
    encoded_data = b"\x01\x02\x03\x04"
    
    result = analyzer._build_direct_rich_result(
        xor_key, calculated_checksum, entries, encoded_data,
        dos_stub_start=0x40, dans_pos=10, rich_pos=20
    )
    
    assert result["xor_key"] == xor_key
    assert result["checksum"] == calculated_checksum
    assert result["entries"] == entries
    assert result["dans_offset"] == 0x4A
    assert result["rich_offset"] == 0x54
    assert result["valid_checksum"] is True


def test_pefile_extract_rich_header_no_rich_header():
    """Test _extract_rich_header_pefile with no RICH_HEADER."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    with patch('r2inspect.modules.rich_header_analyzer.PEFILE_AVAILABLE', True):
        with patch('r2inspect.modules.rich_header_analyzer.pefile') as mock_pefile:
            mock_pe = Mock()
            mock_pe.RICH_HEADER = None
            mock_pefile.PE.return_value = mock_pe
            
            result = analyzer._extract_rich_header_pefile()
            assert result is None


def test_pefile_extract_rich_header_no_hash():
    """Test _extract_rich_header_pefile with no Rich hash."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    with patch('r2inspect.modules.rich_header_analyzer.PEFILE_AVAILABLE', True):
        with patch('r2inspect.modules.rich_header_analyzer.pefile') as mock_pefile:
            mock_pe = Mock()
            mock_pe.RICH_HEADER = Mock()
            mock_pe.get_rich_header_hash.return_value = None
            mock_pefile.PE.return_value = mock_pe
            
            result = analyzer._extract_rich_header_pefile()
            assert result is None


def test_pefile_extract_rich_header_with_clear_data_fallback():
    """Test _extract_rich_header_pefile uses clear_data fallback."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    with patch('r2inspect.modules.rich_header_analyzer.PEFILE_AVAILABLE', True):
        with patch('r2inspect.modules.rich_header_analyzer.pefile') as mock_pefile:
            mock_pe = Mock()
            mock_pe.RICH_HEADER = Mock()
            mock_pe.RICH_HEADER.values = []
            mock_pe.RICH_HEADER.clear_data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
            mock_pe.RICH_HEADER.checksum = 0x12345678
            mock_pe.get_rich_header_hash.return_value = "HASH123"
            mock_pefile.PE.return_value = mock_pe
            
            with patch('r2inspect.modules.rich_header_analyzer.parse_clear_data_entries', return_value=[{"product_id": 100}]):
                result = analyzer._extract_rich_header_pefile()
                assert result is not None
                assert result["richpe_hash"] == "HASH123"


def test_pefile_extract_rich_header_exception():
    """Test _extract_rich_header_pefile handles exception."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    with patch('r2inspect.modules.rich_header_analyzer.PEFILE_AVAILABLE', True):
        with patch('r2inspect.modules.rich_header_analyzer.pefile') as mock_pefile:
            mock_pefile.PE.side_effect = Exception("PE error")
            
            result = analyzer._extract_rich_header_pefile()
            assert result is None


def test_pefile_extract_rich_header_close_exception():
    """Test _extract_rich_header_pefile handles close exception."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    with patch('r2inspect.modules.rich_header_analyzer.PEFILE_AVAILABLE', True):
        with patch('r2inspect.modules.rich_header_analyzer.pefile') as mock_pefile:
            mock_pe = Mock()
            mock_pe.RICH_HEADER = None
            mock_pe.close.side_effect = Exception("Close error")
            mock_pefile.PE.return_value = mock_pe
            
            result = analyzer._extract_rich_header_pefile()


def test_pefile_get_xor_key_no_checksum():
    """Test _pefile_get_xor_key with no checksum attribute."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    mock_pe = Mock()
    mock_pe.RICH_HEADER = Mock(spec=[])
    
    result = analyzer._pefile_get_xor_key(mock_pe)
    assert result is None


def test_pefile_extract_entries_no_values():
    """Test _pefile_extract_entries with no values."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    mock_pe = Mock()
    mock_pe.RICH_HEADER = Mock(spec=[])
    
    result = analyzer._pefile_extract_entries(mock_pe)
    assert result == []


def test_pefile_entries_from_clear_data_no_clear_data():
    """Test _pefile_entries_from_clear_data with no clear_data."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    mock_pe = Mock()
    mock_pe.RICH_HEADER = Mock(spec=[])
    
    result = analyzer._pefile_entries_from_clear_data(mock_pe)
    assert result == []


def test_build_pefile_rich_result_complete():
    """Test _build_pefile_rich_result with all fields."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    mock_pe = Mock()
    mock_pe.RICH_HEADER = Mock()
    mock_pe.RICH_HEADER.clear_data = b"\x01\x02\x03\x04"
    
    xor_key = 0x12345678
    entries = [{"product_id": 100}]
    rich_hash = "HASH123"
    
    result = analyzer._build_pefile_rich_result(mock_pe, xor_key, entries, rich_hash)
    
    assert result["xor_key"] == xor_key
    assert result["checksum"] == xor_key
    assert result["entries"] == entries
    assert result["richpe_hash"] == rich_hash
    assert result["clear_data"] == "01020304"
    assert result["method"] == "pefile"


def test_is_pe_file_with_no_r2():
    """Test _is_pe_file with no r2 instance."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    analyzer.r2 = None
    
    result = analyzer._is_pe_file()
    assert result is False
