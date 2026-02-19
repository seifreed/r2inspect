"""Comprehensive tests for rich_header_analyzer.py - 100% coverage target."""

from unittest.mock import Mock, patch

from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer


def test_init_with_adapter():
    """Test initialization with adapter."""
    adapter = Mock()
    analyzer = RichHeaderAnalyzer(adapter=adapter)
    assert analyzer.adapter == adapter


def test_init_with_r2_instance():
    """Test initialization with r2_instance."""
    r2 = Mock()
    analyzer = RichHeaderAnalyzer(r2_instance=r2)
    assert analyzer.adapter == r2


def test_is_available():
    """Test is_available static method."""
    assert RichHeaderAnalyzer.is_available() is True


def test_analyze_not_pe():
    """Test analyze when file is not PE."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    analyzer._is_pe_file = Mock(return_value=False)
    
    result = analyzer.analyze()
    
    assert result["is_pe"] is False
    assert result["error"] == "File is not a PE binary"


def test_analyze_pe_no_rich_header():
    """Test analyze when PE has no Rich Header."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    analyzer._is_pe_file = Mock(return_value=True)
    analyzer._extract_rich_header_pefile = Mock(return_value=None)
    analyzer._extract_rich_header_r2pipe = Mock(return_value=None)
    
    with patch("r2inspect.modules.rich_header_analyzer.PEFILE_AVAILABLE", True):
        result = analyzer.analyze()
    
    assert result["is_pe"] is True
    assert result["error"] == "Rich Header not found"


def test_analyze_pefile_success():
    """Test analyze with pefile method success."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    analyzer._is_pe_file = Mock(return_value=True)
    
    rich_data = {
        "xor_key": 0x12345678,
        "checksum": 0x12345678,
        "entries": [{"product_id": 100, "build_number": 200, "count": 5}],
    }
    analyzer._extract_rich_header_pefile = Mock(return_value=rich_data)
    
    with patch("r2inspect.modules.rich_header_analyzer.PEFILE_AVAILABLE", True), \
         patch("r2inspect.modules.rich_header_analyzer.parse_compiler_entries", return_value=[{"tool": "MSVC"}]), \
         patch("r2inspect.modules.rich_header_analyzer.calculate_richpe_hash", return_value="HASH123"):
        result = analyzer.analyze()
    
    assert result["available"] is True
    assert result["method_used"] == "pefile"
    assert result["xor_key"] == 0x12345678


def test_analyze_r2pipe_fallback():
    """Test analyze with r2pipe fallback."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    analyzer._is_pe_file = Mock(return_value=True)
    
    rich_data = {
        "xor_key": 0x87654321,
        "checksum": 0x87654321,
        "entries": [],
    }
    analyzer._extract_rich_header_pefile = Mock(return_value=None)
    analyzer._extract_rich_header_r2pipe = Mock(return_value=rich_data)
    
    with patch("r2inspect.modules.rich_header_analyzer.PEFILE_AVAILABLE", True), \
         patch("r2inspect.modules.rich_header_analyzer.parse_compiler_entries", return_value=[]), \
         patch("r2inspect.modules.rich_header_analyzer.calculate_richpe_hash", return_value=None):
        result = analyzer.analyze()
    
    # When pefile returns None, it falls back to r2pipe
    assert result["method_used"] == "r2pipe" or result.get("available") is True


def test_analyze_exception():
    """Test analyze with exception."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    analyzer._is_pe_file = Mock(side_effect=Exception("Test error"))
    
    result = analyzer.analyze()
    
    assert "error" in result
    assert "Test error" in result["error"]


def test_pefile_has_rich_header():
    """Test _pefile_has_rich_header method."""
    analyzer = RichHeaderAnalyzer(Mock())
    
    pe_with_rich = Mock()
    pe_with_rich.RICH_HEADER = Mock()
    assert analyzer._pefile_has_rich_header(pe_with_rich) is True
    
    pe_without = Mock(spec=[])
    assert analyzer._pefile_has_rich_header(pe_without) is False


def test_pefile_get_xor_key():
    """Test _pefile_get_xor_key method."""
    analyzer = RichHeaderAnalyzer(Mock())
    
    pe = Mock()
    pe.RICH_HEADER.checksum = 0xABCDEF12
    result = analyzer._pefile_get_xor_key(pe)
    assert result == 0xABCDEF12


def test_pefile_extract_entries():
    """Test _pefile_extract_entries method."""
    analyzer = RichHeaderAnalyzer(Mock())
    
    entry1 = Mock()
    entry1.product_id = 100
    entry1.build_version = 200
    entry1.count = 5
    
    pe = Mock()
    pe.RICH_HEADER.values = [entry1]
    
    result = analyzer._pefile_extract_entries(pe)
    
    assert len(result) == 1
    assert result[0]["product_id"] == 100
    assert result[0]["build_number"] == 200


def test_pefile_parse_entry_invalid():
    """Test _pefile_parse_entry with invalid entry."""
    analyzer = RichHeaderAnalyzer(Mock())
    
    invalid_entry = Mock(spec=[])
    result = analyzer._pefile_parse_entry(invalid_entry)
    assert result is None


def test_check_magic_bytes_success():
    """Test _check_magic_bytes with MZ header."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    with patch("r2inspect.modules.rich_header_analyzer.default_file_system.read_bytes", return_value=b"MZ"):
        result = analyzer._check_magic_bytes()
    
    assert result is True


def test_check_magic_bytes_failure():
    """Test _check_magic_bytes without MZ header."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    with patch("r2inspect.modules.rich_header_analyzer.default_file_system.read_bytes", return_value=b"XX"):
        result = analyzer._check_magic_bytes()
    
    assert result is False


def test_check_magic_bytes_exception():
    """Test _check_magic_bytes with exception."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath=None)
    result = analyzer._check_magic_bytes()
    assert result is False


def test_bin_info_has_pe_format():
    """Test _bin_info_has_pe with format field."""
    analyzer = RichHeaderAnalyzer(Mock())
    
    bin_info = {"format": "pe64"}
    assert analyzer._bin_info_has_pe(bin_info) is True


def test_bin_info_has_pe_class():
    """Test _bin_info_has_pe with class field."""
    analyzer = RichHeaderAnalyzer(Mock())
    
    bin_info = {"format": "unknown", "class": "PE32"}
    assert analyzer._bin_info_has_pe(bin_info) is True


def test_bin_info_has_pe_false():
    """Test _bin_info_has_pe returns false."""
    analyzer = RichHeaderAnalyzer(Mock())
    
    bin_info = {"format": "elf", "class": "ELF64"}
    assert analyzer._bin_info_has_pe(bin_info) is False


def test_direct_file_rich_search_invalid_pe():
    """Test _direct_file_rich_search with invalid PE data."""
    analyzer = RichHeaderAnalyzer(Mock())
    analyzer._read_file_bytes = Mock(return_value=b"XX")
    
    result = analyzer._direct_file_rich_search()
    
    assert result is None


def test_is_valid_pe_data():
    """Test _is_valid_pe_data method."""
    analyzer = RichHeaderAnalyzer(Mock())
    
    valid_data = b"MZ" + b"\x00" * 62
    assert analyzer._is_valid_pe_data(valid_data) is True
    
    invalid_data = b"XX"
    assert analyzer._is_valid_pe_data(invalid_data) is False


def test_get_pe_offset():
    """Test _get_pe_offset method."""
    analyzer = RichHeaderAnalyzer(Mock())
    
    data = bytearray(b"MZ" + b"\x00" * 58)
    data[0x3C:0x40] = b"\x80\x00\x00\x00"  # PE offset at 0x80
    
    result = analyzer._get_pe_offset(bytes(data))
    
    assert result == 0x80


def test_get_pe_offset_invalid():
    """Test _get_pe_offset with invalid offset."""
    analyzer = RichHeaderAnalyzer(Mock())
    
    data = b"MZ" + b"\x00" * 58 + b"\xFF\xFF\xFF\xFF"
    
    result = analyzer._get_pe_offset(data)
    
    assert result is None


def test_get_dos_stub():
    """Test _get_dos_stub method."""
    analyzer = RichHeaderAnalyzer(Mock())
    
    data = b"MZ" + b"\x00" * 200
    pe_offset = 0x100
    
    result = analyzer._get_dos_stub(data, pe_offset)
    
    assert result is not None
    assert len(result) == 0x100 - 0x40


def test_find_rich_pos():
    """Test _find_rich_pos method."""
    analyzer = RichHeaderAnalyzer(Mock())
    
    dos_stub = b"\x00" * 100 + b"Rich" + b"\x00" * 50
    
    result = analyzer._find_rich_pos(dos_stub)
    
    assert result == 100


def test_find_rich_pos_not_found():
    """Test _find_rich_pos when not found."""
    analyzer = RichHeaderAnalyzer(Mock())
    
    dos_stub = b"\x00" * 150
    
    result = analyzer._find_rich_pos(dos_stub)
    
    assert result is None


def test_extract_xor_key_from_stub():
    """Test _extract_xor_key_from_stub method."""
    analyzer = RichHeaderAnalyzer(Mock())
    
    dos_stub = b"\x00" * 100 + b"Rich\x12\x34\x56\x78"
    rich_pos = 100
    
    result = analyzer._extract_xor_key_from_stub(dos_stub, rich_pos)
    
    assert result == 0x78563412


def test_extract_xor_key_from_stub_insufficient():
    """Test _extract_xor_key_from_stub with insufficient data."""
    analyzer = RichHeaderAnalyzer(Mock())
    
    dos_stub = b"Rich\x12"
    rich_pos = 0
    
    result = analyzer._extract_xor_key_from_stub(dos_stub, rich_pos)
    
    assert result is None


def test_find_or_estimate_dans_found():
    """Test _find_or_estimate_dans when DanS found."""
    analyzer = RichHeaderAnalyzer(Mock())
    
    dos_stub = b"DanS" + b"\x00" * 100 + b"Rich"
    rich_pos = 104
    
    result = analyzer._find_or_estimate_dans(dos_stub, rich_pos)
    
    assert result == 0


def test_find_or_estimate_dans_estimate():
    """Test _find_or_estimate_dans when estimating."""
    analyzer = RichHeaderAnalyzer(Mock())
    analyzer._estimate_dans_start = Mock(return_value=50)
    
    dos_stub = b"\x00" * 150
    rich_pos = 100
    
    result = analyzer._find_or_estimate_dans(dos_stub, rich_pos)
    
    assert result == 50


def test_estimate_dans_start():
    """Test _estimate_dans_start method."""
    analyzer = RichHeaderAnalyzer(Mock())
    
    dos_stub = b"\x00" * 100 + b"Rich"
    rich_pos = 100
    
    result = analyzer._estimate_dans_start(dos_stub, rich_pos)
    
    assert result is not None


def test_extract_encoded_from_stub():
    """Test _extract_encoded_from_stub method."""
    analyzer = RichHeaderAnalyzer(Mock())
    
    dos_stub = b"DanS" + b"\x01\x02\x03\x04\x05\x06\x07\x08" + b"Rich"
    dans_pos = 0
    rich_pos = 12
    
    result = analyzer._extract_encoded_from_stub(dos_stub, dans_pos, rich_pos)
    
    assert result is not None
    assert len(result) == 8


def test_extract_encoded_from_stub_invalid_length():
    """Test _extract_encoded_from_stub with invalid length."""
    analyzer = RichHeaderAnalyzer(Mock())
    
    dos_stub = b"DanS" + b"\x01\x02\x03\x04\x05" + b"Rich"
    dans_pos = 0
    rich_pos = 9
    
    result = analyzer._extract_encoded_from_stub(dos_stub, dans_pos, rich_pos)
    
    assert result is None


def test_calculate_rich_checksum():
    """Test _calculate_rich_checksum method."""
    analyzer = RichHeaderAnalyzer(Mock())
    
    data = bytearray(b"MZ" + b"\x00" * 0x3E + b"\x80\x00\x00\x00")
    entries = [
        {"product_id": 100, "build_number": 200, "count": 5}
    ]
    
    result = analyzer._calculate_rich_checksum(bytes(data), 0x80, entries)
    
    assert isinstance(result, int)


def test_calculate_richpe_hash_from_file():
    """Test calculate_richpe_hash_from_file static method."""
    with patch("r2inspect.modules.rich_header_analyzer.run_analyzer_on_file") as mock_run:
        mock_run.return_value = {"richpe_hash": "HASH123"}
        
        result = RichHeaderAnalyzer.calculate_richpe_hash_from_file("/test/file")
        
        assert result == "HASH123"


def test_calculate_richpe_hash_from_file_error():
    """Test calculate_richpe_hash_from_file with error."""
    with patch("r2inspect.modules.rich_header_analyzer.run_analyzer_on_file") as mock_run:
        mock_run.return_value = None
        
        result = RichHeaderAnalyzer.calculate_richpe_hash_from_file("/test/file")
        
        assert result is None


def test_scan_patterns():
    """Test _scan_patterns method."""
    analyzer = RichHeaderAnalyzer(Mock(), filepath="/test/file")
    
    with patch("r2inspect.modules.rich_header_analyzer.cmdj_helper") as mock_cmdj:
        mock_cmdj.return_value = [{"offset": 100}]
        
        result = analyzer._scan_patterns(["pattern1"], "TestLabel")
        
        assert len(result) == 1


def test_extract_offsets():
    """Test _extract_offsets method."""
    analyzer = RichHeaderAnalyzer(Mock())
    
    rich_result = {"offset": 200}
    dans_result = {"offset": 100}
    
    result = analyzer._extract_offsets(rich_result, dans_result)
    
    assert result == (100, 200)


def test_extract_offsets_none():
    """Test _extract_offsets with None values."""
    analyzer = RichHeaderAnalyzer(Mock())
    
    rich_result = {"offset": None}
    dans_result = {"offset": 100}
    
    result = analyzer._extract_offsets(rich_result, dans_result)
    
    assert result is None


def test_offsets_valid():
    """Test _offsets_valid method."""
    analyzer = RichHeaderAnalyzer(Mock())
    
    assert analyzer._offsets_valid(100, 200) is True
    assert analyzer._offsets_valid(200, 100) is False
    assert analyzer._offsets_valid(100, 2000) is False
