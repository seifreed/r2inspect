"""Comprehensive tests for tlsh_analyzer.py - 100% coverage target."""

from unittest.mock import Mock, patch, MagicMock

from r2inspect.modules.tlsh_analyzer import TLSHAnalyzer


def test_init():
    """Test TLSHAnalyzer initialization."""
    from pathlib import Path
    adapter = Mock()
    analyzer = TLSHAnalyzer(adapter, "/test/file")
    assert str(analyzer.filepath) == "/test/file" or analyzer.filepath == Path("/test/file")


def test_is_available_true():
    """Test is_available when TLSH is available."""
    with patch("r2inspect.modules.tlsh_analyzer.TLSH_AVAILABLE", True):
        assert TLSHAnalyzer.is_available() is True


def test_is_available_false():
    """Test is_available when TLSH is not available."""
    with patch("r2inspect.modules.tlsh_analyzer.TLSH_AVAILABLE", False):
        assert TLSHAnalyzer.is_available() is False


def test_check_library_availability_success():
    """Test _check_library_availability when available."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch("r2inspect.modules.tlsh_analyzer.TLSHAnalyzer.is_available", return_value=True):
        is_avail, error = analyzer._check_library_availability()
        
        assert is_avail is True
        assert error is None


def test_check_library_availability_failure():
    """Test _check_library_availability when not available."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch("r2inspect.modules.tlsh_analyzer.TLSHAnalyzer.is_available", return_value=False):
        is_avail, error = analyzer._check_library_availability()
        
        assert is_avail is False
        assert "not available" in error


def test_calculate_hash_success():
    """Test _calculate_hash success."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    analyzer._calculate_binary_tlsh = Mock(return_value="T1ABCD123")
    
    hash_val, method, error = analyzer._calculate_hash()
    
    assert hash_val == "T1ABCD123"
    assert method == "python_library"
    assert error is None


def test_calculate_hash_no_hash():
    """Test _calculate_hash when no hash returned."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    analyzer._calculate_binary_tlsh = Mock(return_value=None)
    
    hash_val, method, error = analyzer._calculate_hash()
    
    assert hash_val is None
    assert method is None
    assert "too small" in error


def test_calculate_hash_exception():
    """Test _calculate_hash with exception."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    analyzer._calculate_binary_tlsh = Mock(side_effect=Exception("Test error"))
    
    hash_val, method, error = analyzer._calculate_hash()
    
    assert hash_val is None
    assert error is not None


def test_get_hash_type():
    """Test _get_hash_type method."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    assert analyzer._get_hash_type() == "tlsh"


def test_analyze():
    """Test analyze method adds binary_tlsh."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch.object(analyzer, "_check_library_availability", return_value=(True, None)), \
         patch.object(analyzer, "_calculate_hash", return_value=("HASH123", "method", None)):
        result = analyzer.analyze()
        
        assert "binary_tlsh" in result
        assert result["binary_tlsh"] == "HASH123" or result["hash_value"] == "HASH123"


def test_analyze_sections_not_available():
    """Test analyze_sections when TLSH not available."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch("r2inspect.modules.tlsh_analyzer.TLSH_AVAILABLE", False):
        result = analyzer.analyze_sections()
        
        assert result["available"] is False
        assert "error" in result


def test_analyze_sections_success():
    """Test analyze_sections with success."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    analyzer._calculate_binary_tlsh = Mock(return_value="BINARY_HASH")
    analyzer._calculate_section_tlsh = Mock(return_value={".text": "TEXT_HASH", ".data": "DATA_HASH"})
    analyzer._calculate_function_tlsh = Mock(return_value={"func1": "FUNC_HASH"})
    
    with patch("r2inspect.modules.tlsh_analyzer.TLSH_AVAILABLE", True):
        result = analyzer.analyze_sections()
        
        assert result["available"] is True
        assert result["binary_tlsh"] == "BINARY_HASH"
        assert result["text_section_tlsh"] == "TEXT_HASH"
        assert result["stats"]["sections_analyzed"] == 2
        assert result["stats"]["functions_with_tlsh"] == 1


def test_analyze_sections_exception():
    """Test analyze_sections with exception."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    analyzer._calculate_binary_tlsh = Mock(side_effect=Exception("Test error"))
    
    with patch("r2inspect.modules.tlsh_analyzer.TLSH_AVAILABLE", True):
        result = analyzer.analyze_sections()
        
        assert result["available"] is False
        assert "error" in result


def test_calculate_tlsh_from_hex_success():
    """Test _calculate_tlsh_from_hex with valid data."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    hex_data = "00" * 100  # 100 bytes
    
    with patch("r2inspect.modules.tlsh_analyzer.TLSH_AVAILABLE", True), \
         patch("r2inspect.modules.tlsh_analyzer.tlsh.hash", return_value="T1HASH123"):
        result = analyzer._calculate_tlsh_from_hex(hex_data)
        
        assert result == "T1HASH123"


def test_calculate_tlsh_from_hex_too_small():
    """Test _calculate_tlsh_from_hex with data too small."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    hex_data = "00" * 30  # 30 bytes, less than minimum
    
    result = analyzer._calculate_tlsh_from_hex(hex_data)
    
    assert result is None


def test_calculate_tlsh_from_hex_empty():
    """Test _calculate_tlsh_from_hex with empty data."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    result = analyzer._calculate_tlsh_from_hex("")
    
    assert result is None


def test_calculate_tlsh_from_hex_exception():
    """Test _calculate_tlsh_from_hex with exception."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    hex_data = "invalid_hex"
    
    result = analyzer._calculate_tlsh_from_hex(hex_data)
    
    assert result is None


def test_calculate_binary_tlsh_success():
    """Test _calculate_binary_tlsh success."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    file_data = b"A" * 1000
    
    with patch("r2inspect.modules.tlsh_analyzer.default_file_system.read_bytes", return_value=file_data), \
         patch("r2inspect.modules.tlsh_analyzer.tlsh.hash", return_value="BINARY_HASH"):
        result = analyzer._calculate_binary_tlsh()
        
        assert result == "BINARY_HASH"


def test_calculate_binary_tlsh_too_small():
    """Test _calculate_binary_tlsh with file too small."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    file_data = b"A" * 20
    
    with patch("r2inspect.modules.tlsh_analyzer.default_file_system.read_bytes", return_value=file_data):
        result = analyzer._calculate_binary_tlsh()
        
        assert result is None


def test_calculate_binary_tlsh_exception():
    """Test _calculate_binary_tlsh with exception."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch("r2inspect.modules.tlsh_analyzer.default_file_system.read_bytes", side_effect=Exception("Read error")):
        result = analyzer._calculate_binary_tlsh()
        
        assert result is None


def test_calculate_section_tlsh():
    """Test _calculate_section_tlsh method."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    analyzer._get_sections = Mock(return_value=[
        {"name": ".text", "vaddr": 0x1000, "size": 500},
        {"name": ".data", "vaddr": 0x2000, "size": 0}
    ])
    analyzer._read_bytes_hex = Mock(return_value="AA" * 500)
    analyzer._calculate_tlsh_from_hex = Mock(return_value="SECTION_HASH")
    
    result = analyzer._calculate_section_tlsh()
    
    assert ".text" in result
    assert result[".text"] == "SECTION_HASH"
    assert result[".data"] is None


def test_calculate_section_tlsh_exception():
    """Test _calculate_section_tlsh with exception."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    analyzer._get_sections = Mock(side_effect=Exception("Section error"))
    
    result = analyzer._calculate_section_tlsh()
    
    assert result == {}


def test_calculate_function_tlsh():
    """Test _calculate_function_tlsh method."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    analyzer._get_functions = Mock(return_value=[
        {"name": "main", "addr": 0x1000, "size": 200},
        {"name": "helper", "addr": 0x2000, "size": 0}
    ])
    analyzer._read_bytes_hex = Mock(return_value="BB" * 200)
    analyzer._calculate_tlsh_from_hex = Mock(return_value="FUNC_HASH")
    
    result = analyzer._calculate_function_tlsh()
    
    assert "main" in result
    assert result["main"] == "FUNC_HASH"
    assert result["helper"] is None


def test_calculate_function_tlsh_malformed():
    """Test _calculate_function_tlsh with malformed function data."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    analyzer._get_functions = Mock(return_value=[
        "not a dict",
        {"name": "valid", "addr": 0x1000, "size": 100}
    ])
    analyzer._read_bytes_hex = Mock(return_value="CC" * 100)
    analyzer._calculate_tlsh_from_hex = Mock(return_value="HASH")
    
    result = analyzer._calculate_function_tlsh()
    
    assert "valid" in result


def test_calculate_function_tlsh_limit():
    """Test _calculate_function_tlsh with function limit."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    functions = [{"name": f"func{i}", "addr": 0x1000 + i * 100, "size": 100} for i in range(60)]
    analyzer._get_functions = Mock(return_value=functions)
    analyzer._read_bytes_hex = Mock(return_value="DD" * 100)
    analyzer._calculate_tlsh_from_hex = Mock(return_value="HASH")
    
    result = analyzer._calculate_function_tlsh()
    
    # Should only process first 50
    assert len(result) == 50


def test_compare_tlsh():
    """Test compare_tlsh method."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch("r2inspect.modules.tlsh_analyzer.tlsh.diff", return_value=25):
        result = analyzer.compare_tlsh("HASH1", "HASH2")
        
        assert result == 25


def test_compare_tlsh_empty_hash():
    """Test compare_tlsh with empty hash."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    result = analyzer.compare_tlsh("", "HASH2")
    
    assert result is None


def test_compare_tlsh_exception():
    """Test compare_tlsh with exception."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch("r2inspect.modules.tlsh_analyzer.tlsh.diff", side_effect=Exception("Compare error")):
        result = analyzer.compare_tlsh("HASH1", "HASH2")
        
        assert result is None


def test_find_similar_sections():
    """Test find_similar_sections method."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    analyzer.analyze = Mock(return_value={
        "available": True,
        "section_tlsh": {
            ".text": "HASH1",
            ".data": "HASH2",
            ".rdata": "HASH3"
        }
    })
    analyzer.compare_tlsh = Mock(side_effect=lambda h1, h2: 30 if h1 != h2 else 0)
    
    result = analyzer.find_similar_sections(threshold=100)
    
    assert len(result) > 0


def test_find_similar_sections_not_available():
    """Test find_similar_sections when not available."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    analyzer.analyze = Mock(return_value={"available": False})
    
    result = analyzer.find_similar_sections()
    
    assert result == []


def test_compare_hashes_static():
    """Test compare_hashes static method."""
    with patch("r2inspect.modules.tlsh_analyzer.TLSH_AVAILABLE", True), \
         patch("r2inspect.modules.tlsh_analyzer.tlsh.diff", return_value=15):
        result = TLSHAnalyzer.compare_hashes("HASH1", "HASH2")
        
        assert result == 15


def test_compare_hashes_not_available():
    """Test compare_hashes when TLSH not available."""
    with patch("r2inspect.modules.tlsh_analyzer.TLSH_AVAILABLE", False):
        result = TLSHAnalyzer.compare_hashes("HASH1", "HASH2")
        
        assert result is None


def test_compare_hashes_empty():
    """Test compare_hashes with empty hashes."""
    result = TLSHAnalyzer.compare_hashes("", "HASH2")
    assert result is None


def test_get_similarity_level():
    """Test get_similarity_level static method."""
    assert TLSHAnalyzer.get_similarity_level(None) == "Unknown"
    assert TLSHAnalyzer.get_similarity_level(0) == "Identical"
    assert TLSHAnalyzer.get_similarity_level(20) == "Very Similar"
    assert TLSHAnalyzer.get_similarity_level(40) == "Similar"
    assert TLSHAnalyzer.get_similarity_level(75) == "Somewhat Similar"
    assert TLSHAnalyzer.get_similarity_level(150) == "Different"
    assert TLSHAnalyzer.get_similarity_level(300) == "Very Different"


def test_get_sections():
    """Test _get_sections method."""
    adapter = Mock()
    adapter.get_sections.return_value = [{"name": ".text"}]
    analyzer = TLSHAnalyzer(adapter, "/test/file")
    
    result = analyzer._get_sections()
    
    assert len(result) == 1


def test_get_functions():
    """Test _get_functions method."""
    adapter = Mock()
    adapter.get_functions.return_value = [{"name": "main"}]
    analyzer = TLSHAnalyzer(adapter, "/test/file")
    
    result = analyzer._get_functions()
    
    assert len(result) == 1


def test_read_bytes_hex():
    """Test _read_bytes_hex method."""
    adapter = Mock()
    adapter.read_bytes.return_value = b"\x01\x02\x03\x04"
    analyzer = TLSHAnalyzer(adapter, "/test/file")
    
    result = analyzer._read_bytes_hex(0x1000, 4)
    
    assert result == "01020304"


def test_read_bytes_hex_exception():
    """Test _read_bytes_hex with exception."""
    adapter = Mock()
    adapter.read_bytes.side_effect = Exception("Read error")
    analyzer = TLSHAnalyzer(adapter, "/test/file")
    
    result = analyzer._read_bytes_hex(0x1000, 4)
    
    assert result is None
