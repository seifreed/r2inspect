"""Comprehensive tests for tlsh_analyzer.py - hashing functionality."""

import os
from pathlib import Path
from unittest.mock import Mock, patch

from r2inspect.modules.tlsh_analyzer import TLSHAnalyzer

SAMPLES_DIR = Path(__file__).parent.parent.parent / "samples" / "fixtures"
HELLO_PE = SAMPLES_DIR / "hello_pe.exe"


def test_init():
    """Test TLSHAnalyzer initialization."""
    adapter = Mock()
    analyzer = TLSHAnalyzer(adapter, "/test/file")
    assert str(analyzer.filepath) == "/test/file" or analyzer.filepath == Path("/test/file")
    assert analyzer.adapter is adapter


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
    
    with patch.object(TLSHAnalyzer, "is_available", return_value=True):
        is_avail, error = analyzer._check_library_availability()
        
        assert is_avail is True
        assert error is None


def test_check_library_availability_failure():
    """Test _check_library_availability when not available."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch.object(TLSHAnalyzer, "is_available", return_value=False):
        is_avail, error = analyzer._check_library_availability()
        
        assert is_avail is False
        assert "not available" in error


def test_get_hash_type():
    """Test _get_hash_type method."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    assert analyzer._get_hash_type() == "tlsh"


def test_calculate_hash_success():
    """Test _calculate_hash with success."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch.object(analyzer, "_calculate_binary_tlsh", return_value="T1ABCD123"):
        hash_val, method, error = analyzer._calculate_hash()
        
        assert hash_val == "T1ABCD123"
        assert method == "python_library"
        assert error is None


def test_calculate_hash_no_hash():
    """Test _calculate_hash when no hash returned."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch.object(analyzer, "_calculate_binary_tlsh", return_value=None):
        hash_val, method, error = analyzer._calculate_hash()
        
        assert hash_val is None
        assert method is None
        assert "too small" in error


def test_calculate_hash_exception():
    """Test _calculate_hash with exception."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch.object(analyzer, "_calculate_binary_tlsh", side_effect=Exception("Test error")):
        hash_val, method, error = analyzer._calculate_hash()
        
        assert hash_val is None
        assert method is None
        assert "failed" in error


def test_analyze_adds_binary_tlsh():
    """Test analyze method adds binary_tlsh field."""
    adapter = Mock()
    analyzer = TLSHAnalyzer(adapter, "/test/file")
    
    mock_stat = Mock()
    mock_stat.st_size = 1000
    
    with patch.object(analyzer, "_validate_file", return_value=None), \
         patch.object(Path, "stat", return_value=mock_stat), \
         patch.object(analyzer, "_check_library_availability", return_value=(True, None)), \
         patch.object(analyzer, "_calculate_hash", return_value=("HASH123", "method", None)):
        result = analyzer.analyze()
        
        assert "binary_tlsh" in result
        assert result["hash_value"] == "HASH123"
        assert result["binary_tlsh"] == "HASH123"


def test_calculate_tlsh_from_hex_success():
    """Test _calculate_tlsh_from_hex with valid data."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    hex_data = "00" * 100
    
    with patch("r2inspect.modules.tlsh_analyzer.TLSH_AVAILABLE", True), \
         patch("r2inspect.modules.tlsh_analyzer.tlsh.hash", return_value="T1HASH123"):
        result = analyzer._calculate_tlsh_from_hex(hex_data)
        
        assert result == "T1HASH123"


def test_calculate_tlsh_from_hex_too_small():
    """Test _calculate_tlsh_from_hex with data too small."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    hex_data = "00" * 30
    
    result = analyzer._calculate_tlsh_from_hex(hex_data)
    
    assert result is None


def test_calculate_tlsh_from_hex_empty():
    """Test _calculate_tlsh_from_hex with empty data."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    result = analyzer._calculate_tlsh_from_hex("")
    
    assert result is None


def test_calculate_tlsh_from_hex_none():
    """Test _calculate_tlsh_from_hex with None."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    result = analyzer._calculate_tlsh_from_hex(None)
    
    assert result is None


def test_calculate_tlsh_from_hex_whitespace():
    """Test _calculate_tlsh_from_hex with whitespace only."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    result = analyzer._calculate_tlsh_from_hex("   ")
    
    assert result is None


def test_calculate_tlsh_from_hex_invalid_hex():
    """Test _calculate_tlsh_from_hex with invalid hex."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    hex_data = "invalid_hex_data"
    
    result = analyzer._calculate_tlsh_from_hex(hex_data)
    
    assert result is None


def test_calculate_binary_tlsh_success():
    """Test _calculate_binary_tlsh with success."""
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


def test_calculate_binary_tlsh_empty():
    """Test _calculate_binary_tlsh with empty file."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch("r2inspect.modules.tlsh_analyzer.default_file_system.read_bytes", return_value=b""):
        result = analyzer._calculate_binary_tlsh()
        
        assert result is None


def test_calculate_binary_tlsh_none():
    """Test _calculate_binary_tlsh with None data."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch("r2inspect.modules.tlsh_analyzer.default_file_system.read_bytes", return_value=None):
        result = analyzer._calculate_binary_tlsh()
        
        assert result is None


def test_calculate_binary_tlsh_exception():
    """Test _calculate_binary_tlsh with exception."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch("r2inspect.modules.tlsh_analyzer.default_file_system.read_bytes", side_effect=Exception("Read error")):
        result = analyzer._calculate_binary_tlsh()
        
        assert result is None


def test_compare_hashes_success():
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


def test_compare_hashes_empty_hash1():
    """Test compare_hashes with empty first hash."""
    result = TLSHAnalyzer.compare_hashes("", "HASH2")
    
    assert result is None


def test_compare_hashes_empty_hash2():
    """Test compare_hashes with empty second hash."""
    result = TLSHAnalyzer.compare_hashes("HASH1", "")
    
    assert result is None


def test_compare_hashes_none_hash1():
    """Test compare_hashes with None first hash."""
    result = TLSHAnalyzer.compare_hashes(None, "HASH2")
    
    assert result is None


def test_compare_hashes_none_hash2():
    """Test compare_hashes with None second hash."""
    result = TLSHAnalyzer.compare_hashes("HASH1", None)
    
    assert result is None


def test_compare_hashes_exception():
    """Test compare_hashes with exception."""
    with patch("r2inspect.modules.tlsh_analyzer.TLSH_AVAILABLE", True), \
         patch("r2inspect.modules.tlsh_analyzer.tlsh.diff", side_effect=Exception("Compare error")):
        result = TLSHAnalyzer.compare_hashes("HASH1", "HASH2")
        
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


def test_get_similarity_level_boundaries():
    """Test get_similarity_level boundary values."""
    assert TLSHAnalyzer.get_similarity_level(30) == "Very Similar"
    assert TLSHAnalyzer.get_similarity_level(31) == "Similar"
    assert TLSHAnalyzer.get_similarity_level(50) == "Similar"
    assert TLSHAnalyzer.get_similarity_level(51) == "Somewhat Similar"
    assert TLSHAnalyzer.get_similarity_level(100) == "Somewhat Similar"
    assert TLSHAnalyzer.get_similarity_level(101) == "Different"
    assert TLSHAnalyzer.get_similarity_level(200) == "Different"
    assert TLSHAnalyzer.get_similarity_level(201) == "Very Different"


def test_calculate_binary_tlsh_with_real_binary():
    """Test _calculate_binary_tlsh with real binary if available and tlsh installed."""
    if not HELLO_PE.exists():
        return
    
    try:
        import tlsh as tlsh_module
        analyzer = TLSHAnalyzer(Mock(), str(HELLO_PE))
        
        result = analyzer._calculate_binary_tlsh()
        
        if result:
            assert isinstance(result, str)
            assert len(result) > 0
    except ImportError:
        pass


def test_tlsh_min_data_size_constant():
    """Test TLSH_MIN_DATA_SIZE constant."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    assert analyzer.TLSH_MIN_DATA_SIZE == 50
    assert hasattr(analyzer, "TLSH_MIN_DATA_SIZE")
    assert isinstance(analyzer.TLSH_MIN_DATA_SIZE, int)
