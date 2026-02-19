"""Comprehensive tests for telfhash_analyzer.py - hashing functionality."""

import os
from pathlib import Path
from unittest.mock import Mock, patch

from r2inspect.modules.telfhash_analyzer import TelfhashAnalyzer

SAMPLES_DIR = Path(__file__).parent.parent.parent / "samples" / "fixtures"
HELLO_ELF = SAMPLES_DIR / "hello_elf"


def test_init():
    """Test TelfhashAnalyzer initialization."""
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    assert str(analyzer.filepath) == "/test/file" or analyzer.filepath == Path("/test/file")
    assert analyzer.adapter is adapter


def test_is_available_true():
    """Test is_available when telfhash is available."""
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True):
        assert TelfhashAnalyzer.is_available() is True


def test_is_available_false():
    """Test is_available when telfhash is not available."""
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", False):
        assert TelfhashAnalyzer.is_available() is False


def test_check_library_availability_success():
    """Test _check_library_availability when available."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True):
        is_avail, error = analyzer._check_library_availability()
        
        assert is_avail is True
        assert error is None


def test_check_library_availability_failure():
    """Test _check_library_availability when not available."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", False):
        is_avail, error = analyzer._check_library_availability()
        
        assert is_avail is False
        assert "not available" in error


def test_get_hash_type():
    """Test _get_hash_type method."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    assert analyzer._get_hash_type() == "telfhash"


def test_calculate_hash_not_elf():
    """Test _calculate_hash when file is not ELF."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    analyzer._is_elf_file = Mock(return_value=False)
    
    hash_val, method, error = analyzer._calculate_hash()
    
    assert hash_val is None
    assert method is None
    assert "not an ELF" in error


def test_calculate_hash_list_return():
    """Test _calculate_hash when telfhash returns list."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    analyzer._is_elf_file = Mock(return_value=True)
    
    mock_result = [{"telfhash": "T1234ABCD"}]
    
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True), \
         patch("r2inspect.modules.telfhash_analyzer.telfhash", return_value=mock_result):
        hash_val, method, error = analyzer._calculate_hash()
        
        assert hash_val == "T1234ABCD"
        assert method == "python_library"
        assert error is None


def test_calculate_hash_dict_return():
    """Test _calculate_hash when telfhash returns dict."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    analyzer._is_elf_file = Mock(return_value=True)
    
    mock_result = {"telfhash": "T5678EFGH"}
    
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True), \
         patch("r2inspect.modules.telfhash_analyzer.telfhash", return_value=mock_result):
        hash_val, method, error = analyzer._calculate_hash()
        
        assert hash_val == "T5678EFGH"
        assert method == "python_library"
        assert error is None


def test_calculate_hash_string_return():
    """Test _calculate_hash when telfhash returns string."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    analyzer._is_elf_file = Mock(return_value=True)
    
    mock_result = "T9999IJKL"
    
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True), \
         patch("r2inspect.modules.telfhash_analyzer.telfhash", return_value=mock_result):
        hash_val, method, error = analyzer._calculate_hash()
        
        assert hash_val == "T9999IJKL"
        assert method == "python_library"
        assert error is None


def test_calculate_hash_list_with_msg():
    """Test _calculate_hash when telfhash returns list with msg."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    analyzer._is_elf_file = Mock(return_value=True)
    
    mock_result = [{"msg": "Not enough symbols", "telfhash": None}]
    
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True), \
         patch("r2inspect.modules.telfhash_analyzer.telfhash", return_value=mock_result):
        hash_val, method, error = analyzer._calculate_hash()
        
        assert hash_val is None
        assert method is None
        assert "Not enough symbols" in error


def test_calculate_hash_dict_with_msg():
    """Test _calculate_hash when telfhash returns dict with msg."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    analyzer._is_elf_file = Mock(return_value=True)
    
    mock_result = {"msg": "Invalid ELF", "telfhash": None}
    
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True), \
         patch("r2inspect.modules.telfhash_analyzer.telfhash", return_value=mock_result):
        hash_val, method, error = analyzer._calculate_hash()
        
        assert hash_val is None
        assert method is None
        assert "Invalid ELF" in error


def test_calculate_hash_no_hash():
    """Test _calculate_hash when no hash returned."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    analyzer._is_elf_file = Mock(return_value=True)
    
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True), \
         patch("r2inspect.modules.telfhash_analyzer.telfhash", return_value=None):
        hash_val, method, error = analyzer._calculate_hash()
        
        assert hash_val is None
        assert method is None
        assert "returned no hash" in error


def test_calculate_hash_exception():
    """Test _calculate_hash with exception."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    analyzer._is_elf_file = Mock(return_value=True)
    
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True), \
         patch("r2inspect.modules.telfhash_analyzer.telfhash", side_effect=Exception("Test error")):
        hash_val, method, error = analyzer._calculate_hash()
        
        assert hash_val is None
        assert method is None
        assert "failed" in error


def test_analyze_adds_telfhash_field():
    """Test analyze method adds telfhash field."""
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    
    mock_stat = Mock()
    mock_stat.st_size = 1000
    
    with patch.object(analyzer, "_validate_file", return_value=None), \
         patch.object(Path, "stat", return_value=mock_stat), \
         patch.object(analyzer, "_check_library_availability", return_value=(True, None)), \
         patch.object(analyzer, "_calculate_hash", return_value=("HASH123", "method", None)):
        result = analyzer.analyze()
        
        assert "telfhash" in result
        assert result["hash_value"] == "HASH123"
        assert result["telfhash"] == "HASH123"


def test_calculate_telfhash_from_file_success_list():
    """Test calculate_telfhash_from_file with list return."""
    mock_result = [{"telfhash": "T1111AAAA"}]
    
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True), \
         patch("r2inspect.modules.telfhash_analyzer.telfhash", return_value=mock_result):
        result = TelfhashAnalyzer.calculate_telfhash_from_file("/test/file")
        
        assert result == "T1111AAAA"


def test_calculate_telfhash_from_file_success_dict():
    """Test calculate_telfhash_from_file with dict return."""
    mock_result = {"telfhash": "T2222BBBB"}
    
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True), \
         patch("r2inspect.modules.telfhash_analyzer.telfhash", return_value=mock_result):
        result = TelfhashAnalyzer.calculate_telfhash_from_file("/test/file")
        
        assert result == "T2222BBBB"


def test_calculate_telfhash_from_file_success_string():
    """Test calculate_telfhash_from_file with string return."""
    mock_result = "T3333CCCC"
    
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True), \
         patch("r2inspect.modules.telfhash_analyzer.telfhash", return_value=mock_result):
        result = TelfhashAnalyzer.calculate_telfhash_from_file("/test/file")
        
        assert result == "T3333CCCC"


def test_calculate_telfhash_from_file_not_available():
    """Test calculate_telfhash_from_file when not available."""
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", False):
        result = TelfhashAnalyzer.calculate_telfhash_from_file("/test/file")
        
        assert result is None


def test_calculate_telfhash_from_file_exception():
    """Test calculate_telfhash_from_file with exception."""
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True), \
         patch("r2inspect.modules.telfhash_analyzer.telfhash", side_effect=Exception("File not found")):
        result = TelfhashAnalyzer.calculate_telfhash_from_file("/nonexistent/file")
        
        assert result is None


def test_calculate_hash_with_real_elf():
    """Test _calculate_hash with real ELF file if available and telfhash installed."""
    if not HELLO_ELF.exists():
        return
    
    try:
        import telfhash as telfhash_module
        adapter = Mock()
        adapter.get_file_info = Mock(return_value={"bin": {"os": "linux"}})
        
        analyzer = TelfhashAnalyzer(adapter, str(HELLO_ELF))
        analyzer._is_elf_file = Mock(return_value=True)
        
        hash_val, method, error = analyzer._calculate_hash()
        
        if hash_val:
            assert isinstance(hash_val, str)
            assert method == "python_library"
            assert error is None
    except ImportError:
        pass
