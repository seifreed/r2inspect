"""Comprehensive tests for ssdeep_analyzer.py - 100% coverage target."""

from unittest.mock import Mock, patch, MagicMock
import subprocess

from r2inspect.modules.ssdeep_analyzer import SSDeepAnalyzer


def test_init():
    """Test SSDeepAnalyzer initialization."""
    from pathlib import Path
    analyzer = SSDeepAnalyzer("/test/file")
    assert str(analyzer.filepath) == "/test/file" or analyzer.filepath == Path("/test/file")


def test_is_available_with_library():
    """Test is_available when library is available."""
    with patch("r2inspect.modules.ssdeep_analyzer.get_ssdeep", return_value=Mock()):
        assert SSDeepAnalyzer.is_available() is True


def test_is_available_with_binary():
    """Test is_available when binary is available."""
    with patch("r2inspect.modules.ssdeep_analyzer.get_ssdeep", return_value=None), \
         patch("r2inspect.modules.ssdeep_analyzer.SSDeepAnalyzer._resolve_ssdeep_binary", return_value="/usr/bin/ssdeep"), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = Mock(returncode=0)
        
        assert SSDeepAnalyzer.is_available() is True


def test_is_available_false():
    """Test is_available when neither available."""
    with patch("r2inspect.modules.ssdeep_analyzer.get_ssdeep", return_value=None), \
         patch("r2inspect.modules.ssdeep_analyzer.SSDeepAnalyzer._resolve_ssdeep_binary", return_value=None):
        assert SSDeepAnalyzer.is_available() is False


def test_check_library_availability_true():
    """Test _check_library_availability when available."""
    analyzer = SSDeepAnalyzer("/test/file")
    
    with patch.object(SSDeepAnalyzer, "is_available", return_value=True):
        is_avail, error = analyzer._check_library_availability()
        
        assert is_avail is True
        assert error is None


def test_check_library_availability_false():
    """Test _check_library_availability when not available."""
    analyzer = SSDeepAnalyzer("/test/file")
    
    with patch.object(SSDeepAnalyzer, "is_available", return_value=False):
        is_avail, error = analyzer._check_library_availability()
        
        assert is_avail is False
        assert "not available" in error


def test_calculate_hash_library_success():
    """Test _calculate_hash with library success."""
    analyzer = SSDeepAnalyzer("/test/file")
    
    mock_ssdeep = Mock()
    mock_ssdeep.hash.return_value = "ssdeep_hash_123"
    
    with patch("r2inspect.modules.ssdeep_analyzer.get_ssdeep", return_value=mock_ssdeep), \
         patch("r2inspect.modules.ssdeep_analyzer.default_file_system.read_bytes", return_value=b"test data"):
        hash_val, method, error = analyzer._calculate_hash()
        
        assert hash_val == "ssdeep_hash_123"
        assert method == "python_library"
        assert error is None


def test_calculate_hash_library_fallback_to_file():
    """Test _calculate_hash with library fallback to hash_from_file."""
    analyzer = SSDeepAnalyzer("/test/file")
    
    mock_ssdeep = Mock()
    mock_ssdeep.hash.side_effect = OSError("Read error")
    mock_ssdeep.hash_from_file.return_value = "ssdeep_hash_456"
    
    with patch("r2inspect.modules.ssdeep_analyzer.get_ssdeep", return_value=mock_ssdeep):
        hash_val, method, error = analyzer._calculate_hash()
        
        assert hash_val == "ssdeep_hash_456"
        assert method == "python_library"


def test_calculate_hash_binary_success():
    """Test _calculate_hash with binary success."""
    analyzer = SSDeepAnalyzer("/test/file")
    
    with patch("r2inspect.modules.ssdeep_analyzer.get_ssdeep", return_value=None), \
         patch.object(analyzer, "_calculate_with_binary", return_value=("binary_hash", "system_binary")):
        hash_val, method, error = analyzer._calculate_hash()
        
        assert hash_val == "binary_hash"
        assert method == "system_binary"


def test_calculate_hash_binary_failure():
    """Test _calculate_hash with binary failure."""
    analyzer = SSDeepAnalyzer("/test/file")
    
    with patch("r2inspect.modules.ssdeep_analyzer.get_ssdeep", return_value=None), \
         patch.object(analyzer, "_calculate_with_binary", side_effect=Exception("Binary error")):
        hash_val, method, error = analyzer._calculate_hash()
        
        assert hash_val is None
        assert "Binary error" in error


def test_calculate_with_binary_success():
    """Test _calculate_with_binary success."""
    analyzer = SSDeepAnalyzer("/test/file")
    
    mock_result = Mock()
    mock_result.returncode = 0
    mock_result.stdout = "ssdeep,1.1--blocksize:hash:hash,/test/file\n123:ABC:DEF,/test/file"
    
    with patch.object(SSDeepAnalyzer, "_resolve_ssdeep_binary", return_value="/usr/bin/ssdeep"), \
         patch("subprocess.run", return_value=mock_result), \
         patch("r2inspect.modules.ssdeep_analyzer.FileValidator") as mock_validator:
        mock_val_inst = Mock()
        mock_val_inst.validate_path.return_value = "/test/file"
        mock_val_inst.sanitize_for_subprocess.return_value = "/test/file"
        mock_validator.return_value = mock_val_inst
        
        hash_val, method = analyzer._calculate_with_binary()
        
        assert hash_val == "123:ABC:DEF"
        assert method == "system_binary"


def test_calculate_with_binary_no_binary():
    """Test _calculate_with_binary when binary not found."""
    analyzer = SSDeepAnalyzer("/test/file")
    
    with patch.object(SSDeepAnalyzer, "_resolve_ssdeep_binary", return_value=None):
        try:
            analyzer._calculate_with_binary()
            assert False, "Should have raised RuntimeError"
        except RuntimeError as e:
            assert "not found" in str(e)


def test_calculate_with_binary_validation_error():
    """Test _calculate_with_binary with path validation error."""
    analyzer = SSDeepAnalyzer("/test/file")
    
    with patch.object(SSDeepAnalyzer, "_resolve_ssdeep_binary", return_value="/usr/bin/ssdeep"), \
         patch("r2inspect.modules.ssdeep_analyzer.FileValidator") as mock_validator:
        mock_val_inst = Mock()
        mock_val_inst.validate_path.side_effect = ValueError("Invalid path")
        mock_validator.return_value = mock_val_inst
        
        try:
            analyzer._calculate_with_binary()
            assert False, "Should have raised RuntimeError"
        except RuntimeError as e:
            assert "validation failed" in str(e)


def test_calculate_with_binary_timeout():
    """Test _calculate_with_binary with timeout."""
    analyzer = SSDeepAnalyzer("/test/file")
    
    with patch.object(SSDeepAnalyzer, "_resolve_ssdeep_binary", return_value="/usr/bin/ssdeep"), \
         patch("subprocess.run", side_effect=subprocess.TimeoutExpired("ssdeep", 30)), \
         patch("r2inspect.modules.ssdeep_analyzer.FileValidator") as mock_validator:
        mock_val_inst = Mock()
        mock_val_inst.validate_path.return_value = "/test/file"
        mock_val_inst.sanitize_for_subprocess.return_value = "/test/file"
        mock_validator.return_value = mock_val_inst
        
        try:
            analyzer._calculate_with_binary()
            assert False, "Should have raised RuntimeError"
        except RuntimeError as e:
            assert "timed out" in str(e)


def test_get_hash_type():
    """Test _get_hash_type method."""
    analyzer = SSDeepAnalyzer("/test/file")
    assert analyzer._get_hash_type() == "ssdeep"


def test_compare_hashes_library_success():
    """Test compare_hashes with library success."""
    mock_ssdeep = Mock()
    mock_ssdeep.compare.return_value = 85
    
    with patch("r2inspect.modules.ssdeep_analyzer.get_ssdeep", return_value=mock_ssdeep):
        result = SSDeepAnalyzer.compare_hashes("hash1", "hash2")
        
        assert result == 85


def test_compare_hashes_empty():
    """Test compare_hashes with empty hash."""
    result = SSDeepAnalyzer.compare_hashes("", "hash2")
    assert result is None


def test_compare_hashes_binary_fallback():
    """Test compare_hashes with binary fallback."""
    with patch("r2inspect.modules.ssdeep_analyzer.get_ssdeep", return_value=None), \
         patch.object(SSDeepAnalyzer, "_compare_with_binary", return_value=75):
        result = SSDeepAnalyzer.compare_hashes("hash1", "hash2")
        
        assert result == 75


def test_compare_with_binary_success():
    """Test _compare_with_binary success."""
    mock_result = Mock()
    mock_result.returncode = 0
    mock_result.stdout = "hash1,hash2 matches (85)"
    
    with patch.object(SSDeepAnalyzer, "_resolve_ssdeep_binary", return_value="/usr/bin/ssdeep"), \
         patch("subprocess.run", return_value=mock_result), \
         patch("tempfile.TemporaryDirectory") as mock_tempdir, \
         patch.object(SSDeepAnalyzer, "_write_temp_hash_file"):
        mock_td = Mock()
        mock_td.name = "/tmp/test"
        mock_td.__enter__ = Mock(return_value=mock_td)
        mock_td.__exit__ = Mock(return_value=False)
        mock_tempdir.return_value = mock_td
        
        result = SSDeepAnalyzer._compare_with_binary("hash1", "hash2")
        
        assert result == 85


def test_parse_ssdeep_output():
    """Test _parse_ssdeep_output method."""
    output = "file1,file2 matches (92)"
    result = SSDeepAnalyzer._parse_ssdeep_output(output)
    assert result == 92


def test_parse_ssdeep_output_no_match():
    """Test _parse_ssdeep_output with no match."""
    output = "No matches found"
    result = SSDeepAnalyzer._parse_ssdeep_output(output)
    assert result is None


def test_write_temp_hash_file():
    """Test _write_temp_hash_file method."""
    import os
    from pathlib import Path
    
    # Use actual temp file for testing
    with patch("os.open") as mock_open, \
         patch("os.write") as mock_write, \
         patch("os.close") as mock_close:
        mock_open.return_value = 5
        
        SSDeepAnalyzer._write_temp_hash_file(Path("/tmp/test.txt"), "test content")
        
        mock_open.assert_called_once()
        mock_write.assert_called_once()
        mock_close.assert_called_once_with(5)


def test_resolve_ssdeep_binary():
    """Test _resolve_ssdeep_binary method."""
    with patch("shutil.which", return_value="/usr/bin/ssdeep"):
        result = SSDeepAnalyzer._resolve_ssdeep_binary()
        assert result == "/usr/bin/ssdeep"


def test_is_ssdeep_binary_available():
    """Test _is_ssdeep_binary_available method."""
    analyzer = SSDeepAnalyzer("/test/file")
    
    with patch.object(SSDeepAnalyzer, "_resolve_ssdeep_binary", return_value="/usr/bin/ssdeep"):
        assert analyzer._is_ssdeep_binary_available() is True
    
    with patch.object(SSDeepAnalyzer, "_resolve_ssdeep_binary", return_value=None):
        assert analyzer._is_ssdeep_binary_available() is False
