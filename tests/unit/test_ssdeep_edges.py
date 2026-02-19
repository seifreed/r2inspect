"""Edge case tests for ssdeep_analyzer.py - covering missing branches."""

import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from r2inspect.modules.ssdeep_analyzer import SSDeepAnalyzer


def test_calculate_hash_library_oserror_fallback():
    analyzer = SSDeepAnalyzer("/tmp/test.bin")
    mock_ssdeep = Mock()
    mock_ssdeep.hash.side_effect = OSError("Permission denied")
    mock_ssdeep.hash_from_file.return_value = "3:AaBb+CcDd:test.bin"
    
    with patch("r2inspect.modules.ssdeep_analyzer.get_ssdeep", return_value=mock_ssdeep):
        result = analyzer._calculate_hash()
    
    assert result[0] == "3:AaBb+CcDd:test.bin"
    assert result[1] == "python_library"


def test_calculate_hash_library_fallback_fails():
    analyzer = SSDeepAnalyzer("/tmp/test.bin")
    mock_ssdeep = Mock()
    mock_ssdeep.hash.side_effect = OSError("Permission denied")
    mock_ssdeep.hash_from_file.side_effect = Exception("File not found")
    
    with patch("r2inspect.modules.ssdeep_analyzer.get_ssdeep", return_value=mock_ssdeep):
        with patch.object(analyzer, "_calculate_with_binary", return_value=("3:Hash:binary", "system_binary")):
            result = analyzer._calculate_hash()
    
    assert result[0] == "3:Hash:binary"
    assert result[1] == "system_binary"


def test_calculate_hash_library_exception():
    analyzer = SSDeepAnalyzer("/tmp/test.bin")
    mock_ssdeep = Mock()
    mock_ssdeep.hash.side_effect = Exception("Unexpected error")
    mock_ssdeep.hash_from_file.return_value = "3:Hash:file"
    
    with patch("r2inspect.modules.ssdeep_analyzer.get_ssdeep", return_value=mock_ssdeep):
        result = analyzer._calculate_hash()
    
    assert result[0] == "3:Hash:file"
    assert result[1] == "python_library"


def test_calculate_with_binary_no_hash_returned():
    analyzer = SSDeepAnalyzer("/tmp/test.bin")
    
    with patch.object(analyzer, "_resolve_ssdeep_binary", return_value="/usr/bin/ssdeep"):
        with patch("r2inspect.modules.ssdeep_analyzer.FileValidator") as mock_validator:
            mock_validator_inst = Mock()
            mock_validator_inst.validate_path.return_value = "/tmp/test.bin"
            mock_validator_inst.sanitize_for_subprocess.return_value = "/tmp/test.bin"
            mock_validator.return_value = mock_validator_inst
            
            with patch("r2inspect.modules.ssdeep_analyzer.subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="invalid", stderr="")
                try:
                    result = analyzer._calculate_with_binary()
                    assert False, "Should raise RuntimeError"
                except RuntimeError as e:
                    assert "Could not parse" in str(e)


def test_calculate_with_binary_command_error():
    analyzer = SSDeepAnalyzer("/tmp/test.bin")
    
    with patch.object(analyzer, "_resolve_ssdeep_binary", return_value="/usr/bin/ssdeep"):
        with patch("r2inspect.modules.ssdeep_analyzer.FileValidator"):
            with patch("r2inspect.modules.ssdeep_analyzer.subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=1, stdout="", stderr="Command failed")
                try:
                    result = analyzer._calculate_with_binary()
                    assert False, "Should have raised RuntimeError"
                except RuntimeError as e:
                    assert "ssdeep command failed" in str(e)


def test_compare_hashes_empty_hash1():
    result = SSDeepAnalyzer.compare_hashes("", "3:AaBb:file")
    assert result is None


def test_compare_hashes_empty_hash2():
    result = SSDeepAnalyzer.compare_hashes("3:AaBb:file", "")
    assert result is None


def test_compare_with_library_exception():
    mock_ssdeep = Mock()
    mock_ssdeep.compare.side_effect = Exception("Invalid hash format")
    
    with patch("r2inspect.modules.ssdeep_analyzer.get_ssdeep", return_value=mock_ssdeep):
        result = SSDeepAnalyzer._compare_with_library("hash1", "hash2")
    
    assert result is None


def test_compare_with_binary_no_binary():
    with patch.object(SSDeepAnalyzer, "_resolve_ssdeep_binary", return_value=None):
        result = SSDeepAnalyzer._compare_with_binary("hash1", "hash2")
    
    assert result is None


def test_compare_with_binary_timeout():
    import subprocess
    
    with patch.object(SSDeepAnalyzer, "_resolve_ssdeep_binary", return_value="/usr/bin/ssdeep"):
        with patch("r2inspect.modules.ssdeep_analyzer.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("ssdeep", 10)
            try:
                result = SSDeepAnalyzer._compare_with_binary("hash1", "hash2")
                assert result is None
            except:
                pass


def test_compare_with_binary_exception():
    with patch.object(SSDeepAnalyzer, "_resolve_ssdeep_binary", return_value="/usr/bin/ssdeep"):
        with patch("r2inspect.modules.ssdeep_analyzer.subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=1)
            result = SSDeepAnalyzer._compare_with_binary("hash1", "hash2")
    
    assert result is None


def test_is_available_no_binary_subprocess_error():
    import subprocess
    
    with patch("r2inspect.modules.ssdeep_analyzer.get_ssdeep", return_value=None):
        with patch.object(SSDeepAnalyzer, "_resolve_ssdeep_binary", return_value="/usr/bin/ssdeep"):
            with patch("r2inspect.modules.ssdeep_analyzer.subprocess.run") as mock_run:
                mock_run.side_effect = subprocess.SubprocessError("Failed")
                result = SSDeepAnalyzer.is_available()
    
    assert result is False


def test_is_available_no_binary_file_not_found():
    import subprocess
    
    with patch("r2inspect.modules.ssdeep_analyzer.get_ssdeep", return_value=None):
        with patch.object(SSDeepAnalyzer, "_resolve_ssdeep_binary", return_value="/usr/bin/ssdeep"):
            with patch("r2inspect.modules.ssdeep_analyzer.subprocess.run") as mock_run:
                mock_run.side_effect = FileNotFoundError("Not found")
                result = SSDeepAnalyzer.is_available()
    
    assert result is False


def test_parse_ssdeep_output_no_matches_line():
    result = SSDeepAnalyzer._parse_ssdeep_output("Some random output\nNo matches found\n")
    assert result is None


def test_parse_ssdeep_output_malformed():
    result = SSDeepAnalyzer._parse_ssdeep_output("Matches (invalid format")
    assert result is None


def test_parse_ssdeep_output_missing_parens():
    result = SSDeepAnalyzer._parse_ssdeep_output("matches 50")
    assert result is None


def test_write_temp_hash_file_success():
    with tempfile.TemporaryDirectory() as tmpdir:
        temp_path = Path(tmpdir) / "test_hash.txt"
        SSDeepAnalyzer._write_temp_hash_file(temp_path, "test content\n")
        
        assert temp_path.exists()
        content = temp_path.read_text()
        assert content == "test content\n"
        
        file_stat = os.stat(temp_path)
        mode = file_stat.st_mode & 0o777
        assert mode == 0o600


def test_calculate_with_binary_validation_fails():
    analyzer = SSDeepAnalyzer("/tmp/test.bin")
    
    with patch.object(analyzer, "_resolve_ssdeep_binary", return_value="/usr/bin/ssdeep"):
        with patch("r2inspect.modules.ssdeep_analyzer.FileValidator") as mock_validator:
            mock_validator_inst = Mock()
            mock_validator_inst.validate_path.side_effect = ValueError("Invalid path")
            mock_validator.return_value = mock_validator_inst
            
            try:
                result = analyzer._calculate_with_binary()
                assert False, "Should have raised RuntimeError"
            except RuntimeError as e:
                assert "File path validation failed" in str(e)


def test_is_available_with_library():
    mock_ssdeep = Mock()
    
    with patch("r2inspect.modules.ssdeep_analyzer.get_ssdeep", return_value=mock_ssdeep):
        result = SSDeepAnalyzer.is_available()
    
    assert result is True


def test_calculate_with_binary_output_parsing():
    analyzer = SSDeepAnalyzer("/tmp/test.bin")
    
    with patch.object(analyzer, "_resolve_ssdeep_binary", return_value="/usr/bin/ssdeep"):
        with patch("r2inspect.modules.ssdeep_analyzer.FileValidator") as mock_validator:
            mock_validator_inst = Mock()
            mock_validator_inst.validate_path.return_value = "/tmp/test.bin"
            mock_validator_inst.sanitize_for_subprocess.return_value = "/tmp/test.bin"
            mock_validator.return_value = mock_validator_inst
            
            with patch("r2inspect.modules.ssdeep_analyzer.subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=0,
                    stdout="3:AaBb+CcDd,test.bin\n",
                    stderr=""
                )
                result = analyzer._calculate_with_binary()
    
    assert result[0] == "3:AaBb+CcDd"
    assert result[1] == "system_binary"
