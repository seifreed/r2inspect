#!/usr/bin/env python3
"""Extra coverage tests for yara_analyzer module."""

import os
import signal
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest

from r2inspect.modules.yara_analyzer import (
    YaraAnalyzer,
    TimeoutException,
    timeout_handler,
    YARA_COMPILE_TIMEOUT,
    YARA_MAX_RULE_SIZE,
)


class FakeConfig:
    def __init__(self, yara_path=None):
        self._yara_path = yara_path or "/tmp/yara_rules"
    
    def get_yara_rules_path(self):
        return self._yara_path


class FakeAdapter:
    def __init__(self, file_info=None):
        self._file_info = file_info or {}
    
    def cmdj(self, cmd, default):
        if cmd == "ij":
            return self._file_info
        return default


def test_timeout_exception():
    """Test TimeoutException creation"""
    exc = TimeoutException("test timeout")
    assert str(exc) == "test timeout"


def test_timeout_handler():
    """Test timeout signal handler raises TimeoutException"""
    with pytest.raises(TimeoutException, match="YARA compilation timed out"):
        timeout_handler(signal.SIGALRM, None)


def test_yara_analyzer_init_without_config():
    """Test that YaraAnalyzer raises ValueError without config"""
    adapter = FakeAdapter()
    with pytest.raises(ValueError, match="config must be provided"):
        YaraAnalyzer(adapter, config=None)


def test_yara_analyzer_init_with_config():
    """Test YaraAnalyzer initialization with config"""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    assert analyzer.adapter is adapter
    assert analyzer.config is config
    assert analyzer.rules_path == "/tmp/yara_rules"
    assert analyzer.filepath == "/tmp/test.bin"


@patch('r2inspect.modules.yara_analyzer.yara', None)
def test_scan_no_yara_available():
    """Test scan returns empty when yara module not available"""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    matches = analyzer.scan()
    assert matches == []


def test_resolve_file_path_no_filepath():
    """Test _resolve_file_path when filepath is None"""
    file_info = {"core": {"file": "/test/sample.bin"}}
    adapter = FakeAdapter(file_info)
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath=None)
    
    with patch.object(analyzer, '_cmdj', return_value=file_info):
        with patch('os.path.exists', return_value=True):
            path = analyzer._resolve_file_path()
            assert path == "/test/sample.bin"


def test_resolve_file_path_file_not_exists():
    """Test _resolve_file_path returns None when file doesn't exist"""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/nonexistent.bin")
    
    with patch('os.path.exists', return_value=False):
        path = analyzer._resolve_file_path()
        assert path is None


def test_resolve_rules_path_not_exists(tmp_path):
    """Test _resolve_rules_path creates defaults when path doesn't exist"""
    adapter = FakeAdapter()
    rules_path = str(tmp_path / "nonexistent_rules")
    config = FakeConfig(rules_path)
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    with patch.object(analyzer, 'create_default_rules'):
        result = analyzer._resolve_rules_path(None)
        analyzer.create_default_rules.assert_called_once()


def test_validate_rules_path_error():
    """Test _validate_rules_path with validation error"""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    mock_validator = MagicMock()
    mock_validator.validate_path.side_effect = ValueError("Invalid path")
    
    result = analyzer._validate_rules_path(mock_validator, "/bad/path")
    assert result is None


def test_load_single_rule(tmp_path):
    """Test _load_single_rule"""
    rule_file = tmp_path / "test.yar"
    rule_file.write_text("rule test { condition: true }")
    
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    mock_validator = MagicMock()
    mock_validator.validate_path.return_value = rule_file
    
    with patch.object(analyzer, '_read_rule_content', return_value="rule test { condition: true }"):
        result = analyzer._load_single_rule(mock_validator, rule_file)
        assert result == {"single_rule": "rule test { condition: true }"}


def test_load_single_rule_empty():
    """Test _load_single_rule with empty content"""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    mock_validator = MagicMock()
    
    with patch.object(analyzer, '_read_rule_content', return_value=None):
        result = analyzer._load_single_rule(mock_validator, Path("/tmp/test.yar"))
        assert result == {}


def test_discover_rule_files(tmp_path):
    """Test _discover_rule_files finds various extensions"""
    (tmp_path / "test1.yar").touch()
    (tmp_path / "test2.yara").touch()
    (tmp_path / "test3.rule").touch()
    (tmp_path / "subdir").mkdir()
    (tmp_path / "subdir" / "test4.rules").touch()
    
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    rules = analyzer._discover_rule_files(tmp_path)
    assert len(rules) >= 4


def test_read_rule_content_file_too_large(tmp_path):
    """Test _read_rule_content skips files that are too large"""
    large_file = tmp_path / "large.yar"
    large_file.touch()
    
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    mock_validator = MagicMock()
    mock_validator.validate_path.return_value = large_file
    
    with patch.object(Path, 'stat') as mock_stat:
        mock_stat.return_value.st_size = YARA_MAX_RULE_SIZE + 1
        result = analyzer._read_rule_content(mock_validator, large_file)
        assert result is None


def test_read_rule_content_validation_error(tmp_path):
    """Test _read_rule_content with validation error"""
    rule_file = tmp_path / "test.yar"
    rule_file.write_text("rule test { condition: true }")
    
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    mock_validator = MagicMock()
    mock_validator.validate_path.return_value = rule_file
    mock_validator.validate_yara_rule_content.side_effect = ValueError("Bad content")
    
    with patch('r2inspect.modules.yara_analyzer.default_file_system.read_text', return_value="content"):
        result = analyzer._read_rule_content(mock_validator, rule_file)
        assert result is None


def test_read_rule_content_empty_file(tmp_path):
    """Test _read_rule_content with empty file"""
    rule_file = tmp_path / "empty.yar"
    rule_file.write_text("")
    
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    mock_validator = MagicMock()
    mock_validator.validate_path.return_value = rule_file
    
    with patch('r2inspect.modules.yara_analyzer.default_file_system.read_text', return_value=""):
        result = analyzer._read_rule_content(mock_validator, rule_file)
        assert result is None


def test_create_default_rules(tmp_path):
    """Test create_default_rules creates directory and files"""
    rules_path = tmp_path / "yara_rules"
    adapter = FakeAdapter()
    config = FakeConfig(str(rules_path))
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    with patch('r2inspect.modules.yara_analyzer.default_file_system.write_text') as mock_write:
        analyzer.create_default_rules()
        assert rules_path.exists()


def test_create_default_rules_error():
    """Test create_default_rules handles errors"""
    adapter = FakeAdapter()
    config = FakeConfig("/invalid/path")
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    with patch('pathlib.Path.mkdir', side_effect=PermissionError("No permission")):
        analyzer.create_default_rules()  # Should not raise


def test_validate_rules_directory(tmp_path):
    """Test validate_rules with directory"""
    (tmp_path / "test1.yar").write_text("rule test1 { condition: true }")
    (tmp_path / "test2.yara").write_text("rule test2 { condition: true }")
    
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    with patch.object(analyzer, '_compile_rules', return_value=MagicMock()):
        result = analyzer.validate_rules(str(tmp_path))
        assert result["valid"] is True
        assert result["rules_count"] >= 2


def test_validate_rules_single_file(tmp_path):
    """Test validate_rules with single file"""
    rule_file = tmp_path / "test.yar"
    rule_file.write_text("rule test { condition: true }")
    
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    with patch.object(analyzer, '_compile_rules', return_value=MagicMock()):
        result = analyzer.validate_rules(str(rule_file))
        assert result["valid"] is True
        assert result["rules_count"] == 1


def test_validate_rules_failure():
    """Test validate_rules with compilation failure"""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    with patch.object(analyzer, '_compile_rules', return_value=None):
        result = analyzer.validate_rules("/tmp/rules")
        assert result["valid"] is False
        assert "Failed to compile rules" in result["errors"]


def test_validate_rules_exception():
    """Test validate_rules handles exceptions"""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    with patch.object(analyzer, '_compile_rules', side_effect=Exception("test error")):
        result = analyzer.validate_rules("/tmp/rules")
        assert result["valid"] is False
        assert "test error" in result["errors"]


def test_list_available_rules_single_file(tmp_path):
    """Test list_available_rules with single file"""
    rule_file = tmp_path / "test.yar"
    rule_file.write_text("rule test { condition: true }")
    
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    rules = analyzer.list_available_rules(str(rule_file))
    assert len(rules) == 1
    assert rules[0]["name"] == "test.yar"
    assert rules[0]["type"] == "single_file"


def test_list_available_rules_directory(tmp_path):
    """Test list_available_rules with directory"""
    (tmp_path / "test1.yar").write_text("rule test1 { condition: true }")
    (tmp_path / "test2.yara").write_text("rule test2 { condition: true }")
    
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    rules = analyzer.list_available_rules(str(tmp_path))
    assert len(rules) >= 2


def test_list_available_rules_not_exists():
    """Test list_available_rules with non-existent path"""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    rules = analyzer.list_available_rules("/nonexistent/path")
    assert rules == []


def test_list_available_rules_error_handling(tmp_path):
    """Test list_available_rules handles file stat errors"""
    (tmp_path / "test.yar").write_text("rule test { condition: true }")
    
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    with patch.object(Path, 'stat', side_effect=OSError("Permission denied")):
        rules = analyzer.list_available_rules(str(tmp_path))
        # Should continue despite errors


def test_scan_error_handling():
    """Test scan handles errors gracefully"""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    with patch.object(analyzer, '_resolve_file_path', side_effect=Exception("test error")):
        matches = analyzer.scan()
        assert matches == []


@patch('r2inspect.modules.yara_analyzer.yara')
def test_compile_sources_timeout_platform(mock_yara):
    """Test _compile_sources_with_timeout on platform without SIGALRM"""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    mock_yara.compile.return_value = MagicMock()
    
    with patch('signal.SIGALRM', create=True) as mock_sig:
        # Remove SIGALRM to simulate Windows
        delattr(signal, 'SIGALRM')
        
        result = analyzer._compile_sources_with_timeout({"test": "rule test {}"})
        mock_yara.compile.assert_called_once()


@patch('r2inspect.modules.yara_analyzer.yara')
def test_compile_sources_syntax_error(mock_yara):
    """Test _compile_sources_with_timeout handles syntax errors"""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    # Create a proper exception class
    class YaraSyntaxError(Exception):
        pass
    
    mock_yara.SyntaxError = YaraSyntaxError
    mock_yara.compile.side_effect = YaraSyntaxError("Bad syntax")
    
    result = analyzer._compile_sources_with_timeout({"test": "bad rule"})
    assert result is None


def test_load_rules_dir_no_matches(tmp_path):
    """Test _load_rules_dir with no matching files"""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    mock_validator = MagicMock()
    
    with patch.object(analyzer, '_discover_rule_files', return_value=[]):
        result = analyzer._load_rules_dir(mock_validator, tmp_path)
        assert result == {}


def test_collect_rules_sources_invalid_path():
    """Test _collect_rules_sources with invalid path type"""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    mock_validator = MagicMock()
    mock_path = MagicMock()
    mock_path.is_file.return_value = False
    mock_path.is_dir.return_value = False
    
    result = analyzer._collect_rules_sources(mock_validator, mock_path)
    assert result == {}


@patch('r2inspect.modules.yara_analyzer.yara')
def test_compile_default_rules_error(mock_yara, tmp_path):
    """Test _compile_default_rules handles errors"""
    rules_path = tmp_path / "rules"
    rules_path.mkdir()
    
    adapter = FakeAdapter()
    config = FakeConfig(str(rules_path))
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    mock_yara.compile.side_effect = Exception("Compile error")
    
    result = analyzer._compile_default_rules(str(rules_path))
    assert result is None
