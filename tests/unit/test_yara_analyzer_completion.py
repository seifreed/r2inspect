#!/usr/bin/env python3
"""Comprehensive tests for YARA analyzer - complete coverage."""

import os
import signal
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, Mock

import pytest

from r2inspect.modules.yara_analyzer import (
    YaraAnalyzer,
    TimeoutException,
    _COMPILED_CACHE,
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


def test_scan_with_file_path_from_adapter():
    """Test scan with file path from adapter."""
    file_info = {"core": {"file": "/test/sample.bin"}}
    adapter = FakeAdapter(file_info)
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath=None)
    
    with patch.object(analyzer, '_cmdj', return_value=file_info):
        with patch('os.path.exists', return_value=True):
            with patch.object(analyzer, '_resolve_rules_path', return_value=None):
                result = analyzer.scan()
                assert result == []


def test_scan_with_custom_rules_path():
    """Test scan with custom rules path."""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    with patch.object(analyzer, '_resolve_file_path', return_value="/tmp/test.bin"):
        with patch.object(analyzer, '_resolve_rules_path', return_value="/custom/rules"):
            with patch.object(analyzer, '_get_cached_rules', return_value=None):
                result = analyzer.scan(custom_rules_path="/custom/rules")
                assert result == []


def test_scan_with_compiled_rules_and_matches(tmp_path):
    """Test scan with compiled rules that match."""
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"test content")
    
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath=str(test_file))
    
    mock_match = Mock()
    mock_match.rule = "TestRule"
    mock_match.namespace = "default"
    mock_match.tags = ["test"]
    mock_match.meta = {"author": "tester"}
    
    mock_instance = Mock()
    mock_instance.offset = 0
    mock_instance.matched_data = b"test"
    mock_instance.length = 4
    
    mock_string = Mock()
    mock_string.identifier = "$test"
    mock_string.instances = [mock_instance]
    mock_match.strings = [mock_string]
    
    mock_rules = Mock()
    mock_rules.match.return_value = [mock_match]
    
    with patch.object(analyzer, '_get_cached_rules', return_value=mock_rules):
        with patch('os.path.exists', return_value=True):
            result = analyzer.scan()
            assert len(result) == 1
            assert result[0]["rule"] == "TestRule"
            assert len(result[0]["strings"]) == 1


def test_get_cached_rules_cache_hit():
    """Test _get_cached_rules returns from cache."""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    cached_rules = Mock()
    _COMPILED_CACHE["/test/path"] = cached_rules
    
    try:
        result = analyzer._get_cached_rules("/test/path")
        assert result == cached_rules
    finally:
        _COMPILED_CACHE.pop("/test/path", None)


def test_get_cached_rules_cache_miss():
    """Test _get_cached_rules compiles and caches."""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    mock_rules = Mock()
    
    with patch.object(analyzer, '_compile_rules', return_value=mock_rules):
        result = analyzer._get_cached_rules("/new/path")
        assert result == mock_rules
        assert "/new/path" in _COMPILED_CACHE
        _COMPILED_CACHE.pop("/new/path", None)


def test_compile_rules_yara_not_available():
    """Test _compile_rules when yara is None."""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    with patch('r2inspect.modules.yara_analyzer.yara', None):
        result = analyzer._compile_rules("/test/path")
        assert result is None


def test_compile_rules_path_validation_fails():
    """Test _compile_rules with path validation failure."""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    mock_validator = Mock()
    mock_validator.validate_path.side_effect = ValueError("Invalid path")
    
    with patch('r2inspect.modules.yara_analyzer.FileValidator', return_value=mock_validator):
        result = analyzer._compile_rules("/bad/path")
        assert result is None


def test_compile_rules_directory_with_rules(tmp_path):
    """Test _compile_rules with directory containing rules."""
    rule_file = tmp_path / "test.yar"
    rule_file.write_text("rule test { condition: true }")
    
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    mock_validator = Mock()
    mock_validator.validate_path.return_value = tmp_path
    
    mock_compiled = Mock()
    
    with patch('r2inspect.modules.yara_analyzer.FileValidator', return_value=mock_validator):
        with patch.object(analyzer, '_read_rule_content', return_value="rule test { condition: true }"):
            with patch('r2inspect.modules.yara_analyzer.yara') as mock_yara:
                mock_yara.compile.return_value = mock_compiled
                result = analyzer._compile_rules(str(tmp_path))
                assert result == mock_compiled


def test_compile_rules_single_file(tmp_path):
    """Test _compile_rules with single file."""
    rule_file = tmp_path / "test.yar"
    rule_file.write_text("rule test { condition: true }")
    
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    mock_validator = Mock()
    mock_validator.validate_path.return_value = rule_file
    
    mock_compiled = Mock()
    
    with patch('r2inspect.modules.yara_analyzer.FileValidator', return_value=mock_validator):
        with patch.object(analyzer, '_read_rule_content', return_value="rule test { condition: true }"):
            with patch('r2inspect.modules.yara_analyzer.yara') as mock_yara:
                mock_yara.compile.return_value = mock_compiled
                result = analyzer._compile_rules(str(rule_file))
                assert result == mock_compiled


def test_compile_rules_fallback_to_defaults(tmp_path):
    """Test _compile_rules falls back to defaults when no rules found."""
    adapter = FakeAdapter()
    config = FakeConfig(str(tmp_path))
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    mock_validator = Mock()
    mock_validator.validate_path.return_value = tmp_path
    
    with patch('r2inspect.modules.yara_analyzer.FileValidator', return_value=mock_validator):
        with patch.object(analyzer, '_discover_rule_files', return_value=[]):
            with patch.object(analyzer, '_compile_default_rules', return_value=Mock()) as mock_compile_default:
                result = analyzer._compile_rules(str(tmp_path))
                mock_compile_default.assert_called_once()


def test_compile_sources_with_timeout_main_thread_success():
    """Test _compile_sources_with_timeout in main thread with success."""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    mock_compiled = Mock()
    rules_dict = {"test": "rule test { condition: true }"}
    
    with patch('r2inspect.modules.yara_analyzer.yara') as mock_yara:
        mock_yara.compile.return_value = mock_compiled
        with patch('signal.signal'):
            with patch('signal.alarm'):
                result = analyzer._compile_sources_with_timeout(rules_dict)
                assert result == mock_compiled


def test_compile_sources_with_timeout_timeout_exception():
    """Test _compile_sources_with_timeout handles timeout."""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    rules_dict = {"test": "rule test { condition: true }"}
    
    with patch('r2inspect.modules.yara_analyzer.yara') as mock_yara:
        mock_yara.compile.side_effect = TimeoutException("Timeout")
        with patch('signal.signal'):
            with patch('signal.alarm'):
                result = analyzer._compile_sources_with_timeout(rules_dict)
                assert result is None


def test_compile_sources_with_timeout_general_exception():
    """Test _compile_sources_with_timeout handles general exception."""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    rules_dict = {"test": "rule test { condition: true }"}
    
    with patch('r2inspect.modules.yara_analyzer.yara') as mock_yara:
        class YaraSyntaxError(Exception):
            pass
        
        mock_yara.SyntaxError = YaraSyntaxError
        mock_yara.compile.side_effect = ValueError("Compile error")
        with patch('signal.signal'):
            with patch('signal.alarm'):
                result = analyzer._compile_sources_with_timeout(rules_dict)
                assert result is None


def test_process_matches_with_instance_without_length():
    """Test _process_matches with instance without length attribute."""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    mock_match = Mock()
    mock_match.rule = "TestRule"
    mock_match.namespace = "default"
    mock_match.tags = []
    mock_match.meta = {}
    
    mock_instance = Mock(spec=['offset', 'matched_data'])
    mock_instance.offset = 0
    mock_instance.matched_data = b"test"
    
    mock_string = Mock()
    mock_string.identifier = "$test"
    mock_string.instances = [mock_instance]
    mock_match.strings = [mock_string]
    
    result = analyzer._process_matches([mock_match])
    assert len(result) == 1
    assert result[0]["strings"][0]["instances"][0]["length"] == 4


def test_process_matches_error_handling():
    """Test _process_matches handles errors gracefully."""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    mock_match = Mock()
    mock_match.rule.side_effect = Exception("Error")
    
    result = analyzer._process_matches([mock_match])
    assert result == []


def test_load_rules_dir_with_content_read_failure(tmp_path):
    """Test _load_rules_dir when content reading fails."""
    rule_file = tmp_path / "test.yar"
    rule_file.touch()
    
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    mock_validator = Mock()
    
    with patch.object(analyzer, '_discover_rule_files', return_value=[rule_file]):
        with patch.object(analyzer, '_read_rule_content', return_value=None):
            result = analyzer._load_rules_dir(mock_validator, tmp_path)
            assert result == {}


def test_read_rule_content_path_validation_fails(tmp_path):
    """Test _read_rule_content with path validation failure."""
    rule_file = tmp_path / "test.yar"
    rule_file.write_text("content")
    
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    mock_validator = Mock()
    mock_validator.validate_path.side_effect = ValueError("Invalid")
    
    result = analyzer._read_rule_content(mock_validator, rule_file)
    assert result is None


def test_read_rule_content_read_exception(tmp_path):
    """Test _read_rule_content with read exception."""
    rule_file = tmp_path / "test.yar"
    rule_file.write_text("content")
    
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    mock_validator = Mock()
    mock_validator.validate_path.return_value = rule_file
    
    with patch('r2inspect.modules.yara_analyzer.default_file_system.read_text', side_effect=Exception("Read error")):
        result = analyzer._read_rule_content(mock_validator, rule_file)
        assert result is None


def test_compile_default_rules_success(tmp_path):
    """Test _compile_default_rules successfully creates defaults."""
    rules_path = tmp_path / "rules"
    rules_path.mkdir()
    (rules_path / "packer_detection.yar").write_text("rule test { condition: true }")
    
    adapter = FakeAdapter()
    config = FakeConfig(str(rules_path))
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    mock_compiled = Mock()
    
    with patch('r2inspect.modules.yara_analyzer.yara') as mock_yara:
        mock_yara.compile.return_value = mock_compiled
        result = analyzer._compile_default_rules(str(rules_path))
        assert result == mock_compiled


def test_list_available_rules_with_file_errors(tmp_path):
    """Test list_available_rules handles individual file errors."""
    rule_file = tmp_path / "test.yar"
    rule_file.write_text("rule test { condition: true }")
    
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    with patch.object(Path, 'rglob', return_value=[rule_file]):
        with patch.object(Path, 'stat', side_effect=OSError("Permission denied")):
            with patch.object(Path, 'relative_to', return_value=Path("test.yar")):
                rules = analyzer.list_available_rules(str(tmp_path))


def test_list_available_rules_general_exception():
    """Test list_available_rules handles general exception."""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    
    with patch('os.path.exists', side_effect=Exception("Unexpected error")):
        rules = analyzer.list_available_rules("/test/path")
        assert rules == []


def test_scan_resolve_rules_creates_defaults_and_exists(tmp_path):
    """Test scan when resolve_rules_path creates defaults that exist."""
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"test")
    
    rules_path = tmp_path / "rules"
    
    adapter = FakeAdapter()
    config = FakeConfig(str(rules_path))
    analyzer = YaraAnalyzer(adapter, config=config, filepath=str(test_file))
    
    with patch('os.path.exists', side_effect=lambda p: p == str(test_file) or p == str(rules_path)):
        with patch.object(analyzer, 'create_default_rules'):
            with patch.object(analyzer, '_get_cached_rules', return_value=None):
                result = analyzer.scan()
                assert result == []
