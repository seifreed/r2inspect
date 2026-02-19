"""Comprehensive tests for YARA analyzer module in yara_analyzer.py."""

from __future__ import annotations

import os
import signal
import threading
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest

from r2inspect.modules.yara_analyzer import (
    YaraAnalyzer,
    TimeoutException,
    timeout_handler,
    YARA_COMPILE_TIMEOUT,
    YARA_MAX_RULE_SIZE,
)


@pytest.fixture
def mock_adapter():
    """Create a mock adapter for testing."""
    adapter = Mock()
    adapter._cmdj = Mock(return_value={})
    return adapter


@pytest.fixture
def mock_config(tmp_path):
    """Create a mock config for testing."""
    config = Mock()
    rules_path = tmp_path / "yara_rules"
    rules_path.mkdir(exist_ok=True)
    config.get_yara_rules_path.return_value = rules_path
    return config


@pytest.fixture
def sample_yara_rule():
    """Sample YARA rule content."""
    return """
rule TestRule {
    meta:
        description = "Test rule"
        author = "Test"
    strings:
        $str1 = "test"
    condition:
        $str1
}
"""


def test_yara_analyzer_init(mock_adapter, mock_config):
    """Test YaraAnalyzer initialization."""
    analyzer = YaraAnalyzer(mock_adapter, mock_config, filepath="/tmp/test.exe")
    assert analyzer.adapter == mock_adapter
    assert analyzer.config == mock_config
    assert analyzer.filepath == "/tmp/test.exe"


def test_yara_analyzer_init_no_config(mock_adapter):
    """Test YaraAnalyzer initialization without config raises error."""
    with pytest.raises(ValueError, match="config must be provided"):
        YaraAnalyzer(mock_adapter, config=None)


def test_yara_analyzer_scan_no_yara_module(mock_adapter, mock_config):
    """Test scan when YARA module is not available."""
    with patch('r2inspect.modules.yara_analyzer.yara', None):
        analyzer = YaraAnalyzer(mock_adapter, mock_config, filepath="/tmp/test.exe")
        matches = analyzer.scan()
        assert matches == []


def test_yara_analyzer_scan_no_filepath(mock_adapter, mock_config):
    """Test scan when file path cannot be resolved."""
    analyzer = YaraAnalyzer(mock_adapter, mock_config, filepath=None)
    analyzer._cmdj = Mock(return_value={})
    
    matches = analyzer.scan()
    assert matches == []


def test_yara_analyzer_scan_file_not_exists(mock_adapter, mock_config, tmp_path):
    """Test scan when file does not exist."""
    nonexistent = tmp_path / "nonexistent.exe"
    analyzer = YaraAnalyzer(mock_adapter, mock_config, filepath=str(nonexistent))
    
    matches = analyzer.scan()
    assert matches == []


def test_yara_analyzer_scan_rules_not_found(mock_adapter, mock_config, tmp_path):
    """Test scan when rules path does not exist."""
    test_file = tmp_path / "test.exe"
    test_file.write_bytes(b"MZ\x90\x00")
    
    config = Mock()
    config.get_yara_rules_path.return_value = tmp_path / "nonexistent_rules"
    
    with patch('r2inspect.modules.yara_analyzer.yara'):
        analyzer = YaraAnalyzer(mock_adapter, config, filepath=str(test_file))
        matches = analyzer.scan()


def test_yara_analyzer_scan_success(mock_adapter, mock_config, tmp_path, sample_yara_rule):
    """Test successful YARA scan."""
    test_file = tmp_path / "test.exe"
    test_file.write_bytes(b"test content")
    
    rules_path = tmp_path / "yara_rules"
    rules_path.mkdir(exist_ok=True)
    rule_file = rules_path / "test.yar"
    rule_file.write_text(sample_yara_rule)
    
    mock_config.get_yara_rules_path.return_value = rules_path
    
    with patch('r2inspect.modules.yara_analyzer.yara') as mock_yara:
        mock_rules = Mock()
        mock_match = Mock()
        mock_match.rule = "TestRule"
        mock_match.namespace = "default"
        mock_match.tags = []
        mock_match.meta = {"description": "Test rule"}
        mock_match.strings = []
        
        mock_rules.match.return_value = [mock_match]
        mock_yara.compile.return_value = mock_rules
        
        analyzer = YaraAnalyzer(mock_adapter, mock_config, filepath=str(test_file))
        matches = analyzer.scan()
        
        assert len(matches) == 1
        assert matches[0]["rule"] == "TestRule"


def test_yara_analyzer_scan_with_string_matches(mock_adapter, mock_config, tmp_path):
    """Test YARA scan with string matches."""
    test_file = tmp_path / "test.exe"
    test_file.write_bytes(b"test content with pattern")
    
    with patch('r2inspect.modules.yara_analyzer.yara') as mock_yara:
        mock_rules = Mock()
        
        mock_instance = Mock()
        mock_instance.offset = 0
        mock_instance.matched_data = b"pattern"
        mock_instance.length = 7
        
        mock_string = Mock()
        mock_string.identifier = "$pattern"
        mock_string.instances = [mock_instance]
        
        mock_match = Mock()
        mock_match.rule = "TestRule"
        mock_match.namespace = "default"
        mock_match.tags = ["test"]
        mock_match.meta = {}
        mock_match.strings = [mock_string]
        
        mock_rules.match.return_value = [mock_match]
        mock_yara.compile.return_value = mock_rules
        
        analyzer = YaraAnalyzer(mock_adapter, mock_config, filepath=str(test_file))
        matches = analyzer.scan()
        
        assert len(matches) == 1
        assert len(matches[0]["strings"]) == 1
        assert matches[0]["strings"][0]["identifier"] == "$pattern"


def test_yara_analyzer_scan_with_custom_rules(mock_adapter, mock_config, tmp_path, sample_yara_rule):
    """Test scan with custom rules path."""
    test_file = tmp_path / "test.exe"
    test_file.write_bytes(b"test")
    
    custom_rules = tmp_path / "custom_rules"
    custom_rules.mkdir()
    rule_file = custom_rules / "custom.yar"
    rule_file.write_text(sample_yara_rule)
    
    with patch('r2inspect.modules.yara_analyzer.yara') as mock_yara:
        mock_rules = Mock()
        mock_rules.match.return_value = []
        mock_yara.compile.return_value = mock_rules
        
        analyzer = YaraAnalyzer(mock_adapter, mock_config, filepath=str(test_file))
        matches = analyzer.scan(custom_rules_path=str(custom_rules))


def test_yara_analyzer_resolve_file_path_from_adapter(mock_adapter, mock_config):
    """Test resolving file path from adapter."""
    mock_adapter._cmdj = Mock(return_value={
        "core": {"file": "/tmp/test.exe"}
    })
    
    with patch('os.path.exists', return_value=True):
        analyzer = YaraAnalyzer(mock_adapter, mock_config, filepath=None)
        analyzer._cmdj = mock_adapter._cmdj
        file_path = analyzer._resolve_file_path()
        assert file_path == "/tmp/test.exe"


def test_yara_analyzer_compile_rules_single_file(mock_adapter, mock_config, tmp_path, sample_yara_rule):
    """Test compiling rules from single file."""
    rule_file = tmp_path / "test.yar"
    rule_file.write_text(sample_yara_rule)
    
    with patch('r2inspect.modules.yara_analyzer.yara') as mock_yara:
        mock_yara.compile.return_value = Mock()
        
        analyzer = YaraAnalyzer(mock_adapter, mock_config)
        rules = analyzer._compile_rules(str(rule_file))
        
        assert rules is not None
        mock_yara.compile.assert_called_once()


def test_yara_analyzer_compile_rules_directory(mock_adapter, mock_config, tmp_path, sample_yara_rule):
    """Test compiling rules from directory."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    
    rule1 = rules_dir / "rule1.yar"
    rule1.write_text(sample_yara_rule)
    
    rule2 = rules_dir / "rule2.yara"
    rule2.write_text(sample_yara_rule)
    
    with patch('r2inspect.modules.yara_analyzer.yara') as mock_yara:
        mock_yara.compile.return_value = Mock()
        
        analyzer = YaraAnalyzer(mock_adapter, mock_config)
        rules = analyzer._compile_rules(str(rules_dir))
        
        assert rules is not None


def test_yara_analyzer_compile_rules_recursive(mock_adapter, mock_config, tmp_path, sample_yara_rule):
    """Test compiling rules recursively from subdirectories."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    
    subdir = rules_dir / "subdir"
    subdir.mkdir()
    
    rule1 = rules_dir / "rule1.yar"
    rule1.write_text(sample_yara_rule)
    
    rule2 = subdir / "rule2.yar"
    rule2.write_text(sample_yara_rule)
    
    with patch('r2inspect.modules.yara_analyzer.yara') as mock_yara:
        mock_yara.compile.return_value = Mock()
        
        analyzer = YaraAnalyzer(mock_adapter, mock_config)
        rules = analyzer._compile_rules(str(rules_dir))
        
        assert rules is not None


def test_yara_analyzer_compile_rules_with_timeout(mock_adapter, mock_config, tmp_path, sample_yara_rule):
    """Test compiling rules with timeout handling."""
    rule_file = tmp_path / "test.yar"
    rule_file.write_text(sample_yara_rule)
    
    with patch('r2inspect.modules.yara_analyzer.yara') as mock_yara:
        with patch('signal.signal'):
            with patch('signal.alarm'):
                mock_yara.compile.return_value = Mock()
                
                analyzer = YaraAnalyzer(mock_adapter, mock_config)
                rules = analyzer._compile_rules(str(rule_file))
                
                assert rules is not None


def test_yara_analyzer_compile_rules_timeout_exception(mock_adapter, mock_config, tmp_path):
    """Test handling timeout exception during compilation."""
    rule_file = tmp_path / "test.yar"
    rule_file.write_text("rule test { condition: true }")
    
    with patch('r2inspect.modules.yara_analyzer.yara') as mock_yara:
        with patch('signal.signal'):
            with patch('signal.alarm'):
                mock_yara.compile.side_effect = TimeoutException("Timeout")
                
                analyzer = YaraAnalyzer(mock_adapter, mock_config)
                rules = analyzer._compile_rules(str(rule_file))
                
                assert rules is None


def test_yara_analyzer_compile_rules_syntax_error(mock_adapter, mock_config, tmp_path):
    """Test handling YARA syntax error during compilation."""
    rule_file = tmp_path / "bad.yar"
    rule_file.write_text("invalid yara rule")
    
    with patch('r2inspect.modules.yara_analyzer.yara') as mock_yara:
        mock_yara.SyntaxError = Exception
        mock_yara.compile.side_effect = mock_yara.SyntaxError("Syntax error")
        
        analyzer = YaraAnalyzer(mock_adapter, mock_config)
        rules = analyzer._compile_rules(str(rule_file))
        
        assert rules is None


def test_yara_analyzer_compile_rules_file_too_large(mock_adapter, mock_config, tmp_path):
    """Test skipping rule file that exceeds size limit."""
    large_file = tmp_path / "large.yar"
    large_file.write_bytes(b"x" * (YARA_MAX_RULE_SIZE + 1))
    
    with patch('r2inspect.modules.yara_analyzer.yara') as mock_yara:
        analyzer = YaraAnalyzer(mock_adapter, mock_config)
        rules = analyzer._compile_rules(str(large_file))


def test_yara_analyzer_compile_rules_empty_file(mock_adapter, mock_config, tmp_path):
    """Test handling empty rule file."""
    empty_file = tmp_path / "empty.yar"
    empty_file.write_text("")
    
    with patch('r2inspect.modules.yara_analyzer.yara') as mock_yara:
        analyzer = YaraAnalyzer(mock_adapter, mock_config)
        rules = analyzer._compile_rules(str(empty_file))


def test_yara_analyzer_compile_rules_invalid_path(mock_adapter, mock_config, tmp_path):
    """Test compiling rules with invalid path."""
    with patch('r2inspect.modules.yara_analyzer.yara'):
        analyzer = YaraAnalyzer(mock_adapter, mock_config)
        rules = analyzer._compile_rules("/invalid/path")
        assert rules is None


def test_yara_analyzer_compile_rules_caching(mock_adapter, mock_config, tmp_path, sample_yara_rule):
    """Test that compiled rules are cached."""
    rule_file = tmp_path / "test.yar"
    rule_file.write_text(sample_yara_rule)
    
    with patch('r2inspect.modules.yara_analyzer.yara') as mock_yara:
        mock_yara.compile.return_value = Mock()
        
        analyzer = YaraAnalyzer(mock_adapter, mock_config)
        
        rules1 = analyzer._get_cached_rules(str(rule_file))
        rules2 = analyzer._get_cached_rules(str(rule_file))
        
        assert rules1 == rules2
        assert mock_yara.compile.call_count == 1


def test_yara_analyzer_create_default_rules(mock_adapter, mock_config, tmp_path):
    """Test creating default YARA rules."""
    rules_path = tmp_path / "yara_rules"
    mock_config.get_yara_rules_path.return_value = rules_path
    
    analyzer = YaraAnalyzer(mock_adapter, mock_config)
    analyzer.create_default_rules()
    
    assert rules_path.exists()
    rule_files = list(rules_path.glob("*.yar"))
    assert len(rule_files) > 0


def test_yara_analyzer_create_default_rules_error(mock_adapter, mock_config, tmp_path):
    """Test handling error when creating default rules."""
    rules_path = tmp_path / "yara_rules"
    mock_config.get_yara_rules_path.return_value = rules_path
    
    with patch('r2inspect.modules.yara_analyzer.default_file_system.write_text', side_effect=Exception("Write error")):
        analyzer = YaraAnalyzer(mock_adapter, mock_config)
        analyzer.create_default_rules()


def test_yara_analyzer_validate_rules_success(mock_adapter, mock_config, tmp_path, sample_yara_rule):
    """Test successful rule validation."""
    rules_path = tmp_path / "rules"
    rules_path.mkdir()
    rule_file = rules_path / "test.yar"
    rule_file.write_text(sample_yara_rule)
    
    with patch('r2inspect.modules.yara_analyzer.yara') as mock_yara:
        mock_yara.compile.return_value = Mock()
        
        analyzer = YaraAnalyzer(mock_adapter, mock_config)
        result = analyzer.validate_rules(str(rules_path))
        
        assert result["valid"] is True
        assert result["rules_count"] > 0


def test_yara_analyzer_validate_rules_failure(mock_adapter, mock_config, tmp_path):
    """Test rule validation failure."""
    rules_path = tmp_path / "rules"
    rules_path.mkdir()
    bad_rule = rules_path / "bad.yar"
    bad_rule.write_text("invalid rule")
    
    with patch('r2inspect.modules.yara_analyzer.yara') as mock_yara:
        mock_yara.SyntaxError = Exception
        mock_yara.compile.side_effect = mock_yara.SyntaxError("Syntax error")
        
        analyzer = YaraAnalyzer(mock_adapter, mock_config)
        result = analyzer.validate_rules(str(rules_path))
        
        assert result["valid"] is False
        assert len(result["errors"]) > 0


def test_yara_analyzer_validate_rules_single_file(mock_adapter, mock_config, tmp_path, sample_yara_rule):
    """Test validating single rule file."""
    rule_file = tmp_path / "test.yar"
    rule_file.write_text(sample_yara_rule)
    
    with patch('r2inspect.modules.yara_analyzer.yara') as mock_yara:
        mock_yara.compile.return_value = Mock()
        
        analyzer = YaraAnalyzer(mock_adapter, mock_config)
        result = analyzer.validate_rules(str(rule_file))
        
        assert result["valid"] is True
        assert result["rules_count"] == 1


def test_yara_analyzer_list_available_rules_directory(mock_adapter, mock_config, tmp_path, sample_yara_rule):
    """Test listing available rules from directory."""
    rules_path = tmp_path / "rules"
    rules_path.mkdir()
    
    rule1 = rules_path / "rule1.yar"
    rule1.write_text(sample_yara_rule)
    
    rule2 = rules_path / "rule2.yara"
    rule2.write_text(sample_yara_rule)
    
    analyzer = YaraAnalyzer(mock_adapter, mock_config)
    available = analyzer.list_available_rules(str(rules_path))
    
    assert len(available) >= 2
    assert any(r["name"] == "rule1.yar" for r in available)
    assert any(r["name"] == "rule2.yara" for r in available)


def test_yara_analyzer_list_available_rules_single_file(mock_adapter, mock_config, tmp_path, sample_yara_rule):
    """Test listing available rules from single file."""
    rule_file = tmp_path / "test.yar"
    rule_file.write_text(sample_yara_rule)
    
    analyzer = YaraAnalyzer(mock_adapter, mock_config)
    available = analyzer.list_available_rules(str(rule_file))
    
    assert len(available) == 1
    assert available[0]["name"] == "test.yar"
    assert available[0]["type"] == "single_file"


def test_yara_analyzer_list_available_rules_recursive(mock_adapter, mock_config, tmp_path, sample_yara_rule):
    """Test listing available rules recursively."""
    rules_path = tmp_path / "rules"
    rules_path.mkdir()
    
    subdir = rules_path / "subdir"
    subdir.mkdir()
    
    rule1 = rules_path / "rule1.yar"
    rule1.write_text(sample_yara_rule)
    
    rule2 = subdir / "rule2.yar"
    rule2.write_text(sample_yara_rule)
    
    analyzer = YaraAnalyzer(mock_adapter, mock_config)
    available = analyzer.list_available_rules(str(rules_path))
    
    assert len(available) >= 2


def test_yara_analyzer_list_available_rules_not_exists(mock_adapter, mock_config, tmp_path):
    """Test listing rules when path does not exist."""
    analyzer = YaraAnalyzer(mock_adapter, mock_config)
    available = analyzer.list_available_rules(str(tmp_path / "nonexistent"))
    
    assert available == []


def test_yara_analyzer_list_available_rules_with_metadata(mock_adapter, mock_config, tmp_path, sample_yara_rule):
    """Test that listed rules include metadata."""
    rule_file = tmp_path / "test.yar"
    rule_file.write_text(sample_yara_rule)
    
    analyzer = YaraAnalyzer(mock_adapter, mock_config)
    available = analyzer.list_available_rules(str(rule_file))
    
    assert len(available) == 1
    assert "size" in available[0]
    assert "modified" in available[0]
    assert "path" in available[0]


def test_yara_analyzer_process_matches_no_strings(mock_adapter, mock_config):
    """Test processing matches without string matches."""
    mock_match = Mock()
    mock_match.rule = "TestRule"
    mock_match.namespace = "default"
    mock_match.tags = ["test", "malware"]
    mock_match.meta = {"author": "Test Author"}
    mock_match.strings = []
    
    analyzer = YaraAnalyzer(mock_adapter, mock_config)
    matches = analyzer._process_matches([mock_match])
    
    assert len(matches) == 1
    assert matches[0]["rule"] == "TestRule"
    assert matches[0]["tags"] == ["test", "malware"]
    assert matches[0]["meta"]["author"] == "Test Author"
    assert matches[0]["strings"] == []


def test_yara_analyzer_process_matches_with_strings(mock_adapter, mock_config):
    """Test processing matches with string instances."""
    mock_instance = Mock()
    mock_instance.offset = 100
    mock_instance.matched_data = b"test_pattern"
    mock_instance.length = 12
    
    mock_string = Mock()
    mock_string.identifier = "$pattern1"
    mock_string.instances = [mock_instance]
    
    mock_match = Mock()
    mock_match.rule = "TestRule"
    mock_match.namespace = "default"
    mock_match.tags = []
    mock_match.meta = {}
    mock_match.strings = [mock_string]
    
    analyzer = YaraAnalyzer(mock_adapter, mock_config)
    matches = analyzer._process_matches([mock_match])
    
    assert len(matches) == 1
    assert len(matches[0]["strings"]) == 1
    assert matches[0]["strings"][0]["identifier"] == "$pattern1"
    assert len(matches[0]["strings"][0]["instances"]) == 1
    assert matches[0]["strings"][0]["instances"][0]["offset"] == 100


def test_yara_analyzer_process_matches_no_length_attribute(mock_adapter, mock_config):
    """Test processing matches when instance lacks length attribute."""
    mock_instance = Mock(spec=['offset', 'matched_data'])
    mock_instance.offset = 50
    mock_instance.matched_data = b"pattern"
    
    mock_string = Mock()
    mock_string.identifier = "$str"
    mock_string.instances = [mock_instance]
    
    mock_match = Mock()
    mock_match.rule = "Rule"
    mock_match.namespace = "default"
    mock_match.tags = []
    mock_match.meta = {}
    mock_match.strings = [mock_string]
    
    analyzer = YaraAnalyzer(mock_adapter, mock_config)
    matches = analyzer._process_matches([mock_match])
    
    assert matches[0]["strings"][0]["instances"][0]["length"] == 7


def test_yara_analyzer_process_matches_error_handling(mock_adapter, mock_config):
    """Test error handling in match processing."""
    bad_match = Mock()
    bad_match.rule = "TestRule"
    bad_match.namespace = Mock(side_effect=Exception("Error"))
    
    analyzer = YaraAnalyzer(mock_adapter, mock_config)
    matches = analyzer._process_matches([bad_match])
    
    assert matches == []


def test_yara_analyzer_process_matches_multiple(mock_adapter, mock_config):
    """Test processing multiple matches."""
    match1 = Mock()
    match1.rule = "Rule1"
    match1.namespace = "default"
    match1.tags = []
    match1.meta = {}
    match1.strings = []
    
    match2 = Mock()
    match2.rule = "Rule2"
    match2.namespace = "default"
    match2.tags = []
    match2.meta = {}
    match2.strings = []
    
    analyzer = YaraAnalyzer(mock_adapter, mock_config)
    matches = analyzer._process_matches([match1, match2])
    
    assert len(matches) == 2
    assert matches[0]["rule"] == "Rule1"
    assert matches[1]["rule"] == "Rule2"


def test_yara_analyzer_discover_rule_files_multiple_extensions(mock_adapter, mock_config, tmp_path):
    """Test discovering rule files with multiple extensions."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    
    (rules_dir / "rule1.yar").touch()
    (rules_dir / "rule2.yara").touch()
    (rules_dir / "rule3.rule").touch()
    (rules_dir / "rule4.rules").touch()
    
    analyzer = YaraAnalyzer(mock_adapter, mock_config)
    rules_found = analyzer._discover_rule_files(rules_dir)
    
    assert len(rules_found) >= 4


def test_yara_analyzer_no_platform_timeout(mock_adapter, mock_config, tmp_path, sample_yara_rule):
    """Test compilation on platforms without SIGALRM."""
    rule_file = tmp_path / "test.yar"
    rule_file.write_text(sample_yara_rule)
    
    with patch('r2inspect.modules.yara_analyzer.yara') as mock_yara:
        with patch('signal.SIGALRM', create=True, new=None):
            delattr(signal, 'SIGALRM')
            mock_yara.compile.return_value = Mock()
            
            analyzer = YaraAnalyzer(mock_adapter, mock_config)
            rules = analyzer._compile_rules(str(rule_file))
            
            assert rules is not None


def test_yara_analyzer_non_main_thread_compilation(mock_adapter, mock_config, tmp_path, sample_yara_rule):
    """Test compilation from non-main thread."""
    rule_file = tmp_path / "test.yar"
    rule_file.write_text(sample_yara_rule)
    
    result = []
    
    def compile_in_thread():
        with patch('r2inspect.modules.yara_analyzer.yara') as mock_yara:
            mock_yara.compile.return_value = Mock()
            analyzer = YaraAnalyzer(mock_adapter, mock_config)
            rules = analyzer._compile_rules(str(rule_file))
            result.append(rules)
    
    thread = threading.Thread(target=compile_in_thread)
    thread.start()
    thread.join()
    
    assert len(result) == 1


def test_timeout_handler():
    """Test timeout signal handler."""
    with pytest.raises(TimeoutException):
        timeout_handler(signal.SIGALRM, None)


def test_yara_analyzer_scan_exception_handling(mock_adapter, mock_config, tmp_path):
    """Test exception handling during scan."""
    test_file = tmp_path / "test.exe"
    test_file.write_bytes(b"test")
    
    with patch('r2inspect.modules.yara_analyzer.yara') as mock_yara:
        mock_yara.compile.side_effect = Exception("Compilation error")
        
        analyzer = YaraAnalyzer(mock_adapter, mock_config, filepath=str(test_file))
        matches = analyzer.scan()
        
        assert matches == []
