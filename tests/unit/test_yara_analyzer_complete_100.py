"""Comprehensive tests for yara_analyzer.py - 100% coverage target."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from tests.helpers.r2_fakes import FakeR2Adapter


class FakeYaraConfig:
    """Minimal config object for YaraAnalyzer tests."""

    def __init__(self, rules_path: str = "/tmp/yara_rules") -> None:
        self._rules_path = rules_path

    def get_yara_rules_path(self) -> Path:
        return Path(self._rules_path)


def test_yara_analyzer_init():
    """Test YaraAnalyzer initialization."""
    from r2inspect.modules.yara_analyzer import YaraAnalyzer

    adapter = FakeR2Adapter()
    with tempfile.TemporaryDirectory() as tmpdir:
        config = FakeYaraConfig(rules_path=tmpdir)
        analyzer = YaraAnalyzer(adapter=adapter, config=config)
        assert analyzer.adapter is adapter
        assert analyzer.config is config
        assert analyzer.rules_path == tmpdir


def test_yara_analyzer_init_requires_config():
    """Test YaraAnalyzer raises ValueError without config."""
    from r2inspect.modules.yara_analyzer import YaraAnalyzer

    adapter = FakeR2Adapter()
    try:
        YaraAnalyzer(adapter=adapter, config=None)
        pytest.fail("Should have raised ValueError")
    except ValueError as e:
        assert "config must be provided" in str(e)


def test_yara_analyzer_scan_no_file():
    """Test scan returns empty list when file is not accessible."""
    from r2inspect.modules.yara_analyzer import YaraAnalyzer

    adapter = FakeR2Adapter(cmdj_responses={"ij": {"core": {"file": "/nonexistent"}}})
    with tempfile.TemporaryDirectory() as tmpdir:
        config = FakeYaraConfig(rules_path=tmpdir)
        analyzer = YaraAnalyzer(adapter=adapter, config=config, filepath="/nonexistent")
        result = analyzer.scan()
        assert result == []


def test_yara_analyzer_create_default_rules():
    """Test default YARA rules creation."""
    from r2inspect.modules.yara_analyzer import YaraAnalyzer

    adapter = FakeR2Adapter()
    with tempfile.TemporaryDirectory() as tmpdir:
        rules_dir = os.path.join(tmpdir, "rules")
        config = FakeYaraConfig(rules_path=rules_dir)
        analyzer = YaraAnalyzer(adapter=adapter, config=config)
        analyzer.create_default_rules()
        # Rules directory should be created
        assert os.path.isdir(rules_dir)


def test_yara_analyzer_validate_rules_no_path():
    """Test validate_rules with nonexistent path returns invalid."""
    from r2inspect.modules.yara_analyzer import YaraAnalyzer

    adapter = FakeR2Adapter()
    with tempfile.TemporaryDirectory() as tmpdir:
        config = FakeYaraConfig(rules_path=tmpdir)
        analyzer = YaraAnalyzer(adapter=adapter, config=config)
        result = analyzer.validate_rules("/nonexistent/path")
        assert isinstance(result, dict)
        assert "valid" in result


def test_yara_analyzer_list_available_rules():
    """Test listing available YARA rules."""
    from r2inspect.modules.yara_analyzer import YaraAnalyzer

    adapter = FakeR2Adapter()
    with tempfile.TemporaryDirectory() as tmpdir:
        config = FakeYaraConfig(rules_path=tmpdir)
        analyzer = YaraAnalyzer(adapter=adapter, config=config)
        rules = analyzer.list_available_rules()
        assert isinstance(rules, list)


def test_yara_analyzer_resolve_file_path_from_adapter():
    """Test _resolve_file_path falls back to adapter info."""
    from r2inspect.modules.yara_analyzer import YaraAnalyzer

    adapter = FakeR2Adapter(cmdj_responses={"ij": {"core": {"file": "/nonexistent"}}})
    with tempfile.TemporaryDirectory() as tmpdir:
        config = FakeYaraConfig(rules_path=tmpdir)
        analyzer = YaraAnalyzer(adapter=adapter, config=config, filepath=None)
        path = analyzer._resolve_file_path()
        # File doesn't exist, should return None
        assert path is None


def test_yara_analyzer_resolve_file_path_with_filepath():
    """Test _resolve_file_path uses filepath when provided and exists."""
    from r2inspect.modules.yara_analyzer import YaraAnalyzer

    adapter = FakeR2Adapter()
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "sample.bin")
        with open(test_file, "wb") as f:
            f.write(b"\x00" * 64)
        config = FakeYaraConfig(rules_path=tmpdir)
        analyzer = YaraAnalyzer(adapter=adapter, config=config, filepath=test_file)
        path = analyzer._resolve_file_path()
        assert path == test_file


def test_yara_analyzer_resolve_rules_path_nonexistent():
    """Test _resolve_rules_path when path doesn't exist."""
    from r2inspect.modules.yara_analyzer import YaraAnalyzer

    adapter = FakeR2Adapter()
    with tempfile.TemporaryDirectory() as tmpdir:
        config = FakeYaraConfig(rules_path=tmpdir)
        analyzer = YaraAnalyzer(adapter=adapter, config=config)
        result = analyzer._resolve_rules_path("/definitely/nonexistent/path")
        # Should try to create defaults and return None if still nonexistent
        assert result is None


def test_yara_analyzer_edge_cases():
    """Test edge cases in yara_analyzer."""
    from r2inspect.modules.yara_analyzer import TimeoutException, timeout_handler

    # Test TimeoutException is raised by timeout_handler
    try:
        timeout_handler(0, None)
        pytest.fail("Should have raised TimeoutException")
    except TimeoutException:
        pass
