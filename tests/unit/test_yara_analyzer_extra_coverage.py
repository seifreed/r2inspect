#!/usr/bin/env python3
"""Extra coverage tests for yara_analyzer module.

All tests use real objects — NO mocks, NO monkeypatch, NO @patch.
YaraAnalyzer is exercised through FakeR2 + R2PipeAdapter.
Real YARA rule files are created via tmp_path.
"""

import json
import os
import signal
from pathlib import Path
from typing import Any

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.yara_analyzer import (
    YARA_COMPILE_TIMEOUT,
    YARA_MAX_RULE_SIZE,
    TimeoutException,
    YaraAnalyzer,
    timeout_handler,
)

try:
    import yara as _yara_mod
except Exception:
    _yara_mod = None


# ---------------------------------------------------------------------------
# Helpers — real lightweight objects, no mocks
# ---------------------------------------------------------------------------


class FakeR2:
    """Minimal r2pipe-like object backed by static command maps."""

    def __init__(
        self,
        cmd_map: dict[str, str] | None = None,
        cmdj_map: dict[str, Any] | None = None,
    ):
        self._cmd_map = cmd_map or {}
        self._cmdj_map = cmdj_map or {}

    def cmd(self, command: str) -> str:
        return self._cmd_map.get(command, "")

    def cmdj(self, command: str) -> Any:
        return self._cmdj_map.get(command)


class FakeConfig:
    """Minimal config object providing a YARA rules path."""

    def __init__(self, yara_path: str = "/tmp/yara_rules"):
        self._yara_path = yara_path

    def get_yara_rules_path(self) -> str:
        return self._yara_path


def _make_adapter(
    cmd_map: dict[str, str] | None = None,
    cmdj_map: dict[str, Any] | None = None,
) -> R2PipeAdapter:
    return R2PipeAdapter(FakeR2(cmd_map=cmd_map, cmdj_map=cmdj_map))


def _make_analyzer(
    tmp_path: Path,
    filepath: str | None = None,
    rules_path: str | None = None,
    cmdj_map: dict[str, Any] | None = None,
) -> YaraAnalyzer:
    adapter = _make_adapter(cmdj_map=cmdj_map)
    rp = rules_path or str(tmp_path / "yara_rules")
    config = FakeConfig(rp)
    return YaraAnalyzer(adapter, config=config, filepath=filepath)


def _write_rule(path: Path, name: str = "test_rule") -> Path:
    """Write a valid YARA rule file and return its path."""
    content = f'rule {name} {{ strings: $a = "test" condition: $a }}'
    path.write_text(content, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Basic construction tests
# ---------------------------------------------------------------------------


def test_timeout_exception():
    """TimeoutException stores message correctly."""
    exc = TimeoutException("test timeout")
    assert str(exc) == "test timeout"


def test_timeout_handler():
    """timeout_handler raises TimeoutException."""
    with pytest.raises(TimeoutException, match="YARA compilation timed out"):
        timeout_handler(signal.SIGALRM, None)


def test_yara_analyzer_init_without_config():
    """YaraAnalyzer raises ValueError when config is None."""
    adapter = _make_adapter()
    with pytest.raises(ValueError, match="config must be provided"):
        YaraAnalyzer(adapter, config=None)


def test_yara_analyzer_init_with_config(tmp_path):
    """YaraAnalyzer stores adapter, config, rules_path, filepath."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    adapter = _make_adapter()
    config = FakeConfig(str(rules_dir))
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")

    assert analyzer.adapter is adapter
    assert analyzer.config is config
    assert analyzer.rules_path == str(rules_dir)
    assert analyzer.filepath == "/tmp/test.bin"


# ---------------------------------------------------------------------------
# _resolve_file_path
# ---------------------------------------------------------------------------


def test_resolve_file_path_with_existing_filepath(tmp_path):
    """_resolve_file_path returns filepath when it exists on disk."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x00" * 16)
    analyzer = _make_analyzer(tmp_path, filepath=str(sample))

    path = analyzer._resolve_file_path()
    assert path == str(sample)


def test_resolve_file_path_no_filepath_falls_back_to_r2(tmp_path):
    """_resolve_file_path queries r2 'ij' when filepath is None."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x00" * 16)
    cmdj_map = {"ij": {"core": {"file": str(sample)}}}
    analyzer = _make_analyzer(tmp_path, filepath=None, cmdj_map=cmdj_map)

    path = analyzer._resolve_file_path()
    assert path == str(sample)


def test_resolve_file_path_nonexistent():
    """_resolve_file_path returns None when file does not exist."""
    adapter = _make_adapter()
    config = FakeConfig("/tmp/yara_rules")
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/nonexistent_path_xyz.bin")

    path = analyzer._resolve_file_path()
    assert path is None


def test_resolve_file_path_none_filepath_no_r2_info(tmp_path):
    """_resolve_file_path returns None when filepath is None and r2 gives nothing."""
    analyzer = _make_analyzer(tmp_path, filepath=None)
    path = analyzer._resolve_file_path()
    assert path is None


# ---------------------------------------------------------------------------
# _resolve_rules_path
# ---------------------------------------------------------------------------


def test_resolve_rules_path_existing_dir(tmp_path):
    """_resolve_rules_path returns path when the dir already exists."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    analyzer = _make_analyzer(tmp_path, rules_path=str(rules_dir))

    result = analyzer._resolve_rules_path(None)
    assert result == str(rules_dir)


def test_resolve_rules_path_custom(tmp_path):
    """_resolve_rules_path honours a custom rules path."""
    custom = tmp_path / "custom_rules"
    custom.mkdir()
    analyzer = _make_analyzer(tmp_path)

    result = analyzer._resolve_rules_path(str(custom))
    assert result == str(custom)


def test_resolve_rules_path_creates_defaults(tmp_path):
    """_resolve_rules_path creates default rules when path missing."""
    rules_dir = tmp_path / "yara_rules"
    analyzer = _make_analyzer(tmp_path, rules_path=str(rules_dir))

    # Rules path does not exist yet; _resolve_rules_path should call
    # create_default_rules which creates the directory.
    result = analyzer._resolve_rules_path(None)
    # After creating defaults the directory should exist.
    assert rules_dir.exists()
    assert result == str(rules_dir)


# ---------------------------------------------------------------------------
# _validate_rules_path
# ---------------------------------------------------------------------------


def test_validate_rules_path_success(tmp_path):
    """_validate_rules_path returns Path for a valid existing path."""
    from r2inspect.security.validators import FileValidator

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    analyzer = _make_analyzer(tmp_path)
    validator = FileValidator()

    result = analyzer._validate_rules_path(validator, str(rules_dir))
    assert result is not None
    assert result == rules_dir.resolve()


def test_validate_rules_path_nonexistent(tmp_path):
    """_validate_rules_path returns None for non-existent path."""
    from r2inspect.security.validators import FileValidator

    analyzer = _make_analyzer(tmp_path)
    validator = FileValidator()

    result = analyzer._validate_rules_path(validator, str(tmp_path / "does_not_exist"))
    assert result is None


# ---------------------------------------------------------------------------
# _discover_rule_files
# ---------------------------------------------------------------------------


def test_discover_rule_files_multiple_extensions(tmp_path):
    """_discover_rule_files finds .yar, .yara, .rule, .rules files."""
    (tmp_path / "a.yar").touch()
    (tmp_path / "b.yara").touch()
    (tmp_path / "c.rule").touch()
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "d.rules").touch()

    analyzer = _make_analyzer(tmp_path)
    found = analyzer._discover_rule_files(tmp_path)
    names = {f.name for f in found}
    assert {"a.yar", "b.yara", "c.rule", "d.rules"}.issubset(names)


def test_discover_rule_files_empty_dir(tmp_path):
    """_discover_rule_files returns empty list for empty directory."""
    analyzer = _make_analyzer(tmp_path)
    found = analyzer._discover_rule_files(tmp_path)
    assert found == []


# ---------------------------------------------------------------------------
# _read_rule_content
# ---------------------------------------------------------------------------


def test_read_rule_content_valid(tmp_path):
    """_read_rule_content reads a valid YARA rule file."""
    from r2inspect.security.validators import FileValidator

    rule_file = tmp_path / "test.yar"
    _write_rule(rule_file)

    analyzer = _make_analyzer(tmp_path)
    validator = FileValidator()

    content = analyzer._read_rule_content(validator, rule_file)
    assert content is not None
    assert "rule test_rule" in content


def test_read_rule_content_empty_file(tmp_path):
    """_read_rule_content returns None for empty file."""
    from r2inspect.security.validators import FileValidator

    rule_file = tmp_path / "empty.yar"
    rule_file.write_text("", encoding="utf-8")

    analyzer = _make_analyzer(tmp_path)
    validator = FileValidator()

    content = analyzer._read_rule_content(validator, rule_file)
    assert content is None


def test_read_rule_content_file_too_large(tmp_path):
    """_read_rule_content returns None when file exceeds YARA_MAX_RULE_SIZE."""
    from r2inspect.security.validators import FileValidator

    rule_file = tmp_path / "huge.yar"
    # Create a file larger than max size by writing sparse content
    # We can't actually write 10MB+, but we can make the stat report it.
    # Instead, just write YARA_MAX_RULE_SIZE + 1 bytes.
    rule_file.write_bytes(b"x" * (YARA_MAX_RULE_SIZE + 1))

    analyzer = _make_analyzer(tmp_path)
    validator = FileValidator()

    content = analyzer._read_rule_content(validator, rule_file)
    assert content is None


# ---------------------------------------------------------------------------
# _load_single_rule / _load_rules_dir
# ---------------------------------------------------------------------------


def test_load_single_rule_valid(tmp_path):
    """_load_single_rule returns dict with content for valid rule."""
    from r2inspect.security.validators import FileValidator

    rule_file = tmp_path / "single.yar"
    _write_rule(rule_file, "single_test")

    analyzer = _make_analyzer(tmp_path)
    validator = FileValidator()

    result = analyzer._load_single_rule(validator, rule_file)
    assert "single_rule" in result
    assert "rule single_test" in result["single_rule"]


def test_load_single_rule_empty(tmp_path):
    """_load_single_rule returns {} when file is empty."""
    from r2inspect.security.validators import FileValidator

    rule_file = tmp_path / "empty.yar"
    rule_file.write_text("", encoding="utf-8")

    analyzer = _make_analyzer(tmp_path)
    validator = FileValidator()

    result = analyzer._load_single_rule(validator, rule_file)
    assert result == {}


def test_load_rules_dir_with_rules(tmp_path):
    """_load_rules_dir loads all valid rules from directory."""
    from r2inspect.security.validators import FileValidator

    _write_rule(tmp_path / "a.yar", "rule_a")
    _write_rule(tmp_path / "b.yar", "rule_b")

    analyzer = _make_analyzer(tmp_path)
    validator = FileValidator()

    result = analyzer._load_rules_dir(validator, tmp_path)
    assert len(result) == 2
    assert any("rule_a" in v for v in result.values())
    assert any("rule_b" in v for v in result.values())


def test_load_rules_dir_no_matches(tmp_path):
    """_load_rules_dir returns {} when directory has no rule files."""
    from r2inspect.security.validators import FileValidator

    analyzer = _make_analyzer(tmp_path)
    validator = FileValidator()

    result = analyzer._load_rules_dir(validator, tmp_path)
    assert result == {}


# ---------------------------------------------------------------------------
# _collect_rules_sources
# ---------------------------------------------------------------------------


def test_collect_rules_sources_file(tmp_path):
    """_collect_rules_sources handles a single file path."""
    from r2inspect.security.validators import FileValidator

    rule_file = tmp_path / "single.yar"
    _write_rule(rule_file, "single_src")

    analyzer = _make_analyzer(tmp_path)
    validator = FileValidator()

    result = analyzer._collect_rules_sources(validator, rule_file)
    assert "single_rule" in result


def test_collect_rules_sources_dir(tmp_path):
    """_collect_rules_sources handles a directory."""
    from r2inspect.security.validators import FileValidator

    _write_rule(tmp_path / "r.yar", "dir_rule")

    analyzer = _make_analyzer(tmp_path)
    validator = FileValidator()

    result = analyzer._collect_rules_sources(validator, tmp_path)
    assert len(result) >= 1


# ---------------------------------------------------------------------------
# create_default_rules
# ---------------------------------------------------------------------------


def test_create_default_rules(tmp_path):
    """create_default_rules creates directory and writes default rule files."""
    rules_dir = tmp_path / "yara_defaults"
    analyzer = _make_analyzer(tmp_path, rules_path=str(rules_dir))

    analyzer.create_default_rules()

    assert rules_dir.exists()
    yar_files = list(rules_dir.glob("*.yar"))
    assert len(yar_files) > 0
    # Check content was actually written
    for f in yar_files:
        assert f.stat().st_size > 0


def test_create_default_rules_already_exists(tmp_path):
    """create_default_rules does not overwrite existing files."""
    rules_dir = tmp_path / "yara_defaults"
    rules_dir.mkdir()
    sentinel = rules_dir / "packer_detection.yar"
    sentinel.write_text("sentinel content", encoding="utf-8")

    analyzer = _make_analyzer(tmp_path, rules_path=str(rules_dir))
    analyzer.create_default_rules()

    # The sentinel content should remain intact because the file already existed.
    assert sentinel.read_text() == "sentinel content"


def test_create_default_rules_readonly_parent(tmp_path):
    """create_default_rules does not raise on permission errors."""
    # Use a path inside /nonexistent so mkdir will fail without raising
    analyzer = _make_analyzer(tmp_path, rules_path="/nonexistent/readonly/yara")
    # Should not raise
    analyzer.create_default_rules()


# ---------------------------------------------------------------------------
# validate_rules
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_yara_mod is None, reason="python-yara not installed")
def test_validate_rules_directory(tmp_path):
    """validate_rules returns valid=True for a directory with valid rules."""
    _write_rule(tmp_path / "a.yar", "val_rule_a")
    _write_rule(tmp_path / "b.yara", "val_rule_b")

    analyzer = _make_analyzer(tmp_path)
    result = analyzer.validate_rules(str(tmp_path))

    assert result["valid"] is True
    assert result["rules_count"] >= 2


@pytest.mark.skipif(_yara_mod is None, reason="python-yara not installed")
def test_validate_rules_single_file(tmp_path):
    """validate_rules returns valid=True for a single valid rule file."""
    rule_file = tmp_path / "single.yar"
    _write_rule(rule_file, "val_single")

    analyzer = _make_analyzer(tmp_path)
    result = analyzer.validate_rules(str(rule_file))

    assert result["valid"] is True
    assert result["rules_count"] == 1


@pytest.mark.skipif(_yara_mod is None, reason="python-yara not installed")
def test_validate_rules_compile_failure(tmp_path):
    """validate_rules returns valid=False when rules have syntax errors."""
    bad_rule = tmp_path / "bad.yar"
    bad_rule.write_text("this is not valid yara syntax at all", encoding="utf-8")

    analyzer = _make_analyzer(tmp_path)
    result = analyzer.validate_rules(str(bad_rule))

    # With invalid syntax the compile will fail; valid should be False.
    assert result["valid"] is False


def test_validate_rules_nonexistent_path(tmp_path):
    """validate_rules returns valid=False for non-existent path."""
    analyzer = _make_analyzer(tmp_path)
    result = analyzer.validate_rules(str(tmp_path / "does_not_exist"))

    assert result["valid"] is False


# ---------------------------------------------------------------------------
# list_available_rules
# ---------------------------------------------------------------------------


def test_list_available_rules_single_file(tmp_path):
    """list_available_rules returns info for a single file."""
    rule_file = tmp_path / "test.yar"
    _write_rule(rule_file)

    analyzer = _make_analyzer(tmp_path)
    rules = analyzer.list_available_rules(str(rule_file))

    assert len(rules) == 1
    assert rules[0]["name"] == "test.yar"
    assert rules[0]["type"] == "single_file"


def test_list_available_rules_directory(tmp_path):
    """list_available_rules finds rules in a directory."""
    _write_rule(tmp_path / "r1.yar", "dir1")
    _write_rule(tmp_path / "r2.yara", "dir2")

    analyzer = _make_analyzer(tmp_path)
    rules = analyzer.list_available_rules(str(tmp_path))

    names = {r["name"] for r in rules}
    assert "r1.yar" in names
    assert "r2.yara" in names


def test_list_available_rules_not_exists(tmp_path):
    """list_available_rules returns [] for non-existent path."""
    analyzer = _make_analyzer(tmp_path)
    rules = analyzer.list_available_rules("/nonexistent/path/xyz")
    assert rules == []


# ---------------------------------------------------------------------------
# scan — end-to-end
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_yara_mod is None, reason="python-yara not installed")
def test_scan_with_matching_rule(tmp_path):
    """scan returns matches when a rule matches the target file."""
    # Create a sample binary containing the string "TESTMARKER"
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x00" * 16 + b"TESTMARKER" + b"\x00" * 16)

    # Create a YARA rule that matches "TESTMARKER"
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "marker.yar").write_text(
        'rule MarkerRule { strings: $m = "TESTMARKER" condition: $m }',
        encoding="utf-8",
    )

    # Clear the compiled cache to avoid cross-test contamination
    from r2inspect.modules.yara_analyzer import _COMPILED_CACHE

    _COMPILED_CACHE.pop(str(rules_dir), None)

    analyzer = _make_analyzer(tmp_path, filepath=str(sample), rules_path=str(rules_dir))
    matches = analyzer.scan()

    assert len(matches) >= 1
    assert matches[0]["rule"] == "MarkerRule"


@pytest.mark.skipif(_yara_mod is None, reason="python-yara not installed")
def test_scan_no_match(tmp_path):
    """scan returns empty list when no rules match."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x00" * 64)

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "nomatch.yar").write_text(
        'rule NoMatch { strings: $x = "UNIQUE_STRING_XYZ_999" condition: $x }',
        encoding="utf-8",
    )

    from r2inspect.modules.yara_analyzer import _COMPILED_CACHE

    _COMPILED_CACHE.pop(str(rules_dir), None)

    analyzer = _make_analyzer(tmp_path, filepath=str(sample), rules_path=str(rules_dir))
    matches = analyzer.scan()
    assert matches == []


def test_scan_file_not_found(tmp_path):
    """scan returns [] when target file does not exist."""
    analyzer = _make_analyzer(tmp_path, filepath="/nonexistent_file_xyz.bin")
    matches = analyzer.scan()
    assert matches == []


def test_scan_no_rules_path(tmp_path):
    """scan returns [] when rules path does not exist and defaults fail."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x00" * 16)

    # Use a rules path that does not exist and cannot be created
    analyzer = _make_analyzer(
        tmp_path,
        filepath=str(sample),
        rules_path="/nonexistent/rules/xyz",
    )
    matches = analyzer.scan()
    assert matches == []


# ---------------------------------------------------------------------------
# _compile_rules
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_yara_mod is None, reason="python-yara not installed")
def test_compile_rules_valid(tmp_path):
    """_compile_rules returns compiled rules for valid YARA files."""
    rules_dir = tmp_path / "compile_test"
    rules_dir.mkdir()
    _write_rule(rules_dir / "good.yar", "compile_good")

    analyzer = _make_analyzer(tmp_path)
    compiled = analyzer._compile_rules(str(rules_dir))
    assert compiled is not None


def test_compile_rules_nonexistent(tmp_path):
    """_compile_rules returns None for non-existent path."""
    analyzer = _make_analyzer(tmp_path)
    compiled = analyzer._compile_rules("/nonexistent/rules/xyz")
    assert compiled is None


# ---------------------------------------------------------------------------
# _compile_sources_with_timeout
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_yara_mod is None, reason="python-yara not installed")
def test_compile_sources_with_timeout_valid(tmp_path):
    """_compile_sources_with_timeout compiles valid rule sources."""
    analyzer = _make_analyzer(tmp_path)
    sources = {"test": 'rule TimeoutTest { strings: $a = "abc" condition: $a }'}

    compiled = analyzer._compile_sources_with_timeout(sources)
    assert compiled is not None


@pytest.mark.skipif(_yara_mod is None, reason="python-yara not installed")
def test_compile_sources_with_timeout_syntax_error(tmp_path):
    """_compile_sources_with_timeout returns None on syntax errors."""
    analyzer = _make_analyzer(tmp_path)
    sources = {"bad": "this is not valid yara syntax at all"}

    compiled = analyzer._compile_sources_with_timeout(sources)
    assert compiled is None


# ---------------------------------------------------------------------------
# _compile_default_rules
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_yara_mod is None, reason="python-yara not installed")
def test_compile_default_rules(tmp_path):
    """_compile_default_rules creates and compiles built-in defaults."""
    rules_dir = tmp_path / "yara_defaults"
    analyzer = _make_analyzer(tmp_path, rules_path=str(rules_dir))

    # First create the defaults so the file exists
    analyzer.create_default_rules()
    compiled = analyzer._compile_default_rules(str(rules_dir))
    assert compiled is not None


def test_compile_default_rules_unwritable(tmp_path):
    """_compile_default_rules returns None when defaults cannot be created."""
    # Point rules_path at a location that cannot be created (nested under a file)
    blocker = tmp_path / "blocker"
    blocker.write_text("not a dir")
    impossible_path = str(blocker / "rules")
    analyzer = _make_analyzer(tmp_path, rules_path=impossible_path)

    result = analyzer._compile_default_rules(impossible_path)
    assert result is None


# ---------------------------------------------------------------------------
# _get_cached_rules
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_yara_mod is None, reason="python-yara not installed")
def test_get_cached_rules_caches(tmp_path):
    """_get_cached_rules caches compiled rules on second call."""
    from r2inspect.modules.yara_analyzer import _COMPILED_CACHE

    rules_dir = tmp_path / "cache_test"
    rules_dir.mkdir()
    _write_rule(rules_dir / "cache.yar", "cache_rule")

    cache_key = str(rules_dir)
    _COMPILED_CACHE.pop(cache_key, None)

    analyzer = _make_analyzer(tmp_path)

    first = analyzer._get_cached_rules(cache_key)
    assert first is not None
    assert cache_key in _COMPILED_CACHE

    # Second call should return cached version
    second = analyzer._get_cached_rules(cache_key)
    assert second is first

    # Cleanup
    _COMPILED_CACHE.pop(cache_key, None)


# ---------------------------------------------------------------------------
# Constants sanity
# ---------------------------------------------------------------------------


def test_constants():
    """YARA constants have expected values."""
    assert YARA_COMPILE_TIMEOUT == 30
    assert YARA_MAX_RULE_SIZE == 10 * 1024 * 1024
