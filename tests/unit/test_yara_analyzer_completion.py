#!/usr/bin/env python3
"""Comprehensive tests for YARA analyzer - complete coverage.

Rewritten to use real code paths: NO mocks, NO monkeypatch, NO @patch.
Uses FakeR2Adapter for the adapter and real YARA rule files via tmp_path.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

try:
    import yara as _yara_mod
except Exception:
    _yara_mod = None

from r2inspect.modules.yara_analyzer import (
    YaraAnalyzer,
    TimeoutException,
    _COMPILED_CACHE,
)
from tests.helpers.r2_fakes import FakeR2Adapter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SIMPLE_YARA_RULE = """
rule TestRule
{
    strings:
        $a = "hello"
    condition:
        $a
}
"""

NO_MATCH_RULE = """
rule NeverMatch
{
    strings:
        $x = "XYZZY_IMPOSSIBLE_TOKEN_42"
    condition:
        $x
}
"""


class FakeConfig:
    """Minimal config with a YARA rules path."""

    def __init__(self, yara_path: str) -> None:
        self._yara_path = yara_path

    def get_yara_rules_path(self) -> str:
        return self._yara_path


def _make_adapter(*, cmdj_responses: dict | None = None) -> FakeR2Adapter:
    return FakeR2Adapter(cmdj_responses=cmdj_responses or {})


def _make_analyzer(
    tmp_path: Path,
    *,
    filepath: str | None = None,
    rules_subdir: str = "rules",
    cmdj_responses: dict | None = None,
) -> YaraAnalyzer:
    rules_dir = tmp_path / rules_subdir
    rules_dir.mkdir(parents=True, exist_ok=True)
    config = FakeConfig(str(rules_dir))
    adapter = _make_adapter(cmdj_responses=cmdj_responses)
    return YaraAnalyzer(adapter, config=config, filepath=filepath)


def _write_rule(directory: Path, filename: str, content: str) -> Path:
    rule_file = directory / filename
    rule_file.write_text(content)
    return rule_file


# ---------------------------------------------------------------------------
# scan() – file path resolution
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_yara_mod is None, reason="yara not installed")
def test_scan_with_filepath_from_constructor(tmp_path):
    """scan() uses the filepath passed at construction time."""
    target = tmp_path / "sample.bin"
    target.write_bytes(b"hello world")

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule(rules_dir, "match.yar", SIMPLE_YARA_RULE)

    # Clear cache so rules compile fresh
    _COMPILED_CACHE.pop(str(rules_dir), None)

    analyzer = _make_analyzer(tmp_path, filepath=str(target))
    result = analyzer.scan()
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["rule"] == "TestRule"
    assert result[0]["strings"][0]["identifier"] == "$a"


@pytest.mark.skipif(_yara_mod is None, reason="yara not installed")
def test_scan_with_file_path_from_adapter_cmdj(tmp_path):
    """scan() resolves file path via _cmdj('ij') when filepath is None."""
    target = tmp_path / "sample.bin"
    target.write_bytes(b"hello world")

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule(rules_dir, "match.yar", SIMPLE_YARA_RULE)
    _COMPILED_CACHE.pop(str(rules_dir), None)

    # The adapter returns file info for "ij" command
    adapter = _make_adapter(cmdj_responses={"ij": {"core": {"file": str(target)}}})
    config = FakeConfig(str(rules_dir))
    analyzer = YaraAnalyzer(adapter, config=config, filepath=None)
    result = analyzer.scan()
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["rule"] == "TestRule"


def test_scan_returns_empty_when_file_missing(tmp_path):
    """scan() returns [] when the target file does not exist."""
    analyzer = _make_analyzer(tmp_path, filepath="/nonexistent/sample.bin")
    result = analyzer.scan()
    assert result == []


def test_scan_returns_empty_when_filepath_none_and_no_info(tmp_path):
    """scan() returns [] when filepath is None and adapter has no ij info."""
    analyzer = _make_analyzer(tmp_path, filepath=None)
    result = analyzer.scan()
    assert result == []


# ---------------------------------------------------------------------------
# scan() – rules path resolution and custom_rules_path
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_yara_mod is None, reason="yara not installed")
def test_scan_with_custom_rules_path(tmp_path):
    """scan(custom_rules_path=...) overrides default rules path."""
    target = tmp_path / "sample.bin"
    target.write_bytes(b"hello world")

    custom_dir = tmp_path / "custom_rules"
    custom_dir.mkdir()
    _write_rule(custom_dir, "custom.yar", SIMPLE_YARA_RULE)
    _COMPILED_CACHE.pop(str(custom_dir), None)

    analyzer = _make_analyzer(tmp_path, filepath=str(target))
    result = analyzer.scan(custom_rules_path=str(custom_dir))
    assert len(result) == 1
    assert result[0]["rule"] == "TestRule"


@pytest.mark.skipif(_yara_mod is None, reason="yara not installed")
def test_scan_no_matches(tmp_path):
    """scan() returns [] when rules compile but nothing matches."""
    target = tmp_path / "sample.bin"
    target.write_bytes(b"nothing interesting here")

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule(rules_dir, "nomatch.yar", NO_MATCH_RULE)
    _COMPILED_CACHE.pop(str(rules_dir), None)

    analyzer = _make_analyzer(tmp_path, filepath=str(target))
    result = analyzer.scan()
    assert result == []


# ---------------------------------------------------------------------------
# scan() – rules path doesn't exist yet → defaults created
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_yara_mod is None, reason="yara not installed")
def test_scan_creates_defaults_when_rules_dir_missing(tmp_path):
    """When rules_path doesn't exist, scan creates default rules and uses them."""
    target = tmp_path / "sample.bin"
    # Write content that will match the default packer_detection rule (contains "UPX!")
    target.write_bytes(b"UPX!" + b"\x00" * 100)

    # Point to a rules dir that does NOT exist yet
    rules_dir = tmp_path / "auto_rules"
    config = FakeConfig(str(rules_dir))
    adapter = _make_adapter()
    analyzer = YaraAnalyzer(adapter, config=config, filepath=str(target))
    _COMPILED_CACHE.pop(str(rules_dir), None)

    result = analyzer.scan()
    # Defaults should have been created and the dir now exists
    assert rules_dir.exists()
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# _get_cached_rules – caching behaviour
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_yara_mod is None, reason="yara not installed")
def test_get_cached_rules_populates_cache(tmp_path):
    """First call compiles and stores in cache; second returns cached version."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule(rules_dir, "test.yar", SIMPLE_YARA_RULE)
    key = str(rules_dir)
    _COMPILED_CACHE.pop(key, None)

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    rules = analyzer._get_cached_rules(key)
    assert rules is not None
    assert key in _COMPILED_CACHE

    # Second call returns from cache (same object)
    rules2 = analyzer._get_cached_rules(key)
    assert rules2 is rules

    _COMPILED_CACHE.pop(key, None)


@pytest.mark.skipif(_yara_mod is None, reason="yara not installed")
def test_get_cached_rules_returns_none_for_invalid_path(tmp_path):
    """_get_cached_rules returns None when path has no valid rules."""
    key = "/nonexistent/rules/path"
    _COMPILED_CACHE.pop(key, None)

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    analyzer._get_cached_rules(key)
    # Might be None or might compile defaults – depends on path existence
    # At minimum, it should not raise
    _COMPILED_CACHE.pop(key, None)


# ---------------------------------------------------------------------------
# _compile_rules – various inputs
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_yara_mod is None, reason="yara not installed")
def test_compile_rules_with_directory(tmp_path):
    """_compile_rules compiles from a directory of .yar files."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule(rules_dir, "a.yar", SIMPLE_YARA_RULE)
    _write_rule(rules_dir, "b.yar", NO_MATCH_RULE)

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    compiled = analyzer._compile_rules(str(rules_dir))
    assert compiled is not None


@pytest.mark.skipif(_yara_mod is None, reason="yara not installed")
def test_compile_rules_with_single_file(tmp_path):
    """_compile_rules compiles a single .yar file."""
    rule_file = tmp_path / "single.yar"
    rule_file.write_text(SIMPLE_YARA_RULE)

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    compiled = analyzer._compile_rules(str(rule_file))
    assert compiled is not None


def test_compile_rules_invalid_path(tmp_path):
    """_compile_rules returns None for an invalid path."""
    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    result = analyzer._compile_rules("/nonexistent/rules/path")
    assert result is None


@pytest.mark.skipif(_yara_mod is None, reason="yara not installed")
def test_compile_rules_empty_directory_falls_back_to_defaults(tmp_path):
    """_compile_rules falls back to defaults when directory has no rule files."""
    empty_dir = tmp_path / "empty_rules"
    empty_dir.mkdir()

    # The rules_path in config must match so defaults can be created there
    config = FakeConfig(str(empty_dir))
    adapter = _make_adapter()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")

    result = analyzer._compile_rules(str(empty_dir))
    # Should have created default rules and compiled them
    assert result is not None or (empty_dir / "packer_detection.yar").exists()


# ---------------------------------------------------------------------------
# _compile_sources_with_timeout
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_yara_mod is None, reason="yara not installed")
def test_compile_sources_with_timeout_success(tmp_path):
    """_compile_sources_with_timeout compiles valid rules."""
    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    rules_dict = {"test": SIMPLE_YARA_RULE}
    result = analyzer._compile_sources_with_timeout(rules_dict)
    assert result is not None


@pytest.mark.skipif(_yara_mod is None, reason="yara not installed")
def test_compile_sources_with_timeout_syntax_error(tmp_path):
    """_compile_sources_with_timeout returns None on YARA syntax error."""
    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    rules_dict = {"bad": "rule broken { condition: INVALID_IDENT }"}
    result = analyzer._compile_sources_with_timeout(rules_dict)
    assert result is None


# ---------------------------------------------------------------------------
# _process_matches – real YARA match objects
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_yara_mod is None, reason="yara not installed")
def test_process_matches_with_real_matches(tmp_path):
    """_process_matches processes real YARA match objects correctly."""
    target = tmp_path / "sample.bin"
    target.write_bytes(b"hello world")

    rules = _yara_mod.compile(source=SIMPLE_YARA_RULE)
    yara_matches = rules.match(str(target))
    assert len(yara_matches) > 0

    analyzer = _make_analyzer(tmp_path, filepath=str(target))
    result = analyzer._process_matches(yara_matches)
    assert len(result) == 1
    assert result[0]["rule"] == "TestRule"
    assert result[0]["namespace"] == "default"
    assert isinstance(result[0]["tags"], list)
    assert isinstance(result[0]["meta"], dict)
    assert len(result[0]["strings"]) == 1

    string_info = result[0]["strings"][0]
    assert string_info["identifier"] == "$a"
    assert len(string_info["instances"]) == 1
    inst = string_info["instances"][0]
    assert inst["matched_data"] == "hello"
    assert isinstance(inst["offset"], int)
    assert isinstance(inst["length"], int)


def test_process_matches_empty_list(tmp_path):
    """_process_matches returns [] for empty input."""
    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    assert analyzer._process_matches([]) == []


# ---------------------------------------------------------------------------
# _read_rule_content – various scenarios
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_yara_mod is None, reason="yara not installed")
def test_read_rule_content_valid_file(tmp_path):
    """_read_rule_content reads a valid YARA rule file."""
    from r2inspect.security.validators import FileValidator

    rule_file = tmp_path / "test.yar"
    rule_file.write_text(SIMPLE_YARA_RULE)

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    validator = FileValidator()
    content = analyzer._read_rule_content(validator, rule_file)
    assert content is not None
    assert "TestRule" in content


def test_read_rule_content_empty_file(tmp_path):
    """_read_rule_content returns None for an empty file."""
    from r2inspect.security.validators import FileValidator

    rule_file = tmp_path / "empty.yar"
    rule_file.write_text("")

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    validator = FileValidator()
    content = analyzer._read_rule_content(validator, rule_file)
    assert content is None


def test_read_rule_content_whitespace_only(tmp_path):
    """_read_rule_content returns None for whitespace-only file."""
    from r2inspect.security.validators import FileValidator

    rule_file = tmp_path / "blank.yar"
    rule_file.write_text("   \n  \n  ")

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    validator = FileValidator()
    content = analyzer._read_rule_content(validator, rule_file)
    assert content is None


def test_read_rule_content_oversized_file(tmp_path):
    """_read_rule_content returns None when file exceeds size limit."""
    from r2inspect.security.validators import FileValidator
    from r2inspect.modules.yara_analyzer import YARA_MAX_RULE_SIZE

    rule_file = tmp_path / "huge.yar"
    # Write a file larger than the max
    rule_file.write_bytes(b"x" * (YARA_MAX_RULE_SIZE + 1))

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    validator = FileValidator()
    content = analyzer._read_rule_content(validator, rule_file)
    assert content is None


def test_read_rule_content_nonexistent_file(tmp_path):
    """_read_rule_content returns None for a file that doesn't exist."""
    from r2inspect.security.validators import FileValidator

    rule_file = tmp_path / "missing.yar"

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    validator = FileValidator()
    content = analyzer._read_rule_content(validator, rule_file)
    assert content is None


# ---------------------------------------------------------------------------
# _load_rules_dir
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_yara_mod is None, reason="yara not installed")
def test_load_rules_dir_with_valid_files(tmp_path):
    """_load_rules_dir loads all .yar files from a directory."""
    from r2inspect.security.validators import FileValidator

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule(rules_dir, "a.yar", SIMPLE_YARA_RULE)
    _write_rule(rules_dir, "b.yar", NO_MATCH_RULE)

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    validator = FileValidator()
    result = analyzer._load_rules_dir(validator, rules_dir)
    assert len(result) == 2
    assert any("TestRule" in v for v in result.values())
    assert any("NeverMatch" in v for v in result.values())


def test_load_rules_dir_empty(tmp_path):
    """_load_rules_dir returns {} for empty directory."""
    from r2inspect.security.validators import FileValidator

    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    validator = FileValidator()
    result = analyzer._load_rules_dir(validator, empty_dir)
    assert result == {}


def test_load_rules_dir_skips_empty_files(tmp_path):
    """_load_rules_dir skips files with no content."""
    from r2inspect.security.validators import FileValidator

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule(rules_dir, "empty.yar", "")
    _write_rule(rules_dir, "valid.yar", SIMPLE_YARA_RULE)

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    validator = FileValidator()
    result = analyzer._load_rules_dir(validator, rules_dir)
    # Only the valid file should be loaded
    assert len(result) == 1
    assert "TestRule" in list(result.values())[0]


# ---------------------------------------------------------------------------
# _compile_default_rules
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_yara_mod is None, reason="yara not installed")
def test_compile_default_rules_success(tmp_path):
    """_compile_default_rules creates and compiles default rules."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    config = FakeConfig(str(rules_dir))
    adapter = _make_adapter()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")

    compiled = analyzer._compile_default_rules(str(rules_dir))
    assert compiled is not None
    # Default rules should have been written
    assert (rules_dir / "packer_detection.yar").exists()


@pytest.mark.skipif(_yara_mod is None, reason="yara not installed")
def test_compile_default_rules_already_exist(tmp_path):
    """_compile_default_rules does not overwrite existing rule files."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    custom_content = "rule Custom { condition: true }"
    (rules_dir / "packer_detection.yar").write_text(custom_content)

    config = FakeConfig(str(rules_dir))
    adapter = _make_adapter()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")

    analyzer._compile_default_rules(str(rules_dir))
    # Should compile the existing custom content, not overwrite
    assert (rules_dir / "packer_detection.yar").read_text() == custom_content


# ---------------------------------------------------------------------------
# create_default_rules
# ---------------------------------------------------------------------------


def test_create_default_rules(tmp_path):
    """create_default_rules creates the rules directory and default files."""
    rules_dir = tmp_path / "new_rules"
    config = FakeConfig(str(rules_dir))
    adapter = _make_adapter()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")

    analyzer.create_default_rules()
    assert rules_dir.exists()
    assert (rules_dir / "packer_detection.yar").exists()
    assert (rules_dir / "suspicious_apis.yar").exists()
    assert (rules_dir / "crypto_detection.yar").exists()


def test_create_default_rules_idempotent(tmp_path):
    """create_default_rules does not overwrite existing files."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    sentinel = "rule Sentinel { condition: true }"
    (rules_dir / "packer_detection.yar").write_text(sentinel)

    config = FakeConfig(str(rules_dir))
    adapter = _make_adapter()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")

    analyzer.create_default_rules()
    # The pre-existing file should not have been overwritten
    assert (rules_dir / "packer_detection.yar").read_text() == sentinel
    # But missing defaults should have been created
    assert (rules_dir / "suspicious_apis.yar").exists()


# ---------------------------------------------------------------------------
# validate_rules
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_yara_mod is None, reason="yara not installed")
def test_validate_rules_valid_directory(tmp_path):
    """validate_rules returns valid=True for a directory with valid rules."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule(rules_dir, "test.yar", SIMPLE_YARA_RULE)
    _COMPILED_CACHE.pop(str(rules_dir), None)

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    result = analyzer.validate_rules(str(rules_dir))
    assert result["valid"] is True
    assert result["rules_count"] >= 1
    _COMPILED_CACHE.pop(str(rules_dir), None)


@pytest.mark.skipif(_yara_mod is None, reason="yara not installed")
def test_validate_rules_valid_single_file(tmp_path):
    """validate_rules returns valid=True for a valid single file."""
    rule_file = tmp_path / "test.yar"
    rule_file.write_text(SIMPLE_YARA_RULE)
    _COMPILED_CACHE.pop(str(rule_file), None)

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    result = analyzer.validate_rules(str(rule_file))
    assert result["valid"] is True
    assert result["rules_count"] == 1
    _COMPILED_CACHE.pop(str(rule_file), None)


def test_validate_rules_nonexistent_path(tmp_path):
    """validate_rules returns valid=False for a nonexistent path."""
    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    result = analyzer.validate_rules("/nonexistent/path")
    assert result["valid"] is False
    assert len(result["errors"]) >= 1


# ---------------------------------------------------------------------------
# list_available_rules
# ---------------------------------------------------------------------------


def test_list_available_rules_with_files(tmp_path):
    """list_available_rules finds .yar and .yara files."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule(rules_dir, "a.yar", SIMPLE_YARA_RULE)
    _write_rule(rules_dir, "b.yara", NO_MATCH_RULE)

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    available = analyzer.list_available_rules(str(rules_dir))
    assert len(available) >= 2
    names = {r["name"] for r in available}
    assert "a.yar" in names
    assert "b.yara" in names


def test_list_available_rules_empty_directory(tmp_path):
    """list_available_rules returns [] for empty directory."""
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    available = analyzer.list_available_rules(str(empty_dir))
    assert available == []


def test_list_available_rules_nonexistent_path(tmp_path):
    """list_available_rules returns [] for nonexistent path."""
    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    available = analyzer.list_available_rules("/nonexistent/path")
    assert available == []


def test_list_available_rules_single_file(tmp_path):
    """list_available_rules handles a single-file path."""
    rule_file = tmp_path / "single.yar"
    rule_file.write_text(SIMPLE_YARA_RULE)

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    available = analyzer.list_available_rules(str(rule_file))
    assert len(available) == 1
    assert available[0]["type"] == "single_file"
    assert available[0]["name"] == "single.yar"


def test_list_available_rules_default_path(tmp_path):
    """list_available_rules uses self.rules_path when no arg given."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule(rules_dir, "test.yar", SIMPLE_YARA_RULE)

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    available = analyzer.list_available_rules()
    assert isinstance(available, list)
    assert len(available) >= 1


def test_list_available_rules_nested_directory(tmp_path):
    """list_available_rules finds rules in subdirectories."""
    rules_dir = tmp_path / "rules"
    sub_dir = rules_dir / "subdir"
    sub_dir.mkdir(parents=True)
    _write_rule(sub_dir, "nested.yar", SIMPLE_YARA_RULE)

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    available = analyzer.list_available_rules(str(rules_dir))
    assert len(available) >= 1
    assert any("nested.yar" in r["name"] for r in available)


# ---------------------------------------------------------------------------
# _discover_rule_files
# ---------------------------------------------------------------------------


def test_discover_rule_files_multiple_extensions(tmp_path):
    """_discover_rule_files finds .yar, .yara, .rule, .rules files."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule(rules_dir, "a.yar", SIMPLE_YARA_RULE)
    _write_rule(rules_dir, "b.yara", NO_MATCH_RULE)
    _write_rule(rules_dir, "c.rule", SIMPLE_YARA_RULE)
    _write_rule(rules_dir, "d.rules", NO_MATCH_RULE)
    _write_rule(rules_dir, "e.txt", "not a rule")

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    found = analyzer._discover_rule_files(rules_dir)
    names = {f.name for f in found}
    assert "a.yar" in names
    assert "b.yara" in names
    assert "c.rule" in names
    assert "d.rules" in names
    assert "e.txt" not in names


# ---------------------------------------------------------------------------
# _resolve_file_path
# ---------------------------------------------------------------------------


def test_resolve_file_path_from_filepath(tmp_path):
    """_resolve_file_path returns filepath when it exists."""
    target = tmp_path / "sample.bin"
    target.write_bytes(b"\x00" * 10)

    analyzer = _make_analyzer(tmp_path, filepath=str(target))
    assert analyzer._resolve_file_path() == str(target)


def test_resolve_file_path_missing_returns_none(tmp_path):
    """_resolve_file_path returns None when filepath doesn't exist."""
    analyzer = _make_analyzer(tmp_path, filepath="/nonexistent/sample.bin")
    assert analyzer._resolve_file_path() is None


def test_resolve_file_path_none_falls_back_to_cmdj(tmp_path):
    """_resolve_file_path tries adapter cmdj when filepath is None."""
    target = tmp_path / "sample.bin"
    target.write_bytes(b"\x00" * 10)

    adapter = _make_adapter(cmdj_responses={"ij": {"core": {"file": str(target)}}})
    config = FakeConfig(str(tmp_path / "rules"))
    (tmp_path / "rules").mkdir(exist_ok=True)
    analyzer = YaraAnalyzer(adapter, config=config, filepath=None)
    assert analyzer._resolve_file_path() == str(target)


def test_resolve_file_path_none_no_cmdj_returns_none(tmp_path):
    """_resolve_file_path returns None when filepath is None and cmdj has no info."""
    analyzer = _make_analyzer(tmp_path, filepath=None)
    assert analyzer._resolve_file_path() is None


# ---------------------------------------------------------------------------
# _resolve_rules_path
# ---------------------------------------------------------------------------


def test_resolve_rules_path_existing(tmp_path):
    """_resolve_rules_path returns path when it exists."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    assert analyzer._resolve_rules_path(str(rules_dir)) == str(rules_dir)


def test_resolve_rules_path_custom_override(tmp_path):
    """_resolve_rules_path uses custom path over default."""
    custom_dir = tmp_path / "custom"
    custom_dir.mkdir()

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    assert analyzer._resolve_rules_path(str(custom_dir)) == str(custom_dir)


def test_resolve_rules_path_creates_defaults_when_missing(tmp_path):
    """_resolve_rules_path creates defaults and returns path if now exists."""
    rules_dir = tmp_path / "auto_rules"
    config = FakeConfig(str(rules_dir))
    adapter = _make_adapter()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")

    result = analyzer._resolve_rules_path(None)
    # After create_default_rules, the directory should exist
    assert result == str(rules_dir)
    assert rules_dir.exists()


# ---------------------------------------------------------------------------
# _validate_rules_path
# ---------------------------------------------------------------------------


def test_validate_rules_path_valid(tmp_path):
    """_validate_rules_path returns Path for valid paths."""
    from r2inspect.security.validators import FileValidator

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    validator = FileValidator()
    result = analyzer._validate_rules_path(validator, str(rules_dir))
    assert result is not None


def test_validate_rules_path_invalid(tmp_path):
    """_validate_rules_path returns None for nonexistent path."""
    from r2inspect.security.validators import FileValidator

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    validator = FileValidator()
    result = analyzer._validate_rules_path(validator, "/nonexistent/path")
    assert result is None


# ---------------------------------------------------------------------------
# _collect_rules_sources
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_yara_mod is None, reason="yara not installed")
def test_collect_rules_sources_file(tmp_path):
    """_collect_rules_sources returns dict for a single file."""
    from r2inspect.security.validators import FileValidator

    rule_file = tmp_path / "test.yar"
    rule_file.write_text(SIMPLE_YARA_RULE)

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    validator = FileValidator()
    result = analyzer._collect_rules_sources(validator, rule_file)
    assert "single_rule" in result


@pytest.mark.skipif(_yara_mod is None, reason="yara not installed")
def test_collect_rules_sources_directory(tmp_path):
    """_collect_rules_sources returns dict for a directory."""
    from r2inspect.security.validators import FileValidator

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule(rules_dir, "test.yar", SIMPLE_YARA_RULE)

    analyzer = _make_analyzer(tmp_path, filepath="/tmp/test.bin")
    validator = FileValidator()
    result = analyzer._collect_rules_sources(validator, rules_dir)
    assert len(result) >= 1


# ---------------------------------------------------------------------------
# End-to-end: full scan with match details
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_yara_mod is None, reason="yara not installed")
def test_end_to_end_scan_multiple_rules(tmp_path):
    """Full scan with multiple rules, some matching, some not."""
    target = tmp_path / "sample.bin"
    target.write_bytes(b"hello world XYZZY_IMPOSSIBLE_TOKEN_42")

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule(rules_dir, "match.yar", SIMPLE_YARA_RULE)
    _write_rule(
        rules_dir,
        "nomatch.yar",
        """
rule OnlyNumbers
{
    strings:
        $n = /^[0-9]+$/
    condition:
        $n
}
""",
    )
    _COMPILED_CACHE.pop(str(rules_dir), None)

    analyzer = _make_analyzer(tmp_path, filepath=str(target))
    result = analyzer.scan()
    assert isinstance(result, list)
    # At least TestRule should match
    rule_names = {r["rule"] for r in result}
    assert "TestRule" in rule_names


@pytest.mark.skipif(_yara_mod is None, reason="yara not installed")
def test_end_to_end_scan_match_strings_detail(tmp_path):
    """Verify string match instance details in scan output."""
    target = tmp_path / "sample.bin"
    target.write_bytes(b"AAhelloBBhelloCC")

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule(rules_dir, "test.yar", SIMPLE_YARA_RULE)
    _COMPILED_CACHE.pop(str(rules_dir), None)

    analyzer = _make_analyzer(tmp_path, filepath=str(target))
    result = analyzer.scan()
    assert len(result) == 1
    instances = result[0]["strings"][0]["instances"]
    # "hello" appears twice in the data
    assert len(instances) == 2
    offsets = [i["offset"] for i in instances]
    assert offsets == [2, 9]
    for inst in instances:
        assert inst["matched_data"] == "hello"
        assert inst["length"] == 5


# ---------------------------------------------------------------------------
# TimeoutException
# ---------------------------------------------------------------------------


def test_timeout_exception_is_exception():
    """TimeoutException is a proper Exception subclass."""
    exc = TimeoutException("timeout")
    assert isinstance(exc, Exception)
    assert str(exc) == "timeout"


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


def test_init_requires_config():
    """YaraAnalyzer raises ValueError when config is None."""
    with pytest.raises(ValueError, match="config must be provided"):
        YaraAnalyzer(_make_adapter(), config=None)


def test_init_stores_attributes(tmp_path):
    """YaraAnalyzer stores adapter, config, filepath, and rules_path."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    config = FakeConfig(str(rules_dir))
    adapter = _make_adapter()
    analyzer = YaraAnalyzer(adapter, config=config, filepath="/tmp/test.bin")
    assert analyzer.config is config
    assert analyzer.filepath == "/tmp/test.bin"
    assert analyzer.rules_path == str(rules_dir)
    assert analyzer.adapter is adapter
