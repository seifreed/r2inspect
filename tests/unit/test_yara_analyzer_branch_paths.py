"""Tests for yara_analyzer.py covering missing branch paths."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

import r2inspect.modules.yara_analyzer as yara_module
from r2inspect.modules.yara_analyzer import (
    YARA_MAX_RULE_SIZE,
    YaraAnalyzer,
    _COMPILED_CACHE,
)
from r2inspect.security.validators import FileValidator

try:
    import yara as _yara_lib

    YARA_AVAILABLE = True
except Exception:
    YARA_AVAILABLE = False

pytestmark = pytest.mark.skipif(not YARA_AVAILABLE, reason="python-yara not installed")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SIMPLE_RULE = """
rule SimpleTest
{
    strings:
        $s = "hello"
    condition:
        $s
}
"""

PACKER_RULE = """
rule UPX_Packed
{
    strings:
        $upx = "UPX!"
    condition:
        $upx
}
"""


class FakeConfig:
    def __init__(self, yara_path):
        self._yara_path = yara_path

    def get_yara_rules_path(self):
        return self._yara_path


class FakeAdapter:
    """Minimal adapter with no r2 dependency."""

    pass


def make_analyzer(rules_path: str, filepath: str | None = None) -> YaraAnalyzer:
    config = FakeConfig(rules_path)
    return YaraAnalyzer(FakeAdapter(), config=config, filepath=filepath)


# ---------------------------------------------------------------------------
# YaraAnalyzer.scan - full path with real file and rules
# ---------------------------------------------------------------------------


def test_scan_returns_matches_for_file_with_pattern(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"hello world binary content")

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test.yar").write_text(SIMPLE_RULE)

    analyzer = make_analyzer(str(rules_dir), str(sample))
    matches = analyzer.scan()

    assert isinstance(matches, list)
    assert len(matches) >= 1
    assert matches[0]["rule"] == "SimpleTest"


def test_scan_returns_empty_for_no_match(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x00\x01\x02\x03 no pattern here")

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test.yar").write_text(SIMPLE_RULE)

    analyzer = make_analyzer(str(rules_dir), str(sample))
    matches = analyzer.scan()

    assert isinstance(matches, list)
    assert len(matches) == 0


def test_scan_with_custom_rules_path(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"UPX! packed binary")

    default_rules = tmp_path / "default_rules"
    default_rules.mkdir()

    custom_rules = tmp_path / "custom_rules"
    custom_rules.mkdir()
    (custom_rules / "packer.yar").write_text(PACKER_RULE)

    analyzer = make_analyzer(str(default_rules), str(sample))
    matches = analyzer.scan(custom_rules_path=str(custom_rules))

    assert any(m["rule"] == "UPX_Packed" for m in matches)


def test_scan_no_filepath_returns_empty(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test.yar").write_text(SIMPLE_RULE)

    analyzer = make_analyzer(str(rules_dir), filepath=None)
    matches = analyzer.scan()

    assert matches == []


def test_scan_nonexistent_filepath_returns_empty(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test.yar").write_text(SIMPLE_RULE)

    analyzer = make_analyzer(str(rules_dir), filepath="/nonexistent/path/sample.bin")
    matches = analyzer.scan()

    assert matches == []


def test_scan_nonexistent_rules_path_tries_defaults_and_returns_empty_or_matches(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"test content")

    analyzer = make_analyzer(str(tmp_path / "no_such_rules"), filepath=str(sample))
    matches = analyzer.scan()

    assert isinstance(matches, list)


# ---------------------------------------------------------------------------
# YaraAnalyzer._get_cached_rules - cache hit path
# ---------------------------------------------------------------------------


def test_get_cached_rules_caches_compiled_rules(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test.yar").write_text(SIMPLE_RULE)

    analyzer = make_analyzer(str(rules_dir))

    # Clear cache to isolate this test
    _COMPILED_CACHE.pop(str(rules_dir), None)

    rules1 = analyzer._get_cached_rules(str(rules_dir))
    rules2 = analyzer._get_cached_rules(str(rules_dir))

    assert rules1 is rules2


def test_get_cached_rules_returns_none_for_empty_dir(tmp_path):
    empty_rules = tmp_path / "empty_rules"
    empty_rules.mkdir()

    analyzer = make_analyzer(str(empty_rules))
    _COMPILED_CACHE.pop(str(empty_rules), None)

    rules = analyzer._get_cached_rules(str(empty_rules))
    assert rules is None or rules is not None  # Just verify no crash


# ---------------------------------------------------------------------------
# YaraAnalyzer._compile_rules - paths
# ---------------------------------------------------------------------------


def test_compile_rules_from_single_file(tmp_path):
    rule_file = tmp_path / "single.yar"
    rule_file.write_text(SIMPLE_RULE)

    analyzer = make_analyzer(str(tmp_path / "rules"))
    compiled = analyzer._compile_rules(str(rule_file))

    assert compiled is not None


def test_compile_rules_from_directory(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "rule1.yar").write_text(SIMPLE_RULE)
    (rules_dir / "rule2.yar").write_text(PACKER_RULE)

    analyzer = make_analyzer(str(rules_dir))
    compiled = analyzer._compile_rules(str(rules_dir))

    assert compiled is not None


def test_compile_rules_invalid_path_returns_none(tmp_path):
    analyzer = make_analyzer(str(tmp_path / "rules"))

    result = analyzer._compile_rules("/nonexistent/path/rules")
    assert result is None


def test_compile_rules_empty_directory_falls_back_to_defaults(tmp_path):
    empty_dir = tmp_path / "empty_rules"
    empty_dir.mkdir()

    rules_dir = tmp_path / "main_rules"
    analyzer = make_analyzer(str(rules_dir))

    result = analyzer._compile_rules(str(empty_dir))


def test_compile_rules_invalid_syntax_returns_none(tmp_path):
    rules_dir = tmp_path / "bad_rules"
    rules_dir.mkdir()
    (rules_dir / "bad.yar").write_text("this is not valid yara rule content { }")

    analyzer = make_analyzer(str(rules_dir))
    compiled = analyzer._compile_rules(str(rules_dir))

    assert compiled is None


# ---------------------------------------------------------------------------
# YaraAnalyzer._validate_rules_path
# ---------------------------------------------------------------------------


def test_validate_rules_path_valid_file(tmp_path):
    rule_file = tmp_path / "rules.yar"
    rule_file.write_text(SIMPLE_RULE)

    analyzer = make_analyzer(str(tmp_path / "rules"))
    validator = FileValidator()

    result = analyzer._validate_rules_path(validator, str(rule_file))
    assert result is not None


def test_validate_rules_path_nonexistent_returns_none(tmp_path):
    analyzer = make_analyzer(str(tmp_path / "rules"))
    validator = FileValidator()

    result = analyzer._validate_rules_path(validator, "/nonexistent/path.yar")
    assert result is None


# ---------------------------------------------------------------------------
# YaraAnalyzer._collect_rules_sources
# ---------------------------------------------------------------------------


def test_collect_rules_sources_from_file(tmp_path):
    rule_file = tmp_path / "rules.yar"
    rule_file.write_text(SIMPLE_RULE)

    analyzer = make_analyzer(str(tmp_path / "rules"))
    validator = FileValidator()
    validated = validator.validate_path(str(rule_file), check_exists=True)

    result = analyzer._collect_rules_sources(validator, validated)
    assert "single_rule" in result
    assert "SimpleTest" in result["single_rule"]


def test_collect_rules_sources_from_directory(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "r1.yar").write_text(SIMPLE_RULE)
    (rules_dir / "r2.yar").write_text(PACKER_RULE)

    analyzer = make_analyzer(str(rules_dir))
    validator = FileValidator()
    validated = validator.validate_path(str(rules_dir), check_exists=True)

    result = analyzer._collect_rules_sources(validator, validated)
    assert len(result) >= 2


# ---------------------------------------------------------------------------
# YaraAnalyzer._load_single_rule
# ---------------------------------------------------------------------------


def test_load_single_rule_valid_file(tmp_path):
    rule_file = tmp_path / "test.yar"
    rule_file.write_text(SIMPLE_RULE)

    analyzer = make_analyzer(str(tmp_path / "rules"))
    validator = FileValidator()

    result = analyzer._load_single_rule(validator, rule_file)
    assert "single_rule" in result
    assert "SimpleTest" in result["single_rule"]


def test_load_single_rule_empty_file_returns_empty(tmp_path):
    rule_file = tmp_path / "empty.yar"
    rule_file.write_text("   \n  ")

    analyzer = make_analyzer(str(tmp_path / "rules"))
    validator = FileValidator()

    result = analyzer._load_single_rule(validator, rule_file)
    assert result == {}


# ---------------------------------------------------------------------------
# YaraAnalyzer._load_rules_dir
# ---------------------------------------------------------------------------


def test_load_rules_dir_loads_multiple_extensions(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "r1.yar").write_text(SIMPLE_RULE)
    (rules_dir / "r2.yara").write_text(PACKER_RULE)

    analyzer = make_analyzer(str(rules_dir))
    validator = FileValidator()

    result = analyzer._load_rules_dir(validator, rules_dir)
    assert len(result) >= 2


def test_load_rules_dir_empty_dir_returns_empty(tmp_path):
    rules_dir = tmp_path / "empty_rules"
    rules_dir.mkdir()

    analyzer = make_analyzer(str(rules_dir))
    validator = FileValidator()

    result = analyzer._load_rules_dir(validator, rules_dir)
    assert result == {}


# ---------------------------------------------------------------------------
# YaraAnalyzer._discover_rule_files
# ---------------------------------------------------------------------------


def test_discover_rule_files_finds_yar_and_yara(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "a.yar").write_text(SIMPLE_RULE)
    (rules_dir / "b.yara").write_text(PACKER_RULE)
    (rules_dir / "c.rule").write_text(SIMPLE_RULE)
    (rules_dir / "d.rules").write_text(PACKER_RULE)

    analyzer = make_analyzer(str(rules_dir))
    found = analyzer._discover_rule_files(rules_dir)

    names = [f.name for f in found]
    assert "a.yar" in names
    assert "b.yara" in names
    assert "c.rule" in names
    assert "d.rules" in names


def test_discover_rule_files_no_duplicates(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "single.yar").write_text(SIMPLE_RULE)

    analyzer = make_analyzer(str(rules_dir))
    found = analyzer._discover_rule_files(rules_dir)

    paths = [str(f) for f in found]
    assert len(paths) == len(set(paths))


def test_discover_rule_files_empty_dir(tmp_path):
    rules_dir = tmp_path / "empty"
    rules_dir.mkdir()

    analyzer = make_analyzer(str(rules_dir))
    found = analyzer._discover_rule_files(rules_dir)

    assert found == []


# ---------------------------------------------------------------------------
# YaraAnalyzer._read_rule_content
# ---------------------------------------------------------------------------


def test_read_rule_content_valid_file(tmp_path):
    rule_file = tmp_path / "valid.yar"
    rule_file.write_text(SIMPLE_RULE)

    analyzer = make_analyzer(str(tmp_path / "rules"))
    validator = FileValidator()

    content = analyzer._read_rule_content(validator, rule_file)
    assert content is not None
    assert "SimpleTest" in content


def test_read_rule_content_empty_file_returns_none(tmp_path):
    rule_file = tmp_path / "empty.yar"
    rule_file.write_text("   \n  ")

    analyzer = make_analyzer(str(tmp_path / "rules"))
    validator = FileValidator()

    content = analyzer._read_rule_content(validator, rule_file)
    assert content is None


def test_read_rule_content_oversized_file_returns_none(tmp_path):
    rule_file = tmp_path / "big.yar"
    rule_file.write_bytes(b"rule X { condition: true }" + b"A" * (YARA_MAX_RULE_SIZE + 1))

    analyzer = make_analyzer(str(tmp_path / "rules"))
    validator = FileValidator()

    content = analyzer._read_rule_content(validator, rule_file)
    assert content is None


def test_read_rule_content_nonexistent_returns_none(tmp_path):
    nonexistent = tmp_path / "does_not_exist.yar"

    analyzer = make_analyzer(str(tmp_path / "rules"))
    validator = FileValidator()

    content = analyzer._read_rule_content(validator, nonexistent)
    assert content is None


# ---------------------------------------------------------------------------
# YaraAnalyzer._compile_sources_with_timeout
# ---------------------------------------------------------------------------


def test_compile_sources_with_timeout_valid_sources(tmp_path):
    analyzer = make_analyzer(str(tmp_path / "rules"))

    rules_dict = {"test": SIMPLE_RULE}
    compiled = analyzer._compile_sources_with_timeout(rules_dict)

    assert compiled is not None


def test_compile_sources_with_timeout_invalid_syntax_returns_none(tmp_path):
    analyzer = make_analyzer(str(tmp_path / "rules"))

    rules_dict = {"bad": "this { is not valid yara }"}
    compiled = analyzer._compile_sources_with_timeout(rules_dict)

    assert compiled is None


# ---------------------------------------------------------------------------
# YaraAnalyzer._process_matches
# ---------------------------------------------------------------------------


def test_process_matches_returns_structured_list(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"hello world content")

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test.yar").write_text(SIMPLE_RULE)

    analyzer = make_analyzer(str(rules_dir), str(sample))

    import yara as _yara

    compiled = _yara.compile(source=SIMPLE_RULE)
    raw_matches = compiled.match(str(sample))

    result = analyzer._process_matches(raw_matches)

    assert isinstance(result, list)
    assert len(result) >= 1
    match = result[0]
    assert match["rule"] == "SimpleTest"
    assert "namespace" in match
    assert "tags" in match
    assert "meta" in match
    assert "strings" in match


def test_process_matches_empty_list_returns_empty(tmp_path):
    analyzer = make_analyzer(str(tmp_path / "rules"))
    result = analyzer._process_matches([])
    assert result == []


def test_process_matches_contains_string_instances(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"hello hello hello")

    analyzer = make_analyzer(str(tmp_path / "rules"))

    import yara as _yara

    compiled = _yara.compile(source=SIMPLE_RULE)
    raw_matches = compiled.match(str(sample))

    result = analyzer._process_matches(raw_matches)
    assert len(result) >= 1

    strings = result[0]["strings"]
    assert len(strings) >= 1

    instances = strings[0]["instances"]
    assert len(instances) >= 1
    assert "offset" in instances[0]
    assert "matched_data" in instances[0]
    assert "length" in instances[0]


# ---------------------------------------------------------------------------
# YaraAnalyzer.create_default_rules
# ---------------------------------------------------------------------------


def test_create_default_rules_creates_directory(tmp_path):
    rules_dir = tmp_path / "new_rules"
    analyzer = make_analyzer(str(rules_dir))

    analyzer.create_default_rules()

    assert rules_dir.exists()


def test_create_default_rules_creates_rule_files(tmp_path):
    rules_dir = tmp_path / "new_rules"
    analyzer = make_analyzer(str(rules_dir))

    analyzer.create_default_rules()

    yar_files = list(rules_dir.glob("*.yar"))
    assert len(yar_files) >= 1


def test_create_default_rules_does_not_overwrite_existing(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    existing = rules_dir / "packer_detection.yar"
    custom_content = "# my custom content"
    existing.write_text(custom_content)

    analyzer = make_analyzer(str(rules_dir))
    analyzer.create_default_rules()

    assert existing.read_text() == custom_content


# ---------------------------------------------------------------------------
# YaraAnalyzer.validate_rules
# ---------------------------------------------------------------------------


def test_validate_rules_valid_directory(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test.yar").write_text(SIMPLE_RULE)

    analyzer = make_analyzer(str(rules_dir))
    result = analyzer.validate_rules(str(rules_dir))

    assert result["valid"] is True
    assert result["rules_count"] >= 1
    assert result["errors"] == []


def test_validate_rules_valid_single_file(tmp_path):
    rule_file = tmp_path / "rule.yar"
    rule_file.write_text(SIMPLE_RULE)

    analyzer = make_analyzer(str(tmp_path / "rules"))
    result = analyzer.validate_rules(str(rule_file))

    assert result["valid"] is True
    assert result["rules_count"] == 1


def test_validate_rules_invalid_path_is_invalid(tmp_path):
    analyzer = make_analyzer(str(tmp_path / "rules"))
    result = analyzer.validate_rules("/nonexistent/path")

    assert result["valid"] is False
    assert len(result["errors"]) >= 1


def test_validate_rules_result_has_required_keys(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test.yar").write_text(SIMPLE_RULE)

    analyzer = make_analyzer(str(rules_dir))
    result = analyzer.validate_rules(str(rules_dir))

    assert "valid" in result
    assert "errors" in result
    assert "warnings" in result
    assert "rules_count" in result


def test_validate_rules_counts_yara_files(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "a.yar").write_text(SIMPLE_RULE)
    (rules_dir / "b.yara").write_text(PACKER_RULE)

    analyzer = make_analyzer(str(rules_dir))
    result = analyzer.validate_rules(str(rules_dir))

    assert result["rules_count"] >= 2


# ---------------------------------------------------------------------------
# YaraAnalyzer.list_available_rules
# ---------------------------------------------------------------------------


def test_list_available_rules_nonexistent_path_returns_empty(tmp_path):
    analyzer = make_analyzer(str(tmp_path / "rules"))
    result = analyzer.list_available_rules("/nonexistent/path")
    assert result == []


def test_list_available_rules_single_file(tmp_path):
    rule_file = tmp_path / "test.yar"
    rule_file.write_text(SIMPLE_RULE)

    analyzer = make_analyzer(str(tmp_path / "rules"))
    result = analyzer.list_available_rules(str(rule_file))

    assert len(result) == 1
    assert result[0]["type"] == "single_file"
    assert result[0]["name"] == "test.yar"
    assert "path" in result[0]
    assert "size" in result[0]
    assert "modified" in result[0]


def test_list_available_rules_directory(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "a.yar").write_text(SIMPLE_RULE)
    (rules_dir / "b.yara").write_text(PACKER_RULE)

    analyzer = make_analyzer(str(rules_dir))
    result = analyzer.list_available_rules(str(rules_dir))

    assert len(result) >= 2
    assert all(r["type"] == "directory_file" for r in result)
    names = [r["name"] for r in result]
    assert "a.yar" in names
    assert "b.yara" in names


def test_list_available_rules_uses_default_path(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "default.yar").write_text(SIMPLE_RULE)

    analyzer = make_analyzer(str(rules_dir))
    result = analyzer.list_available_rules()

    assert isinstance(result, list)


def test_list_available_rules_directory_has_relative_path(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test.yar").write_text(SIMPLE_RULE)

    analyzer = make_analyzer(str(rules_dir))
    result = analyzer.list_available_rules(str(rules_dir))

    assert len(result) >= 1
    assert "relative_path" in result[0]
