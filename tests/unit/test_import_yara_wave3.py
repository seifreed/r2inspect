#!/usr/bin/env python3
"""Tests targeting missing coverage lines in import_analyzer.py and yara_analyzer.py.

No mocks, no unittest.mock, no MagicMock, no patch. Real code only.
"""

from __future__ import annotations

import os
import re
import threading
from pathlib import Path

import pytest

import r2inspect.modules.yara_analyzer as yara_module
from r2inspect.modules.import_analyzer import ImportAnalyzer
from r2inspect.modules.yara_analyzer import (
    TimeoutException,
    YaraAnalyzer,
    _COMPILED_CACHE,
    timeout_handler,
)

try:
    import yara as _yara_lib
    YARA_AVAILABLE = True
except Exception:
    YARA_AVAILABLE = False

YARA_MARK = pytest.mark.skipif(not YARA_AVAILABLE, reason="python-yara not installed")

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

SIMPLE_RULE = """
rule HelloWorld
{
    strings:
        $s = "hello"
    condition:
        $s
}
"""

SYNTAX_ERROR_RULE = "rule BrokenSyntax { condition: @@@INVALID@@@ }"


class MinimalAdapter:
    """Stub adapter backed by dicts, compatible with CommandHelperMixin via .cmd / .cmdj."""

    def __init__(self):
        self._json: dict = {}

    def cmd(self, command: str) -> str:
        return ""

    def cmdj(self, command: str) -> object:
        return self._json.get(command, None)


class FileInfoAdapter(MinimalAdapter):
    """Adapter that exposes a real file path via get_file_info() for the 'ij' r2 command."""

    def __init__(self, file_path: str):
        super().__init__()
        self._file_path = file_path

    def get_file_info(self) -> dict:
        return {"core": {"file": self._file_path}}


class FakeConfig:
    def __init__(self, yara_path: str):
        self._path = yara_path

    def get_yara_rules_path(self) -> str:
        return self._path


class FakeAdapter:
    pass


def make_yara_analyzer(rules_path: str, filepath: str | None = None) -> YaraAnalyzer:
    config = FakeConfig(rules_path)
    return YaraAnalyzer(FakeAdapter(), config=config, filepath=filepath)


def _clear_yara_cache():
    _COMPILED_CACHE.clear()


# ---------------------------------------------------------------------------
# import_analyzer.py - Lines 35, 38: get_category / get_description
# ---------------------------------------------------------------------------

def test_get_category_returns_metadata():
    """Line 35: get_category() returns 'metadata'."""
    analyzer = ImportAnalyzer(MinimalAdapter())
    assert analyzer.get_category() == "metadata"


def test_get_description_is_meaningful_string():
    """Line 38: get_description() returns a non-empty string about imports."""
    analyzer = ImportAnalyzer(MinimalAdapter())
    desc = analyzer.get_description()
    assert isinstance(desc, str)
    assert len(desc) > 10


# ---------------------------------------------------------------------------
# import_analyzer.py - Lines 49-102: analyze() full execution path
# ---------------------------------------------------------------------------

def test_analyze_full_path_all_keys_present():
    """Lines 49-102: analyze() completes successfully with all expected keys."""
    adapter = MinimalAdapter()
    adapter._json["iij"] = [
        {"name": "CreateFile", "plt": 0x1000, "libname": "kernel32.dll"},
        {"name": "VirtualAlloc", "plt": 0x2000, "libname": "kernel32.dll"},
        {"name": "GetProcAddress", "plt": 0x3000, "libname": "kernel32.dll"},
    ]
    adapter._json["izj"] = []
    analyzer = ImportAnalyzer(adapter)
    result = analyzer.analyze()

    assert result.get("available") is True
    for key in ("total_imports", "total_dlls", "imports", "dlls",
                "api_analysis", "obfuscation", "dll_analysis", "anomalies",
                "forwarding", "statistics"):
        assert key in result, f"Missing key: {key}"
    assert result["total_imports"] == 3


def test_analyze_statistics_block():
    """Lines 84-102: statistics block is populated correctly."""
    adapter = MinimalAdapter()
    adapter._json["iij"] = [
        {"name": f"CreateRemoteThread{i}", "plt": 0x1000 + i, "libname": "kernel32.dll"}
        for i in range(5)
    ]
    adapter._json["izj"] = []
    analyzer = ImportAnalyzer(adapter)
    result = analyzer.analyze()

    stats = result.get("statistics", {})
    assert "total_risk_score" in stats
    assert "risk_level" in stats
    assert "suspicious_indicators" in stats
    assert 0 <= stats["total_risk_score"] <= 100


# ---------------------------------------------------------------------------
# import_analyzer.py - Lines 112-115: _count_suspicious_indicators
# ---------------------------------------------------------------------------

def test_count_suspicious_indicators_sum_all_sources():
    """Lines 112-115: all three sources contribute to the total count."""
    analyzer = ImportAnalyzer(MinimalAdapter())
    data = {
        "api_analysis": {"suspicious_apis": ["a", "b", "c"]},
        "obfuscation": {"indicators": ["x", "y"]},
        "anomalies": {"count": 4},
    }
    assert analyzer._count_suspicious_indicators(data) == 9


def test_count_suspicious_indicators_missing_keys():
    """Lines 112-115: missing sub-keys default to zero."""
    analyzer = ImportAnalyzer(MinimalAdapter())
    data: dict = {}
    assert analyzer._count_suspicious_indicators(data) == 0


# ---------------------------------------------------------------------------
# import_analyzer.py - Lines 224-237: get_import_statistics body (non-empty)
# ---------------------------------------------------------------------------

def test_import_statistics_populates_distributions():
    """Lines 224-237: non-empty imports trigger distribution computation."""
    adapter = MinimalAdapter()
    adapter._json["iij"] = [
        {"name": "CreateFile", "plt": 0x1000, "libname": "kernel32.dll"},
        {"name": "CreateProcess", "plt": 0x2000, "libname": "kernel32.dll"},
        {"name": "printf", "plt": 0x3000, "libname": "msvcrt.dll"},
    ]
    analyzer = ImportAnalyzer(adapter)
    stats = analyzer.get_import_statistics()

    assert stats["total_imports"] == 3
    assert stats["unique_libraries"] == 2
    assert isinstance(stats["category_distribution"], dict)
    assert isinstance(stats["risk_distribution"], dict)
    assert isinstance(stats["library_distribution"], dict)
    assert isinstance(stats["suspicious_patterns"], list)


def test_import_statistics_library_distribution_counts():
    """Lines 232-235: Counter correctly counts library occurrences."""
    adapter = MinimalAdapter()
    adapter._json["iij"] = [
        {"name": "f1", "plt": 0x1000, "libname": "ntdll.dll"},
        {"name": "f2", "plt": 0x2000, "libname": "ntdll.dll"},
        {"name": "f3", "plt": 0x3000, "libname": "user32.dll"},
    ]
    analyzer = ImportAnalyzer(adapter)
    stats = analyzer.get_import_statistics()

    assert stats["library_distribution"]["ntdll.dll"] == 2
    assert stats["library_distribution"]["user32.dll"] == 1
    assert stats["unique_libraries"] == 2


# ---------------------------------------------------------------------------
# import_analyzer.py - Line 259: missing.append in get_missing_imports
# ---------------------------------------------------------------------------

def test_missing_imports_detects_unimported_known_api():
    """Line 259: a string matching a known API that is not in imported_apis is appended."""
    adapter = MinimalAdapter()
    adapter._json["iij"] = [
        {"name": "printf", "plt": 0x1000, "libname": "msvcrt.dll"},
    ]
    adapter._json["izj"] = [
        {"string": "CreateProcess"},
        {"string": "CreateRemoteThread"},
        {"string": "just a sentence"},
    ]
    analyzer = ImportAnalyzer(adapter)
    missing = analyzer.get_missing_imports()

    assert isinstance(missing, list)
    # CreateProcess / CreateRemoteThread should be flagged as candidate missing APIs
    assert len(missing) >= 1


# ---------------------------------------------------------------------------
# import_analyzer.py - Lines 288-290: analyze_api_usage return with imports
# ---------------------------------------------------------------------------

def test_analyze_api_usage_return_structure_non_empty():
    """Lines 288-290: return dict contains categories, suspicious_apis, risk_score."""
    analyzer = ImportAnalyzer(MinimalAdapter())
    imports = [
        {"name": "CreateRemoteThread", "category": "Process", "library": "kernel32.dll"},
        {"name": "VirtualAllocEx", "category": "Memory", "library": "kernel32.dll"},
    ]
    result = analyzer.analyze_api_usage(imports)

    assert "categories" in result
    assert "suspicious_apis" in result
    assert "risk_score" in result
    assert 0 <= result["risk_score"] <= 100


def test_analyze_api_usage_clamps_score_to_100():
    """Lines 288-290: risk_score is clamped to [0, 100]."""
    analyzer = ImportAnalyzer(MinimalAdapter())
    high_risk = [
        {"name": "CreateRemoteThread", "category": "Process", "library": "kernel32.dll"},
        {"name": "WriteProcessMemory", "category": "Process", "library": "kernel32.dll"},
        {"name": "VirtualAllocEx", "category": "Memory", "library": "kernel32.dll"},
        {"name": "LoadLibraryA", "category": "Module", "library": "kernel32.dll"},
        {"name": "GetProcAddress", "category": "Module", "library": "kernel32.dll"},
    ]
    result = analyzer.analyze_api_usage(high_risk)
    assert result["risk_score"] <= 100


# ---------------------------------------------------------------------------
# import_analyzer.py - Lines 421-423: analyze_dll_dependencies exception path
# ---------------------------------------------------------------------------

def test_analyze_dll_dependencies_exception_returns_safe_defaults():
    """Lines 421-423: AttributeError on dll.lower() is caught; returns safe defaults."""
    analyzer = ImportAnalyzer(MinimalAdapter())
    # Integers have no .lower(); passing them forces the except branch
    result = analyzer.analyze_dll_dependencies([1, 2, 3])  # type: ignore[arg-type]
    assert result == {"common_dlls": [], "suspicious_dlls": [], "analysis": {}}


# ---------------------------------------------------------------------------
# import_analyzer.py - Line 514: check_import_forwarding forwards.append
# ---------------------------------------------------------------------------

def test_check_import_forwarding_matches_backslash_pattern():
    """Line 514: a string matching r'^\\\\w+\\\\.\\\\w+$' causes forwards.append to run."""
    adapter = MinimalAdapter()
    # The regex r"^\\w+\\.\\w+$" matches a string that starts with backslash + w chars,
    # then backslash + any char, then backslash + w chars.
    # Python string "\\w\\.\\w" equals the 6-char sequence: \w\.\w
    matching_string = "\\w\\.\\w"
    assert re.match(r"^\\w+\\.\\w+$", matching_string), \
        "Precondition: regex must match the constructed string"

    adapter._json["izj"] = [
        {"string": matching_string, "vaddr": 0xDEAD},
    ]
    analyzer = ImportAnalyzer(adapter)
    result = analyzer.check_import_forwarding()

    assert result["detected"] is True
    assert result["count"] >= 1
    assert result["forwards"][0]["forward"] == matching_string
    assert result["forwards"][0]["address"] == 0xDEAD


# ---------------------------------------------------------------------------
# yara_analyzer.py - Line 42: timeout_handler raises TimeoutException
# ---------------------------------------------------------------------------

def test_timeout_handler_raises_timeout_exception():
    """Line 42: calling timeout_handler always raises TimeoutException."""
    with pytest.raises(TimeoutException, match="timed out"):
        timeout_handler(0, None)


# ---------------------------------------------------------------------------
# yara_analyzer.py - Line 60: __init__ raises ValueError when config is None
# ---------------------------------------------------------------------------

def test_init_raises_value_error_without_config():
    """Line 60: YaraAnalyzer.__init__ raises ValueError when config is None."""
    with pytest.raises(ValueError, match="config must be provided"):
        YaraAnalyzer(FakeAdapter(), config=None)


# ---------------------------------------------------------------------------
# yara_analyzer.py - Lines 71-72: scan returns [] when yara module is None
# ---------------------------------------------------------------------------

def test_scan_returns_empty_when_yara_module_unavailable(tmp_path):
    """Lines 71-72: scan() short-circuits with [] when yara is None."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"hello world")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test.yar").write_text(SIMPLE_RULE)

    _clear_yara_cache()
    original = yara_module.yara
    yara_module.yara = None
    try:
        analyzer = make_yara_analyzer(str(rules_dir), str(sample))
        assert analyzer.scan() == []
    finally:
        yara_module.yara = original


# ---------------------------------------------------------------------------
# yara_analyzer.py - Line 79: scan returns [] when rules_path resolves to None
# ---------------------------------------------------------------------------

def test_scan_returns_empty_when_rules_path_unresolvable(tmp_path):
    """Line 79: _resolve_rules_path returns None for an uncreatable path."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"content")
    # A path under a nonexistent root directory that cannot be written
    bad_rules = "/nonexistent_root_dir_uvwxyz/yara_rules_test"
    _clear_yara_cache()
    analyzer = make_yara_analyzer(bad_rules, str(sample))
    assert analyzer.scan() == []


# ---------------------------------------------------------------------------
# yara_analyzer.py - Line 83: scan returns [] when rules compile to None
# ---------------------------------------------------------------------------

@YARA_MARK
def test_scan_returns_empty_when_rules_compile_fails(tmp_path):
    """Line 83: _get_cached_rules returns None for a bad rule; scan returns []."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"hello world")

    rules_dir = tmp_path / "rules_bad"
    rules_dir.mkdir()
    (rules_dir / "bad.yar").write_text(SYNTAX_ERROR_RULE)

    default_rules_dir = tmp_path / "default_rules"
    _clear_yara_cache()
    config = FakeConfig(str(default_rules_dir))
    analyzer = YaraAnalyzer(FakeAdapter(), config=config, filepath=str(sample))
    result = analyzer.scan(custom_rules_path=str(rules_dir))
    assert result == []


# ---------------------------------------------------------------------------
# yara_analyzer.py - Lines 88-89: scan exception path
# ---------------------------------------------------------------------------

@YARA_MARK
def test_scan_exception_when_filepath_is_directory(tmp_path):
    """Lines 88-89: yara.match on a directory path raises; scan catches and returns []."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test.yar").write_text(SIMPLE_RULE)

    # Pass a directory path as the file to scan; yara.match raises on directories
    scan_target = tmp_path / "not_a_file"
    scan_target.mkdir()

    _clear_yara_cache()
    analyzer = make_yara_analyzer(str(rules_dir), str(scan_target))
    result = analyzer.scan()
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# yara_analyzer.py - Line 98: _resolve_file_path reads file path from adapter
# ---------------------------------------------------------------------------

def test_resolve_file_path_uses_adapter_get_file_info(tmp_path):
    """Line 98: when filepath is None, falls back to adapter's ij command."""
    real_file = tmp_path / "binary.bin"
    real_file.write_bytes(b"data")

    adapter = FileInfoAdapter(str(real_file))
    config = FakeConfig(str(tmp_path / "rules"))
    analyzer = YaraAnalyzer(adapter, config=config, filepath=None)
    result = analyzer._resolve_file_path()
    assert result == str(real_file)


def test_resolve_file_path_returns_none_for_nonexistent_file_from_adapter(tmp_path):
    """Line 98+: adapter returns a path that does not exist; _resolve_file_path returns None."""
    adapter = FileInfoAdapter("/this_file_does_not_exist_xyz_abc.bin")
    config = FakeConfig(str(tmp_path / "rules"))
    analyzer = YaraAnalyzer(adapter, config=config, filepath=None)
    assert analyzer._resolve_file_path() is None


# ---------------------------------------------------------------------------
# yara_analyzer.py - Lines 140-141: _compile_rules returns None when yara=None
# ---------------------------------------------------------------------------

def test_compile_rules_returns_none_when_yara_is_none(tmp_path):
    """Lines 140-141: _compile_rules returns None when the yara module is unavailable."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test.yar").write_text(SIMPLE_RULE)

    _clear_yara_cache()
    original = yara_module.yara
    yara_module.yara = None
    try:
        analyzer = make_yara_analyzer(str(rules_dir))
        assert analyzer._compile_rules(str(rules_dir)) is None
    finally:
        yara_module.yara = original


# ---------------------------------------------------------------------------
# yara_analyzer.py - Line 203: subdirectory rule files appended in _discover_rule_files
# ---------------------------------------------------------------------------

@YARA_MARK
def test_discover_rule_files_includes_nested_subdirectory(tmp_path):
    """Line 203: rule files only in subdirectories are appended (not in top-level glob)."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    sub_dir = rules_dir / "subdir"
    sub_dir.mkdir()
    top = rules_dir / "top.yar"
    top.write_text(SIMPLE_RULE)
    nested = sub_dir / "nested.yar"
    nested.write_text(SIMPLE_RULE)

    _clear_yara_cache()
    analyzer = make_yara_analyzer(str(rules_dir))
    found = analyzer._discover_rule_files(Path(rules_dir))
    found_paths = [str(f) for f in found]

    assert str(top) in found_paths
    assert str(nested) in found_paths


# ---------------------------------------------------------------------------
# yara_analyzer.py - Lines 241-253: _compile_default_rules
# ---------------------------------------------------------------------------

@YARA_MARK
def test_compile_default_rules_returns_none_when_self_rules_path_is_file(tmp_path):
    """Lines 241-252: when self.rules_path is a file, mkdir fails and read_text fails -> None."""
    existing_file = tmp_path / "not_a_directory.txt"
    existing_file.write_text("placeholder")

    empty_dir = tmp_path / "empty_rules"
    empty_dir.mkdir()

    _clear_yara_cache()
    config = FakeConfig(str(existing_file))
    analyzer = YaraAnalyzer(FakeAdapter(), config=config, filepath=None)
    result = analyzer._compile_default_rules(str(empty_dir))
    assert result is None


# ---------------------------------------------------------------------------
# yara_analyzer.py - Lines 270-271: _compile_sources_with_timeout in non-main thread
# ---------------------------------------------------------------------------

@YARA_MARK
def test_compile_sources_with_timeout_in_non_main_thread(tmp_path):
    """Lines 270-271: compilation in a worker thread takes the non-SIGALRM code path."""
    _clear_yara_cache()
    analyzer = make_yara_analyzer(str(tmp_path / "rules"))
    rules_dict = {"hello": SIMPLE_RULE}

    results: list = []

    def run_in_thread():
        compiled = analyzer._compile_sources_with_timeout(rules_dict)
        results.append(compiled)

    t = threading.Thread(target=run_in_thread)
    t.start()
    t.join(timeout=10)

    assert len(results) == 1
    assert results[0] is not None


# ---------------------------------------------------------------------------
# yara_analyzer.py - Lines 272-274: SyntaxError in _compile_sources_with_timeout
# ---------------------------------------------------------------------------

@YARA_MARK
def test_compile_sources_syntax_error_returns_none(tmp_path):
    """Lines 272-274: yara.SyntaxError during compilation is caught; returns None."""
    _clear_yara_cache()
    analyzer = make_yara_analyzer(str(tmp_path / "rules"))
    result = analyzer._compile_sources_with_timeout({"bad": SYNTAX_ERROR_RULE})
    assert result is None


# ---------------------------------------------------------------------------
# yara_analyzer.py - Lines 275-277: generic exception in _compile_sources_with_timeout
# ---------------------------------------------------------------------------

@YARA_MARK
def test_compile_sources_generic_exception_returns_none(tmp_path):
    """Lines 275-277: a non-SyntaxError exception during compile is caught; returns None."""
    _clear_yara_cache()
    analyzer = make_yara_analyzer(str(tmp_path / "rules"))
    # yara.compile rejects non-string source values, raising a TypeError (not yara.SyntaxError)
    result = analyzer._compile_sources_with_timeout({"bad": 12345})  # type: ignore[dict-item]
    assert result is None


# ---------------------------------------------------------------------------
# yara_analyzer.py - Line 308: instance.length attribute used in _process_matches
# ---------------------------------------------------------------------------

@YARA_MARK
def test_process_matches_uses_instance_length_attribute(tmp_path):
    """Line 308: when yara instance has .length, that attribute is stored."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"hello hello hello")

    _clear_yara_cache()
    analyzer = make_yara_analyzer(str(tmp_path / "rules"))

    compiled = _yara_lib.compile(source=SIMPLE_RULE)
    raw_matches = compiled.match(str(sample))
    result = analyzer._process_matches(raw_matches)

    assert len(result) >= 1
    instances = result[0]["strings"][0]["instances"]
    assert len(instances) >= 1
    assert "length" in instances[0]

    first_instance = raw_matches[0].strings[0].instances[0]
    if hasattr(first_instance, "length"):
        # Line 308 was executed; verify the stored value matches
        assert instances[0]["length"] == first_instance.length


# ---------------------------------------------------------------------------
# yara_analyzer.py - Lines 318-319: _process_matches exception
# ---------------------------------------------------------------------------

def test_process_matches_handles_exception_from_bad_match_object(tmp_path):
    """Lines 318-319: exception from a bad match object is caught; partial list returned."""
    _clear_yara_cache()
    analyzer = make_yara_analyzer(str(tmp_path / "rules"))

    class BadMatchObj:
        @property
        def rule(self) -> str:
            raise RuntimeError("simulated attribute error")

    result = analyzer._process_matches([BadMatchObj()])
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# yara_analyzer.py - Lines 334-335: create_default_rules exception path
# ---------------------------------------------------------------------------

def test_create_default_rules_does_not_raise_when_path_is_existing_file(tmp_path):
    """Lines 334-335: mkdir fails on an existing file path; exception is silently caught."""
    existing_file = tmp_path / "not_a_dir.txt"
    existing_file.write_text("content")

    _clear_yara_cache()
    config = FakeConfig(str(existing_file))
    analyzer = YaraAnalyzer(FakeAdapter(), config=config, filepath=None)
    # Must not raise
    analyzer.create_default_rules()


# ---------------------------------------------------------------------------
# yara_analyzer.py - Lines 361-363: validate_rules counts .yar/.yara in a directory
# ---------------------------------------------------------------------------

@YARA_MARK
def test_validate_rules_counts_yar_and_yara_files_in_directory(tmp_path):
    """Lines 361-363: validate_rules on a directory reports rules_count >= number of files."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "first.yar").write_text(SIMPLE_RULE)
    (rules_dir / "second.yara").write_text(SIMPLE_RULE)

    _clear_yara_cache()
    analyzer = make_yara_analyzer(str(rules_dir))
    result = analyzer.validate_rules(str(rules_dir))

    assert result["valid"] is True
    assert result["rules_count"] >= 2


# ---------------------------------------------------------------------------
# yara_analyzer.py - Lines 409-411: list_available_rules skips broken symlinks
# ---------------------------------------------------------------------------

def test_list_available_rules_skips_broken_symlink(tmp_path):
    """Lines 409-411: broken symlink found by rglob causes stat() to fail; entry is skipped."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    broken_link = rules_dir / "broken.yar"
    os.symlink("/nonexistent_symlink_target_xyz_abc.bin", str(broken_link))

    _clear_yara_cache()
    analyzer = make_yara_analyzer(str(rules_dir))
    result = analyzer.list_available_rules(str(rules_dir))
    # Broken symlink is skipped; result is empty or contains only valid entries
    assert isinstance(result, list)
    for entry in result:
        assert Path(entry["path"]).exists()
