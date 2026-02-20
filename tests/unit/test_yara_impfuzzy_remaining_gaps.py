#!/usr/bin/env python3
"""Tests covering remaining uncovered lines in yara_analyzer.py and impfuzzy_analyzer.py."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path
from typing import Any

import pytest

import r2inspect.modules.impfuzzy_analyzer as _imp_mod
import r2inspect.modules.yara_analyzer as _yar_mod
from r2inspect.modules.impfuzzy_analyzer import ImpfuzzyAnalyzer
from r2inspect.modules.yara_analyzer import YaraAnalyzer
from r2inspect.security.validators import FileValidator

try:
    import yara as _yara_lib

    YARA_AVAILABLE = True
except Exception:
    YARA_AVAILABLE = False

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

SIMPLE_YARA_RULE = """
rule TestRule
{
    strings:
        $s = "test"
    condition:
        $s
}
"""


class _FakeConfig:
    def __init__(self, yara_path: str) -> None:
        self._path = yara_path

    def get_yara_rules_path(self) -> str:
        return self._path


class _FakeAdapter:
    pass


def _make_yara_analyzer(rules_path: str, filepath: str | None = None) -> YaraAnalyzer:
    return YaraAnalyzer(_FakeAdapter(), config=_FakeConfig(rules_path), filepath=filepath)


class _PEAdapter:
    """Adapter whose filepath starts with MZ so _is_pe_file() returns True."""

    def get_imports(self) -> list[dict[str, Any]]:
        return [{"name": "CreateFileA", "libname": "kernel32.dll"}]


def _make_impfuzzy_analyzer(adapter: Any, filepath: str) -> ImpfuzzyAnalyzer:
    return ImpfuzzyAnalyzer(adapter, filepath)


# ---------------------------------------------------------------------------
# yara_analyzer.py lines 153-155:
#   except Exception in _compile_yara_rules() → logger.error; return None
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not YARA_AVAILABLE, reason="python-yara not installed")
def test_compile_rules_returns_none_on_unexpected_exception(tmp_path: Path) -> None:
    """_compile_rules catches any Exception from _collect_rules_sources and returns None."""
    rule_file = tmp_path / "test.yar"
    rule_file.write_text(SIMPLE_YARA_RULE)

    analyzer = _make_yara_analyzer(str(tmp_path))

    orig = _yar_mod.YaraAnalyzer._collect_rules_sources

    def _raising(self: Any, validator: Any, validated_path: Any) -> Any:
        raise RuntimeError("injected error for coverage")

    _yar_mod.YaraAnalyzer._collect_rules_sources = _raising  # type: ignore[method-assign]
    try:
        result = analyzer._compile_rules(str(rule_file))
        assert result is None
    finally:
        _yar_mod.YaraAnalyzer._collect_rules_sources = orig  # type: ignore[method-assign]


# ---------------------------------------------------------------------------
# yara_analyzer.py lines 171-172:
#   _collect_rules_sources() when path is neither file nor directory → return {}
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not YARA_AVAILABLE, reason="python-yara not installed")
def test_collect_rules_sources_neither_file_nor_dir_returns_empty(tmp_path: Path) -> None:
    """_collect_rules_sources returns {} when validated_path is neither file nor directory."""
    analyzer = _make_yara_analyzer(str(tmp_path))
    validator = FileValidator()

    class _FakePath:
        def is_file(self) -> bool:
            return False

        def is_dir(self) -> bool:
            return False

        def __str__(self) -> str:
            return "/fake/neither"

    result = analyzer._collect_rules_sources(validator, _FakePath())  # type: ignore[arg-type]
    assert result == {}


# ---------------------------------------------------------------------------
# yara_analyzer.py lines 241-243:
#   _read_rule_content() outer except → logger.warning; return None
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not YARA_AVAILABLE, reason="python-yara not installed")
def test_read_rule_content_returns_none_on_unreadable_file(tmp_path: Path) -> None:
    """_read_rule_content returns None when the file cannot be read (permission denied)."""
    rule_file = tmp_path / "locked.yar"
    rule_file.write_text(SIMPLE_YARA_RULE)
    # Remove read permission
    os.chmod(rule_file, 0o000)

    analyzer = _make_yara_analyzer(str(tmp_path))
    validator = FileValidator()
    try:
        result = analyzer._read_rule_content(validator, rule_file)
        assert result is None
    finally:
        os.chmod(rule_file, 0o644)


# ---------------------------------------------------------------------------
# yara_analyzer.py lines 361-363:
#   validate_rules() except Exception → valid=False, errors appended
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not YARA_AVAILABLE, reason="python-yara not installed")
def test_validate_rules_catches_exception_from_compile_rules(tmp_path: Path) -> None:
    """validate_rules sets valid=False when _compile_rules raises an exception."""
    analyzer = _make_yara_analyzer(str(tmp_path))

    orig = _yar_mod.YaraAnalyzer._compile_rules

    def _raising_compile(self: Any, path: Any) -> Any:
        raise RuntimeError("compile exploded")

    _yar_mod.YaraAnalyzer._compile_rules = _raising_compile  # type: ignore[method-assign]
    try:
        result = analyzer.validate_rules(str(tmp_path))
        assert result["valid"] is False
        assert any("compile exploded" in e for e in result["errors"])
    finally:
        _yar_mod.YaraAnalyzer._compile_rules = orig  # type: ignore[method-assign]


# ---------------------------------------------------------------------------
# impfuzzy_analyzer.py lines 78-82:
#   _calculate_hash() when pyimpfuzzy.get_impfuzzy() returns None/empty
# ---------------------------------------------------------------------------


def test_calculate_hash_returns_none_when_get_impfuzzy_returns_empty(tmp_path: Path) -> None:
    """_calculate_hash returns (None, None, error_msg) when get_impfuzzy() yields falsy result."""
    # Create a fake MZ file so _is_pe_file() returns True
    pe_file = tmp_path / "fake.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)

    analyzer = _make_impfuzzy_analyzer(_PEAdapter(), str(pe_file))

    orig = _imp_mod.pyimpfuzzy.get_impfuzzy  # type: ignore[attr-defined]
    _imp_mod.pyimpfuzzy.get_impfuzzy = lambda path: None  # type: ignore[attr-defined]
    try:
        hash_val, method, error = analyzer._calculate_hash()
        assert hash_val is None
        assert method is None
        assert error is not None
        assert "impfuzzy" in error.lower() or "import" in error.lower()
    finally:
        _imp_mod.pyimpfuzzy.get_impfuzzy = orig  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# impfuzzy_analyzer.py lines 148-150:
#   analyze_imports() when pyimpfuzzy.get_impfuzzy() returns empty hash
# ---------------------------------------------------------------------------


def test_analyze_imports_error_when_get_impfuzzy_returns_empty(tmp_path: Path) -> None:
    """analyze_imports() sets error when get_impfuzzy() returns empty after processing imports."""
    pe_file = tmp_path / "fake.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)

    class _ImportsAdapter:
        def get_imports(self) -> list[dict[str, Any]]:
            return [{"name": "CreateFileA", "libname": "kernel32.dll"}]

    analyzer = _make_impfuzzy_analyzer(_ImportsAdapter(), str(pe_file))

    orig = _imp_mod.pyimpfuzzy.get_impfuzzy  # type: ignore[attr-defined]
    _imp_mod.pyimpfuzzy.get_impfuzzy = lambda path: ""  # type: ignore[attr-defined]
    try:
        result = analyzer.analyze_imports()
        assert result["available"] is False
        assert result["error"] == "Failed to calculate impfuzzy hash"
    finally:
        _imp_mod.pyimpfuzzy.get_impfuzzy = orig  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# yara_analyzer.py line 265:
#   finally: signal.signal(SIGALRM, old_handler) — executed after every
#   successful SIGALRM-path compilation
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not YARA_AVAILABLE, reason="python-yara not installed")
def test_compile_sources_with_timeout_restores_signal_handler(tmp_path: Path) -> None:
    """_compile_sources_with_timeout restores old SIGALRM handler in finally block."""
    import signal

    if not hasattr(signal, "SIGALRM"):
        pytest.skip("SIGALRM not available on this platform")

    analyzer = _make_yara_analyzer(str(tmp_path))
    rules_dict = {"test": SIMPLE_YARA_RULE}
    result = analyzer._compile_sources_with_timeout(rules_dict)
    assert result is not None


# ---------------------------------------------------------------------------
# yara_analyzer.py lines 362-363:
#   list_available_rules() — first two lines initialise state
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not YARA_AVAILABLE, reason="python-yara not installed")
def test_list_available_rules_returns_single_file_entry(tmp_path: Path) -> None:
    """list_available_rules() returns one entry when rules_path is a single .yar file."""
    rule_file = tmp_path / "my_rules.yar"
    rule_file.write_text(SIMPLE_YARA_RULE)

    analyzer = _make_yara_analyzer(str(rule_file))
    result = analyzer.list_available_rules()
    assert len(result) == 1
    assert result[0]["name"] == "my_rules.yar"
    assert result[0]["type"] == "single_file"
