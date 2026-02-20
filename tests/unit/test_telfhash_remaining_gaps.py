"""Tests covering remaining uncovered lines in telfhash_analyzer.py."""

from typing import Any

import pytest

import r2inspect.modules.telfhash_analyzer as _tel_mod
from r2inspect.modules.telfhash_analyzer import TELFHASH_AVAILABLE, TelfhashAnalyzer

ELF_FIXTURE = "samples/fixtures/hello_elf"


# ---------------------------------------------------------------------------
# Shared stubs
# ---------------------------------------------------------------------------


class SimpleAdapter:
    """Minimal adapter returning empty/None results."""

    def get_file_info(self) -> Any:
        return {}

    def get_symbols(self) -> list:
        return []

    def cmd(self, command: str) -> str:
        return ""

    def cmdj(self, command: str) -> Any:
        return None

    def get_info_text(self) -> str:
        return ""


class AlwaysElfTelfhashAnalyzer(TelfhashAnalyzer):
    """TelfhashAnalyzer subclass where _is_elf_file() always returns True."""

    def _is_elf_file(self) -> bool:
        return True


# ---------------------------------------------------------------------------
# Line 44: _check_library_availability when TELFHASH_AVAILABLE is False
# ---------------------------------------------------------------------------


def test_check_library_availability_unavailable_line_44():
    """Cover line 44: returns (False, message) when TELFHASH_AVAILABLE is False."""
    orig = _tel_mod.TELFHASH_AVAILABLE
    try:
        _tel_mod.TELFHASH_AVAILABLE = False
        analyzer = TelfhashAnalyzer(SimpleAdapter(), filepath="/tmp/test.elf")
        available, error = analyzer._check_library_availability()
        assert available is False
        assert error is not None
        assert "not available" in error
    finally:
        _tel_mod.TELFHASH_AVAILABLE = orig


# ---------------------------------------------------------------------------
# Lines 72-73: _calculate_hash list result with falsy hash and truthy msg
# ---------------------------------------------------------------------------


def test_calculate_hash_list_falsy_hash_lines_72_73():
    """Cover lines 72-73: list result with empty hash and error msg in _calculate_hash."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    orig_fn = _tel_mod.telfhash
    try:
        _tel_mod.telfhash = lambda fp: [{"telfhash": "", "msg": "no symbols found"}]
        analyzer = AlwaysElfTelfhashAnalyzer(SimpleAdapter(), filepath=ELF_FIXTURE)
        h, method, error = analyzer._calculate_hash()
        assert h is None
        assert method is None
        assert error == "no symbols found"
    finally:
        _tel_mod.telfhash = orig_fn


# ---------------------------------------------------------------------------
# Lines 75-77: _calculate_hash dict result with falsy hash and truthy msg
# ---------------------------------------------------------------------------


def test_calculate_hash_dict_falsy_hash_lines_75_77():
    """Cover lines 75-77: dict result with empty hash and error msg in _calculate_hash."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    orig_fn = _tel_mod.telfhash
    try:
        _tel_mod.telfhash = lambda fp: {"telfhash": "", "msg": "dict error msg"}
        analyzer = AlwaysElfTelfhashAnalyzer(SimpleAdapter(), filepath=ELF_FIXTURE)
        h, method, error = analyzer._calculate_hash()
        assert h is None
        assert method is None
        assert error == "dict error msg"
    finally:
        _tel_mod.telfhash = orig_fn


# ---------------------------------------------------------------------------
# Lines 129-131: analyze_symbols when TELFHASH_AVAILABLE is False
# ---------------------------------------------------------------------------


def test_analyze_symbols_unavailable_lines_129_131():
    """Cover lines 129-131: analyze_symbols returns early when telfhash unavailable."""
    orig = _tel_mod.TELFHASH_AVAILABLE
    try:
        _tel_mod.TELFHASH_AVAILABLE = False
        analyzer = TelfhashAnalyzer(SimpleAdapter(), filepath="/tmp/test.elf")
        result = analyzer.analyze_symbols()
        assert result["available"] is False
        assert result["error"] is not None
        assert "not available" in result["error"]
    finally:
        _tel_mod.TELFHASH_AVAILABLE = orig


# ---------------------------------------------------------------------------
# Line 166: analyze_symbols sets error when list result has falsy hash
# ---------------------------------------------------------------------------


def test_analyze_symbols_list_falsy_hash_sets_error_line_166():
    """Cover line 166: error set when list result has empty hash and truthy msg."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    orig_fn = _tel_mod.telfhash
    try:
        _tel_mod.telfhash = lambda fp: [{"telfhash": "", "msg": "sym calc failed"}]
        analyzer = AlwaysElfTelfhashAnalyzer(SimpleAdapter(), filepath=ELF_FIXTURE)
        result = analyzer.analyze_symbols()
        assert result["error"] == "sym calc failed"
    finally:
        _tel_mod.telfhash = orig_fn


# ---------------------------------------------------------------------------
# Lines 168-173: analyze_symbols dict result path
# ---------------------------------------------------------------------------


def test_analyze_symbols_dict_result_lines_168_173():
    """Cover lines 168-173: dict result with empty hash and error msg in analyze_symbols."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    orig_fn = _tel_mod.telfhash
    try:
        _tel_mod.telfhash = lambda fp: {"telfhash": "", "msg": "dict sym error"}
        analyzer = AlwaysElfTelfhashAnalyzer(SimpleAdapter(), filepath=ELF_FIXTURE)
        result = analyzer.analyze_symbols()
        assert result["error"] == "dict sym error"
    finally:
        _tel_mod.telfhash = orig_fn


# ---------------------------------------------------------------------------
# Lines 175-176: analyze_symbols else branch (non-list, non-dict)
# ---------------------------------------------------------------------------


def test_analyze_symbols_else_branch_lines_175_176():
    """Cover lines 175-176: else branch when telfhash returns a plain string."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    orig_fn = _tel_mod.telfhash
    try:
        _tel_mod.telfhash = lambda fp: "T1:direct_string_hash"
        analyzer = AlwaysElfTelfhashAnalyzer(SimpleAdapter(), filepath=ELF_FIXTURE)
        result = analyzer.analyze_symbols()
        assert result["telfhash"] == "T1:direct_string_hash"
    finally:
        _tel_mod.telfhash = orig_fn


# ---------------------------------------------------------------------------
# Lines 178-180: inner exception in analyze_symbols telfhash call
# ---------------------------------------------------------------------------


def test_analyze_symbols_inner_exception_lines_178_180():
    """Cover lines 178-180: inner except block when telfhash function raises."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    orig_fn = _tel_mod.telfhash

    def _raising(fp: str) -> None:
        raise RuntimeError("inner telfhash error")

    try:
        _tel_mod.telfhash = _raising
        analyzer = AlwaysElfTelfhashAnalyzer(SimpleAdapter(), filepath=ELF_FIXTURE)
        result = analyzer.analyze_symbols()
        assert result["error"] is not None
        assert "inner telfhash error" in result["error"]
    finally:
        _tel_mod.telfhash = orig_fn


# ---------------------------------------------------------------------------
# Line 361: compare_hashes returns None when TELFHASH_AVAILABLE is False
# ---------------------------------------------------------------------------


def test_compare_hashes_unavailable_line_361():
    """Cover line 361: compare_hashes returns None when telfhash unavailable."""
    orig = _tel_mod.TELFHASH_AVAILABLE
    try:
        _tel_mod.TELFHASH_AVAILABLE = False
        result = TelfhashAnalyzer.compare_hashes("T1:abc", "T1:def")
        assert result is None
    finally:
        _tel_mod.TELFHASH_AVAILABLE = orig


# ---------------------------------------------------------------------------
# Lines 370-371: compare_hashes when get_ssdeep returns None
# ---------------------------------------------------------------------------


def test_compare_hashes_no_ssdeep_lines_370_371():
    """Cover lines 370-371: compare_hashes returns None when ssdeep unavailable."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    orig_fn = _tel_mod.get_ssdeep
    try:
        _tel_mod.get_ssdeep = lambda: None
        result = TelfhashAnalyzer.compare_hashes("T1:abc123", "T1:abc456")
        assert result is None
    finally:
        _tel_mod.get_ssdeep = orig_fn


# ---------------------------------------------------------------------------
# Line 399: calculate_telfhash_from_file returns None when unavailable
# ---------------------------------------------------------------------------


def test_calculate_telfhash_from_file_unavailable_line_399():
    """Cover line 399: calculate_telfhash_from_file returns None when unavailable."""
    orig = _tel_mod.TELFHASH_AVAILABLE
    try:
        _tel_mod.TELFHASH_AVAILABLE = False
        result = TelfhashAnalyzer.calculate_telfhash_from_file("/some/file.elf")
        assert result is None
    finally:
        _tel_mod.TELFHASH_AVAILABLE = orig


# ---------------------------------------------------------------------------
# Line 406: calculate_telfhash_from_file dict result path
# ---------------------------------------------------------------------------


def test_calculate_telfhash_from_file_dict_result_line_406():
    """Cover line 406: dict result path in calculate_telfhash_from_file."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    orig_fn = _tel_mod.telfhash
    try:
        _tel_mod.telfhash = lambda fp: {"telfhash": "T1:dict_result"}
        result = TelfhashAnalyzer.calculate_telfhash_from_file("/some/file.elf")
        assert result == "T1:dict_result"
    finally:
        _tel_mod.telfhash = orig_fn


# ---------------------------------------------------------------------------
# Lines 408-410: exception in calculate_telfhash_from_file
# ---------------------------------------------------------------------------


def test_calculate_telfhash_from_file_exception_lines_408_410():
    """Cover lines 408-410: except block when telfhash raises in calculate_telfhash_from_file."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    orig_fn = _tel_mod.telfhash

    def _raising(fp: str) -> None:
        raise RuntimeError("calc error")

    try:
        _tel_mod.telfhash = _raising
        result = TelfhashAnalyzer.calculate_telfhash_from_file("/some/file.elf")
        assert result is None
    finally:
        _tel_mod.telfhash = orig_fn
