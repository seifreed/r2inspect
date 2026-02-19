"""Final coverage tests for telfhash_analyzer.py and ssdeep_analyzer.py."""

import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

from r2inspect.modules.ssdeep_analyzer import SSDeepAnalyzer
from r2inspect.modules.telfhash_analyzer import TELFHASH_AVAILABLE, TelfhashAnalyzer

ELF_FIXTURE = "samples/fixtures/hello_elf"


# ---------------------------------------------------------------------------
# Shared stubs
# ---------------------------------------------------------------------------


class RaisingFileInfoAdapter:
    """Adapter whose get_file_info() raises, all other methods return empty."""

    def get_file_info(self) -> Any:
        raise RuntimeError("forced get_file_info error")

    def get_symbols(self) -> Any:
        return []

    def cmd(self, command: str) -> str:
        return ""

    def cmdj(self, command: str) -> Any:
        return None

    def get_info_text(self) -> str:
        return ""


class EmptyFileInfoRaisingSymbolsAdapter:
    """Adapter whose get_file_info() returns {} and get_symbols() raises."""

    def get_file_info(self) -> dict:
        return {}

    def get_symbols(self) -> Any:
        raise RuntimeError("forced get_symbols error")

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


class RaisingElfCheckTelfhashAnalyzer(TelfhashAnalyzer):
    """TelfhashAnalyzer subclass where _is_elf_file() raises an exception."""

    def _is_elf_file(self) -> bool:
        raise RuntimeError("forced _is_elf_file error")


# ---------------------------------------------------------------------------
# telfhash_analyzer.py - lines 86-88: exception handler in _calculate_hash
# ---------------------------------------------------------------------------


def test_calculate_hash_exception_handler_lines_86_88():
    """Cover lines 86-88: outer except in _calculate_hash when _is_elf_file raises."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    analyzer = RaisingElfCheckTelfhashAnalyzer(RaisingFileInfoAdapter(), filepath="/tmp/test.elf")
    hash_value, method, error = analyzer._calculate_hash()
    assert hash_value is None
    assert method is None
    assert error is not None
    assert "Telfhash calculation failed" in error


# ---------------------------------------------------------------------------
# telfhash_analyzer.py - lines 182-184: outer exception in analyze_symbols
# ---------------------------------------------------------------------------


def test_analyze_symbols_outer_exception_lines_182_184():
    """Cover lines 182-184: outer except in analyze_symbols when _is_elf_file raises."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    analyzer = RaisingElfCheckTelfhashAnalyzer(RaisingFileInfoAdapter(), filepath="/tmp/test.elf")
    result = analyzer.analyze_symbols()
    assert isinstance(result, dict)
    assert result["error"] is not None
    # is_elf remains False because the outer exception fires before setting it
    assert result["available"] is True


# ---------------------------------------------------------------------------
# telfhash_analyzer.py - lines 203-205: exception in _is_elf_file
# ---------------------------------------------------------------------------


def test_is_elf_file_get_file_info_raises_lines_203_205(tmp_path):
    """Cover lines 203-205: except in _is_elf_file when _cmdj('ij') raises."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    # Non-ELF file so is_elf_file() returns False without raising
    non_elf = tmp_path / "data.bin"
    non_elf.write_bytes(b"not an elf file at all" * 50)

    adapter = RaisingFileInfoAdapter()
    # r2 = adapter (non-None), so _is_elf_file does not short-circuit at line 196
    analyzer = TelfhashAnalyzer(adapter, filepath=str(non_elf))
    # is_elf_file() catches the get_file_info exception internally, returns False.
    # Then _is_elf_file calls self._cmdj("ij", {}) which raises again → lines 203-205
    result = analyzer._is_elf_file()
    assert result is False


# ---------------------------------------------------------------------------
# telfhash_analyzer.py - lines 216-218: exception in _has_elf_symbols
# ---------------------------------------------------------------------------


def test_has_elf_symbols_get_symbols_raises_lines_216_218(tmp_path):
    """Cover lines 216-218: except in _has_elf_symbols when _cmd_list raises."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    non_elf = tmp_path / "data.bin"
    non_elf.write_bytes(b"not an elf file at all" * 50)

    adapter = EmptyFileInfoRaisingSymbolsAdapter()
    analyzer = TelfhashAnalyzer(adapter, filepath=str(non_elf))
    # is_elf_file() returns False (empty get_file_info, non-ELF magic).
    # _is_elf_file calls _cmdj("ij") → {} → calls _has_elf_symbols({}).
    # Inside _has_elf_symbols, _cmd_list("isj") calls get_symbols() which raises.
    # Lines 216-218 are hit.
    result = analyzer._is_elf_file()
    assert result is False


def test_has_elf_symbols_direct_get_symbols_raises_lines_216_218():
    """Cover lines 216-218 by calling _has_elf_symbols directly with raising adapter."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    adapter = EmptyFileInfoRaisingSymbolsAdapter()
    analyzer = TelfhashAnalyzer(adapter, filepath="/tmp/test.elf")
    # _cmd_list("isj") calls adapter.get_symbols() which raises → caught at 216-218
    result = analyzer._has_elf_symbols({"bin": {"os": "linux"}})
    assert result is False


# ---------------------------------------------------------------------------
# telfhash_analyzer.py - lines 237-239: exception in _get_elf_symbols
# ---------------------------------------------------------------------------


def test_get_elf_symbols_get_symbols_raises_lines_237_239():
    """Cover lines 237-239: except in _get_elf_symbols when _cmd_list raises."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    adapter = EmptyFileInfoRaisingSymbolsAdapter()
    analyzer = TelfhashAnalyzer(adapter, filepath="/tmp/test.elf")
    result = analyzer._get_elf_symbols()
    assert result == []


def test_analyze_symbols_covers_237_239_via_elf_override(tmp_path):
    """Cover 237-239 via analyze_symbols with _is_elf_file=True and get_symbols raising."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    non_elf = tmp_path / "data.bin"
    non_elf.write_bytes(b"not an elf file" * 50)
    adapter = EmptyFileInfoRaisingSymbolsAdapter()

    analyzer = AlwaysElfTelfhashAnalyzer(adapter, filepath=str(non_elf))
    result = analyzer.analyze_symbols()
    assert isinstance(result, dict)
    assert result["is_elf"] is True
    assert result["symbol_count"] == 0


# ---------------------------------------------------------------------------
# ssdeep_analyzer.py - lines 67, 70, 73-74: OSError fallback in _calculate_hash
# ---------------------------------------------------------------------------


def test_calculate_hash_oserror_path_nonexistent_lines_67_73_74():
    """Cover lines 67, 70, 73-74: OSError fallback when file does not exist."""
    analyzer = SSDeepAnalyzer(filepath="/nonexistent/path/for_coverage_test.bin")
    hash_value, method, error = analyzer._calculate_hash()
    assert hash_value is None
    assert error is not None


def test_calculate_hash_oserror_path_unreadable_lines_67_73_74(tmp_path):
    """Cover lines 67, 70, 73-74: OSError fallback when file is not readable."""
    f = tmp_path / "unreadable.bin"
    f.write_bytes(b"A" * 10000)
    os.chmod(str(f), 0o000)
    try:
        analyzer = SSDeepAnalyzer(filepath=str(f))
        hash_value, method, error = analyzer._calculate_hash()
        assert hash_value is None
        assert error is not None
    finally:
        os.chmod(str(f), 0o644)


# ---------------------------------------------------------------------------
# ssdeep_analyzer.py - lines 87-89: binary exception fallback in _calculate_hash
# ---------------------------------------------------------------------------


def test_calculate_hash_binary_exception_fallback_lines_87_89():
    """Cover lines 87-89: binary method raises RuntimeError (non-existent file)."""
    # Non-existent file: library fails (OSError), binary validator also fails
    analyzer = SSDeepAnalyzer(filepath="/nonexistent/path/for_coverage_87_89.bin")
    hash_value, method, error = analyzer._calculate_hash()
    assert hash_value is None
    assert error is not None
    assert "Binary error" in error or "binary" in error.lower() or "Path" in error


# ---------------------------------------------------------------------------
# ssdeep_analyzer.py - line 146: unreadable file causes ssdeep binary to
# return empty output, triggering RuntimeError("Could not parse ssdeep output")
# ---------------------------------------------------------------------------


def test_calculate_hash_binary_unparsable_output_line_146(tmp_path):
    """Cover line 146: ssdeep binary runs but output can't be parsed (unreadable file)."""
    ssdeep_path = SSDeepAnalyzer._resolve_ssdeep_binary()
    if not ssdeep_path:
        pytest.skip("ssdeep binary not available")

    f = tmp_path / "unreadable2.bin"
    f.write_bytes(b"B" * 10000)
    os.chmod(str(f), 0o000)
    try:
        analyzer = SSDeepAnalyzer(filepath=str(f))
        hash_value, method, error = analyzer._calculate_hash()
        # Binary runs on unreadable file, produces no parsable hash lines
        assert hash_value is None
        assert error is not None
    finally:
        os.chmod(str(f), 0o644)


# ---------------------------------------------------------------------------
# Additional: verify _check_library_availability returns True for ssdeep
# ---------------------------------------------------------------------------


def test_ssdeep_check_library_availability_true(tmp_path):
    """Cover line 45: _check_library_availability returns True when ssdeep available."""
    if not SSDeepAnalyzer.is_available():
        pytest.skip("ssdeep not available")
    f = tmp_path / "sample.bin"
    f.write_bytes(b"A" * 100)
    analyzer = SSDeepAnalyzer(filepath=str(f))
    available, error = analyzer._check_library_availability()
    assert available is True
    assert error is None


# ---------------------------------------------------------------------------
# Additional: verify telfhash _check_library_availability when available
# ---------------------------------------------------------------------------


def test_telfhash_check_library_availability_true():
    """Cover line 43: _check_library_availability returns True when telfhash available."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    analyzer = TelfhashAnalyzer(RaisingFileInfoAdapter(), filepath="/tmp/test.elf")
    available, error = analyzer._check_library_availability()
    assert available is True
    assert error is None
