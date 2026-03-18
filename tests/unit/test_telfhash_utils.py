"""Comprehensive tests for r2inspect/modules/telfhash_analyzer.py -- no mocks."""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.telfhash_analyzer import TELFHASH_AVAILABLE, TelfhashAnalyzer


# ---------------------------------------------------------------------------
# Minimal fake r2 backend
# ---------------------------------------------------------------------------


class FakeR2:
    """Minimal r2pipe-like object backed by static command maps."""

    def __init__(self, cmd_map=None, cmdj_map=None):
        self._cmd_map = cmd_map or {}
        self._cmdj_map = cmdj_map or {}

    def cmd(self, command):
        return self._cmd_map.get(command, "")

    def cmdj(self, command):
        val = self._cmdj_map.get(command)
        if val is None:
            return None
        return val


def _make_adapter(cmd_map=None, cmdj_map=None):
    return R2PipeAdapter(FakeR2(cmd_map=cmd_map, cmdj_map=cmdj_map))


# ---------------------------------------------------------------------------
# Helper: create a minimal ELF binary on disk
# ---------------------------------------------------------------------------


def _make_elf_file(tmp_path: Path, *, symbols: list[dict] | None = None) -> str:
    """Write a minimal valid ELF-64 binary to *tmp_path* and return its path.

    The binary only needs to have the \x7fELF magic so that ``_is_elf_file``
    recognises it.  It is not executable.
    """
    path = tmp_path / "test.elf"
    # Minimal ELF-64 header (64 bytes)
    e_ident = b"\x7fELF"  # magic
    e_ident += b"\x02"  # 64-bit
    e_ident += b"\x01"  # little-endian
    e_ident += b"\x01"  # ELF version
    e_ident += b"\x00" * 9  # padding to 16 bytes
    header = e_ident
    header += struct.pack("<H", 2)  # e_type: ET_EXEC
    header += struct.pack("<H", 0x3E)  # e_machine: x86-64
    header += struct.pack("<I", 1)  # e_version
    header += struct.pack("<Q", 0)  # e_entry
    header += struct.pack("<Q", 0)  # e_phoff
    header += struct.pack("<Q", 0)  # e_shoff
    header += struct.pack("<I", 0)  # e_flags
    header += struct.pack("<H", 64)  # e_ehsize
    header += struct.pack("<H", 0)  # e_phentsize
    header += struct.pack("<H", 0)  # e_phnum
    header += struct.pack("<H", 0)  # e_shentsize
    header += struct.pack("<H", 0)  # e_shnum
    header += struct.pack("<H", 0)  # e_shstrndx
    path.write_bytes(header)
    return str(path)


def _make_non_elf_file(tmp_path: Path) -> str:
    """Write a non-ELF file and return its path."""
    path = tmp_path / "test.bin"
    path.write_bytes(b"NOT_ELF_CONTENT" + b"\x00" * 64)
    return str(path)


def _make_pe_file(tmp_path: Path) -> str:
    """Write a minimal PE-like file (MZ header) and return its path."""
    path = tmp_path / "test.exe"
    path.write_bytes(b"MZ" + b"\x00" * 128)
    return str(path)


# ---------------------------------------------------------------------------
# Adapter factories for common scenarios
# ---------------------------------------------------------------------------


def _elf_adapter(filepath: str, *, symbols: list[dict] | None = None):
    """Build a FakeR2+R2PipeAdapter that reports an ELF binary."""
    sym_list = symbols or []
    info_json = {"bin": {"format": "elf", "class": "ELF64", "os": "linux"}}
    cmdj_map = {
        "ij": info_json,
        "isj": sym_list,
    }
    cmd_map = {
        "i": "format elf\nclass ELF64",
        "isj": json.dumps(sym_list),
    }
    return _make_adapter(cmd_map=cmd_map, cmdj_map=cmdj_map)


def _non_elf_adapter():
    """Build a FakeR2+R2PipeAdapter that reports a non-ELF binary."""
    info_json = {"bin": {"format": "pe", "class": "PE32"}}
    return _make_adapter(
        cmd_map={"i": "format pe"},
        cmdj_map={"ij": info_json, "isj": []},
    )


# ---------------------------------------------------------------------------
# Init / basic accessors
# ---------------------------------------------------------------------------


def test_telfhash_analyzer_init(tmp_path):
    filepath = _make_elf_file(tmp_path)
    adapter = _elf_adapter(filepath)
    analyzer = TelfhashAnalyzer(adapter, filepath)
    assert analyzer.adapter is adapter
    assert str(analyzer.filepath) == filepath


def test_telfhash_analyzer_check_library_availability(tmp_path):
    filepath = _make_elf_file(tmp_path)
    analyzer = TelfhashAnalyzer(_elf_adapter(filepath), filepath)
    available, error = analyzer._check_library_availability()
    if TELFHASH_AVAILABLE:
        assert available is True
        assert error is None
    else:
        assert available is False
        assert "telfhash library not available" in error


def test_telfhash_analyzer_get_hash_type(tmp_path):
    filepath = _make_elf_file(tmp_path)
    analyzer = TelfhashAnalyzer(_elf_adapter(filepath), filepath)
    assert analyzer._get_hash_type() == "telfhash"


def test_telfhash_analyzer_is_available():
    assert TelfhashAnalyzer.is_available() == TELFHASH_AVAILABLE


# ---------------------------------------------------------------------------
# analyze_symbols when library is unavailable
# ---------------------------------------------------------------------------


def test_telfhash_analyzer_analyze_symbols_not_available(tmp_path):
    filepath = _make_elf_file(tmp_path)
    analyzer = TelfhashAnalyzer(_elf_adapter(filepath), filepath)
    if not TELFHASH_AVAILABLE:
        result = analyzer.analyze_symbols()
        assert result["available"] is False
        assert result["error"] == "telfhash library not available"
        assert result["telfhash"] is None
    else:
        pytest.skip("telfhash library is installed; cannot test unavailable path")


# ---------------------------------------------------------------------------
# _is_elf_file
# ---------------------------------------------------------------------------


def test_telfhash_analyzer_is_elf_file_no_r2(tmp_path):
    filepath = _make_elf_file(tmp_path)
    adapter = _elf_adapter(filepath)
    analyzer = TelfhashAnalyzer(adapter, filepath)
    # Force r2 to None to exercise the early-return branch
    analyzer.r2 = None
    assert analyzer._is_elf_file() is False


def test_telfhash_analyzer_is_elf_file_real_elf(tmp_path):
    filepath = _make_elf_file(tmp_path)
    adapter = _elf_adapter(filepath)
    analyzer = TelfhashAnalyzer(adapter, filepath)
    assert analyzer._is_elf_file() is True


def test_telfhash_analyzer_is_elf_file_non_elf(tmp_path):
    filepath = _make_non_elf_file(tmp_path)
    adapter = _non_elf_adapter()
    analyzer = TelfhashAnalyzer(adapter, filepath)
    assert analyzer._is_elf_file() is False


# ---------------------------------------------------------------------------
# _filter_symbols_for_telfhash
# ---------------------------------------------------------------------------


def test_telfhash_analyzer_filter_symbols_for_telfhash(tmp_path):
    filepath = _make_elf_file(tmp_path)
    analyzer = TelfhashAnalyzer(_elf_adapter(filepath), filepath)

    symbols = [
        {"type": "FUNC", "bind": "GLOBAL", "name": "main"},
        {"type": "FUNC", "bind": "LOCAL", "name": "local_func"},
        {"type": "OBJECT", "bind": "GLOBAL", "name": "global_var"},
        {"type": "NOTYPE", "bind": "GLOBAL", "name": "notype_symbol"},
        {"type": "FUNC", "bind": "WEAK", "name": "weak_func"},
        {"type": "FUNC", "bind": "GLOBAL", "name": ""},
        {"type": "FUNC", "bind": "GLOBAL", "name": "__internal"},
    ]

    filtered = analyzer._filter_symbols_for_telfhash(symbols)

    assert len(filtered) == 3
    names = {s["name"] for s in filtered}
    assert "main" in names
    assert "global_var" in names
    assert "weak_func" in names


def test_telfhash_analyzer_filter_symbols_case_insensitive(tmp_path):
    filepath = _make_elf_file(tmp_path)
    analyzer = TelfhashAnalyzer(_elf_adapter(filepath), filepath)

    symbols = [
        {"type": "func", "bind": "global", "name": "main"},
        {"type": "FUNC", "bind": "GLOBAL", "name": "printf"},
    ]

    filtered = analyzer._filter_symbols_for_telfhash(symbols)
    assert len(filtered) == 2


def test_telfhash_analyzer_filter_symbols_empty_name(tmp_path):
    filepath = _make_elf_file(tmp_path)
    analyzer = TelfhashAnalyzer(_elf_adapter(filepath), filepath)

    symbols = [
        {"type": "FUNC", "bind": "GLOBAL", "name": ""},
        {"type": "FUNC", "bind": "GLOBAL", "name": "   "},
    ]

    filtered = analyzer._filter_symbols_for_telfhash(symbols)
    assert len(filtered) == 0


def test_telfhash_analyzer_filter_symbols_object_type(tmp_path):
    filepath = _make_elf_file(tmp_path)
    analyzer = TelfhashAnalyzer(_elf_adapter(filepath), filepath)

    symbols = [
        {"type": "OBJECT", "bind": "GLOBAL", "name": "data_object"},
        {"type": "OBJECT", "bind": "WEAK", "name": "weak_object"},
    ]

    filtered = analyzer._filter_symbols_for_telfhash(symbols)
    assert len(filtered) == 2


def test_telfhash_analyzer_filter_symbols_mixed(tmp_path):
    filepath = _make_elf_file(tmp_path)
    analyzer = TelfhashAnalyzer(_elf_adapter(filepath), filepath)

    symbols = [
        {"type": "FUNC", "bind": "GLOBAL", "name": "function1"},
        {"type": "OBJECT", "bind": "GLOBAL", "name": "variable1"},
        {"type": "SECTION", "bind": "LOCAL", "name": "section1"},
        {"type": "FILE", "bind": "LOCAL", "name": "file1"},
    ]

    filtered = analyzer._filter_symbols_for_telfhash(symbols)
    assert len(filtered) == 2
    assert all(s["type"] in ["FUNC", "OBJECT"] for s in filtered)


# ---------------------------------------------------------------------------
# _should_skip_symbol
# ---------------------------------------------------------------------------


def test_telfhash_analyzer_should_skip_symbol(tmp_path):
    filepath = _make_elf_file(tmp_path)
    analyzer = TelfhashAnalyzer(_elf_adapter(filepath), filepath)

    assert analyzer._should_skip_symbol("") is True
    assert analyzer._should_skip_symbol("a") is True
    assert analyzer._should_skip_symbol("__internal") is True
    assert analyzer._should_skip_symbol("_GLOBAL_OFFSET_TABLE_") is True
    assert analyzer._should_skip_symbol("_DYNAMIC") is True
    assert analyzer._should_skip_symbol(".Llocal") is True
    assert analyzer._should_skip_symbol("_edata") is True
    assert analyzer._should_skip_symbol("_end") is True
    assert analyzer._should_skip_symbol("_start") is True

    assert analyzer._should_skip_symbol("main") is False
    assert analyzer._should_skip_symbol("printf") is False


def test_telfhash_analyzer_should_skip_multiple_patterns(tmp_path):
    filepath = _make_elf_file(tmp_path)
    analyzer = TelfhashAnalyzer(_elf_adapter(filepath), filepath)

    skip_symbols = [
        "__init_array",
        "_GLOBAL_test",
        "_DYNAMIC_section",
        ".Ltext",
        "_edata_marker",
        "_end_marker",
        "_start_main",
    ]

    for symbol in skip_symbols:
        assert analyzer._should_skip_symbol(symbol) is True


# ---------------------------------------------------------------------------
# _extract_symbol_names
# ---------------------------------------------------------------------------


def test_telfhash_analyzer_extract_symbol_names(tmp_path):
    filepath = _make_elf_file(tmp_path)
    analyzer = TelfhashAnalyzer(_elf_adapter(filepath), filepath)

    symbols = [
        {"name": "zebra"},
        {"name": "apple"},
        {"name": "banana"},
        {"name": ""},
    ]

    names = analyzer._extract_symbol_names(symbols)
    assert names == ["apple", "banana", "zebra"]


def test_telfhash_analyzer_extract_symbol_names_with_whitespace(tmp_path):
    filepath = _make_elf_file(tmp_path)
    analyzer = TelfhashAnalyzer(_elf_adapter(filepath), filepath)

    symbols = [
        {"name": "  func1  "},
        {"name": " func2"},
    ]

    names = analyzer._extract_symbol_names(symbols)
    assert "func1" in names
    assert "func2" in names


def test_telfhash_analyzer_extract_symbol_names_empty_list(tmp_path):
    filepath = _make_elf_file(tmp_path)
    analyzer = TelfhashAnalyzer(_elf_adapter(filepath), filepath)

    names = analyzer._extract_symbol_names([])
    assert names == []


# ---------------------------------------------------------------------------
# _get_elf_symbols (via FakeR2 command maps)
# ---------------------------------------------------------------------------


def test_telfhash_analyzer_get_elf_symbols_empty(tmp_path):
    filepath = _make_elf_file(tmp_path)
    # Adapter returns empty symbol list
    adapter = _make_adapter(
        cmdj_map={"isj": []},
        cmd_map={"isj": "[]"},
    )
    analyzer = TelfhashAnalyzer(adapter, filepath)
    symbols = analyzer._get_elf_symbols()
    assert symbols == []


def test_telfhash_analyzer_get_elf_symbols_exception(tmp_path):
    filepath = _make_elf_file(tmp_path)
    # Adapter returns None (simulating missing command) -- _cmd_list should
    # return [] or raise; the analyzer catches exceptions and returns [].
    adapter = _make_adapter(cmdj_map={"isj": None}, cmd_map={})
    analyzer = TelfhashAnalyzer(adapter, filepath)
    symbols = analyzer._get_elf_symbols()
    assert symbols == []


def test_telfhash_analyzer_get_elf_symbols_with_count(tmp_path):
    filepath = _make_elf_file(tmp_path)
    test_symbols = [{"name": f"func{i}"} for i in range(100)]
    adapter = _make_adapter(
        cmdj_map={"isj": test_symbols},
        cmd_map={"isj": json.dumps(test_symbols)},
    )
    analyzer = TelfhashAnalyzer(adapter, filepath)
    symbols = analyzer._get_elf_symbols()
    assert len(symbols) == 100


# ---------------------------------------------------------------------------
# _has_elf_symbols
# ---------------------------------------------------------------------------


def test_telfhash_analyzer_has_elf_symbols_no_symbols(tmp_path):
    filepath = _make_elf_file(tmp_path)
    adapter = _make_adapter(cmdj_map={"isj": None})
    analyzer = TelfhashAnalyzer(adapter, filepath)
    assert analyzer._has_elf_symbols({}) is False


def test_telfhash_analyzer_has_elf_symbols_no_bin(tmp_path):
    filepath = _make_elf_file(tmp_path)
    adapter = _make_adapter(cmdj_map={"isj": [{"name": "symbol"}]})
    analyzer = TelfhashAnalyzer(adapter, filepath)
    assert analyzer._has_elf_symbols({}) is False


def test_telfhash_analyzer_has_elf_symbols_linux(tmp_path):
    filepath = _make_elf_file(tmp_path)
    adapter = _make_adapter(cmdj_map={"isj": [{"name": "symbol"}]})
    analyzer = TelfhashAnalyzer(adapter, filepath)
    info_cmd = {"bin": {"os": "linux"}}
    assert analyzer._has_elf_symbols(info_cmd) is True


def test_telfhash_analyzer_has_elf_symbols_unix(tmp_path):
    filepath = _make_elf_file(tmp_path)
    adapter = _make_adapter(cmdj_map={"isj": [{"name": "symbol"}]})
    analyzer = TelfhashAnalyzer(adapter, filepath)
    info_cmd = {"bin": {"os": "unix"}}
    assert analyzer._has_elf_symbols(info_cmd) is True


def test_telfhash_analyzer_has_elf_symbols_exception(tmp_path):
    """When the underlying command raises, _has_elf_symbols returns False."""
    filepath = _make_elf_file(tmp_path)

    class RaisingR2:
        def cmd(self, command):
            raise RuntimeError("boom")

        def cmdj(self, command):
            raise RuntimeError("boom")

    adapter = R2PipeAdapter(RaisingR2())
    analyzer = TelfhashAnalyzer(adapter, filepath)
    assert analyzer._has_elf_symbols({"bin": {"os": "linux"}}) is False


# ---------------------------------------------------------------------------
# analyze() -- template-method compatibility
# ---------------------------------------------------------------------------


def test_telfhash_analyzer_analyze_adds_telfhash_field(tmp_path):
    filepath = _make_elf_file(tmp_path)
    adapter = _elf_adapter(filepath)
    analyzer = TelfhashAnalyzer(adapter, filepath)
    result = analyzer.analyze()
    # analyze() always includes a "telfhash" key
    assert "telfhash" in result


def test_telfhash_analyzer_analyze_telfhash_field_present(tmp_path):
    filepath = _make_elf_file(tmp_path)
    adapter = _elf_adapter(filepath)
    analyzer = TelfhashAnalyzer(adapter, filepath)
    result = analyzer.analyze()
    # When telfhash is not installed the value will be None; when installed
    # it will either be a hash string or None (file may be too minimal).
    assert "telfhash" in result
    assert isinstance(result.get("telfhash"), (str, type(None)))


# ---------------------------------------------------------------------------
# _calculate_hash  -- non-ELF path
# ---------------------------------------------------------------------------


def test_telfhash_analyzer_calculate_hash_non_elf(tmp_path):
    filepath = _make_non_elf_file(tmp_path)
    adapter = _non_elf_adapter()
    analyzer = TelfhashAnalyzer(adapter, filepath)
    hash_value, method, error = analyzer._calculate_hash()
    if not TELFHASH_AVAILABLE:
        # _check_library_availability fires first in the template
        pytest.skip("telfhash library not installed")
    assert hash_value is None
    assert method is None
    assert "not an ELF binary" in error


# ---------------------------------------------------------------------------
# analyze_symbols -- non-ELF path
# ---------------------------------------------------------------------------


def test_telfhash_analyzer_analyze_symbols_non_elf(tmp_path):
    filepath = _make_non_elf_file(tmp_path)
    adapter = _non_elf_adapter()
    analyzer = TelfhashAnalyzer(adapter, filepath)

    if TELFHASH_AVAILABLE:
        result = analyzer.analyze_symbols()
        assert result["is_elf"] is False
        assert result["error"] == "File is not an ELF binary"
    else:
        result = analyzer.analyze_symbols()
        assert result["available"] is False


# ---------------------------------------------------------------------------
# compare_hashes
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not TELFHASH_AVAILABLE, reason="telfhash library not available")
def test_telfhash_analyzer_compare_hashes():
    hash1 = "test_hash1"
    hash2 = "test_hash2"
    # Result depends on ssdeep availability; just exercise the path
    TelfhashAnalyzer.compare_hashes(hash1, hash2)


def test_telfhash_analyzer_compare_hashes_empty():
    result = TelfhashAnalyzer.compare_hashes("", "hash2")
    assert result is None

    result = TelfhashAnalyzer.compare_hashes("hash1", "")
    assert result is None

    result = TelfhashAnalyzer.compare_hashes(None, "hash2")
    assert result is None


def test_telfhash_analyzer_compare_hashes_not_available():
    if not TELFHASH_AVAILABLE:
        result = TelfhashAnalyzer.compare_hashes("hash1", "hash2")
        assert result is None
    else:
        pytest.skip("telfhash is installed; cannot test unavailable path")


# ---------------------------------------------------------------------------
# calculate_telfhash_from_file
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not TELFHASH_AVAILABLE, reason="telfhash library not available")
def test_telfhash_analyzer_calculate_telfhash_from_file():
    # Using a non-existent path; telfhash should handle gracefully
    TelfhashAnalyzer.calculate_telfhash_from_file("/nonexistent/file.elf")


def test_telfhash_analyzer_calculate_telfhash_from_file_not_available():
    if not TELFHASH_AVAILABLE:
        result = TelfhashAnalyzer.calculate_telfhash_from_file("/test/file.elf")
        assert result is None
    else:
        pytest.skip("telfhash is installed; cannot test unavailable path")


# ---------------------------------------------------------------------------
# analyze_symbols with symbols present (ELF path, library available)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not TELFHASH_AVAILABLE, reason="telfhash library not available")
def test_telfhash_analyzer_analyze_symbols_with_elf(tmp_path):
    filepath = _make_elf_file(tmp_path)
    test_symbols = [
        {"type": "FUNC", "bind": "GLOBAL", "name": "main"},
        {"type": "FUNC", "bind": "GLOBAL", "name": "printf"},
        {"type": "OBJECT", "bind": "GLOBAL", "name": "stderr"},
    ]
    adapter = _elf_adapter(filepath, symbols=test_symbols)
    analyzer = TelfhashAnalyzer(adapter, filepath)

    result = analyzer.analyze_symbols()
    assert result["available"] is True
    assert result["is_elf"] is True
    assert result["symbol_count"] == 3
    assert result["filtered_symbols"] >= 0


# ---------------------------------------------------------------------------
# _is_elf_file with PE file
# ---------------------------------------------------------------------------


def test_telfhash_analyzer_is_elf_file_pe(tmp_path):
    filepath = _make_pe_file(tmp_path)
    adapter = _make_adapter(
        cmd_map={"i": "format pe"},
        cmdj_map={"ij": {"bin": {"format": "pe", "class": "PE32"}}},
    )
    analyzer = TelfhashAnalyzer(adapter, filepath)
    assert analyzer._is_elf_file() is False
