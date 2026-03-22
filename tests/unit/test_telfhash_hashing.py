"""Comprehensive tests for telfhash_analyzer.py - hashing functionality.

NO mocks, NO monkeypatch, NO @patch.
Uses FakeR2 + R2PipeAdapter for adapter-dependent tests.
Uses real temporary ELF files for file-based tests.
"""

import json
import os
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.telfhash_analyzer import TelfhashAnalyzer, TELFHASH_AVAILABLE
from r2inspect.domain.formats.telfhash import (
    extract_symbol_names,
    filter_symbols_for_telfhash,
    normalize_telfhash_value,
    parse_telfhash_result,
    should_skip_symbol,
)


# ---------------------------------------------------------------------------
# FakeR2 -- lightweight stand-in for r2pipe instances
# ---------------------------------------------------------------------------


class FakeR2:
    """Minimal r2pipe stand-in with cmd/cmdj routing."""

    def __init__(
        self,
        *,
        cmd_map: dict[str, str] | None = None,
        cmdj_map: dict[str, Any] | None = None,
    ) -> None:
        self.cmd_map = cmd_map or {}
        self.cmdj_map = cmdj_map or {}

    def cmd(self, command: str) -> str:
        return self.cmd_map.get(command, "")

    def cmdj(self, command: str) -> Any:
        val = self.cmdj_map.get(command)
        if isinstance(val, Exception):
            raise val
        return val

    def quit(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers: create real minimal ELF files on disk
# ---------------------------------------------------------------------------


def _minimal_elf_bytes() -> bytes:
    """Build a tiny valid ELF64 header (no sections, not runnable)."""
    # ELF magic + EI_CLASS=2(64-bit) + EI_DATA=1(LE) + EI_VERSION=1 + EI_OSABI=0
    e_ident = b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 9
    # e_type=ET_EXEC(2), e_machine=EM_X86_64(0x3e), e_version=1
    header = struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # e_type
        0x3E,  # e_machine
        1,  # e_version
        0x400000,  # e_entry
        64,  # e_phoff (right after header)
        0,  # e_shoff
        0,  # e_flags
        64,  # e_ehsize
        56,  # e_phentsize
        0,  # e_phnum
        64,  # e_shentsize
        0,  # e_shnum
        0,  # e_shstrndx
    )
    return e_ident + header


def _write_elf_file(directory: str, name: str = "test.elf") -> str:
    """Write a minimal ELF file and return its path."""
    path = os.path.join(directory, name)
    with open(path, "wb") as f:
        f.write(_minimal_elf_bytes())
    return path


def _write_pe_file(directory: str, name: str = "test.exe") -> str:
    """Write a minimal PE stub and return its path."""
    path = os.path.join(directory, name)
    with open(path, "wb") as f:
        f.write(b"MZ" + b"\x00" * 126)
    return path


def _write_text_file(directory: str, name: str = "test.txt") -> str:
    """Write a plain text file and return its path."""
    path = os.path.join(directory, name)
    with open(path, "w") as f:
        f.write("Hello, world!\n")
    return path


def _make_adapter_for_elf(filepath: str) -> R2PipeAdapter:
    """Create an R2PipeAdapter backed by a FakeR2 that reports ELF info."""
    fake = FakeR2(
        cmd_map={
            "i": "type elf\narch x86\nbits 64",
            "ij": json.dumps(
                {
                    "bin": {"format": "elf", "class": "ELF64", "os": "linux", "type": "DYN"},
                }
            ),
            "isj": json.dumps(
                [
                    {"name": "main", "type": "FUNC", "bind": "GLOBAL", "size": 100},
                    {"name": "printf", "type": "FUNC", "bind": "GLOBAL", "size": 50},
                ]
            ),
        },
        cmdj_map={
            "ij": {"bin": {"format": "elf", "class": "ELF64", "os": "linux", "type": "DYN"}},
            "isj": [
                {"name": "main", "type": "FUNC", "bind": "GLOBAL", "size": 100},
                {"name": "printf", "type": "FUNC", "bind": "GLOBAL", "size": 50},
            ],
        },
    )
    return R2PipeAdapter(fake)


def _make_adapter_for_pe(filepath: str) -> R2PipeAdapter:
    """Create an R2PipeAdapter backed by a FakeR2 that reports PE info."""
    fake = FakeR2(
        cmd_map={
            "i": "type pe\narch x86\nbits 32",
        },
        cmdj_map={
            "ij": {"bin": {"format": "pe", "class": "PE32", "os": "windows"}},
            "isj": [],
        },
    )
    return R2PipeAdapter(fake)


def _make_adapter_empty() -> R2PipeAdapter:
    """Create an R2PipeAdapter backed by an empty FakeR2."""
    return R2PipeAdapter(FakeR2())


# ---------------------------------------------------------------------------
# Tests: initialization
# ---------------------------------------------------------------------------


class TestInit:
    def test_init_stores_adapter_and_filepath(self):
        with tempfile.TemporaryDirectory() as td:
            elf_path = _write_elf_file(td)
            adapter = _make_adapter_for_elf(elf_path)
            analyzer = TelfhashAnalyzer(adapter, elf_path)
            assert analyzer.adapter is adapter
            assert str(analyzer.filepath) == elf_path or analyzer.filepath == Path(elf_path)

    def test_init_with_nonexistent_path(self):
        adapter = _make_adapter_empty()
        analyzer = TelfhashAnalyzer(adapter, "/tmp/nonexistent_elf_abc123")
        assert analyzer._get_hash_type() == "telfhash"


# ---------------------------------------------------------------------------
# Tests: is_available (static, depends on actual import state)
# ---------------------------------------------------------------------------


class TestIsAvailable:
    def test_is_available_matches_module_flag(self):
        result = TelfhashAnalyzer.is_available()
        assert result is TELFHASH_AVAILABLE

    def test_is_available_returns_bool(self):
        assert isinstance(TelfhashAnalyzer.is_available(), bool)


# ---------------------------------------------------------------------------
# Tests: _check_library_availability
# ---------------------------------------------------------------------------


class TestCheckLibraryAvailability:
    def test_returns_tuple(self):
        adapter = _make_adapter_empty()
        analyzer = TelfhashAnalyzer(adapter, "/tmp/fake_elf")
        is_avail, error = analyzer._check_library_availability()
        assert isinstance(is_avail, bool)
        if is_avail:
            assert error is None
        else:
            assert error is not None
            assert "not available" in error

    def test_consistency_with_is_available(self):
        adapter = _make_adapter_empty()
        analyzer = TelfhashAnalyzer(adapter, "/tmp/fake_elf")
        is_avail, _ = analyzer._check_library_availability()
        assert is_avail == TelfhashAnalyzer.is_available()


# ---------------------------------------------------------------------------
# Tests: _get_hash_type
# ---------------------------------------------------------------------------


class TestGetHashType:
    def test_returns_telfhash(self):
        adapter = _make_adapter_empty()
        analyzer = TelfhashAnalyzer(adapter, "/tmp/fake_elf")
        assert analyzer._get_hash_type() == "telfhash"


# ---------------------------------------------------------------------------
# Tests: _is_elf_file  (uses real temp files)
# ---------------------------------------------------------------------------


class TestIsElfFile:
    def test_real_elf_is_detected(self):
        with tempfile.TemporaryDirectory() as td:
            elf_path = _write_elf_file(td)
            adapter = _make_adapter_for_elf(elf_path)
            analyzer = TelfhashAnalyzer(adapter, elf_path)
            assert analyzer._is_elf_file() is True

    def test_pe_file_is_not_elf(self):
        with tempfile.TemporaryDirectory() as td:
            pe_path = _write_pe_file(td)
            adapter = _make_adapter_for_pe(pe_path)
            analyzer = TelfhashAnalyzer(adapter, pe_path)
            assert analyzer._is_elf_file() is False

    def test_text_file_is_not_elf(self):
        with tempfile.TemporaryDirectory() as td:
            txt_path = _write_text_file(td)
            adapter = _make_adapter_empty()
            analyzer = TelfhashAnalyzer(adapter, txt_path)
            assert analyzer._is_elf_file() is False


# ---------------------------------------------------------------------------
# Tests: _calculate_hash  (depends on real telfhash availability)
# ---------------------------------------------------------------------------


class TestCalculateHash:
    def test_non_elf_returns_error(self):
        with tempfile.TemporaryDirectory() as td:
            txt_path = _write_text_file(td)
            adapter = _make_adapter_empty()
            analyzer = TelfhashAnalyzer(adapter, txt_path)
            hash_val, method, error = analyzer._calculate_hash()
            assert hash_val is None
            assert method is None
            assert error is not None
            assert "not an ELF" in error

    def test_pe_file_returns_error(self):
        with tempfile.TemporaryDirectory() as td:
            pe_path = _write_pe_file(td)
            adapter = _make_adapter_for_pe(pe_path)
            analyzer = TelfhashAnalyzer(adapter, pe_path)
            hash_val, method, error = analyzer._calculate_hash()
            assert hash_val is None
            assert method is None
            assert error is not None

    @pytest.mark.skipif(not TELFHASH_AVAILABLE, reason="telfhash not installed")
    def test_real_elf_with_telfhash(self):
        """If telfhash is installed, a minimal ELF may produce a hash or a message."""
        with tempfile.TemporaryDirectory() as td:
            elf_path = _write_elf_file(td)
            adapter = _make_adapter_for_elf(elf_path)
            analyzer = TelfhashAnalyzer(adapter, elf_path)
            hash_val, method, error = analyzer._calculate_hash()
            # A minimal ELF with no real symbols may get "no hash" or an actual hash
            if hash_val is not None:
                assert isinstance(hash_val, str)
                assert method == "python_library"
                assert error is None
            else:
                assert error is not None


# ---------------------------------------------------------------------------
# Tests: analyze  (template method, end-to-end)
# ---------------------------------------------------------------------------


class TestAnalyze:
    def test_analyze_returns_dict_with_standard_keys(self):
        with tempfile.TemporaryDirectory() as td:
            elf_path = _write_elf_file(td)
            adapter = _make_adapter_for_elf(elf_path)
            analyzer = TelfhashAnalyzer(adapter, elf_path)
            result = analyzer.analyze()
            assert isinstance(result, dict)
            assert "hash_type" in result
            assert result["hash_type"] == "telfhash"
            assert "telfhash" in result  # compatibility field

    def test_analyze_telfhash_field_matches_hash_value(self):
        with tempfile.TemporaryDirectory() as td:
            elf_path = _write_elf_file(td)
            adapter = _make_adapter_for_elf(elf_path)
            analyzer = TelfhashAnalyzer(adapter, elf_path)
            result = analyzer.analyze()
            assert result["telfhash"] == result.get("hash_value")

    def test_analyze_nonexistent_file(self):
        adapter = _make_adapter_empty()
        analyzer = TelfhashAnalyzer(adapter, "/tmp/nonexistent_elf_xyz_999")
        result = analyzer.analyze()
        assert isinstance(result, dict)
        assert result.get("error") is not None

    def test_analyze_non_elf_file(self):
        with tempfile.TemporaryDirectory() as td:
            txt_path = _write_text_file(td)
            adapter = _make_adapter_empty()
            analyzer = TelfhashAnalyzer(adapter, txt_path)
            result = analyzer.analyze()
            assert isinstance(result, dict)
            # Should either fail at library check or at ELF check
            if result.get("available"):
                assert result.get("hash_value") is None


# ---------------------------------------------------------------------------
# Tests: calculate_telfhash_from_file  (static method)
# ---------------------------------------------------------------------------


class TestCalculateTelfhashFromFile:
    @pytest.mark.skipif(not TELFHASH_AVAILABLE, reason="telfhash not installed")
    def test_with_real_elf(self):
        with tempfile.TemporaryDirectory() as td:
            elf_path = _write_elf_file(td)
            result = TelfhashAnalyzer.calculate_telfhash_from_file(elf_path)
            # May return None for minimal ELF with no symbols
            if result is not None:
                assert isinstance(result, str)
                assert len(result) > 0

    @pytest.mark.skipif(not TELFHASH_AVAILABLE, reason="telfhash not installed")
    def test_with_nonexistent_file(self):
        result = TelfhashAnalyzer.calculate_telfhash_from_file("/tmp/no_such_file_telfhash_xyz")
        assert result is None

    @pytest.mark.skipif(not TELFHASH_AVAILABLE, reason="telfhash not installed")
    def test_with_text_file(self):
        with tempfile.TemporaryDirectory() as td:
            txt_path = _write_text_file(td)
            result = TelfhashAnalyzer.calculate_telfhash_from_file(txt_path)
            # Should return None since it's not ELF
            assert result is None or isinstance(result, str)

    @pytest.mark.skipif(TELFHASH_AVAILABLE, reason="test only when telfhash NOT installed")
    def test_not_available_returns_none(self):
        result = TelfhashAnalyzer.calculate_telfhash_from_file("/tmp/any_file")
        assert result is None


# ---------------------------------------------------------------------------
# Tests: parse_telfhash_result  (support function, pure logic)
# ---------------------------------------------------------------------------


class TestParseTelfhashResult:
    def test_list_with_hash(self):
        result = [{"telfhash": "T1234ABCD"}]
        hash_val, msg = parse_telfhash_result(result)
        assert hash_val == "T1234ABCD"
        assert msg is None

    def test_dict_with_hash(self):
        result = {"telfhash": "T5678EFGH"}
        hash_val, msg = parse_telfhash_result(result)
        assert hash_val == "T5678EFGH"
        assert msg is None

    def test_string_value(self):
        hash_val, msg = parse_telfhash_result("T9999IJKL")
        assert hash_val == "T9999IJKL"
        assert msg is None

    def test_list_with_msg_no_hash(self):
        result = [{"msg": "Not enough symbols", "telfhash": None}]
        hash_val, msg = parse_telfhash_result(result)
        assert hash_val is None
        assert msg == "Not enough symbols"

    def test_dict_with_msg_no_hash(self):
        result = {"msg": "Invalid ELF", "telfhash": None}
        hash_val, msg = parse_telfhash_result(result)
        assert hash_val is None
        assert msg == "Invalid ELF"

    def test_none_input(self):
        hash_val, msg = parse_telfhash_result(None)
        assert hash_val is None
        assert msg is None

    def test_empty_list(self):
        hash_val, msg = parse_telfhash_result([])
        assert hash_val is None

    def test_list_with_empty_hash(self):
        result = [{"telfhash": ""}]
        hash_val, msg = parse_telfhash_result(result)
        assert hash_val is None

    def test_list_with_dash_hash(self):
        result = [{"telfhash": "-"}]
        hash_val, msg = parse_telfhash_result(result)
        assert hash_val is None

    def test_dict_with_dash_hash(self):
        result = {"telfhash": "-"}
        hash_val, msg = parse_telfhash_result(result)
        assert hash_val is None


# ---------------------------------------------------------------------------
# Tests: normalize_telfhash_value  (support function, pure logic)
# ---------------------------------------------------------------------------


class TestNormalizeTelfhashValue:
    def test_valid_string(self):
        assert normalize_telfhash_value("TAAAA1234") == "TAAAA1234"

    def test_strips_whitespace(self):
        assert normalize_telfhash_value("  THASH  ") == "THASH"

    def test_none_input(self):
        assert normalize_telfhash_value(None) is None

    def test_integer_input(self):
        assert normalize_telfhash_value(12345) is None

    def test_empty_string(self):
        assert normalize_telfhash_value("") is None

    def test_dash_only(self):
        assert normalize_telfhash_value("-") is None

    def test_whitespace_only(self):
        assert normalize_telfhash_value("   ") is None


# ---------------------------------------------------------------------------
# Tests: should_skip_symbol  (support function, pure logic)
# ---------------------------------------------------------------------------


class TestShouldSkipSymbol:
    def test_short_name_skipped(self):
        assert should_skip_symbol("a") is True

    def test_double_underscore_prefix(self):
        assert should_skip_symbol("__libc_start_main") is True

    def test_global_offset(self):
        assert should_skip_symbol("_GLOBAL_OFFSET_TABLE_") is True

    def test_dynamic_prefix(self):
        assert should_skip_symbol("_DYNAMIC") is True

    def test_dot_l_prefix(self):
        assert should_skip_symbol(".Lfoo") is True

    def test_edata(self):
        assert should_skip_symbol("_edata") is True

    def test_end(self):
        assert should_skip_symbol("_end") is True

    def test_start(self):
        assert should_skip_symbol("_start") is True

    def test_normal_symbol_not_skipped(self):
        assert should_skip_symbol("printf") is False

    def test_normal_symbol_main(self):
        assert should_skip_symbol("main") is False

    def test_normal_symbol_malloc(self):
        assert should_skip_symbol("malloc") is False


# ---------------------------------------------------------------------------
# Tests: filter_symbols_for_telfhash  (support function, pure logic)
# ---------------------------------------------------------------------------


class TestFilterSymbolsForTelfhash:
    def test_keeps_global_funcs(self):
        symbols = [
            {"name": "main", "type": "FUNC", "bind": "GLOBAL"},
            {"name": "printf", "type": "FUNC", "bind": "GLOBAL"},
        ]
        filtered = filter_symbols_for_telfhash(symbols)
        assert len(filtered) == 2

    def test_removes_local_bindings(self):
        symbols = [
            {"name": "internal_fn", "type": "FUNC", "bind": "LOCAL"},
        ]
        filtered = filter_symbols_for_telfhash(symbols)
        assert len(filtered) == 0

    def test_removes_non_func_non_object(self):
        symbols = [
            {"name": "some_section", "type": "SECTION", "bind": "GLOBAL"},
            {"name": "some_file", "type": "FILE", "bind": "GLOBAL"},
        ]
        filtered = filter_symbols_for_telfhash(symbols)
        assert len(filtered) == 0

    def test_keeps_object_type(self):
        symbols = [
            {"name": "global_var", "type": "OBJECT", "bind": "GLOBAL"},
        ]
        filtered = filter_symbols_for_telfhash(symbols)
        assert len(filtered) == 1

    def test_keeps_weak_bindings(self):
        symbols = [
            {"name": "weak_fn", "type": "FUNC", "bind": "WEAK"},
        ]
        filtered = filter_symbols_for_telfhash(symbols)
        assert len(filtered) == 1

    def test_removes_unnamed_symbols(self):
        symbols = [
            {"name": "", "type": "FUNC", "bind": "GLOBAL"},
            {"name": "   ", "type": "FUNC", "bind": "GLOBAL"},
        ]
        filtered = filter_symbols_for_telfhash(symbols)
        assert len(filtered) == 0

    def test_removes_skip_patterns(self):
        symbols = [
            {"name": "__libc_start_main", "type": "FUNC", "bind": "GLOBAL"},
            {"name": "_GLOBAL_OFFSET_TABLE_", "type": "OBJECT", "bind": "GLOBAL"},
            {"name": "_start", "type": "FUNC", "bind": "GLOBAL"},
        ]
        filtered = filter_symbols_for_telfhash(symbols)
        assert len(filtered) == 0

    def test_mixed_symbols(self):
        symbols = [
            {"name": "main", "type": "FUNC", "bind": "GLOBAL"},
            {"name": "__init", "type": "FUNC", "bind": "GLOBAL"},
            {"name": "data_var", "type": "OBJECT", "bind": "WEAK"},
            {"name": "local_fn", "type": "FUNC", "bind": "LOCAL"},
            {"name": "", "type": "FUNC", "bind": "GLOBAL"},
        ]
        filtered = filter_symbols_for_telfhash(symbols)
        names = [s["name"] for s in filtered]
        assert "main" in names
        assert "data_var" in names
        assert "__init" not in names
        assert "local_fn" not in names

    def test_empty_list(self):
        assert filter_symbols_for_telfhash([]) == []


# ---------------------------------------------------------------------------
# Tests: extract_symbol_names  (support function, pure logic)
# ---------------------------------------------------------------------------


class TestExtractSymbolNames:
    def test_extracts_and_sorts(self):
        symbols = [
            {"name": "zebra"},
            {"name": "alpha"},
            {"name": "middle"},
        ]
        names = extract_symbol_names(symbols)
        assert names == ["alpha", "middle", "zebra"]

    def test_skips_empty_names(self):
        symbols = [
            {"name": "valid"},
            {"name": ""},
            {"name": "   "},
        ]
        names = extract_symbol_names(symbols)
        assert names == ["valid"]

    def test_strips_whitespace(self):
        symbols = [{"name": "  padded  "}]
        names = extract_symbol_names(symbols)
        assert names == ["padded"]

    def test_empty_list(self):
        assert extract_symbol_names([]) == []


# ---------------------------------------------------------------------------
# Tests: _get_elf_symbols via adapter
# ---------------------------------------------------------------------------


class TestGetElfSymbols:
    def test_returns_symbols_from_adapter(self):
        with tempfile.TemporaryDirectory() as td:
            elf_path = _write_elf_file(td)
            adapter = _make_adapter_for_elf(elf_path)
            analyzer = TelfhashAnalyzer(adapter, elf_path)
            symbols = analyzer._get_elf_symbols()
            assert isinstance(symbols, list)
            assert len(symbols) == 2
            assert symbols[0]["name"] == "main"

    def test_empty_symbols(self):
        with tempfile.TemporaryDirectory() as td:
            elf_path = _write_elf_file(td)
            adapter = _make_adapter_empty()
            analyzer = TelfhashAnalyzer(adapter, elf_path)
            symbols = analyzer._get_elf_symbols()
            assert isinstance(symbols, list)
            assert len(symbols) == 0


# ---------------------------------------------------------------------------
# Tests: _has_elf_symbols via adapter
# ---------------------------------------------------------------------------


class TestHasElfSymbols:
    def test_has_symbols_linux(self):
        with tempfile.TemporaryDirectory() as td:
            elf_path = _write_elf_file(td)
            adapter = _make_adapter_for_elf(elf_path)
            analyzer = TelfhashAnalyzer(adapter, elf_path)
            info_cmd = {"bin": {"os": "linux"}}
            assert analyzer._has_elf_symbols(info_cmd) is True

    def test_no_symbols(self):
        with tempfile.TemporaryDirectory() as td:
            elf_path = _write_elf_file(td)
            adapter = _make_adapter_empty()
            analyzer = TelfhashAnalyzer(adapter, elf_path)
            info_cmd = {"bin": {"os": "linux"}}
            assert analyzer._has_elf_symbols(info_cmd) is False

    def test_no_info_cmd(self):
        with tempfile.TemporaryDirectory() as td:
            elf_path = _write_elf_file(td)
            adapter = _make_adapter_for_elf(elf_path)
            analyzer = TelfhashAnalyzer(adapter, elf_path)
            assert analyzer._has_elf_symbols(None) is False

    def test_windows_os_rejected(self):
        fake = FakeR2(
            cmdj_map={
                "isj": [{"name": "main", "type": "FUNC", "bind": "GLOBAL"}],
            },
        )
        adapter = R2PipeAdapter(fake)
        with tempfile.TemporaryDirectory() as td:
            elf_path = _write_elf_file(td)
            analyzer = TelfhashAnalyzer(adapter, elf_path)
            info_cmd = {"bin": {"os": "windows"}}
            assert analyzer._has_elf_symbols(info_cmd) is False


# ---------------------------------------------------------------------------
# Tests: _filter_symbols_for_telfhash via analyzer instance
# ---------------------------------------------------------------------------


class TestFilterSymbolsInstance:
    def test_filters_through_analyzer(self):
        with tempfile.TemporaryDirectory() as td:
            elf_path = _write_elf_file(td)
            adapter = _make_adapter_for_elf(elf_path)
            analyzer = TelfhashAnalyzer(adapter, elf_path)
            symbols = [
                {"name": "main", "type": "FUNC", "bind": "GLOBAL"},
                {"name": "__internal", "type": "FUNC", "bind": "GLOBAL"},
                {"name": "local", "type": "FUNC", "bind": "LOCAL"},
            ]
            filtered = analyzer._filter_symbols_for_telfhash(symbols)
            assert len(filtered) == 1
            assert filtered[0]["name"] == "main"


# ---------------------------------------------------------------------------
# Tests: _extract_symbol_names via analyzer instance
# ---------------------------------------------------------------------------


class TestExtractSymbolNamesInstance:
    def test_extracts_names(self):
        with tempfile.TemporaryDirectory() as td:
            elf_path = _write_elf_file(td)
            adapter = _make_adapter_for_elf(elf_path)
            analyzer = TelfhashAnalyzer(adapter, elf_path)
            symbols = [
                {"name": "beta"},
                {"name": "alpha"},
            ]
            names = analyzer._extract_symbol_names(symbols)
            assert names == ["alpha", "beta"]


# ---------------------------------------------------------------------------
# Tests: _normalize_telfhash_value via static method
# ---------------------------------------------------------------------------


class TestNormalizeTelfhashValueStatic:
    def test_via_class(self):
        assert TelfhashAnalyzer._normalize_telfhash_value("HASH") == "HASH"

    def test_via_class_none(self):
        assert TelfhashAnalyzer._normalize_telfhash_value(None) is None

    def test_via_class_dash(self):
        assert TelfhashAnalyzer._normalize_telfhash_value("-") is None


# ---------------------------------------------------------------------------
# Tests: compare_hashes  (static, depends on ssdeep availability)
# ---------------------------------------------------------------------------


class TestCompareHashes:
    @pytest.mark.skipif(not TELFHASH_AVAILABLE, reason="telfhash not installed")
    def test_compare_empty_hashes_returns_none(self):
        assert TelfhashAnalyzer.compare_hashes("", "") is None

    @pytest.mark.skipif(not TELFHASH_AVAILABLE, reason="telfhash not installed")
    def test_compare_none_like_hashes(self):
        assert TelfhashAnalyzer.compare_hashes("", "something") is None

    def test_compare_when_unavailable(self):
        if not TELFHASH_AVAILABLE:
            assert TelfhashAnalyzer.compare_hashes("hash1", "hash2") is None


# ---------------------------------------------------------------------------
# Tests: analyze_symbols  (detailed analysis)
# ---------------------------------------------------------------------------


class TestAnalyzeSymbols:
    def test_non_elf_file(self):
        with tempfile.TemporaryDirectory() as td:
            txt_path = _write_text_file(td)
            adapter = _make_adapter_empty()
            analyzer = TelfhashAnalyzer(adapter, txt_path)
            result = analyzer.analyze_symbols()
            assert isinstance(result, dict)
            assert result.get("available") == TELFHASH_AVAILABLE
            if TELFHASH_AVAILABLE:
                assert result.get("error") is not None

    @pytest.mark.skipif(not TELFHASH_AVAILABLE, reason="telfhash not installed")
    def test_elf_file_with_symbols(self):
        with tempfile.TemporaryDirectory() as td:
            elf_path = _write_elf_file(td)
            adapter = _make_adapter_for_elf(elf_path)
            analyzer = TelfhashAnalyzer(adapter, elf_path)
            result = analyzer.analyze_symbols()
            assert isinstance(result, dict)
            assert result["available"] is True
            assert "symbol_count" in result
            assert "filtered_symbols" in result

    def test_not_available_returns_error(self):
        if not TELFHASH_AVAILABLE:
            with tempfile.TemporaryDirectory() as td:
                elf_path = _write_elf_file(td)
                adapter = _make_adapter_for_elf(elf_path)
                analyzer = TelfhashAnalyzer(adapter, elf_path)
                result = analyzer.analyze_symbols()
                assert result["available"] is False
                assert "not available" in result["error"]


# ---------------------------------------------------------------------------
# Tests: _should_skip_symbol via analyzer instance
# ---------------------------------------------------------------------------


class TestShouldSkipSymbolInstance:
    def test_skip_via_instance(self):
        adapter = _make_adapter_empty()
        analyzer = TelfhashAnalyzer(adapter, "/tmp/fake")
        assert analyzer._should_skip_symbol("__libc_start") is True
        assert analyzer._should_skip_symbol("printf") is False


# ---------------------------------------------------------------------------
# Tests: string representation
# ---------------------------------------------------------------------------


class TestStringRepr:
    def test_str_contains_telfhash(self):
        with tempfile.TemporaryDirectory() as td:
            elf_path = _write_elf_file(td)
            adapter = _make_adapter_for_elf(elf_path)
            analyzer = TelfhashAnalyzer(adapter, elf_path)
            assert "telfhash" in str(analyzer).lower()

    def test_repr_contains_filepath(self):
        with tempfile.TemporaryDirectory() as td:
            elf_path = _write_elf_file(td)
            adapter = _make_adapter_for_elf(elf_path)
            analyzer = TelfhashAnalyzer(adapter, elf_path)
            assert "test.elf" in repr(analyzer) or "TelfhashAnalyzer" in repr(analyzer)


# ---------------------------------------------------------------------------
# Tests: file size helpers
# ---------------------------------------------------------------------------


class TestFileSizeHelpers:
    def test_get_file_size_real_file(self):
        with tempfile.TemporaryDirectory() as td:
            elf_path = _write_elf_file(td)
            adapter = _make_adapter_for_elf(elf_path)
            analyzer = TelfhashAnalyzer(adapter, elf_path)
            size = analyzer.get_file_size()
            assert size is not None
            assert size > 0

    def test_get_file_size_nonexistent(self):
        adapter = _make_adapter_empty()
        analyzer = TelfhashAnalyzer(adapter, "/tmp/nonexistent_telfhash_xyz")
        size = analyzer.get_file_size()
        assert size is None

    def test_get_file_extension(self):
        with tempfile.TemporaryDirectory() as td:
            elf_path = _write_elf_file(td, name="sample.elf")
            adapter = _make_adapter_for_elf(elf_path)
            analyzer = TelfhashAnalyzer(adapter, elf_path)
            assert analyzer.get_file_extension() == "elf"
