"""Comprehensive tests for telfhash_analyzer.py - analysis paths and symbol processing.

Telfhash availability and results are supplied through the constructor /
static-method DI seams (``telfhash_fn``, ``telfhash_available``,
``ssdeep_loader``); the rest exercises real adapters / hand-rolled doubles.
No module patching.
"""

from __future__ import annotations

import tempfile
from typing import Any

from r2inspect.modules.telfhash_analyzer import TelfhashAnalyzer
from r2inspect.testing.fake_r2 import FakeR2


def _make_elf_file() -> str:
    """Create a temporary file with ELF magic bytes and return its path."""
    with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
        f.write(b"\x7fELF" + b"\x00" * 100)
        f.flush()
        return f.name


def _elf_adapter(
    cmdj_extra: dict[str, Any] | None = None,
    cmd_extra: dict[str, Any] | None = None,
    elf_path: str | None = None,
    *,
    telfhash_fn: Any = None,
    telfhash_available: bool | None = None,
) -> TelfhashAnalyzer:
    """Create a FakeR2 that behaves like an ELF binary, and a TelfhashAnalyzer."""
    filepath = elf_path or _make_elf_file()
    cmdj_map: dict[str, Any] = {
        "ij": {"bin": {"format": "elf", "class": "ELF64", "os": "linux", "type": "DYN"}},
        "isj": [],
    }
    cmd_map = {"i": "format   elf64"}
    if cmdj_extra:
        cmdj_map.update(cmdj_extra)
    if cmd_extra:
        cmd_map.update(cmd_extra)
    adapter = FakeR2(cmdj_map=cmdj_map, cmd_map=cmd_map)
    return TelfhashAnalyzer(
        adapter,
        filepath,
        telfhash_fn=telfhash_fn,
        telfhash_available=telfhash_available,
    )


# --- analyze_symbols tests ---


def test_analyze_symbols_not_available() -> None:
    analyzer = TelfhashAnalyzer(FakeR2(), "/test/file", telfhash_available=False)
    result = analyzer.analyze_symbols()
    assert result["available"] is False
    assert "not available" in result["error"]


def test_analyze_symbols_not_elf() -> None:
    adapter = FakeR2(
        cmdj_map={"ij": {"bin": {"format": "pe", "class": "PE32"}}},
        cmd_map={"i": "format   pe"},
    )
    analyzer = TelfhashAnalyzer(adapter, "/nonexistent/not_elf.exe", telfhash_available=True)
    result = analyzer.analyze_symbols()
    assert result["available"] is True
    assert result["is_elf"] is False
    assert result["error"] is not None


def test_analyze_symbols_success() -> None:
    symbols = [
        {"name": "func1", "type": "FUNC", "bind": "GLOBAL"},
        {"name": "func2", "type": "FUNC", "bind": "GLOBAL"},
    ]
    analyzer = _elf_adapter(
        cmdj_extra={"isj": symbols},
        elf_path=_make_elf_file(),
        telfhash_fn=lambda filepath: [{"telfhash": "T1234HASH"}],
        telfhash_available=True,
    )
    result = analyzer.analyze_symbols()

    assert result["available"] is True
    assert result["is_elf"] is True
    assert result["telfhash"] == "T1234HASH"
    assert result["symbol_count"] == 2
    assert result["filtered_symbols"] == 2
    assert "func1" in result["symbols_used"]
    assert "func2" in result["symbols_used"]


def test_analyze_symbols_telfhash_exception() -> None:
    def failing_telfhash(filepath: str) -> None:
        raise Exception("Calc error")

    analyzer = _elf_adapter(
        elf_path=_make_elf_file(),
        telfhash_fn=failing_telfhash,
        telfhash_available=True,
    )
    result = analyzer.analyze_symbols()

    assert result["available"] is True
    assert result["is_elf"] is True
    assert "failed" in result["error"].lower() or "error" in result["error"].lower()


def test_analyze_symbols_general_exception() -> None:
    class BrokenAnalyzer(TelfhashAnalyzer):
        def _is_elf_file(self) -> bool:
            raise Exception("General error")

    analyzer = BrokenAnalyzer(FakeR2(), "/test/file", telfhash_available=True)
    result = analyzer.analyze_symbols()

    assert "error" in result
    assert "General error" in result["error"]


# --- _is_elf_file tests ---


def test_is_elf_file_via_elf_magic() -> None:
    analyzer = _elf_adapter(elf_path=_make_elf_file())
    assert analyzer._is_elf_file() is True


def test_is_elf_file_not_elf() -> None:
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"MZ" + b"\x00" * 100)
        f.flush()
        filepath = f.name

    adapter = FakeR2(
        cmdj_map={"ij": {"bin": {"format": "pe", "class": "PE32"}}},
        cmd_map={"i": "format   pe"},
    )
    analyzer = TelfhashAnalyzer(adapter, filepath)
    assert analyzer._is_elf_file() is False


def test_is_elf_file_no_adapter() -> None:
    analyzer = TelfhashAnalyzer(None, "/test/file")
    assert analyzer._is_elf_file() is False


def test_is_elf_file_exception() -> None:
    adapter = FakeR2(cmdj_map={}, cmd_map={})
    analyzer = TelfhashAnalyzer(adapter, "/nonexistent/check_error_file")
    assert analyzer._is_elf_file() is False


# --- _has_elf_symbols tests ---


def test_has_elf_symbols_success() -> None:
    adapter = FakeR2(cmdj_map={"isj": [{"name": "sym"}]})
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    assert analyzer._has_elf_symbols({"bin": {"os": "linux"}}) is True


def test_has_elf_symbols_unix() -> None:
    adapter = FakeR2(cmdj_map={"isj": [{"name": "sym"}]})
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    assert analyzer._has_elf_symbols({"bin": {"os": "unix"}}) is True


def test_has_elf_symbols_no_symbols() -> None:
    adapter = FakeR2(cmdj_map={"isj": []})
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    assert analyzer._has_elf_symbols({"bin": {"os": "linux"}}) is False


def test_has_elf_symbols_no_info() -> None:
    adapter = FakeR2(cmdj_map={"isj": [{"name": "sym"}]})
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    assert analyzer._has_elf_symbols(None) is False


def test_has_elf_symbols_exception() -> None:
    class BrokenR2(FakeR2):
        def cmdj(self, command: str) -> Any:
            if command == "isj":
                raise Exception("Cmd error")
            return super().cmdj(command)

    analyzer = TelfhashAnalyzer(BrokenR2(), "/test/file")
    assert analyzer._has_elf_symbols({"bin": {"os": "linux"}}) is False


# --- _get_elf_symbols tests ---


def test_get_elf_symbols_success() -> None:
    symbols = [
        {"name": "main", "type": "FUNC"},
        {"name": "helper", "type": "FUNC"},
    ]
    adapter = FakeR2(cmdj_map={"isj": symbols})
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    result = analyzer._get_elf_symbols()
    assert len(result) == 2
    assert result[0]["name"] == "main"


def test_get_elf_symbols_empty() -> None:
    adapter = FakeR2(cmdj_map={"isj": []})
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    assert analyzer._get_elf_symbols() == []


def test_get_elf_symbols_exception() -> None:
    class BrokenR2(FakeR2):
        def cmdj(self, command: str) -> Any:
            if command == "isj":
                raise Exception("Symbol error")
            return super().cmdj(command)

    analyzer = TelfhashAnalyzer(BrokenR2(), "/test/file")
    assert analyzer._get_elf_symbols() == []


# --- _filter_symbols_for_telfhash tests ---


def test_filter_symbols_for_telfhash() -> None:
    analyzer = TelfhashAnalyzer(FakeR2(), "/test/file")

    symbols = [
        {"name": "main", "type": "FUNC", "bind": "GLOBAL"},
        {"name": "helper", "type": "OBJECT", "bind": "WEAK"},
        {"name": "local_func", "type": "FUNC", "bind": "LOCAL"},
        {"name": "__internal", "type": "FUNC", "bind": "GLOBAL"},
        {"name": "section", "type": "SECTION", "bind": "LOCAL"},
        {"name": "", "type": "FUNC", "bind": "GLOBAL"},
        {"name": "a", "type": "FUNC", "bind": "GLOBAL"},
    ]

    result = analyzer._filter_symbols_for_telfhash(symbols)

    assert len(result) == 2
    assert result[0]["name"] == "main"
    assert result[1]["name"] == "helper"


def test_filter_symbols_for_telfhash_skips_malformed_symbols() -> None:
    analyzer = TelfhashAnalyzer(FakeR2(), "/test/file")

    symbols = [
        "bad",
        {"name": "missing_type", "type": None, "bind": "GLOBAL"},
        {"name": "main", "type": "FUNC", "bind": "GLOBAL"},
    ]

    result = analyzer._filter_symbols_for_telfhash(symbols)  # type: ignore[arg-type]
    assert result == [{"name": "main", "type": "FUNC", "bind": "GLOBAL"}]


# --- _extract_symbol_names tests ---


def test_extract_symbol_names() -> None:
    analyzer = TelfhashAnalyzer(FakeR2(), "/test/file")

    symbols = [
        {"name": "zebra"},
        {"name": "apple"},
        {"name": ""},
        {"name": "banana"},
    ]

    result = analyzer._extract_symbol_names(symbols)
    assert result == ["apple", "banana", "zebra"]


def test_extract_symbol_names_skips_malformed_symbols() -> None:
    analyzer = TelfhashAnalyzer(FakeR2(), "/test/file")

    symbols = ["bad", {"name": None}, {"name": "main"}]

    result = analyzer._extract_symbol_names(symbols)  # type: ignore[arg-type]
    assert result == ["main"]


# --- compare_hashes tests ---


def test_compare_hashes_not_available() -> None:
    assert TelfhashAnalyzer.compare_hashes("HASH1", "HASH2", telfhash_available=False) is None


def test_compare_hashes_empty_hash1() -> None:
    assert TelfhashAnalyzer.compare_hashes("", "HASH2", telfhash_available=True) is None


def test_compare_hashes_empty_hash2() -> None:
    assert TelfhashAnalyzer.compare_hashes("HASH1", "", telfhash_available=True) is None


def test_compare_hashes_success() -> None:
    class FakeSsdeep:
        def compare(self, left: str, right: str) -> int:
            return 42

    result = TelfhashAnalyzer.compare_hashes(
        "HASH1", "HASH2", telfhash_available=True, ssdeep_loader=lambda: FakeSsdeep()
    )
    assert result == 42


def test_compare_hashes_no_ssdeep() -> None:
    result = TelfhashAnalyzer.compare_hashes(
        "HASH1", "HASH2", telfhash_available=True, ssdeep_loader=lambda: None
    )
    assert result is None


def test_compare_hashes_exception() -> None:
    class RaisingSsdeep:
        def compare(self, left: str, right: str) -> int:
            raise RuntimeError("bad compare")

    result = TelfhashAnalyzer.compare_hashes(
        "HASH1", "HASH2", telfhash_available=True, ssdeep_loader=lambda: RaisingSsdeep()
    )
    assert result is None


# --- analyze_symbols result format tests ---


def test_analyze_symbols_with_dict_result() -> None:
    analyzer = _elf_adapter(
        elf_path=_make_elf_file(),
        telfhash_fn=lambda filepath: {"telfhash": "T5678DICT"},
        telfhash_available=True,
    )
    result = analyzer.analyze_symbols()
    assert result["telfhash"] == "T5678DICT"


def test_analyze_symbols_with_string_result() -> None:
    analyzer = _elf_adapter(
        elf_path=_make_elf_file(),
        telfhash_fn=lambda filepath: "T9999STR",
        telfhash_available=True,
    )
    result = analyzer.analyze_symbols()
    assert result["telfhash"] == "T9999STR"


def test_analyze_symbols_with_msg_list() -> None:
    analyzer = _elf_adapter(
        elf_path=_make_elf_file(),
        telfhash_fn=lambda filepath: [{"msg": "Error message", "telfhash": None}],
        telfhash_available=True,
    )
    result = analyzer.analyze_symbols()
    assert "Error message" in result["error"]


def test_analyze_symbols_with_msg_dict() -> None:
    analyzer = _elf_adapter(
        elf_path=_make_elf_file(),
        telfhash_fn=lambda filepath: {"msg": "Dict error", "telfhash": None},
        telfhash_available=True,
    )
    result = analyzer.analyze_symbols()
    assert "Dict error" in result["error"]
