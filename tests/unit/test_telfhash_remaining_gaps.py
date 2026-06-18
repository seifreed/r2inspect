"""Tests covering remaining branches in telfhash_analyzer.py.

Every branch is driven through the constructor / static-method DI seams
(``telfhash_fn``, ``telfhash_available``, ``ssdeep_loader``) and hand-rolled
adapter / subclass doubles — no module patching.
"""

from __future__ import annotations

from typing import Any

from r2inspect.modules.telfhash_analyzer import TelfhashAnalyzer

ELF_PATH = "/tmp/test.elf"


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


class DirectAdapter:
    def __init__(self, cmdj_map: dict[str, Any] | None = None) -> None:
        self._cmdj_map = cmdj_map or {}

    def cmd(self, command: str) -> str:
        return ""

    def cmdj(self, command: str) -> Any:
        return self._cmdj_map.get(command)


class ExplodingAdapter:
    def cmd(self, command: str) -> str:
        raise RuntimeError("adapter boom")

    def cmdj(self, command: str) -> Any:
        raise RuntimeError("adapter boom")


class AlwaysElfTelfhashAnalyzer(TelfhashAnalyzer):
    """TelfhashAnalyzer subclass whose _is_elf_file() always returns True."""

    def _is_elf_file(self) -> bool:
        return True


class RaisingSymbolsAnalyzer(AlwaysElfTelfhashAnalyzer):
    """ELF analyzer whose symbol enumeration fails."""

    def _get_elf_symbols(self) -> list[dict[str, Any]]:
        raise RuntimeError("outer symbols failure")


def _elf_analyzer(*, telfhash_fn: Any) -> AlwaysElfTelfhashAnalyzer:
    return AlwaysElfTelfhashAnalyzer(
        SimpleAdapter(), filepath=ELF_PATH, telfhash_fn=telfhash_fn, telfhash_available=True
    )


def test_check_library_availability_unavailable() -> None:
    analyzer = TelfhashAnalyzer(SimpleAdapter(), filepath=ELF_PATH, telfhash_available=False)
    available, error = analyzer._check_library_availability()
    assert available is False
    assert error is not None
    assert "not available" in error


def test_calculate_hash_list_falsy_hash() -> None:
    analyzer = _elf_analyzer(telfhash_fn=lambda fp: [{"telfhash": "", "msg": "no symbols found"}])
    h, method, error = analyzer._calculate_hash()
    assert h is None
    assert method is None
    assert error == "no symbols found"


def test_calculate_hash_no_hash_returned() -> None:
    analyzer = _elf_analyzer(telfhash_fn=lambda fp: None)
    h, method, error = analyzer._calculate_hash()
    assert h is None
    assert method is None
    assert error == "Telfhash calculation returned no hash"


def test_calculate_hash_malformed_list_result_returns_no_hash() -> None:
    analyzer = _elf_analyzer(telfhash_fn=lambda fp: ["bad"])
    h, method, error = analyzer._calculate_hash()
    assert h is None
    assert method is None
    assert error == "Telfhash calculation returned no hash"


def test_calculate_hash_dict_falsy_hash() -> None:
    analyzer = _elf_analyzer(telfhash_fn=lambda fp: {"telfhash": "", "msg": "dict error msg"})
    h, method, error = analyzer._calculate_hash()
    assert h is None
    assert method is None
    assert error == "dict error msg"


def test_analyze_symbols_unavailable() -> None:
    analyzer = TelfhashAnalyzer(SimpleAdapter(), filepath=ELF_PATH, telfhash_available=False)
    result = analyzer.analyze_symbols()
    assert result["available"] is False
    assert result["error"] is not None
    assert "not available" in result["error"]


def test_analyze_symbols_list_falsy_hash_sets_error() -> None:
    analyzer = _elf_analyzer(telfhash_fn=lambda fp: [{"telfhash": "", "msg": "sym calc failed"}])
    result = analyzer.analyze_symbols()
    assert result["error"] == "sym calc failed"


def test_analyze_symbols_dict_result() -> None:
    analyzer = _elf_analyzer(telfhash_fn=lambda fp: {"telfhash": "", "msg": "dict sym error"})
    result = analyzer.analyze_symbols()
    assert result["error"] == "dict sym error"


def test_analyze_symbols_else_branch_string_result() -> None:
    analyzer = _elf_analyzer(telfhash_fn=lambda fp: "T1:direct_string_hash")
    result = analyzer.analyze_symbols()
    assert result["telfhash"] == "T1:direct_string_hash"


def test_analyze_symbols_inner_exception() -> None:
    def _raising(fp: str) -> None:
        raise RuntimeError("inner telfhash error")

    analyzer = _elf_analyzer(telfhash_fn=_raising)
    result = analyzer.analyze_symbols()
    assert result["error"] is not None
    assert "inner telfhash error" in result["error"]


def test_analyze_symbols_outer_exception() -> None:
    analyzer = RaisingSymbolsAnalyzer(
        SimpleAdapter(),
        filepath=ELF_PATH,
        telfhash_fn=lambda fp: "T1:x",
        telfhash_available=True,
    )
    result = analyzer.analyze_symbols()
    assert result["error"] == "outer symbols failure"


def test_is_elf_file_handles_adapter_exception() -> None:
    analyzer = TelfhashAnalyzer(ExplodingAdapter(), filepath="/tmp/test")
    assert analyzer._is_elf_file() is False


def test_is_elf_file_returns_true_via_info_command() -> None:
    analyzer = TelfhashAnalyzer(
        DirectAdapter(cmdj_map={"ij": {"bin": {"os": "linux"}}, "isj": [{"name": "main"}]}),
        filepath="/tmp/test",
    )
    assert analyzer._is_elf_file() is True


def test_has_elf_symbols_without_bin_metadata() -> None:
    analyzer = TelfhashAnalyzer(
        DirectAdapter(cmdj_map={"isj": [{"name": "main"}]}), filepath="/tmp/test"
    )
    assert analyzer._has_elf_symbols({"other": {}}) is False


def test_has_elf_symbols_exception() -> None:
    analyzer = TelfhashAnalyzer(ExplodingAdapter(), filepath="/tmp/test")
    assert analyzer._has_elf_symbols({"bin": {"os": "linux"}}) is False


def test_get_elf_symbols_exception() -> None:
    analyzer = TelfhashAnalyzer(ExplodingAdapter(), filepath="/tmp/test")
    assert analyzer._get_elf_symbols() == []


def test_filter_skips_empty_symbol_name() -> None:
    analyzer = TelfhashAnalyzer(SimpleAdapter(), filepath="/tmp/test")
    filtered = analyzer._filter_symbols_for_telfhash(
        [{"type": "FUNC", "bind": "GLOBAL", "name": "   "}]
    )
    assert filtered == []


def test_normalize_telfhash_value_non_str() -> None:
    assert TelfhashAnalyzer._normalize_telfhash_value(123) is None


def test_compare_hashes_empty_input() -> None:
    assert TelfhashAnalyzer.compare_hashes("", "") is None


def test_compare_hashes_unavailable() -> None:
    assert TelfhashAnalyzer.compare_hashes("T1:abc", "T1:def", telfhash_available=False) is None


def test_compare_hashes_no_ssdeep() -> None:
    assert (
        TelfhashAnalyzer.compare_hashes(
            "T1:abc123", "T1:abc456", telfhash_available=True, ssdeep_loader=lambda: None
        )
        is None
    )


def test_calculate_telfhash_from_file_unavailable() -> None:
    assert (
        TelfhashAnalyzer.calculate_telfhash_from_file("/some/file.elf", telfhash_available=False)
        is None
    )


def test_calculate_telfhash_from_file_dict_result() -> None:
    assert (
        TelfhashAnalyzer.calculate_telfhash_from_file(
            "/some/file.elf",
            telfhash_fn=lambda fp: {"telfhash": "T1:dict_result"},
            telfhash_available=True,
        )
        == "T1:dict_result"
    )


def test_calculate_telfhash_from_file_exception() -> None:
    def _raising(fp: str) -> None:
        raise RuntimeError("calc error")

    assert (
        TelfhashAnalyzer.calculate_telfhash_from_file(
            "/some/file.elf", telfhash_fn=_raising, telfhash_available=True
        )
        is None
    )
