"""Comprehensive tests for Telfhash analyzer branches.

Telfhash is driven through the constructor / static-method DI seams
(``telfhash_fn``, ``telfhash_available``, ``ssdeep_loader``) so every branch
is exercised with hand-rolled doubles instead of patching the module.
"""

from __future__ import annotations

from typing import Any

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.telfhash_analyzer import TelfhashAnalyzer
from r2inspect.testing.fake_r2 import FakeR2


def make_adapter(cmd_map: Any = None, cmdj_map: Any = None) -> R2PipeAdapter:
    return R2PipeAdapter(FakeR2(cmd_map=cmd_map, cmdj_map=cmdj_map))


class DirectAdapter:
    def __init__(self, cmdj_map: dict[str, Any] | None = None) -> None:
        self._cmdj_map = cmdj_map or {}

    def cmd(self, command: str) -> str:
        return ""

    def cmdj(self, command: str) -> Any:
        return self._cmdj_map.get(command)


class FakeCallable:
    """Hand-rolled telfhash double: returns a fixed result or raises."""

    def __init__(self, result: Any) -> None:
        self.result = result

    def __call__(self, _filepath: str) -> Any:
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


def _elf_adapter(symbols: list[dict[str, Any]] | None = None) -> DirectAdapter:
    """Adapter whose r2 info makes ``_is_elf_file()`` resolve True."""
    return DirectAdapter(
        cmdj_map={
            "ij": {"bin": {"os": "linux"}},
            "isj": (
                symbols
                if symbols is not None
                else [{"name": "main", "type": "FUNC", "bind": "GLOBAL"}]
            ),
        }
    )


def test_unavailable_library_reports_unavailable() -> None:
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test", telfhash_available=False)
    available, error = analyzer._check_library_availability()
    assert available is False
    assert error is not None

    result = analyzer.analyze_symbols()
    assert result["available"] is False
    assert result["error"] == "telfhash library not available"
    assert result["telfhash"] is None

    assert isinstance(TelfhashAnalyzer.is_available(), bool)


def test_check_library_availability_true_false() -> None:
    available, error = TelfhashAnalyzer(
        make_adapter(), filepath="/tmp/test", telfhash_available=True
    )._check_library_availability()
    assert (available, error) == (True, None)

    available, error = TelfhashAnalyzer(
        make_adapter(), filepath="/tmp/test", telfhash_available=False
    )._check_library_availability()
    assert available is False
    assert error is not None


def test_calculate_hash_not_elf_returns_error() -> None:
    analyzer = TelfhashAnalyzer(None, filepath="/tmp/not_elf", telfhash_available=True)

    hash_value, method, error = analyzer._calculate_hash()
    assert hash_value is None
    assert method is None
    assert error == "File is not an ELF binary"


def test_calculate_hash_list_result() -> None:
    analyzer = TelfhashAnalyzer(
        _elf_adapter(),
        filepath="/tmp/test",
        telfhash_fn=FakeCallable([{"telfhash": " TABC123 ", "msg": ""}]),
        telfhash_available=True,
    )

    hash_value, method, error = analyzer._calculate_hash()
    assert hash_value == "TABC123"
    assert method == "python_library"
    assert error is None


def test_calculate_hash_dict_result_with_missing_hash() -> None:
    analyzer = TelfhashAnalyzer(
        _elf_adapter(),
        filepath="/tmp/test",
        telfhash_fn=FakeCallable({"telfhash": " - ", "msg": "invalid file"}),
        telfhash_available=True,
    )

    hash_value, method, error = analyzer._calculate_hash()
    assert hash_value is None
    assert method is None
    assert error == "invalid file"


def test_calculate_hash_scalar_result_and_exception() -> None:
    analyzer = TelfhashAnalyzer(
        _elf_adapter(),
        filepath="/tmp/test",
        telfhash_fn=FakeCallable("  TFLAT"),
        telfhash_available=True,
    )
    hash_value, method, error = analyzer._calculate_hash()
    assert hash_value == "TFLAT"
    assert method == "python_library"
    assert error is None

    raising = TelfhashAnalyzer(
        _elf_adapter(),
        filepath="/tmp/test",
        telfhash_fn=FakeCallable(RuntimeError("calc failure")),
        telfhash_available=True,
    )
    hash_value, method, error = raising._calculate_hash()
    assert hash_value is None
    assert method is None
    assert error == "Telfhash calculation failed: calc failure"


def test_analyze_symbols_without_library() -> None:
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test", telfhash_available=False)

    result = analyzer.analyze_symbols()

    assert result["available"] is False
    assert result["error"] == "telfhash library not available"
    assert result["telfhash"] is None


def test_analyze_symbols_non_elf_file() -> None:
    analyzer = TelfhashAnalyzer(None, filepath="/tmp/not_elf", telfhash_available=True)
    result = analyzer.analyze_symbols()

    assert result["is_elf"] is False
    assert result["error"] == "File is not an ELF binary"
    assert result["symbol_count"] == 0


def test_analyze_symbols_with_list_result_and_symbol_filters() -> None:
    symbols = [
        {"type": "FUNC", "bind": "GLOBAL", "name": "open"},
        {"type": "SECTION", "bind": "GLOBAL", "name": "text"},
        {"type": "FUNC", "bind": "LOCAL", "name": "local"},
    ]
    analyzer = TelfhashAnalyzer(
        _elf_adapter(symbols),
        filepath="/tmp/test",
        telfhash_fn=FakeCallable([{"telfhash": " H1234", "msg": None}]),
        telfhash_available=True,
    )

    result = analyzer.analyze_symbols()

    assert result["is_elf"] is True
    assert result["symbol_count"] == 3
    assert result["filtered_symbols"] == 1
    assert result["symbols_used"] == ["open"]
    assert result["telfhash"] == "H1234"


def test_analyze_symbols_message_when_no_hash_for_dict() -> None:
    analyzer = TelfhashAnalyzer(
        _elf_adapter(),
        filepath="/tmp/test",
        telfhash_fn=FakeCallable({"telfhash": " - ", "msg": "unsupported"}),
        telfhash_available=True,
    )

    result = analyzer.analyze_symbols()
    assert result["error"] == "unsupported"
    assert result["telfhash"] is None


def test_analyze_symbols_telfhash_call_exception() -> None:
    analyzer = TelfhashAnalyzer(
        _elf_adapter(),
        filepath="/tmp/test",
        telfhash_fn=FakeCallable(RuntimeError("bad telfhash")),
        telfhash_available=True,
    )

    result = analyzer.analyze_symbols()
    assert result["error"] == "Telfhash calculation failed: bad telfhash"


def test_is_elf_file_none_r2_returns_false() -> None:
    analyzer = TelfhashAnalyzer(None, filepath="/tmp/test")
    assert analyzer._is_elf_file() is False


def test_is_elf_file_falls_back_to_info_command() -> None:
    analyzer = TelfhashAnalyzer(
        DirectAdapter(cmdj_map={"ij": {"bin": {"os": "linux"}}, "isj": [{"name": "main"}]}),
        filepath="/tmp/test",
    )
    assert analyzer._is_elf_file() is True


def test_is_elf_file_handles_exception() -> None:
    class Exploding:
        def cmd(self, command: str) -> str:
            raise RuntimeError("boom")

        def cmdj(self, command: str) -> Any:
            return None

    analyzer = TelfhashAnalyzer(Exploding(), filepath="/tmp/test")
    assert analyzer._is_elf_file() is False


def test_has_elf_symbols_returns_false_when_no_matches() -> None:
    analyzer = TelfhashAnalyzer(DirectAdapter(cmdj_map={"isj": []}), filepath="/tmp/test")
    assert analyzer._has_elf_symbols({"bin": {"os": "linux"}}) is False

    analyzer = TelfhashAnalyzer(
        DirectAdapter(cmdj_map={"isj": [{"name": "main"}]}), filepath="/tmp/test"
    )
    assert analyzer._has_elf_symbols({"bin": {"os": "windows"}}) is False
    assert analyzer._has_elf_symbols({"other": {}}) is False


def test_has_elf_symbols_exception_path() -> None:
    class Exploding:
        def cmd(self, command: str) -> str:
            raise RuntimeError("boom")

        def cmdj(self, command: str) -> Any:
            return None

    analyzer = TelfhashAnalyzer(Exploding(), filepath="/tmp/test")
    assert analyzer._has_elf_symbols({"bin": {"os": "linux"}}) is False


def test_get_elf_symbols_logs_and_returns_empty_on_error() -> None:
    class Exploding:
        def cmd(self, command: str) -> str:
            return ""

        def cmdj(self, command: str) -> Any:
            raise RuntimeError("decode")

    analyzer = TelfhashAnalyzer(Exploding(), filepath="/tmp/test")
    assert analyzer._get_elf_symbols() == []


def test_filter_and_extract_symbol_names_are_normalized() -> None:
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test")

    symbols = [
        {"type": "FUNC", "bind": "GLOBAL", "name": " zzz "},
        {"type": "FUNC", "bind": "LOCAL", "name": "loc"},
        {"type": "OBJECT", "bind": "WEAK", "name": "aa"},
        {"type": "SECTION", "bind": "GLOBAL", "name": "text"},
        {"type": "FUNC", "bind": "GLOBAL", "name": "__skip"},
    ]

    filtered = analyzer._filter_symbols_for_telfhash(symbols)
    names = analyzer._extract_symbol_names(filtered)

    assert names == ["aa", "zzz"]


def test_compare_hashes_paths() -> None:
    class FakeSsdeep:
        def compare(self, left: str, right: str) -> int:
            return 87

    class RaisingSsdeep:
        def compare(self, _left: str, _right: str) -> int:
            raise RuntimeError("bad compare")

    assert (
        TelfhashAnalyzer.compare_hashes(
            "A", "B", telfhash_available=True, ssdeep_loader=lambda: FakeSsdeep()
        )
        == 87
    )
    assert (
        TelfhashAnalyzer.compare_hashes(
            "A", "B", telfhash_available=True, ssdeep_loader=lambda: None
        )
        is None
    )
    assert (
        TelfhashAnalyzer.compare_hashes(
            "A", "B", telfhash_available=True, ssdeep_loader=lambda: RaisingSsdeep()
        )
        is None
    )
    assert (
        TelfhashAnalyzer.compare_hashes(
            "A", "B", telfhash_available=False, ssdeep_loader=lambda: FakeSsdeep()
        )
        is None
    )


def test_calculate_telfhash_from_file_branches() -> None:
    assert (
        TelfhashAnalyzer.calculate_telfhash_from_file("/tmp/test", telfhash_available=False) is None
    )

    assert (
        TelfhashAnalyzer.calculate_telfhash_from_file(
            "/tmp/test",
            telfhash_fn=FakeCallable([{"telfhash": "  FILE1 "}]),
            telfhash_available=True,
        )
        == "FILE1"
    )
    assert (
        TelfhashAnalyzer.calculate_telfhash_from_file(
            "/tmp/test",
            telfhash_fn=FakeCallable({"telfhash": "-"}),
            telfhash_available=True,
        )
        is None
    )
    assert (
        TelfhashAnalyzer.calculate_telfhash_from_file(
            "/tmp/test",
            telfhash_fn=FakeCallable(" FILE2 "),
            telfhash_available=True,
        )
        == "FILE2"
    )
    assert (
        TelfhashAnalyzer.calculate_telfhash_from_file(
            "/tmp/test",
            telfhash_fn=FakeCallable(RuntimeError("bad file")),
            telfhash_available=True,
        )
        is None
    )
