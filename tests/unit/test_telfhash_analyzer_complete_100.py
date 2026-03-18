"""Comprehensive tests for Telfhash analyzer branches."""

import importlib
import builtins

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules import telfhash_analyzer as analyzer_module


class FakeR2:
    def __init__(self, cmd_map=None, cmdj_map=None):
        self._cmd_map = cmd_map or {}
        self._cmdj_map = cmdj_map or {}

    def cmd(self, command):
        return self._cmd_map.get(command, "")

    def cmdj(self, command):
        return self._cmdj_map.get(command)


def make_adapter(cmd_map=None, cmdj_map=None):
    return R2PipeAdapter(FakeR2(cmd_map=cmd_map, cmdj_map=cmdj_map))


class DirectAdapter:
    def __init__(self, cmdj_map=None):
        self._cmdj_map = cmdj_map or {}

    def cmd(self, command):
        return ""

    def cmdj(self, command):
        return self._cmdj_map.get(command)


class FakeCallable:
    def __init__(self, result):
        self.result = result

    def __call__(self, _filepath):
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


def _module():
    return importlib.import_module("r2inspect.modules.telfhash_analyzer")


def test_import_error_branch_sets_unavailable(monkeypatch):
    module = _module()
    original_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "telfhash":
            raise ImportError("simulated unavailable dependency")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    reloaded = importlib.reload(module)

    assert reloaded.TELFHASH_AVAILABLE is False
    assert reloaded.TelfhashAnalyzer.is_available() is False

    module.TELFHASH_AVAILABLE = analyzer_module.TELFHASH_AVAILABLE


def test_check_library_availability_true_false():
    module = _module()
    module.TELFHASH_AVAILABLE = True
    analyzer = module.TelfhashAnalyzer(make_adapter(), filepath="/tmp/test")
    assert analyzer._check_library_availability() == (True, None)

    module.TELFHASH_AVAILABLE = False
    analyzer = module.TelfhashAnalyzer(make_adapter(), filepath="/tmp/test")
    available, error = analyzer._check_library_availability()
    assert available is False
    assert error is not None

    module.TELFHASH_AVAILABLE = analyzer_module.TELFHASH_AVAILABLE


def test_calculate_hash_not_elf_returns_error():
    module = _module()
    module.TELFHASH_AVAILABLE = True
    analyzer = module.TelfhashAnalyzer(None, filepath="/tmp/not_elf")

    hash_value, method, error = analyzer._calculate_hash()
    assert hash_value is None
    assert method is None
    assert error == "File is not an ELF binary"


def test_calculate_hash_list_result(monkeypatch):
    module = _module()
    module.TELFHASH_AVAILABLE = True
    monkeypatch.setattr(module, "telfhash", FakeCallable([{"telfhash": " TABC123 ", "msg": ""}]))

    analyzer = module.TelfhashAnalyzer(make_adapter(), filepath="/tmp/test")
    monkeypatch.setattr(analyzer, "_is_elf_file", lambda: True)

    hash_value, method, error = analyzer._calculate_hash()
    assert hash_value == "TABC123"
    assert method == "python_library"
    assert error is None


def test_calculate_hash_dict_result_with_missing_hash(monkeypatch):
    module = _module()
    module.TELFHASH_AVAILABLE = True
    monkeypatch.setattr(
        module,
        "telfhash",
        FakeCallable({"telfhash": " - ", "msg": "invalid file"}),
    )

    analyzer = module.TelfhashAnalyzer(make_adapter(), filepath="/tmp/test")
    monkeypatch.setattr(analyzer, "_is_elf_file", lambda: True)

    hash_value, method, error = analyzer._calculate_hash()
    assert hash_value is None
    assert method is None
    assert error == "invalid file"


def test_calculate_hash_scalar_result_and_exception(monkeypatch):
    module = _module()
    module.TELFHASH_AVAILABLE = True
    monkeypatch.setattr(module, "telfhash", FakeCallable("  TFLAT"))

    analyzer = module.TelfhashAnalyzer(make_adapter(), filepath="/tmp/test")
    monkeypatch.setattr(analyzer, "_is_elf_file", lambda: True)

    hash_value, method, error = analyzer._calculate_hash()
    assert hash_value == "TFLAT"
    assert method == "python_library"
    assert error is None

    monkeypatch.setattr(module, "telfhash", FakeCallable(RuntimeError("calc failure")))
    hash_value, method, error = analyzer._calculate_hash()
    assert hash_value is None
    assert method is None
    assert error == "Telfhash calculation failed: calc failure"


def test_analyze_symbols_without_library(monkeypatch):
    module = _module()
    module.TELFHASH_AVAILABLE = False
    analyzer = module.TelfhashAnalyzer(make_adapter(), filepath="/tmp/test")

    result = analyzer.analyze_symbols()

    assert result["available"] is False
    assert result["error"] == "telfhash library not available"
    assert result["telfhash"] is None


def test_analyze_symbols_non_elf_file(monkeypatch):
    module = _module()
    module.TELFHASH_AVAILABLE = True

    analyzer = module.TelfhashAnalyzer(None, filepath="/tmp/not_elf")
    result = analyzer.analyze_symbols()

    assert result["is_elf"] is False
    assert result["error"] == "File is not an ELF binary"
    assert result["symbol_count"] == 0


def test_analyze_symbols_with_list_result_and_symbol_filters(monkeypatch):
    module = _module()
    module.TELFHASH_AVAILABLE = True
    monkeypatch.setattr(
        module,
        "telfhash",
        FakeCallable([{"telfhash": " H1234", "msg": None}]),
    )

    symbols = [
        {"type": "FUNC", "bind": "GLOBAL", "name": "open"},
        {"type": "SECTION", "bind": "GLOBAL", "name": "text"},
        {"type": "FUNC", "bind": "LOCAL", "name": "local"},
    ]
    adapter = DirectAdapter(cmdj_map={"ij": {"bin": {"os": "linux"}}, "isj": symbols})
    analyzer = module.TelfhashAnalyzer(adapter, filepath="/tmp/test")

    result = analyzer.analyze_symbols()

    assert result["is_elf"] is True
    assert result["symbol_count"] == 3
    assert result["filtered_symbols"] == 1
    assert result["symbols_used"] == ["open"]
    assert result["telfhash"] == "H1234"


def test_analyze_symbols_message_when_no_hash_for_dict(monkeypatch):
    module = _module()
    module.TELFHASH_AVAILABLE = True
    monkeypatch.setattr(
        module,
        "telfhash",
        FakeCallable({"telfhash": " - ", "msg": "unsupported"}),
    )

    adapter = DirectAdapter(cmdj_map={"ij": {"bin": {"os": "linux"}}, "isj": []})
    analyzer = module.TelfhashAnalyzer(adapter, filepath="/tmp/test")
    monkeypatch.setattr(analyzer, "_is_elf_file", lambda: True)

    result = analyzer.analyze_symbols()
    assert result["error"] == "unsupported"
    assert result["telfhash"] is None


def test_analyze_symbols_telfhash_call_exception(monkeypatch):
    module = _module()
    module.TELFHASH_AVAILABLE = True
    monkeypatch.setattr(module, "telfhash", FakeCallable(RuntimeError("bad telfhash")))

    adapter = DirectAdapter(cmdj_map={"ij": {"bin": {"os": "linux"}}, "isj": []})
    analyzer = module.TelfhashAnalyzer(adapter, filepath="/tmp/test")
    monkeypatch.setattr(analyzer, "_is_elf_file", lambda: True)

    result = analyzer.analyze_symbols()
    assert result["error"] == "Telfhash calculation failed: bad telfhash"


def test_is_elf_file_none_r2_returns_false():
    analyzer = analyzer_module.TelfhashAnalyzer(None, filepath="/tmp/test")
    assert analyzer._is_elf_file() is False


def test_is_elf_file_falls_back_to_info_command(monkeypatch):
    module = _module()

    monkeypatch.setattr(module, "is_elf_file", lambda *_args, **_kwargs: False)
    adapter = DirectAdapter(cmdj_map={"ij": {"bin": {"os": "linux"}}, "isj": [{"name": "main"}]})
    analyzer = module.TelfhashAnalyzer(adapter, filepath="/tmp/test")

    assert analyzer._is_elf_file() is True


def test_is_elf_file_handles_exception():
    class Exploding:
        def cmd(self, command):
            raise RuntimeError("boom")

        def cmdj(self, command):
            return None

    analyzer = analyzer_module.TelfhashAnalyzer(Exploding(), filepath="/tmp/test")
    assert analyzer._is_elf_file() is False


def test_has_elf_symbols_returns_false_when_no_matches():
    adapter = DirectAdapter(cmdj_map={"isj": []})
    analyzer = analyzer_module.TelfhashAnalyzer(adapter, filepath="/tmp/test")
    assert analyzer._has_elf_symbols({"bin": {"os": "linux"}}) is False

    adapter = DirectAdapter(cmdj_map={"isj": [{"name": "main"}]})
    assert analyzer._has_elf_symbols({"bin": {"os": "windows"}}) is False
    assert analyzer._has_elf_symbols({"other": {}}) is False


def test_has_elf_symbols_exception_path():
    class Exploding:
        def cmd(self, command):
            raise RuntimeError("boom")

        def cmdj(self, command):
            return None

    analyzer = analyzer_module.TelfhashAnalyzer(Exploding(), filepath="/tmp/test")
    assert analyzer._has_elf_symbols({"bin": {"os": "linux"}}) is False


def test_get_elf_symbols_logs_and_returns_empty_on_error():
    class Exploding:
        def cmd(self, command):
            return ""

        def cmdj(self, command):
            raise RuntimeError("decode")

    analyzer = analyzer_module.TelfhashAnalyzer(Exploding(), filepath="/tmp/test")
    assert analyzer._get_elf_symbols() == []


def test_filter_and_extract_symbol_names_are_normalized():
    adapter = make_adapter()
    analyzer = analyzer_module.TelfhashAnalyzer(adapter, filepath="/tmp/test")

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


def test_compare_hashes_paths(monkeypatch):
    module = _module()
    module.TELFHASH_AVAILABLE = True

    class FakeSsdeep:
        def compare(self, left, right):
            return 87

    monkeypatch.setattr(module, "get_ssdeep", lambda: FakeSsdeep())
    assert module.TelfhashAnalyzer.compare_hashes("A", "B") == 87

    monkeypatch.setattr(module, "get_ssdeep", lambda: None)
    assert module.TelfhashAnalyzer.compare_hashes("A", "B") is None

    class RaisingSsdeep:
        def compare(self, _left, _right):
            raise RuntimeError("bad compare")

    monkeypatch.setattr(module, "get_ssdeep", lambda: RaisingSsdeep())
    assert module.TelfhashAnalyzer.compare_hashes("A", "B") is None

    module.TELFHASH_AVAILABLE = False
    assert module.TelfhashAnalyzer.compare_hashes("A", "B") is None


def test_calculate_telfhash_from_file_branches(monkeypatch):
    module = _module()
    module.TELFHASH_AVAILABLE = False
    assert module.TelfhashAnalyzer.calculate_telfhash_from_file("/tmp/test") is None

    module.TELFHASH_AVAILABLE = True
    monkeypatch.setattr(module, "telfhash", FakeCallable([{"telfhash": "  FILE1 "}]))
    assert module.TelfhashAnalyzer.calculate_telfhash_from_file("/tmp/test") == "FILE1"

    monkeypatch.setattr(module, "telfhash", FakeCallable({"telfhash": "-"}))
    assert module.TelfhashAnalyzer.calculate_telfhash_from_file("/tmp/test") is None

    monkeypatch.setattr(module, "telfhash", FakeCallable(" FILE2 "))
    assert module.TelfhashAnalyzer.calculate_telfhash_from_file("/tmp/test") == "FILE2"

    monkeypatch.setattr(module, "telfhash", FakeCallable(RuntimeError("bad file")))
    assert module.TelfhashAnalyzer.calculate_telfhash_from_file("/tmp/test") is None
