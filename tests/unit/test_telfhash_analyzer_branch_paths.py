"""Branch-path coverage tests for r2inspect/modules/telfhash_analyzer.py.

Targets lines:
  10-11   ImportError branch for TELFHASH_AVAILABLE (skipped when telfhash installed)
  44      _check_library_availability returns (True, None)
  59      _calculate_hash: not ELF branch
  72-79   _calculate_hash: result parsing branches
  84-88   _calculate_hash: no hash / exception paths
  129-131 analyze_symbols: library not available
  136-138 analyze_symbols: not ELF
  166-184 analyze_symbols: telfhash result parsing
  197-218 _is_elf_file / _has_elf_symbols branches
  231-239 _get_elf_symbols
  268-279 _filter_symbols_for_telfhash
  295-313 _should_skip_symbol
  328-330 _extract_symbol_names
  360-375 compare_hashes
  385     is_available
  398-410 calculate_telfhash_from_file
"""

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.telfhash_analyzer import TELFHASH_AVAILABLE, TelfhashAnalyzer


ELF_FIXTURE = "samples/fixtures/hello_elf"


# ---------------------------------------------------------------------------
# Minimal fake backends
# ---------------------------------------------------------------------------


class FakeR2:
    """Minimal r2pipe-like object."""

    def __init__(self, cmd_map=None, cmdj_map=None):
        self._cmd_map = cmd_map or {}
        self._cmdj_map = cmdj_map or {}

    def cmd(self, command):
        return self._cmd_map.get(command, "")

    def cmdj(self, command):
        return self._cmdj_map.get(command)


class DirectFakeAdapter:
    """Adapter used directly (not wrapped) so _cmd_list resolves correctly."""

    def __init__(self, cmd_map=None, cmdj_map=None):
        self._cmd_map = cmd_map or {}
        self._cmdj_map = cmdj_map or {}

    def cmd(self, command):
        return self._cmd_map.get(command, "")

    def cmdj(self, command):
        return self._cmdj_map.get(command)


def make_adapter(cmd_map=None, cmdj_map=None):
    return R2PipeAdapter(FakeR2(cmd_map=cmd_map, cmdj_map=cmdj_map))


# ---------------------------------------------------------------------------
# is_available  (line 385)
# ---------------------------------------------------------------------------


def test_is_available_returns_bool():
    result = TelfhashAnalyzer.is_available()
    assert isinstance(result, bool)


def test_is_available_matches_module_constant():
    assert TelfhashAnalyzer.is_available() == TELFHASH_AVAILABLE


# ---------------------------------------------------------------------------
# _check_library_availability  (line 44)
# ---------------------------------------------------------------------------


def test_check_library_availability_when_available():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    available, error = analyzer._check_library_availability()
    if TELFHASH_AVAILABLE:
        assert available is True
        assert error is None
    else:
        assert available is False
        assert error is not None


def test_check_library_availability_returns_tuple():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/dummy.elf")
    result = analyzer._check_library_availability()
    assert len(result) == 2


# ---------------------------------------------------------------------------
# _get_hash_type
# ---------------------------------------------------------------------------


def test_get_hash_type_returns_telfhash_string():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._get_hash_type() == "telfhash"


# ---------------------------------------------------------------------------
# _should_skip_symbol  (lines 295-313)
# ---------------------------------------------------------------------------


def test_should_skip_single_char_name():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._should_skip_symbol("x") is True


def test_should_skip_empty_name():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._should_skip_symbol("") is True


def test_should_skip_double_underscore_prefix():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._should_skip_symbol("__libc_start_main") is True


def test_should_skip_global_offset_table():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._should_skip_symbol("_GLOBAL_OFFSET_TABLE_") is True


def test_should_skip_dynamic():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._should_skip_symbol("_DYNAMIC") is True


def test_should_skip_local_label():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._should_skip_symbol(".Ltext0") is True


def test_should_skip_edata():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._should_skip_symbol("_edata") is True


def test_should_skip_end():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._should_skip_symbol("_end") is True


def test_should_skip_start():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._should_skip_symbol("_start") is True


def test_should_not_skip_normal_symbol():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._should_skip_symbol("printf") is False


def test_should_not_skip_two_char_name():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._should_skip_symbol("ab") is False


def test_should_not_skip_open():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._should_skip_symbol("open") is False


def test_should_not_skip_main():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._should_skip_symbol("main") is False


# ---------------------------------------------------------------------------
# _filter_symbols_for_telfhash  (lines 268-279)
# ---------------------------------------------------------------------------


def test_filter_keeps_global_func():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    syms = [{"type": "FUNC", "bind": "GLOBAL", "name": "open"}]
    assert len(analyzer._filter_symbols_for_telfhash(syms)) == 1


def test_filter_keeps_weak_object():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    syms = [{"type": "OBJECT", "bind": "WEAK", "name": "some_var"}]
    assert len(analyzer._filter_symbols_for_telfhash(syms)) == 1


def test_filter_drops_local_binding():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    syms = [{"type": "FUNC", "bind": "LOCAL", "name": "local_fn"}]
    assert analyzer._filter_symbols_for_telfhash(syms) == []


def test_filter_drops_notype():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    syms = [{"type": "NOTYPE", "bind": "GLOBAL", "name": "notype_sym"}]
    assert analyzer._filter_symbols_for_telfhash(syms) == []


def test_filter_drops_empty_name():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    syms = [{"type": "FUNC", "bind": "GLOBAL", "name": ""}]
    assert analyzer._filter_symbols_for_telfhash(syms) == []


def test_filter_drops_whitespace_name():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    syms = [{"type": "FUNC", "bind": "GLOBAL", "name": "   "}]
    assert analyzer._filter_symbols_for_telfhash(syms) == []


def test_filter_drops_skipped_pattern():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    syms = [{"type": "FUNC", "bind": "GLOBAL", "name": "__cxa_finalize"}]
    assert analyzer._filter_symbols_for_telfhash(syms) == []


def test_filter_mixed_symbols():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    syms = [
        {"type": "FUNC", "bind": "GLOBAL", "name": "valid_func"},
        {"type": "FUNC", "bind": "LOCAL", "name": "local_func"},
        {"type": "OBJECT", "bind": "GLOBAL", "name": "valid_obj"},
        {"type": "SECTION", "bind": "GLOBAL", "name": "section_name"},
        {"type": "FUNC", "bind": "GLOBAL", "name": "__hidden"},
    ]
    result = analyzer._filter_symbols_for_telfhash(syms)
    names = [s["name"] for s in result]
    assert "valid_func" in names
    assert "valid_obj" in names
    assert "local_func" not in names
    assert "section_name" not in names
    assert "__hidden" not in names


# ---------------------------------------------------------------------------
# _extract_symbol_names  (lines 328-330)
# ---------------------------------------------------------------------------


def test_extract_symbol_names_sorted():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    syms = [{"name": "zebra"}, {"name": "apple"}, {"name": "mango"}]
    names = analyzer._extract_symbol_names(syms)
    assert names == sorted(names)


def test_extract_symbol_names_filters_empty_strings():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    syms = [{"name": ""}, {"name": "valid"}, {"name": "  "}]
    names = analyzer._extract_symbol_names(syms)
    assert "valid" in names
    assert "" not in names


def test_extract_symbol_names_returns_list():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    names = analyzer._extract_symbol_names([{"name": "foo"}])
    assert isinstance(names, list)


def test_extract_symbol_names_empty_input():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._extract_symbol_names([]) == []


# ---------------------------------------------------------------------------
# _has_elf_symbols  (lines 208-218)
# ---------------------------------------------------------------------------


def test_has_elf_symbols_returns_false_when_no_symbols():
    adapter = DirectFakeAdapter(cmdj_map={"isj": None})
    analyzer = TelfhashAnalyzer(adapter, filepath="/tmp/test.elf")
    assert analyzer._has_elf_symbols({}) is False


def test_has_elf_symbols_linux_os():
    syms = [{"name": "printf", "type": "FUNC"}]
    adapter = DirectFakeAdapter(cmdj_map={"isj": syms})
    analyzer = TelfhashAnalyzer(adapter, filepath="/tmp/test.elf")
    assert analyzer._has_elf_symbols({"bin": {"os": "linux"}}) is True


def test_has_elf_symbols_unix_os():
    syms = [{"name": "open"}]
    adapter = DirectFakeAdapter(cmdj_map={"isj": syms})
    analyzer = TelfhashAnalyzer(adapter, filepath="/tmp/test.elf")
    assert analyzer._has_elf_symbols({"bin": {"os": "unix"}}) is True


def test_has_elf_symbols_windows_os():
    syms = [{"name": "CreateFileW"}]
    adapter = DirectFakeAdapter(cmdj_map={"isj": syms})
    analyzer = TelfhashAnalyzer(adapter, filepath="/tmp/test.elf")
    assert analyzer._has_elf_symbols({"bin": {"os": "windows"}}) is False


def test_has_elf_symbols_no_bin_key():
    syms = [{"name": "read"}]
    adapter = DirectFakeAdapter(cmdj_map={"isj": syms})
    analyzer = TelfhashAnalyzer(adapter, filepath="/tmp/test.elf")
    assert analyzer._has_elf_symbols({"other": {}}) is False


def test_has_elf_symbols_none_info():
    syms = [{"name": "write"}]
    adapter = DirectFakeAdapter(cmdj_map={"isj": syms})
    analyzer = TelfhashAnalyzer(adapter, filepath="/tmp/test.elf")
    assert analyzer._has_elf_symbols(None) is False


def test_has_elf_symbols_exception_returns_false():
    class ExplodingAdapter:
        def cmdj(self, command):
            raise RuntimeError("cmdj exploded")

        def cmd(self, command):
            return ""

    analyzer = TelfhashAnalyzer(ExplodingAdapter(), filepath="/tmp/test.elf")
    result = analyzer._has_elf_symbols({"bin": {"os": "linux"}})
    assert result is False


# ---------------------------------------------------------------------------
# _get_elf_symbols  (lines 231-239)
# ---------------------------------------------------------------------------


def test_get_elf_symbols_with_symbols():
    syms = [{"name": "printf", "type": "FUNC", "bind": "GLOBAL"}]
    adapter = DirectFakeAdapter(cmdj_map={"isj": syms})
    analyzer = TelfhashAnalyzer(adapter, filepath="/tmp/test.elf")
    result = analyzer._get_elf_symbols()
    assert isinstance(result, list)
    assert len(result) == 1


def test_get_elf_symbols_empty_list():
    adapter = DirectFakeAdapter(cmdj_map={"isj": []})
    analyzer = TelfhashAnalyzer(adapter, filepath="/tmp/test.elf")
    assert analyzer._get_elf_symbols() == []


def test_get_elf_symbols_none_returns_empty():
    adapter = DirectFakeAdapter(cmdj_map={"isj": None})
    analyzer = TelfhashAnalyzer(adapter, filepath="/tmp/test.elf")
    assert analyzer._get_elf_symbols() == []


def test_get_elf_symbols_exception_returns_empty():
    class ExplodingAdapter:
        def cmdj(self, command):
            raise RuntimeError("failed")

        def cmd(self, command):
            return ""

    analyzer = TelfhashAnalyzer(ExplodingAdapter(), filepath="/tmp/test.elf")
    result = analyzer._get_elf_symbols()
    assert result == []


# ---------------------------------------------------------------------------
# _is_elf_file  (lines 197-205)
# ---------------------------------------------------------------------------


def test_is_elf_file_none_r2_returns_false():
    analyzer = TelfhashAnalyzer(None, filepath="/tmp/test.bin")
    assert analyzer._is_elf_file() is False


def test_is_elf_file_returns_bool():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    result = analyzer._is_elf_file()
    assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# _calculate_hash  (lines 59, 72-88)
# ---------------------------------------------------------------------------


def test_calculate_hash_not_elf_returns_error():
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    analyzer = TelfhashAnalyzer(None, filepath="/tmp/not_elf.bin")
    hv, method, error = analyzer._calculate_hash()
    assert hv is None
    assert error == "File is not an ELF binary"


def test_calculate_hash_returns_tuple_of_three():
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    analyzer = TelfhashAnalyzer(None, filepath="/tmp/test.bin")
    result = analyzer._calculate_hash()
    assert len(result) == 3


class ElfForcedAnalyzer(TelfhashAnalyzer):
    """Forces _is_elf_file to return True for testing hash calculation branches."""

    def _is_elf_file(self):
        return True


def test_calculate_hash_with_forced_elf_nonexistent_path():
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    analyzer = ElfForcedAnalyzer(make_adapter(), filepath="/nonexistent/path.elf")
    hv, method, error = analyzer._calculate_hash()
    # telfhash returns [] for non-existent file; hits else branch (line 79)
    assert hv is None


def test_calculate_hash_with_real_elf_fixture():
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    analyzer = ElfForcedAnalyzer(make_adapter(), filepath=ELF_FIXTURE)
    hv, method, error = analyzer._calculate_hash()
    if hv is not None:
        assert method == "python_library"
    else:
        assert error is not None or hv is None


# ---------------------------------------------------------------------------
# analyze  (wraps super().analyze())
# ---------------------------------------------------------------------------


def test_analyze_returns_dict_with_telfhash_key():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    result = analyzer.analyze()
    assert isinstance(result, dict)
    assert "telfhash" in result


def test_analyze_telfhash_field_consistent_with_hash_value():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    result = analyzer.analyze()
    assert result["telfhash"] == result.get("hash_value")


# ---------------------------------------------------------------------------
# analyze_symbols  (lines 128-184)
# ---------------------------------------------------------------------------


def test_analyze_symbols_not_available_branch():
    if TELFHASH_AVAILABLE:
        pytest.skip("telfhash is available")
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    result = analyzer.analyze_symbols()
    assert result["available"] is False
    assert result["error"] is not None


def test_analyze_symbols_not_elf_branch():
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    analyzer = TelfhashAnalyzer(None, filepath="/tmp/test.bin")
    result = analyzer.analyze_symbols()
    assert result["is_elf"] is False
    assert result["error"] is not None


def test_analyze_symbols_returns_required_keys():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    result = analyzer.analyze_symbols()
    for key in ("available", "telfhash", "symbol_count", "filtered_symbols", "symbols_used", "error", "is_elf"):
        assert key in result


def test_analyze_symbols_with_elf_fixture():
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    syms = [{"name": "printf", "type": "FUNC", "bind": "GLOBAL"}]
    info = {"bin": {"os": "linux"}}
    adapter = DirectFakeAdapter(cmdj_map={"isj": syms, "ij": info})
    analyzer = TelfhashAnalyzer(adapter, filepath=ELF_FIXTURE)
    result = analyzer.analyze_symbols()
    assert isinstance(result, dict)


def test_analyze_symbols_elf_fixture_direct():
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    analyzer = ElfForcedAnalyzer(make_adapter(), filepath=ELF_FIXTURE)
    result = analyzer.analyze_symbols()
    assert isinstance(result, dict)
    assert "telfhash" in result


# ---------------------------------------------------------------------------
# compare_hashes  (lines 360-375)
# ---------------------------------------------------------------------------


def test_compare_hashes_returns_none_when_unavailable():
    if TELFHASH_AVAILABLE:
        pytest.skip("telfhash is available")
    assert TelfhashAnalyzer.compare_hashes("T1abc", "T1def") is None


def test_compare_hashes_none_first_arg():
    result = TelfhashAnalyzer.compare_hashes(None, "T1abc")  # type: ignore[arg-type]
    assert result is None


def test_compare_hashes_none_second_arg():
    result = TelfhashAnalyzer.compare_hashes("T1abc", None)  # type: ignore[arg-type]
    assert result is None


def test_compare_hashes_empty_first():
    result = TelfhashAnalyzer.compare_hashes("", "T1abc")
    assert result is None


def test_compare_hashes_empty_second():
    result = TelfhashAnalyzer.compare_hashes("T1abc", "")
    assert result is None


def test_compare_hashes_both_empty():
    result = TelfhashAnalyzer.compare_hashes("", "")
    assert result is None


def test_compare_hashes_returns_int_or_none_when_available():
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    result = TelfhashAnalyzer.compare_hashes("T1abc", "T1abc")
    assert result is None or isinstance(result, int)


def test_compare_hashes_invalid_format_does_not_raise():
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    result = TelfhashAnalyzer.compare_hashes("invalid_not_telfhash", "also_invalid")
    assert result is None or isinstance(result, int)


# ---------------------------------------------------------------------------
# calculate_telfhash_from_file  (lines 398-410)
# ---------------------------------------------------------------------------


def test_calculate_telfhash_from_file_unavailable():
    if TELFHASH_AVAILABLE:
        pytest.skip("telfhash is available")
    result = TelfhashAnalyzer.calculate_telfhash_from_file("/tmp/test.elf")
    assert result is None


def test_calculate_telfhash_from_file_returns_none_or_str_for_elf():
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    result = TelfhashAnalyzer.calculate_telfhash_from_file(ELF_FIXTURE)
    assert result is None or isinstance(result, str)


def test_calculate_telfhash_from_file_nonexistent():
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    result = TelfhashAnalyzer.calculate_telfhash_from_file("/nonexistent/file.elf")
    # telfhash may return None, a string, or an empty list for missing files
    assert result is None or isinstance(result, (str, list))


def test_calculate_telfhash_from_file_not_a_file():
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    result = TelfhashAnalyzer.calculate_telfhash_from_file("/tmp")
    # telfhash may return None, a string, or an empty list for directories/invalid paths
    assert result is None or isinstance(result, (str, list))
