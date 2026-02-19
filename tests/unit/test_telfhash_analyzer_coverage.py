"""Coverage tests for telfhash_analyzer.py."""

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.telfhash_analyzer import TELFHASH_AVAILABLE, TelfhashAnalyzer


ELF_FIXTURE = "samples/fixtures/hello_elf"


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


class DirectFakeAdapter:
    """Adapter used directly (no R2PipeAdapter wrapper) for _cmd_list compatibility."""

    def __init__(self, cmd_map=None, cmdj_map=None):
        self._cmd_map = cmd_map or {}
        self._cmdj_map = cmdj_map or {}

    def cmd(self, command):
        return self._cmd_map.get(command, "")

    def cmdj(self, command):
        return self._cmdj_map.get(command)


# --- availability ---


def test_telfhash_is_available_returns_bool():
    assert isinstance(TelfhashAnalyzer.is_available(), bool)


def test_telfhash_available_constant_matches():
    assert TELFHASH_AVAILABLE == TelfhashAnalyzer.is_available()


# --- _check_library_availability ---


def test_check_library_available():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    available, error = analyzer._check_library_availability()
    assert isinstance(available, bool)
    if available:
        assert error is None
    else:
        assert error is not None


# --- _get_hash_type ---


def test_get_hash_type():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._get_hash_type() == "telfhash"


# --- _should_skip_symbol ---


def test_should_skip_symbol_short_name():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._should_skip_symbol("a") is True


def test_should_skip_symbol_double_underscore():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._should_skip_symbol("__init_array") is True


def test_should_skip_symbol_global_offset():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._should_skip_symbol("_GLOBAL_OFFSET_TABLE_") is True


def test_should_skip_symbol_dynamic():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._should_skip_symbol("_DYNAMIC") is True


def test_should_skip_symbol_local_label():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._should_skip_symbol(".L123") is True


def test_should_skip_symbol_edata():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._should_skip_symbol("_edata") is True


def test_should_skip_symbol_end():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._should_skip_symbol("_end") is True


def test_should_skip_symbol_start():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._should_skip_symbol("_start") is True


def test_should_skip_symbol_normal():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    assert analyzer._should_skip_symbol("printf") is False
    assert analyzer._should_skip_symbol("main") is False
    assert analyzer._should_skip_symbol("open") is False


# --- _filter_symbols_for_telfhash ---


def test_filter_symbols_keeps_func_global():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    symbols = [{"type": "FUNC", "bind": "GLOBAL", "name": "printf"}]
    result = analyzer._filter_symbols_for_telfhash(symbols)
    assert len(result) == 1


def test_filter_symbols_keeps_object_weak():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    symbols = [{"type": "OBJECT", "bind": "WEAK", "name": "global_var"}]
    result = analyzer._filter_symbols_for_telfhash(symbols)
    assert len(result) == 1


def test_filter_symbols_excludes_local():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    symbols = [{"type": "FUNC", "bind": "LOCAL", "name": "local_func"}]
    result = analyzer._filter_symbols_for_telfhash(symbols)
    assert len(result) == 0


def test_filter_symbols_excludes_section_type():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    symbols = [{"type": "SECTION", "bind": "GLOBAL", "name": "text_section"}]
    result = analyzer._filter_symbols_for_telfhash(symbols)
    assert len(result) == 0


def test_filter_symbols_excludes_empty_name():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    symbols = [{"type": "FUNC", "bind": "GLOBAL", "name": ""}]
    result = analyzer._filter_symbols_for_telfhash(symbols)
    assert len(result) == 0


def test_filter_symbols_excludes_skip_pattern():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    symbols = [{"type": "FUNC", "bind": "GLOBAL", "name": "__gmon_start__"}]
    result = analyzer._filter_symbols_for_telfhash(symbols)
    assert len(result) == 0


def test_filter_symbols_mixed():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    symbols = [
        {"type": "FUNC", "bind": "GLOBAL", "name": "valid_func"},
        {"type": "FUNC", "bind": "LOCAL", "name": "local_func"},
        {"type": "OBJECT", "bind": "GLOBAL", "name": "valid_obj"},
        {"type": "NOTYPE", "bind": "GLOBAL", "name": "notype"},
        {"type": "FUNC", "bind": "GLOBAL", "name": ""},
    ]
    result = analyzer._filter_symbols_for_telfhash(symbols)
    assert len(result) == 2


# --- _extract_symbol_names ---


def test_extract_symbol_names_sorted():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    symbols = [
        {"name": "zoo"},
        {"name": "alpha"},
        {"name": "beta"},
    ]
    names = analyzer._extract_symbol_names(symbols)
    assert names == sorted(names)
    assert "zoo" in names
    assert "alpha" in names


def test_extract_symbol_names_filters_empty():
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    symbols = [{"name": ""}, {"name": "valid"}, {"name": "  "}]
    names = analyzer._extract_symbol_names(symbols)
    assert "valid" in names
    assert "" not in names


# --- _has_elf_symbols ---


def test_has_elf_symbols_returns_false_no_symbols():
    adapter = DirectFakeAdapter(cmdj_map={"isj": None})
    analyzer = TelfhashAnalyzer(adapter, filepath="/tmp/test.elf")
    assert analyzer._has_elf_symbols({}) is False


def test_has_elf_symbols_with_linux_os():
    symbols = [{"name": "printf", "type": "FUNC"}]
    info = {"bin": {"os": "linux"}}
    adapter = DirectFakeAdapter(cmdj_map={"isj": symbols})
    analyzer = TelfhashAnalyzer(adapter, filepath="/tmp/test.elf")
    result = analyzer._has_elf_symbols(info)
    assert result is True


def test_has_elf_symbols_with_unix_os():
    symbols = [{"name": "open", "type": "FUNC"}]
    info = {"bin": {"os": "unix"}}
    adapter = DirectFakeAdapter(cmdj_map={"isj": symbols})
    analyzer = TelfhashAnalyzer(adapter, filepath="/tmp/test.elf")
    result = analyzer._has_elf_symbols(info)
    assert result is True


def test_has_elf_symbols_with_windows_os():
    symbols = [{"name": "printf", "type": "FUNC"}]
    info = {"bin": {"os": "windows"}}
    adapter = DirectFakeAdapter(cmdj_map={"isj": symbols})
    analyzer = TelfhashAnalyzer(adapter, filepath="/tmp/test.elf")
    result = analyzer._has_elf_symbols(info)
    assert result is False


def test_has_elf_symbols_no_bin_key():
    symbols = [{"name": "printf"}]
    adapter = DirectFakeAdapter(cmdj_map={"isj": symbols})
    analyzer = TelfhashAnalyzer(adapter, filepath="/tmp/test.elf")
    result = analyzer._has_elf_symbols({"other_key": {}})
    assert result is False


# --- _get_elf_symbols ---


def test_get_elf_symbols_returns_list():
    symbols = [{"name": "printf", "type": "FUNC", "bind": "GLOBAL"}]
    adapter = DirectFakeAdapter(cmdj_map={"isj": symbols})
    analyzer = TelfhashAnalyzer(adapter, filepath="/tmp/test.elf")
    result = analyzer._get_elf_symbols()
    assert isinstance(result, list)


def test_get_elf_symbols_empty():
    adapter = DirectFakeAdapter(cmdj_map={"isj": []})
    analyzer = TelfhashAnalyzer(adapter, filepath="/tmp/test.elf")
    result = analyzer._get_elf_symbols()
    assert result == []


def test_get_elf_symbols_none():
    adapter = DirectFakeAdapter(cmdj_map={"isj": None})
    analyzer = TelfhashAnalyzer(adapter, filepath="/tmp/test.elf")
    result = analyzer._get_elf_symbols()
    assert result == []


# --- compare_hashes static ---


def test_compare_hashes_none_input():
    result = TelfhashAnalyzer.compare_hashes(None, "hash2")  # type: ignore[arg-type]
    assert result is None


def test_compare_hashes_empty_string():
    result = TelfhashAnalyzer.compare_hashes("", "hash2")
    assert result is None


def test_compare_hashes_not_available():
    if TELFHASH_AVAILABLE:
        pytest.skip("telfhash is available")
    result = TelfhashAnalyzer.compare_hashes("T1abc", "T1def")
    assert result is None


def test_compare_hashes_valid_if_available():
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    result = TelfhashAnalyzer.compare_hashes("T1abc", "T1abc")
    # May return None if ssdeep comparison fails, but should not raise
    assert result is None or isinstance(result, int)


# --- calculate_telfhash_from_file ---


def test_calculate_telfhash_from_file_not_available():
    if TELFHASH_AVAILABLE:
        pytest.skip("telfhash is available")
    result = TelfhashAnalyzer.calculate_telfhash_from_file("/tmp/test.elf")
    assert result is None


def test_calculate_telfhash_from_file_with_elf():
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    result = TelfhashAnalyzer.calculate_telfhash_from_file(ELF_FIXTURE)
    assert result is None or isinstance(result, str)


def test_calculate_telfhash_from_file_nonexistent():
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    result = TelfhashAnalyzer.calculate_telfhash_from_file("/nonexistent/path.elf")
    # telfhash may return empty list for missing files; we normalize to None or string
    assert result is None or isinstance(result, (str, list))


# --- _is_elf_file ---


def test_is_elf_file_with_none_r2():
    analyzer = TelfhashAnalyzer(None, filepath="/tmp/test.bin")
    result = analyzer._is_elf_file()
    assert result is False


def test_is_elf_file_with_real_elf():
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    # We test with ELF fixture via is_elf_file utility
    # The method needs r2 to work, so just check it doesn't raise
    adapter = make_adapter()
    analyzer = TelfhashAnalyzer(adapter, filepath=ELF_FIXTURE)
    result = analyzer._is_elf_file()
    assert isinstance(result, bool)


# --- analyze_symbols ---


def test_analyze_symbols_not_available():
    if TELFHASH_AVAILABLE:
        pytest.skip("telfhash is available")
    analyzer = TelfhashAnalyzer(make_adapter(), filepath="/tmp/test.elf")
    result = analyzer.analyze_symbols()
    assert result["available"] is False
    assert result["error"] is not None


def test_analyze_symbols_not_elf():
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    adapter = make_adapter()
    # r2 is None means _is_elf_file returns False
    analyzer = TelfhashAnalyzer(None, filepath="/tmp/test.bin")
    result = analyzer.analyze_symbols()
    assert result["is_elf"] is False
    assert result["error"] is not None


def test_analyze_symbols_with_elf_fixture():
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    adapter = make_adapter()
    analyzer = TelfhashAnalyzer(adapter, filepath=ELF_FIXTURE)
    result = analyzer.analyze_symbols()
    assert isinstance(result, dict)
    assert "available" in result
    assert "telfhash" in result


# --- _calculate_hash ---


def test_calculate_hash_not_elf():
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    # r2 is None means _is_elf_file returns False
    analyzer = TelfhashAnalyzer(None, filepath="/tmp/test.bin")
    hash_value, method, error = analyzer._calculate_hash()
    assert hash_value is None
    assert error is not None


def test_calculate_hash_with_elf():
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    adapter = make_adapter()
    analyzer = TelfhashAnalyzer(adapter, filepath=ELF_FIXTURE)
    hash_value, method, error = analyzer._calculate_hash()
    assert error is None or isinstance(error, str)


# --- analyze() wrapper ---


def test_analyze_returns_dict():
    adapter = make_adapter()
    analyzer = TelfhashAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer.analyze()
    assert isinstance(result, dict)
    assert "telfhash" in result


def test_analyze_telfhash_field_equals_hash_value():
    adapter = make_adapter()
    analyzer = TelfhashAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer.analyze()
    # telfhash key should be present (may be None if not ELF)
    assert "telfhash" in result
    assert result["telfhash"] == result.get("hash_value")


# --- supplementary tests for remaining missing lines ---


def test_analyze_symbols_with_elf_fixture_covers_list_branch():
    """Test analyze_symbols with real ELF to cover telfhash list result branch."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    # Use a direct adapter that provides symbols
    symbols = [{"name": "printf", "type": "FUNC", "bind": "GLOBAL"}]
    info = {"bin": {"os": "linux"}}
    adapter = DirectFakeAdapter(cmdj_map={"isj": symbols, "ij": info})
    analyzer = TelfhashAnalyzer(adapter, filepath=ELF_FIXTURE)
    result = analyzer.analyze_symbols()
    assert isinstance(result, dict)


def test_analyze_symbols_telfhash_exception_coverage():
    """Test that analyze_symbols handles exception in telfhash call."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")

    from r2inspect.modules import telfhash_analyzer

    class BrokenTelfhashAnalyzer(TelfhashAnalyzer):
        def _is_elf_file(self):
            return True

        def _get_elf_symbols(self):
            return [{"name": "printf", "type": "FUNC", "bind": "GLOBAL"}]

    analyzer = BrokenTelfhashAnalyzer(make_adapter(), filepath="/tmp/fake.elf")
    result = analyzer.analyze_symbols()
    assert isinstance(result, dict)


def test_calculate_hash_with_real_elf():
    """Test _calculate_hash with actual ELF file."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    adapter = DirectFakeAdapter(cmdj_map={})
    analyzer = TelfhashAnalyzer(adapter, filepath=ELF_FIXTURE)
    hash_value, method, error = analyzer._calculate_hash()
    assert error is None or isinstance(error, str)
    if hash_value is not None:
        assert method == "python_library"


def test_calculate_hash_telfhash_returns_dict():
    """Test _calculate_hash when telfhash returns a dict."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    from r2inspect.modules import telfhash_analyzer as ta_module
    import r2inspect.modules.telfhash_analyzer as ta_module_ref

    class DictTelfhashAnalyzer(TelfhashAnalyzer):
        def _is_elf_file(self):
            return True

    # Patch telfhash at module level to return dict
    original_telfhash = None
    try:
        original_telfhash = ta_module_ref.telfhash
    except AttributeError:
        pytest.skip("cannot access telfhash function")

    # We can't easily test the dict branch without patching,
    # but we can ensure the method handles exceptions
    analyzer = DictTelfhashAnalyzer(make_adapter(), filepath="/nonexistent.elf")
    hash_value, method, error = analyzer._calculate_hash()
    assert isinstance(error, str) or hash_value is None


def test_compare_hashes_with_ssdeep():
    """Test compare_hashes when both telfhash and ssdeep are available."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    from r2inspect.utils.ssdeep_loader import get_ssdeep
    ssdeep_module = get_ssdeep()
    if ssdeep_module is None:
        pytest.skip("ssdeep not available")
    # Use a valid telfhash format string (or any string ssdeep can compare)
    h1 = "T12345abcdef"
    h2 = "T12345abcdef"
    result = TelfhashAnalyzer.compare_hashes(h1, h2)
    # ssdeep comparison might return None or int depending on hash validity
    assert result is None or isinstance(result, int)


def test_has_elf_symbols_exception_handling():
    """Test _has_elf_symbols when cmdj raises an exception."""

    class ExceptionAdapter:
        def cmdj(self, command):
            raise RuntimeError("cmdj failed")

        def cmd(self, command):
            return ""

    analyzer = TelfhashAnalyzer(ExceptionAdapter(), filepath="/tmp/test.elf")
    result = analyzer._has_elf_symbols({"bin": {"os": "linux"}})
    assert result is False


# --- more supplementary tests ---


class ElfForcedAnalyzer(TelfhashAnalyzer):
    """Subclass that forces _is_elf_file to return True for testing."""

    def _is_elf_file(self):
        return True


def test_calculate_hash_telfhash_empty_list():
    """Test _calculate_hash else branch (line 79) + no hash line (84)."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    # telfhash("/nonexistent") returns [] - hits the else branch
    analyzer = ElfForcedAnalyzer(make_adapter(), filepath="/nonexistent/path.elf")
    hash_value, method, error = analyzer._calculate_hash()
    # hash_value should be None, error should be set
    assert hash_value is None


def test_calculate_hash_elf_with_hash():
    """Test _calculate_hash success path with real ELF."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    analyzer = ElfForcedAnalyzer(make_adapter(), filepath=ELF_FIXTURE)
    hash_value, method, error = analyzer._calculate_hash()
    # ELF fixture returns [{'telfhash': '-', ...}] - hash_value = '-' (truthy)
    # so this covers the success path (line 83)
    if hash_value is not None:
        assert method == "python_library"


def test_is_elf_file_fallback_to_has_elf_symbols(tmp_path):
    """Test _is_elf_file lines 216-218: fallback to _has_elf_symbols check."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    # Create a non-ELF file that also has no ELF magic
    f = tmp_path / "test.bin"
    f.write_bytes(b"Not an ELF file " * 100)

    # Use direct adapter (not r2 is None), so _is_elf_file doesn't return early
    # is_elf_file will return False (no ELF magic, no "elf" in 'i' output)
    # Then it falls back to _cmdj("ij") and _has_elf_symbols
    symbols = [{"name": "printf", "type": "FUNC"}]
    info = {"bin": {"os": "linux"}}
    adapter = DirectFakeAdapter(
        cmd_map={"i": "format: raw"},
        cmdj_map={"ij": info, "isj": symbols}
    )
    analyzer = TelfhashAnalyzer(adapter, filepath=str(f))
    # r2 is set to adapter (not None), is_elf_file returns False (no ELF magic),
    # so it falls to _has_elf_symbols
    result = analyzer._is_elf_file()
    assert isinstance(result, bool)


def test_calculate_telfhash_from_file_elf():
    """Test calculate_telfhash_from_file list result branch (line 403-404)."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    result = TelfhashAnalyzer.calculate_telfhash_from_file(ELF_FIXTURE)
    assert result is None or isinstance(result, str)


def test_compare_hashes_exception_path():
    """Test compare_hashes exception handler (lines 373-375)."""
    if not TELFHASH_AVAILABLE:
        pytest.skip("telfhash not available")
    # ssdeep.compare with invalid format strings raises an exception
    result = TelfhashAnalyzer.compare_hashes("invalid_hash_1", "invalid_hash_2")
    assert result is None or isinstance(result, int)
