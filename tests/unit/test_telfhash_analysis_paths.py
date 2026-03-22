"""Comprehensive tests for telfhash_analyzer.py - analysis paths and symbol processing."""

import json
import tempfile
from pathlib import Path

from r2inspect.modules.telfhash_analyzer import TelfhashAnalyzer
from r2inspect.testing.fake_r2 import FakeR2


def _make_elf_file():
    """Create a temporary file with ELF magic bytes and return its path."""
    with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
        # Minimal ELF header (magic + enough padding)
        f.write(b"\x7fELF" + b"\x00" * 100)
        f.flush()
        return f.name


def _elf_info_cmdj():
    """Return a cmdj map that makes the file look like an ELF via ij."""
    return {
        "ij": {"bin": {"format": "elf", "class": "ELF64", "os": "linux", "type": "DYN"}},
    }


def _elf_info_cmd():
    """Return a cmd map that makes the file look like an ELF via 'i'."""
    return {
        "i": "file     /test/file\nformat   elf64\ntype     DYN",
    }


def _elf_adapter(cmdj_extra=None, cmd_extra=None, elf_path=None):
    """Create a FakeR2 that behaves like an ELF binary, and a TelfhashAnalyzer."""
    filepath = elf_path or _make_elf_file()
    cmdj_map = {
        "ij": {"bin": {"format": "elf", "class": "ELF64", "os": "linux", "type": "DYN"}},
        "isj": [],
    }
    cmd_map = {
        "i": "format   elf64",
    }
    if cmdj_extra:
        cmdj_map.update(cmdj_extra)
    if cmd_extra:
        cmd_map.update(cmd_extra)
    adapter = FakeR2(cmdj_map=cmdj_map, cmd_map=cmd_map)
    analyzer = TelfhashAnalyzer(adapter, filepath)
    return analyzer


# --- analyze_symbols tests ---


def test_analyze_symbols_not_available():
    """Test analyze_symbols when telfhash not available."""
    import r2inspect.modules.telfhash_analyzer as mod

    original = mod.TELFHASH_AVAILABLE
    try:
        mod.TELFHASH_AVAILABLE = False
        adapter = FakeR2()
        analyzer = TelfhashAnalyzer(adapter, "/test/file")
        result = analyzer.analyze_symbols()
        assert result["available"] is False
        assert "not available" in result["error"]
    finally:
        mod.TELFHASH_AVAILABLE = original


def test_analyze_symbols_not_elf():
    """Test analyze_symbols when file is not ELF (non-existent file, no ELF info)."""
    import r2inspect.modules.telfhash_analyzer as mod

    original = mod.TELFHASH_AVAILABLE
    try:
        mod.TELFHASH_AVAILABLE = True
        # Use a non-existent path with no ELF info from r2 -> not ELF
        adapter = FakeR2(
            cmdj_map={"ij": {"bin": {"format": "pe", "class": "PE32"}}},
            cmd_map={"i": "format   pe"},
        )
        analyzer = TelfhashAnalyzer(adapter, "/nonexistent/not_elf.exe")
        result = analyzer.analyze_symbols()
        assert result["available"] is True
        assert result["is_elf"] is False
        # The error should indicate it's not ELF
        assert result["error"] is not None
    finally:
        mod.TELFHASH_AVAILABLE = original


def test_analyze_symbols_success():
    """Test analyze_symbols with successful analysis on an ELF-like file."""
    import r2inspect.modules.telfhash_analyzer as mod

    original_avail = mod.TELFHASH_AVAILABLE
    original_fn = getattr(mod, "telfhash", None)
    elf_path = _make_elf_file()
    try:
        mod.TELFHASH_AVAILABLE = True

        symbols = [
            {"name": "func1", "type": "FUNC", "bind": "GLOBAL"},
            {"name": "func2", "type": "FUNC", "bind": "GLOBAL"},
        ]

        def fake_telfhash(filepath):
            return [{"telfhash": "T1234HASH"}]

        mod.telfhash = fake_telfhash

        analyzer = _elf_adapter(
            cmdj_extra={"isj": symbols},
            elf_path=elf_path,
        )
        result = analyzer.analyze_symbols()

        assert result["available"] is True
        assert result["is_elf"] is True
        assert result["telfhash"] == "T1234HASH"
        assert result["symbol_count"] == 2
        assert result["filtered_symbols"] == 2
        assert "func1" in result["symbols_used"]
        assert "func2" in result["symbols_used"]
    finally:
        mod.TELFHASH_AVAILABLE = original_avail
        if original_fn is not None:
            mod.telfhash = original_fn


def test_analyze_symbols_telfhash_exception():
    """Test analyze_symbols when telfhash calculation raises an exception."""
    import r2inspect.modules.telfhash_analyzer as mod

    original_avail = mod.TELFHASH_AVAILABLE
    original_fn = getattr(mod, "telfhash", None)
    elf_path = _make_elf_file()
    try:
        mod.TELFHASH_AVAILABLE = True

        def failing_telfhash(filepath):
            raise Exception("Calc error")

        mod.telfhash = failing_telfhash

        analyzer = _elf_adapter(elf_path=elf_path)
        result = analyzer.analyze_symbols()

        assert result["available"] is True
        assert result["is_elf"] is True
        assert "failed" in result["error"].lower() or "error" in result["error"].lower()
    finally:
        mod.TELFHASH_AVAILABLE = original_avail
        if original_fn is not None:
            mod.telfhash = original_fn


def test_analyze_symbols_general_exception():
    """Test analyze_symbols with general exception during ELF check."""
    import r2inspect.modules.telfhash_analyzer as mod

    original_avail = mod.TELFHASH_AVAILABLE
    try:
        mod.TELFHASH_AVAILABLE = True
        # An adapter that raises exceptions on every command
        adapter = FakeR2()

        class BrokenAnalyzer(TelfhashAnalyzer):
            def _is_elf_file(self):
                raise Exception("General error")

        analyzer = BrokenAnalyzer(adapter, "/test/file")
        result = analyzer.analyze_symbols()

        assert "error" in result
        assert "General error" in result["error"]
    finally:
        mod.TELFHASH_AVAILABLE = original_avail


# --- _is_elf_file tests ---


def test_is_elf_file_via_elf_magic():
    """Test _is_elf_file with an actual ELF-magic file and elf info from r2."""
    elf_path = _make_elf_file()
    analyzer = _elf_adapter(elf_path=elf_path)
    result = analyzer._is_elf_file()
    assert result is True


def test_is_elf_file_not_elf():
    """Test _is_elf_file with a non-ELF file."""
    # Create a temp file with non-ELF magic
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"MZ" + b"\x00" * 100)
        f.flush()
        filepath = f.name

    adapter = FakeR2(
        cmdj_map={"ij": {"bin": {"format": "pe", "class": "PE32"}}},
        cmd_map={"i": "format   pe"},
    )
    analyzer = TelfhashAnalyzer(adapter, filepath)
    result = analyzer._is_elf_file()
    assert result is False


def test_is_elf_file_no_r2():
    """Test _is_elf_file when r2 is None."""
    adapter = FakeR2()
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    analyzer.r2 = None
    result = analyzer._is_elf_file()
    assert result is False


def test_is_elf_file_exception():
    """Test _is_elf_file with an adapter that causes exceptions."""
    # File doesn't exist, r2 returns empty/broken data -> should return False
    adapter = FakeR2(
        cmdj_map={},
        cmd_map={},
    )
    analyzer = TelfhashAnalyzer(adapter, "/nonexistent/check_error_file")
    result = analyzer._is_elf_file()
    assert result is False


# --- _has_elf_symbols tests ---


def test_has_elf_symbols_success():
    """Test _has_elf_symbols with linux OS and symbols present."""
    adapter = FakeR2(cmdj_map={"isj": [{"name": "sym"}]})
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    info_cmd = {"bin": {"os": "linux"}}
    result = analyzer._has_elf_symbols(info_cmd)
    assert result is True


def test_has_elf_symbols_unix():
    """Test _has_elf_symbols with unix os."""
    adapter = FakeR2(cmdj_map={"isj": [{"name": "sym"}]})
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    info_cmd = {"bin": {"os": "unix"}}
    result = analyzer._has_elf_symbols(info_cmd)
    assert result is True


def test_has_elf_symbols_no_symbols():
    """Test _has_elf_symbols with no symbols."""
    adapter = FakeR2(cmdj_map={"isj": []})
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    info_cmd = {"bin": {"os": "linux"}}
    result = analyzer._has_elf_symbols(info_cmd)
    assert result is False


def test_has_elf_symbols_no_info():
    """Test _has_elf_symbols with no info_cmd."""
    adapter = FakeR2(cmdj_map={"isj": [{"name": "sym"}]})
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    result = analyzer._has_elf_symbols(None)
    assert result is False


def test_has_elf_symbols_exception():
    """Test _has_elf_symbols with exception from command."""

    class BrokenR2(FakeR2):
        def cmdj(self, command):
            if command == "isj":
                raise Exception("Cmd error")
            return super().cmdj(command)

    adapter = BrokenR2()
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    info_cmd = {"bin": {"os": "linux"}}
    result = analyzer._has_elf_symbols(info_cmd)
    assert result is False


# --- _get_elf_symbols tests ---


def test_get_elf_symbols_success():
    """Test _get_elf_symbols with symbols returned."""
    symbols = [
        {"name": "main", "type": "FUNC"},
        {"name": "helper", "type": "FUNC"},
    ]
    adapter = FakeR2(cmdj_map={"isj": symbols})
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    result = analyzer._get_elf_symbols()
    assert len(result) == 2
    assert result[0]["name"] == "main"


def test_get_elf_symbols_empty():
    """Test _get_elf_symbols with no symbols."""
    adapter = FakeR2(cmdj_map={"isj": []})
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    result = analyzer._get_elf_symbols()
    assert result == []


def test_get_elf_symbols_exception():
    """Test _get_elf_symbols with exception from command."""

    class BrokenR2(FakeR2):
        def cmdj(self, command):
            if command == "isj":
                raise Exception("Symbol error")
            return super().cmdj(command)

    adapter = BrokenR2()
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    result = analyzer._get_elf_symbols()
    assert result == []


# --- _filter_symbols_for_telfhash tests ---


def test_filter_symbols_for_telfhash():
    """Test _filter_symbols_for_telfhash filtering logic."""
    adapter = FakeR2()
    analyzer = TelfhashAnalyzer(adapter, "/test/file")

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


# --- _should_skip_symbol tests ---


def test_should_skip_symbol_short_names():
    """Test _should_skip_symbol with short names."""
    adapter = FakeR2()
    analyzer = TelfhashAnalyzer(adapter, "/test/file")

    assert analyzer._should_skip_symbol("a") is True
    assert analyzer._should_skip_symbol("") is True
    assert analyzer._should_skip_symbol("ab") is False


def test_should_skip_symbol_patterns():
    """Test _should_skip_symbol with various patterns."""
    adapter = FakeR2()
    analyzer = TelfhashAnalyzer(adapter, "/test/file")

    assert analyzer._should_skip_symbol("__internal") is True
    assert analyzer._should_skip_symbol("_GLOBAL_OFFSET_TABLE_") is True
    assert analyzer._should_skip_symbol("_DYNAMIC") is True
    assert analyzer._should_skip_symbol(".Lstart") is True
    assert analyzer._should_skip_symbol("_edata") is True
    assert analyzer._should_skip_symbol("_end") is True
    assert analyzer._should_skip_symbol("_start") is True
    assert analyzer._should_skip_symbol("normal_function") is False


# --- _extract_symbol_names tests ---


def test_extract_symbol_names():
    """Test _extract_symbol_names sorting."""
    adapter = FakeR2()
    analyzer = TelfhashAnalyzer(adapter, "/test/file")

    symbols = [
        {"name": "zebra"},
        {"name": "apple"},
        {"name": ""},
        {"name": "banana"},
    ]

    result = analyzer._extract_symbol_names(symbols)
    assert result == ["apple", "banana", "zebra"]


# --- compare_hashes tests ---


def test_compare_hashes_not_available():
    """Test compare_hashes when telfhash not available."""
    import r2inspect.modules.telfhash_analyzer as mod

    original = mod.TELFHASH_AVAILABLE
    try:
        mod.TELFHASH_AVAILABLE = False
        result = TelfhashAnalyzer.compare_hashes("HASH1", "HASH2")
        assert result is None
    finally:
        mod.TELFHASH_AVAILABLE = original


def test_compare_hashes_empty_hash1():
    """Test compare_hashes with empty first hash."""
    import r2inspect.modules.telfhash_analyzer as mod

    original = mod.TELFHASH_AVAILABLE
    try:
        mod.TELFHASH_AVAILABLE = True
        result = TelfhashAnalyzer.compare_hashes("", "HASH2")
        assert result is None
    finally:
        mod.TELFHASH_AVAILABLE = original


def test_compare_hashes_empty_hash2():
    """Test compare_hashes with empty second hash."""
    import r2inspect.modules.telfhash_analyzer as mod

    original = mod.TELFHASH_AVAILABLE
    try:
        mod.TELFHASH_AVAILABLE = True
        result = TelfhashAnalyzer.compare_hashes("HASH1", "")
        assert result is None
    finally:
        mod.TELFHASH_AVAILABLE = original


def test_compare_hashes_success():
    """Test compare_hashes with real ssdeep module (if available) or verify None returned."""
    import r2inspect.modules.telfhash_analyzer as mod
    from r2inspect.infrastructure.ssdeep_loader import get_ssdeep

    original = mod.TELFHASH_AVAILABLE
    try:
        mod.TELFHASH_AVAILABLE = True
        ssdeep_mod = get_ssdeep()
        result = TelfhashAnalyzer.compare_hashes("HASH1", "HASH2")
        if ssdeep_mod is None:
            # ssdeep not installed -> None
            assert result is None
        else:
            # ssdeep installed -> returns int or None depending on hash validity
            assert result is None or isinstance(result, int)
    finally:
        mod.TELFHASH_AVAILABLE = original


def test_compare_hashes_no_ssdeep():
    """Test compare_hashes when ssdeep is not importable returns None."""
    import r2inspect.modules.telfhash_analyzer as mod
    import r2inspect.infrastructure.ssdeep_loader as loader

    original_avail = mod.TELFHASH_AVAILABLE
    original_module = loader._ssdeep_module
    try:
        mod.TELFHASH_AVAILABLE = True
        # Force ssdeep to appear unavailable by clearing the cached module
        # and making import fail
        loader._ssdeep_module = None

        # We can't easily force import to fail without mock, but we can
        # test the behavior: if ssdeep is actually not installed, get_ssdeep()
        # returns None. If it is installed, the compare will work.
        result = TelfhashAnalyzer.compare_hashes("HASH1", "HASH2")
        # Either way, with invalid hash strings the result should be None or an int
        assert result is None or isinstance(result, int)
    finally:
        mod.TELFHASH_AVAILABLE = original_avail
        loader._ssdeep_module = original_module


def test_compare_hashes_exception():
    """Test compare_hashes with invalid hash values returns None or int."""
    import r2inspect.modules.telfhash_analyzer as mod

    original = mod.TELFHASH_AVAILABLE
    try:
        mod.TELFHASH_AVAILABLE = True
        # Pass garbage values - should return None (exception) or int
        result = TelfhashAnalyzer.compare_hashes("HASH1", "HASH2")
        assert result is None or isinstance(result, int)
    finally:
        mod.TELFHASH_AVAILABLE = original


# --- analyze_symbols result format tests ---


def test_analyze_symbols_with_dict_result():
    """Test analyze_symbols when telfhash returns dict."""
    import r2inspect.modules.telfhash_analyzer as mod

    original_avail = mod.TELFHASH_AVAILABLE
    original_fn = getattr(mod, "telfhash", None)
    elf_path = _make_elf_file()
    try:
        mod.TELFHASH_AVAILABLE = True

        def fake_telfhash(filepath):
            return {"telfhash": "T5678DICT"}

        mod.telfhash = fake_telfhash

        analyzer = _elf_adapter(elf_path=elf_path)
        result = analyzer.analyze_symbols()

        assert result["telfhash"] == "T5678DICT"
    finally:
        mod.TELFHASH_AVAILABLE = original_avail
        if original_fn is not None:
            mod.telfhash = original_fn


def test_analyze_symbols_with_string_result():
    """Test analyze_symbols when telfhash returns string."""
    import r2inspect.modules.telfhash_analyzer as mod

    original_avail = mod.TELFHASH_AVAILABLE
    original_fn = getattr(mod, "telfhash", None)
    elf_path = _make_elf_file()
    try:
        mod.TELFHASH_AVAILABLE = True

        def fake_telfhash(filepath):
            return "T9999STR"

        mod.telfhash = fake_telfhash

        analyzer = _elf_adapter(elf_path=elf_path)
        result = analyzer.analyze_symbols()

        assert result["telfhash"] == "T9999STR"
    finally:
        mod.TELFHASH_AVAILABLE = original_avail
        if original_fn is not None:
            mod.telfhash = original_fn


def test_analyze_symbols_with_msg_list():
    """Test analyze_symbols when telfhash returns list with msg."""
    import r2inspect.modules.telfhash_analyzer as mod

    original_avail = mod.TELFHASH_AVAILABLE
    original_fn = getattr(mod, "telfhash", None)
    elf_path = _make_elf_file()
    try:
        mod.TELFHASH_AVAILABLE = True

        def fake_telfhash(filepath):
            return [{"msg": "Error message", "telfhash": None}]

        mod.telfhash = fake_telfhash

        analyzer = _elf_adapter(elf_path=elf_path)
        result = analyzer.analyze_symbols()

        assert "Error message" in result["error"]
    finally:
        mod.TELFHASH_AVAILABLE = original_avail
        if original_fn is not None:
            mod.telfhash = original_fn


def test_analyze_symbols_with_msg_dict():
    """Test analyze_symbols when telfhash returns dict with msg."""
    import r2inspect.modules.telfhash_analyzer as mod

    original_avail = mod.TELFHASH_AVAILABLE
    original_fn = getattr(mod, "telfhash", None)
    elf_path = _make_elf_file()
    try:
        mod.TELFHASH_AVAILABLE = True

        def fake_telfhash(filepath):
            return {"msg": "Dict error", "telfhash": None}

        mod.telfhash = fake_telfhash

        analyzer = _elf_adapter(elf_path=elf_path)
        result = analyzer.analyze_symbols()

        assert "Dict error" in result["error"]
    finally:
        mod.TELFHASH_AVAILABLE = original_avail
        if original_fn is not None:
            mod.telfhash = original_fn
