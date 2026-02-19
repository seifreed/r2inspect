"""Comprehensive tests for r2inspect/modules/telfhash_analyzer.py (15% coverage)"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from r2inspect.modules.telfhash_analyzer import TELFHASH_AVAILABLE, TelfhashAnalyzer


def test_telfhash_analyzer_init():
    adapter = Mock()
    filepath = "/test/file.elf"
    
    analyzer = TelfhashAnalyzer(adapter, filepath)
    
    assert analyzer.adapter == adapter
    assert str(analyzer.filepath) == filepath


def test_telfhash_analyzer_check_library_availability():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.elf")
    
    available, error = analyzer._check_library_availability()
    
    if TELFHASH_AVAILABLE:
        assert available is True
        assert error is None
    else:
        assert available is False
        assert "telfhash library not available" in error


def test_telfhash_analyzer_get_hash_type():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.elf")
    
    hash_type = analyzer._get_hash_type()
    
    assert hash_type == "telfhash"


def test_telfhash_analyzer_is_available():
    result = TelfhashAnalyzer.is_available()
    
    assert result == TELFHASH_AVAILABLE


def test_telfhash_analyzer_analyze_symbols_not_available():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.elf")
    
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", False):
        result = analyzer.analyze_symbols()
        
        assert result["available"] is False
        assert result["error"] == "telfhash library not available"
        assert result["telfhash"] is None


def test_telfhash_analyzer_is_elf_file_no_r2():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.bin")
    analyzer.r2 = None
    
    result = analyzer._is_elf_file()
    
    assert result is False


def test_telfhash_analyzer_filter_symbols_for_telfhash():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.elf")
    
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
    assert any(s["name"] == "main" for s in filtered)
    assert any(s["name"] == "global_var" for s in filtered)
    assert any(s["name"] == "weak_func" for s in filtered)


def test_telfhash_analyzer_should_skip_symbol():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.elf")
    
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


def test_telfhash_analyzer_extract_symbol_names():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.elf")
    
    symbols = [
        {"name": "zebra"},
        {"name": "apple"},
        {"name": "banana"},
        {"name": ""},
    ]
    
    names = analyzer._extract_symbol_names(symbols)
    
    assert names == ["apple", "banana", "zebra"]


def test_telfhash_analyzer_get_elf_symbols_empty():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.elf")
    analyzer._cmd_list = Mock(return_value=[])
    
    symbols = analyzer._get_elf_symbols()
    
    assert symbols == []


def test_telfhash_analyzer_get_elf_symbols_exception():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.elf")
    analyzer._cmd_list = Mock(side_effect=Exception("Test error"))
    
    symbols = analyzer._get_elf_symbols()
    
    assert symbols == []


def test_telfhash_analyzer_has_elf_symbols_no_symbols():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.elf")
    analyzer._cmd_list = Mock(return_value=None)
    
    result = analyzer._has_elf_symbols({})
    
    assert result is False


def test_telfhash_analyzer_has_elf_symbols_no_bin():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.elf")
    analyzer._cmd_list = Mock(return_value=[{"name": "symbol"}])
    
    result = analyzer._has_elf_symbols({})
    
    assert result is False


def test_telfhash_analyzer_has_elf_symbols_linux():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.elf")
    analyzer._cmd_list = Mock(return_value=[{"name": "symbol"}])
    
    info_cmd = {"bin": {"os": "linux"}}
    result = analyzer._has_elf_symbols(info_cmd)
    
    assert result is True


def test_telfhash_analyzer_has_elf_symbols_unix():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.elf")
    analyzer._cmd_list = Mock(return_value=[{"name": "symbol"}])
    
    info_cmd = {"bin": {"os": "unix"}}
    result = analyzer._has_elf_symbols(info_cmd)
    
    assert result is True


def test_telfhash_analyzer_has_elf_symbols_exception():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.elf")
    analyzer._cmd_list = Mock(side_effect=Exception("Test error"))
    
    result = analyzer._has_elf_symbols({"bin": {"os": "linux"}})
    
    assert result is False


def test_telfhash_analyzer_filter_symbols_case_insensitive():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.elf")
    
    symbols = [
        {"type": "func", "bind": "global", "name": "main"},
        {"type": "FUNC", "bind": "GLOBAL", "name": "printf"},
    ]
    
    filtered = analyzer._filter_symbols_for_telfhash(symbols)
    
    assert len(filtered) == 2


def test_telfhash_analyzer_extract_symbol_names_with_whitespace():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.elf")
    
    symbols = [
        {"name": "  func1  "},
        {"name": " func2"},
    ]
    
    names = analyzer._extract_symbol_names(symbols)
    
    assert "func1" in names
    assert "func2" in names


def test_telfhash_analyzer_analyze_adds_telfhash_field():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.elf")
    
    with patch.object(analyzer, "analyze", wraps=analyzer.analyze) as mock_analyze:
        with patch("r2inspect.abstractions.hashing_strategy.R2HashingStrategy.analyze") as super_analyze:
            super_analyze.return_value = {"hash_value": "test_hash"}
            
            result = analyzer.analyze()
            
            assert "telfhash" in result
            assert result["telfhash"] == "test_hash"


def test_telfhash_analyzer_analyze_telfhash_already_present():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.elf")
    
    with patch("r2inspect.abstractions.hashing_strategy.R2HashingStrategy.analyze") as super_analyze:
        super_analyze.return_value = {"telfhash": "existing_hash"}
        
        result = analyzer.analyze()
        
        assert result["telfhash"] == "existing_hash"


@pytest.mark.skipif(not TELFHASH_AVAILABLE, reason="telfhash library not available")
def test_telfhash_analyzer_compare_hashes():
    hash1 = "test_hash1"
    hash2 = "test_hash2"
    
    result = TelfhashAnalyzer.compare_hashes(hash1, hash2)


def test_telfhash_analyzer_compare_hashes_not_available():
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", False):
        result = TelfhashAnalyzer.compare_hashes("hash1", "hash2")
        assert result is None


def test_telfhash_analyzer_compare_hashes_empty():
    result = TelfhashAnalyzer.compare_hashes("", "hash2")
    assert result is None
    
    result = TelfhashAnalyzer.compare_hashes("hash1", "")
    assert result is None
    
    result = TelfhashAnalyzer.compare_hashes(None, "hash2")
    assert result is None


@pytest.mark.skipif(not TELFHASH_AVAILABLE, reason="telfhash library not available")
def test_telfhash_analyzer_calculate_telfhash_from_file():
    result = TelfhashAnalyzer.calculate_telfhash_from_file("/nonexistent/file.elf")


def test_telfhash_analyzer_calculate_telfhash_from_file_not_available():
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", False):
        result = TelfhashAnalyzer.calculate_telfhash_from_file("/test/file.elf")
        assert result is None


def test_telfhash_analyzer_should_skip_multiple_patterns():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.elf")
    
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


def test_telfhash_analyzer_filter_symbols_empty_name():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.elf")
    
    symbols = [
        {"type": "FUNC", "bind": "GLOBAL", "name": ""},
        {"type": "FUNC", "bind": "GLOBAL", "name": "   "},
    ]
    
    filtered = analyzer._filter_symbols_for_telfhash(symbols)
    
    assert len(filtered) == 0


def test_telfhash_analyzer_get_elf_symbols_with_count():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.elf")
    
    test_symbols = [{"name": f"func{i}"} for i in range(100)]
    analyzer._cmd_list = Mock(return_value=test_symbols)
    
    symbols = analyzer._get_elf_symbols()
    
    assert len(symbols) == 100


def test_telfhash_analyzer_extract_symbol_names_empty_list():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.elf")
    
    names = analyzer._extract_symbol_names([])
    
    assert names == []


def test_telfhash_analyzer_filter_symbols_object_type():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.elf")
    
    symbols = [
        {"type": "OBJECT", "bind": "GLOBAL", "name": "data_object"},
        {"type": "OBJECT", "bind": "WEAK", "name": "weak_object"},
    ]
    
    filtered = analyzer._filter_symbols_for_telfhash(symbols)
    
    assert len(filtered) == 2


def test_telfhash_analyzer_filter_symbols_mixed():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.elf")
    
    symbols = [
        {"type": "FUNC", "bind": "GLOBAL", "name": "function1"},
        {"type": "OBJECT", "bind": "GLOBAL", "name": "variable1"},
        {"type": "SECTION", "bind": "LOCAL", "name": "section1"},
        {"type": "FILE", "bind": "LOCAL", "name": "file1"},
    ]
    
    filtered = analyzer._filter_symbols_for_telfhash(symbols)
    
    assert len(filtered) == 2
    assert all(s["type"] in ["FUNC", "OBJECT"] for s in filtered)


def test_telfhash_analyzer_calculate_hash_non_elf():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.bin")
    
    with patch.object(analyzer, "_is_elf_file", return_value=False):
        hash_value, method, error = analyzer._calculate_hash()
        
        assert hash_value is None
        assert method is None
        assert "not an ELF binary" in error


def test_telfhash_analyzer_analyze_symbols_non_elf():
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file.bin")
    
    with patch.object(analyzer, "_is_elf_file", return_value=False):
        with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True):
            result = analyzer.analyze_symbols()
            
            assert result["is_elf"] is False
            assert result["error"] == "File is not an ELF binary"
